#!/usr/bin/env python3
"""
adb_memdump.py - /proc/{pid}/mem based memory dumper via adb root
Bypasses frida/ptrace requirement entirely.

Usage:
  python adb_memdump.py <package_or_pid> [-o outdir] [-r] [-s]
                        [--search TERM] [--include-heap]

  -r             include read-only regions (more data, more I/O errors)
  -s             run strings on dump files after dumping
  --search TERM  search for TERM while dumping (can repeat: --search pw --search jwt)
  --include-heap read regions > --max-size in chunks instead of skipping
"""

import subprocess
import struct
import os
import sys
import argparse
import re

CHUNK_SIZE = 4 * 1024 * 1024  # 4 MB per chunk for large regions
MIN_STRING_LEN = 6             # minimum printable-ASCII run for strings.txt

# ── ADB helpers ──────────────────────────────────────────────────────────────

def adb(*args, binary=False):
    """Run an adb command, return stdout."""
    cmd = ["adb"] + list(args)
    result = subprocess.run(cmd, capture_output=True)
    if binary:
        return result.stdout
    return result.stdout.decode(errors="replace").strip()

def adb_root(cmd):
    """Run a shell command as root via adb, return stdout text."""
    return adb("shell", f"su -c '{cmd}'")

def adb_root_binary(cmd):
    """Run a shell command as root via adb, return raw bytes (exec-out)."""
    result = subprocess.run(
        ["adb", "exec-out", f"su -c '{cmd}'"],
        capture_output=True
    )
    return result.stdout

# ── PID resolution ────────────────────────────────────────────────────────────

def get_pid(target):
    if str(target).isdigit():
        return int(target)
    out = adb_root(f"pidof {target}")
    if out.strip().isdigit():
        return int(out.strip())
    out = adb_root(f"ps -A | grep {target}")
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            return int(parts[1])
        for i, p in enumerate(parts):
            if p.isdigit() and i > 0:
                return int(p)
    return None

# ── Maps parser ───────────────────────────────────────────────────────────────

def read_maps(pid):
    """Returns list of dicts: {start, end, perms, name}"""
    raw = adb_root(f"cat /proc/{pid}/maps")
    regions = []
    for line in raw.splitlines():
        m = re.match(r"([0-9a-f]+)-([0-9a-f]+)\s+(\S+)\s+\S+\s+\S+\s+\S+\s*(.*)", line)
        if not m:
            continue
        start = int(m.group(1), 16)
        end   = int(m.group(2), 16)
        perms = m.group(3)
        name  = m.group(4).strip()
        regions.append({"start": start, "end": end, "perms": perms, "name": name})
    return regions

# ── Memory reader ─────────────────────────────────────────────────────────────

DEVICE_READER = r"""
import sys, os
pid, start_hex, size = int(sys.argv[1]), int(sys.argv[2], 16), int(sys.argv[3])
try:
    with open(f'/proc/{pid}/mem', 'rb', buffering=0) as f:
        f.seek(start_hex)
        remaining = size
        while remaining > 0:
            chunk = min(remaining, 65536)
            data = f.read(chunk)
            if not data:
                break
            sys.stdout.buffer.write(data)
            remaining -= len(data)
except Exception as e:
    sys.stderr.write(str(e) + '\n')
"""

def push_reader_script():
    path = "/data/local/tmp/_memdump_reader.py"
    script_bytes = DEVICE_READER.encode()
    proc = subprocess.run(
        ["adb", "shell", f"su -c 'cat > {path}'"],
        input=script_bytes,
        capture_output=True
    )
    adb_root(f"chmod 755 {path}")
    return path

def read_region_via_python(pid, start, size, reader_path):
    """Use device-side Python to read a memory region."""
    data = subprocess.run(
        ["adb", "exec-out",
         f"su -c 'python3 {reader_path} {pid} {start:x} {size}'"],
        capture_output=True
    ).stdout
    return data

def read_region_via_dd(pid, start, size):
    """Use dd with busybox skip_bytes (works on Magisk busybox)."""
    cmd = (f"dd if=/proc/{pid}/mem bs=4096 "
           f"iflag=skip_bytes,count_bytes "
           f"skip={start} count={size} 2>/dev/null")
    return adb_root_binary(cmd)

def read_region_chunked(pid, start, size, method, reader_path):
    """Read a large region in CHUNK_SIZE pieces, yield (offset, data) tuples."""
    offset = 0
    while offset < size:
        chunk = min(CHUNK_SIZE, size - offset)
        addr  = start + offset
        if method == "python":
            data = read_region_via_python(pid, addr, chunk, reader_path)
        else:
            data = read_region_via_dd(pid, addr, chunk)
        if data:
            yield offset, data
        offset += chunk

def detect_read_method(pid):
    """Auto-detect whether device has python3 or busybox dd."""
    py = adb_root("which python3 2>/dev/null || echo ''").strip()
    if py and py != "''":
        return "python"
    test = adb_root_binary(
        f"dd if=/proc/{pid}/mem bs=1 iflag=skip_bytes,count_bytes skip=0 count=0 2>/dev/null; echo OK"
    )
    if b"OK" in test:
        return "dd"
    return None

# ── String extraction ─────────────────────────────────────────────────────────

_PRINTABLE = re.compile(rb'[ -~]{' + str(MIN_STRING_LEN).encode() + rb',}')

def extract_strings(data):
    """Return list of printable ASCII strings found in data."""
    return [m.group().decode("ascii", errors="replace") for m in _PRINTABLE.finditer(data)]

# ── Search ────────────────────────────────────────────────────────────────────

def search_data(data, terms, region_start, chunk_offset=0):
    """Search data for each term (bytes). Print hits with address."""
    hits = []
    for term in terms:
        term_bytes = term.encode("utf-8") if isinstance(term, str) else term
        pos = 0
        while True:
            idx = data.find(term_bytes, pos)
            if idx == -1:
                break
            abs_addr = region_start + chunk_offset + idx
            ctx_start = max(0, idx - 32)
            ctx_end   = min(len(data), idx + len(term_bytes) + 32)
            ctx = data[ctx_start:ctx_end]
            hits.append((term, abs_addr, ctx))
            pos = idx + 1
    return hits

def print_hit(term, abs_addr, ctx):
    safe = ctx.replace(b'\x00', b'.').decode("ascii", errors=".")
    print(f"  [MATCH] '{term}' @ 0x{abs_addr:016x}  ctx: {safe!r}")

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="adb /proc/pid/mem dumper")
    parser.add_argument("target", help="package name or PID")
    parser.add_argument("-o", "--out", default="dump_adb", help="output directory")
    parser.add_argument("-r", "--read-only", action="store_true",
                        help="also dump read-only (r--) regions")
    parser.add_argument("-s", "--strings-bin", action="store_true",
                        help="run external 'strings' binary on dump files")
    parser.add_argument("--max-size", type=int, default=200*1024*1024,
                        help="regions larger than this are skipped unless --include-heap (bytes, default 200MB)")
    parser.add_argument("--search", metavar="TERM", action="append", default=[],
                        help="search for TERM in memory while dumping (repeatable)")
    parser.add_argument("--include-heap", action="store_true",
                        help="dump regions larger than --max-size in chunks (e.g. 512MB Java heap)")
    args = parser.parse_args()

    # Check adb connection
    devices = adb("devices")
    if "device" not in devices:
        print("No adb device connected."); sys.exit(1)

    print(f"[*] Resolving PID for: {args.target}")
    pid = get_pid(args.target)
    if not pid:
        print(f"[-] Could not find PID for '{args.target}'"); sys.exit(1)
    print(f"[+] PID: {pid}")

    print("[*] Reading /proc/{}/maps ...".format(pid))
    regions = read_maps(pid)
    if not regions:
        print("[-] No memory regions found (check root access)"); sys.exit(1)
    print(f"[+] Found {len(regions)} regions")

    # Filter regions
    if args.read_only:
        target_perms = ("rw", "r-")
    else:
        target_perms = ("rw",)

    def is_target(r):
        return any(r["perms"].startswith(p) for p in target_perms) and (r["end"] - r["start"]) > 0

    normal_regions = [r for r in regions if is_target(r) and (r["end"] - r["start"]) <= args.max_size]
    large_regions  = [r for r in regions if is_target(r) and (r["end"] - r["start"]) >  args.max_size]

    if args.include_heap:
        print(f"[+] Normal regions: {len(normal_regions)}  Large (heap) regions: {len(large_regions)}")
    else:
        if large_regions:
            print(f"[+] Dumpable regions: {len(normal_regions)}  "
                  f"(skipping {len(large_regions)} large regions — use --include-heap to dump them)")
        else:
            print(f"[+] Dumpable regions: {len(normal_regions)}")

    # Detect read method
    print("[*] Detecting read method...")
    method = detect_read_method(pid)
    if method == "python":
        print("[+] Method: device python3")
        reader_path = push_reader_script()
    elif method == "dd":
        print("[+] Method: busybox dd skip_bytes")
        reader_path = None
    else:
        print("[-] Neither python3 nor busybox dd available on device")
        print("    Install Termux python or Magisk busybox")
        sys.exit(1)

    # Output directory
    os.makedirs(args.out, exist_ok=True)

    # Save maps
    maps_path = os.path.join(args.out, "maps.txt")
    with open(maps_path, "w") as f:
        for r in regions:
            f.write(f"{r['start']:016x}-{r['end']:016x} {r['perms']} {r['name']}\n")
    print(f"[+] Maps saved to {maps_path}")

    strings_path = os.path.join(args.out, "strings.txt")
    search_log_path = os.path.join(args.out, "search_hits.txt")

    if args.search:
        print(f"[*] Search terms: {args.search}")
    use_strings = True  # always generate strings.txt

    total_success = 0
    total_errors  = 0

    # ── Dump normal regions ──────────────────────────────────────────────────
    dumpable = normal_regions
    total = len(dumpable)

    with open(strings_path, "w", encoding="utf-8") as sf, \
         open(search_log_path, "w", encoding="utf-8") as hf:

        hf.write(f"Search terms: {args.search}\n\n")

        for i, region in enumerate(dumpable):
            start = region["start"]
            end   = region["end"]
            size  = end - start
            perms = region["perms"]
            name  = region["name"].replace("/", "_").replace(" ", "_")[:40]
            fname = f"{start:016x}_{end:016x}_{perms}_{name}.bin"
            fpath = os.path.join(args.out, fname)

            sys.stdout.write(f"\r[{i+1}/{total}] {start:016x} ({size//1024}K) {perms:<4} {name[:30]:<30}   ")
            sys.stdout.flush()

            try:
                if method == "python":
                    data = read_region_via_python(pid, start, size, reader_path)
                else:
                    data = read_region_via_dd(pid, start, size)

                if not data:
                    total_errors += 1
                    continue

                with open(fpath, "wb") as f:
                    f.write(data)
                total_success += 1

                # strings
                for s in extract_strings(data):
                    sf.write(f"{start:016x}  {s}\n")

                # search
                if args.search:
                    hits = search_data(data, args.search, start)
                    for term, addr, ctx in hits:
                        msg = f"[MATCH] '{term}' @ 0x{addr:016x}  ctx: {ctx.replace(b'\\x00', b'.').decode('ascii','replace')!r}"
                        print(f"\n  {msg}")
                        hf.write(msg + "\n")

            except Exception as e:
                total_errors += 1

        # ── Dump large regions (heap) ────────────────────────────────────────
        if args.include_heap and large_regions:
            print(f"\n[*] Dumping {len(large_regions)} large region(s) in {CHUNK_SIZE//1024//1024}MB chunks...")

            for region in large_regions:
                start = region["start"]
                end   = region["end"]
                size  = end - start
                perms = region["perms"]
                name  = region["name"].replace("/", "_").replace(" ", "_")[:40]
                print(f"  Region: {start:016x}-{end:016x} ({size//1024//1024}MB) {perms} {name[:40]}")

                region_fpath = os.path.join(args.out, f"{start:016x}_{end:016x}_{perms}_{name}.bin")
                n_chunks = (size + CHUNK_SIZE - 1) // CHUNK_SIZE

                with open(region_fpath, "wb") as rf:
                    for chunk_i, (chunk_offset, data) in enumerate(
                            read_region_chunked(pid, start, size, method, reader_path)):
                        sys.stdout.write(
                            f"\r    chunk {chunk_i+1}/{n_chunks} "
                            f"@ {start+chunk_offset:016x} ({len(data)//1024}K)   ")
                        sys.stdout.flush()
                        rf.write(data)
                        total_success += 1

                        # strings
                        for s in extract_strings(data):
                            sf.write(f"{start+chunk_offset:016x}  {s}\n")

                        # search
                        if args.search:
                            hits = search_data(data, args.search, start, chunk_offset)
                            for term, addr, ctx in hits:
                                msg = (f"[MATCH] '{term}' @ 0x{addr:016x}  "
                                       f"ctx: {ctx.replace(b'\\x00', b'.').decode('ascii','replace')!r}")
                                print(f"\n    {msg}")
                                hf.write(msg + "\n")

                print(f"\n  [+] Saved: {region_fpath}")

    print(f"\n\n[+] Done. Success: {total_success}  Errors: {total_errors}")
    print(f"[+] Output:      {os.path.abspath(args.out)}")
    print(f"[+] strings.txt: {os.path.abspath(strings_path)}")
    if args.search:
        print(f"[+] search_hits: {os.path.abspath(search_log_path)}")

    # ── Optional external strings binary ────────────────────────────────────
    if args.strings_bin:
        print("[*] Running external strings binary...")
        for fname in os.listdir(args.out):
            if not fname.endswith(".bin"):
                continue
            fpath = os.path.join(args.out, fname)
            out_path = fpath.replace(".bin", ".ext_strings.txt")
            try:
                result = subprocess.run(["strings", fpath], capture_output=True)
                with open(out_path, "wb") as f:
                    f.write(result.stdout)
            except FileNotFoundError:
                pass


if __name__ == "__main__":
    main()
