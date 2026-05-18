# adb_memdump

Android process memory dumper via `/proc/{pid}/mem` over ADB root.  
**Does not use ptrace, Frida, or any form of process attachment.**

## Why this exists

Standard memory dumping approaches on Android require attaching to the target process:

| Method | Requirement | Blocked by |
|---|---|---|
| Frida | ptrace attach | Anti-debug (self-ptrace, xshield, etc.) |
| gcore | ptrace attach | Same |
| `am dumpheap` | debuggable flag | `SecurityException` on release builds |
| `/proc/pid/mem` | **root only** | Nothing (kernel-level access) |

If the device is rooted and the app has anti-debug that occupies the ptrace slot, this tool is the only reliable option.

## Requirements

**Host**
- Python 3.6+
- `adb` in PATH and a device connected

**Device**
- Root access (`su` available — Magisk, KernelSU, etc.)
- One of:
  - `busybox dd` with `iflag=skip_bytes,count_bytes` support (standard on Magisk busybox)
  - `python3` on device (Termux)

No Frida, no app modification, no debuggable flag.

## Installation

```bash
git clone https://github.com/devjanger/adb_memdump
cd adb_memdump
# no dependencies — stdlib only
```

## Usage

```
python adb_memdump.py <package_or_pid> [options]
```

### Options

| Flag | Description |
|---|---|
| `-o DIR` | Output directory (default: `dump_adb`) |
| `-r` | Include read-only (`r--`) regions in addition to `rw-` |
| `--include-heap` | Dump regions larger than `--max-size` in 4MB chunks (Java heap, etc.) |
| `--search TERM` | Search for TERM while dumping — repeatable, prints hits with address + context |
| `--max-size N` | Skip regions larger than N bytes unless `--include-heap` (default: 200MB) |
| `-s` | Run external `strings` binary on `.bin` files after dumping |

### Examples

**Basic dump (rw regions, skip heap)**
```bash
python adb_memdump.py com.example.app -o out/
```

**Full dump including 512MB Java heap**
```bash
python adb_memdump.py com.example.app -o out/ --include-heap
```

**Search for credentials while dumping**
```bash
python adb_memdump.py com.example.app -o out/ --include-heap \
    --search "password" --search "Bearer " --search "token"
```

**Use PID directly**
```bash
python adb_memdump.py 12345 -o out/
```

**Read-only regions too (e.g. to capture mapped DEX files)**
```bash
python adb_memdump.py com.example.app -o out/ -r
```

## Output

```
out/
├── maps.txt                          # /proc/{pid}/maps snapshot
├── strings.txt                       # all printable ASCII strings (≥6 chars) with addresses
├── search_hits.txt                   # matches for --search terms (if used)
└── <start>_<end>_<perms>_<name>.bin  # one file per memory region
```

**`strings.txt` format:**
```
0000007a1b000000  /data/app/com.example.app-abc123/base.apk
0000007a1b000040  libexample.so
...
```

**`search_hits.txt` format:**
```
[MATCH] 'Bearer ' @ 0x000000135600a4f0  ctx: '...{"alg":"HS256"}Bearer eyJhbGci...'
```

## How it works

1. Resolves the target PID via `pidof` or `ps -A | grep`
2. Reads `/proc/{pid}/maps` to enumerate virtual memory regions
3. For each writable region, reads `/proc/{pid}/mem` by seeking to the region's start address
4. Two read backends are auto-detected:
   - **busybox dd** — `dd if=/proc/{pid}/mem iflag=skip_bytes,count_bytes skip=ADDR count=SIZE`
   - **device python3** — pushes a small reader script to `/data/local/tmp/` and runs it via `adb exec-out`
5. Regions larger than `--max-size` are read in 4MB chunks when `--include-heap` is set
6. Built-in string extraction runs on each chunk as it arrives (no second pass needed)

## Notes on the Java heap

Android's ART runtime allocates the Java heap as a single large anonymous mapping (`[anon:dalvik-main space]`), typically 512MB reserved.  
By default this is skipped (> 200MB limit). Pass `--include-heap` to dump it in chunks.  
Java `String` objects are stored as **UTF-16 LE** in the heap — search for the UTF-16 encoded form if UTF-8 matches nothing.


## Legal

For use on devices and applications you own or have explicit written authorization to test.


``` shell
# Use LDAP to find computers configured for unconstrained delegation.
ldapsearch (&(samAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=524288)) --attributes samAccountName

# Triage tickets
krb_triage

# Confirm that dyork is a Domain Admin.
ldapsearch samAccountName=dyork --attributes memberOf

# Dump the TGT.
krb_dump /user:dyork /service:krbtgt
```

