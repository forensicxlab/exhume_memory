# exhume_memory

`exhume_memory` is a specialized memory forensics tool for acquisition and analysis, built on the `memflow` framework. It supports high-speed BitLocker key extraction, process listing, and triage.

## Features

- **BitLocker Key Recovery**: Fast extraction of FVEK/VMK keys using pool tag and signature scanning.
- **Parallel Scanning**: Multi-threaded physical memory analysis for raw memory dumps.
- **Multiple Connectors**: Supports both LeechCore (FPGA/USB hardware) and raw memory images.
- **Process Listing and Triage**: Enumerate processes and inspect modules with architecture detection.

## Prerequisites

### LeechCore (for pcileech connector)

To use `exhume_memory` with an FPGA device (pcileech), you need the LeechCore runtime libraries.

#### macOS
1. Download the latest LeechCore macOS release ($LEECHCORE_RELEASE_URL).
2. Extract the libraries (`leechcore.dylib`, `leechcore_ft601_driver_macos.dylib`, etc.).
3. Place them in one of the following locations:
   - `src-tauri/binaries/bin-macos/LeechCore/runtime` when embedding `exhume_memory` into the Thanatology Tauri app.
   - A directory named `lc-runtime` in the same folder as the `exhume_memory` binary.
   - Any directory in your `DYLD_LIBRARY_PATH`.
   - `/usr/local/lib` or other standard library paths.

When run inside Thanatology on macOS, `exhume_memory` now prefers the packaged Tauri runtime at `binaries/bin-macos/LeechCore/runtime` and falls back to `lc-runtime` for standalone workflows.

#### Windows / Linux
Follow the standard `memflow` and `leechcore` installation guides for your platform.

## Installation

```bash
# Clone the repository
git clone https://github.com/forensicxlab/exhume_memory.git
cd exhume_memory

# Build the project
cargo build --release
```

## Usage

Use `--json` before the subcommand to emit structured output on stdout.

```bash
./target/release/exhume_memory --json --connector /path/to/dump.raw --connector-type rawmem pslist
```

### BitLocker Recovery

**Raw Memory Dump (High Speed Parallel Scan):**
```bash
./target/release/exhume_memory --connector /path/to/dump.raw --connector-type rawmem bitlocker
```

**Live System (LeechCore FPGA):**
```bash
./target/release/exhume_memory --connector ":device=FPGA" --connector-type pcileech bitlocker
```

### Process Listing (`pslist`)

```bash
./target/release/exhume_memory --connector ":device=FPGA" pslist
```

```bash
./target/release/exhume_memory --json --connector ":device=FPGA" pslist
```

### Process Triage

```bash
./target/release/exhume_memory --connector /path/to/dump.raw --connector-type rawmem triage --pid 640
```

### Environment Variables

```bash
./target/release/exhume_memory --connector /path/to/dump.raw --connector-type rawmem envars --pid 640
```

```bash
./target/release/exhume_memory --connector /path/to/dump.raw --connector-type rawmem envars --pid 640 --name USERDOMAIN
```

### Memory Dumping

```bash
./target/release/exhume_memory memdump --end 0x100000000 --out memory.raw
```

`memdump` always starts at `0x0`. If `--end` is omitted, it dumps to the connector's resolved max
physical address.

```bash
./target/release/exhume_memory memdump --out memory.raw
```

### Example: Raw Dump BitLocker Scan

```bash
cargo run --manifest-path members/exhume_memory/Cargo.toml -- \
  --json \
  --connector-type rawmem \
  --connector /Volumes/Forensics/suspect_memdum.raw \
  bitlocker
```

## License

This project is licensed under the MIT License.
