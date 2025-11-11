# RustPcap - Homemade libpcap Implementation

A pure Rust implementation of libpcap with **zero third-party dependencies**. Uses only the standard library and direct Linux syscalls for maximum efficiency and portability.

## Features

- ✅ **No third-party dependencies** - Only uses Rust standard library
- ✅ **Direct syscalls** - Uses inline assembly for Linux syscalls (no libc)
- ✅ **Live packet capture** - Capture packets from network interfaces
- ✅ **Pcap file I/O** - Read and write standard pcap files
- ✅ **BPF filtering** - Basic BPF filter support
- ✅ **Optimized** - Efficient memory usage and zero-copy where possible
- ✅ **Single file** - Everything in one `rustpcap.rs` file

## Requirements

- Rust 1.59+ (for stable `core::arch::asm!`)
- Linux (x86_64) - Other architectures can be added
- Root privileges for live packet capture

## Compilation

```bash
# Compile the library
rustc --edition 2021 rustpcap.rs

# Compile with example
rustc --edition 2021 example.rs rustpcap.rs
```

## Usage

### Live Packet Capture:

```rust
use rustpcap::*;

// Create and configure capture
let mut pcap = open_live("any", 65535, false, 1000)?;

// Capture packets
loop {
    match pcap.next_ex() {
        Ok(Some((hdr, packet))) => {
            println!("Packet: {} bytes", hdr.caplen);
            // Process packet...
        }
        Ok(None) => continue,
        Err(e) => break,
    }
}
```

### Reading from pcap file:

```rust
let mut pcap_file = PcapFile::open_offline("capture.pcap")?;

while let Some((hdr, packet)) = pcap_file.next_ex()? {
    println!("Packet: {} bytes", hdr.caplen);
}
```

### Writing to pcap file:

```rust
let pcap = Pcap::create("dummy")?;
let mut dumper = PcapDumper::open(&pcap, "output.pcap")?;

dumper.dump(&hdr, &packet_data)?;
dumper.flush()?;
```

## API

### Main Types

- `Pcap` - Live packet capture handle
- `PcapFile` - Pcap file reader
- `PcapDumper` - Pcap file writer
- `PcapPkthdr` - Packet header with timestamp and lengths
- `BpfProgram` - BPF filter program

### Key Functions

- `Pcap::create(device)` - Create capture handle
- `pcap.set_snaplen(len)` - Set snapshot length
- `pcap.set_promisc(enabled)` - Enable promiscuous mode
- `pcap.activate()` - Start capture
- `pcap.next_ex()` - Get next packet
- `pcap.stats()` - Get capture statistics
- `open_live(...)` - Convenience function for live capture
- `PcapFile::open_offline(filename)` - Open pcap file

## Architecture

The implementation uses:

1. **Direct Linux syscalls** via inline assembly (x86_64)
   - `socket()` - Create raw socket
   - `recvfrom()` - Receive packets
   - `setsockopt()` - Configure socket
   - `close()` - Close socket
   - `fcntl()` - Set non-blocking mode

2. **Pcap file format** - Standard libpcap format
   - File header with magic number
   - Packet headers with timestamps
   - Binary packet data

3. **BPF interpreter** - Simplified BPF filter execution
   - Supports basic instructions (LD, JEQ, RET, etc.)
   - Can be extended for full BPF support

## Performance

- Zero-copy packet reading where possible
- Efficient buffer management
- Minimal allocations
- Inline syscalls for low overhead

## Limitations

- Currently Linux x86_64 only (other architectures can be added)
- Simplified BPF filter (full BPF compiler not implemented)
- No promiscuous mode binding (would need additional syscalls)
- No device enumeration (can be added)

## Example

See `example.rs` for a complete example showing:
- Live packet capture
- Reading from pcap files
- Writing to pcap files

Run with:
```bash
sudo ./example  # Requires root for live capture
```

## License

This is a homemade implementation for educational purposes. The original libpcap is BSD licensed.

## Notes

- Requires root/sudo for live packet capture on Linux
- File operations work without special privileges
- Optimized for performance with minimal overhead
- All code in single file for easy integration

