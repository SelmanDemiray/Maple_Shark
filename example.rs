// Example usage of rustpcap
// Compile with: rustc --edition 2021 example.rs rustpcap.rs

mod rustpcap;

use rustpcap::*;
use std::time::Duration;

fn main() {
    println!("RustPcap Example");
    println!("=================");
    
    // Example 1: Capture packets from network interface
    println!("\n1. Attempting to capture packets (requires root)...");
    match open_live("any", 65535, false, 1000) {
        Ok(mut pcap) => {
            println!("   Capture handle created successfully!");
            println!("   Capturing up to 10 packets...");
            
            let mut count = 0;
            while count < 10 {
                match pcap.next_ex() {
                    Ok(Some((hdr, packet))) => {
                        count += 1;
                        println!("   Packet {}: {} bytes captured at {:?}", 
                            count, hdr.caplen, hdr.ts);
                        if packet.len() > 0 {
                            println!("      First 16 bytes: {:02x?}", &packet[..packet.len().min(16)]);
                        }
                    }
                    Ok(None) => {
                        // No packet available, continue
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(rustpcap::PCAP_ERROR_BREAK) => {
                        println!("   Capture loop broken");
                        break;
                    }
                    Err(e) => {
                        println!("   Error: {}", e);
                        break;
                    }
                }
            }
            
            match pcap.stats() {
                Ok(stats) => {
                    println!("   Statistics: {} received, {} dropped", 
                        stats.ps_recv, stats.ps_drop);
                }
                Err(e) => println!("   Failed to get stats: {}", e),
            }
        }
        Err(e) => {
            println!("   Failed to create capture: {}", e);
            println!("   Note: This is normal if not running as root");
        }
    }
    
    // Example 2: Read from pcap file
    println!("\n2. Reading from pcap file (if test.pcap exists)...");
    match PcapFile::open_offline("test.pcap") {
        Ok(mut pcap_file) => {
            println!("   File opened successfully!");
            println!("   Link type: {}", pcap_file.datalink());
            
            let mut count = 0;
            while count < 5 {
                match pcap_file.next_ex() {
                    Ok(Some((hdr, packet))) => {
                        count += 1;
                        println!("   Packet {}: {} bytes", count, hdr.caplen);
                    }
                    Ok(None) => {
                        println!("   End of file");
                        break;
                    }
                    Err(e) => {
                        println!("   Error reading packet: {}", e);
                        break;
                    }
                }
            }
        }
        Err(e) => {
            println!("   Failed to open file: {}", e);
            println!("   (This is normal if test.pcap doesn't exist)");
        }
    }
    
    // Example 3: Write to pcap file
    println!("\n3. Writing test packet to test_out.pcap...");
    match Pcap::create("dummy") {
        Ok(pcap) => {
            match PcapDumper::open(&pcap, "test_out.pcap") {
                Ok(mut dumper) => {
                    let test_packet = vec![0u8; 64];
                    let hdr = PcapPkthdr {
                        ts: std::time::SystemTime::now(),
                        caplen: 64,
                        len: 64,
                    };
                    match dumper.dump(&hdr, &test_packet) {
                        Ok(_) => {
                            dumper.flush().unwrap();
                            println!("   Test packet written successfully!");
                        }
                        Err(e) => println!("   Failed to write packet: {}", e),
                    }
                }
                Err(e) => println!("   Failed to create dumper: {}", e),
            }
        }
        Err(e) => println!("   Failed to create pcap: {}", e),
    }
    
    println!("\nExample completed!");
}

