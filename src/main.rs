mod rustpcap;
mod packet_parser;

use eframe::egui;
use crate::rustpcap::*;
use crate::packet_parser::{PacketInfo, parse_packet, is_in_network};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::SystemTime;

struct NetworkCatcherApp {
    packets: Arc<Mutex<Vec<PacketInfo>>>,
    capture_active: Arc<Mutex<bool>>,
    stats: Arc<Mutex<CaptureStats>>,
    selected_packet: Option<usize>,
    filter_text: String,
    network_filter: String,
    error_message: Arc<Mutex<Option<String>>>,
    repaint_sender: Option<egui::Context>,
}

#[derive(Default, Clone)]
struct CaptureStats {
    total_packets: u64,
    dropped_packets: u64,
    bytes_received: u64,
    all_packets_received: u64,
    parsed_packets: u64,
}

impl NetworkCatcherApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        Self {
            packets: Arc::new(Mutex::new(Vec::new())),
            capture_active: Arc::new(Mutex::new(false)),
            stats: Arc::new(Mutex::new(CaptureStats::default())),
            selected_packet: None,
            filter_text: String::new(),
            network_filter: String::from("192.168.0.0/24"),
            error_message: Arc::new(Mutex::new(None)),
            repaint_sender: Some(cc.egui_ctx.clone()),
        }
    }

    fn start_capture(&self) {
        let packets = self.packets.clone();
        let active = self.capture_active.clone();
        let stats = self.stats.clone();
        let error_message = self.error_message.clone();
        let ctx = self.repaint_sender.clone();
        let network_filter = self.network_filter.clone();

        // Clear any previous error
        *error_message.lock().unwrap() = None;
        *active.lock().unwrap() = true;
        
        // Reset stats when starting new capture
        *stats.lock().unwrap() = CaptureStats::default();
        
        // Request initial repaint to show reset stats
        if let Some(ref ctx) = ctx {
            ctx.request_repaint();
        }

        thread::spawn(move || {
            match open_live("any", 65535, true, 1000) {
                Ok(mut pcap) => {
                    println!("Capture started - waiting for packets...");
                    println!("Note: On Windows, raw sockets can only capture:");
                    println!("  - Outgoing packets from this machine");
                    println!("  - Incoming packets NOT destined for this machine");
                    println!("  - Traffic between other machines on the network");
                    let mut packet_count = 0u64;
                    let mut last_status_time = std::time::Instant::now();
                    let mut last_heartbeat = std::time::Instant::now();
                    let mut recv_attempts = 0u64;
                    loop {
                        if !*active.lock().unwrap() {
                            break;
                        }

                        recv_attempts += 1;
                        // Heartbeat every 10 seconds to show we're still running
                        let now = std::time::Instant::now();
                        if now.duration_since(last_heartbeat).as_secs() >= 10 {
                            println!("[Heartbeat] Still running... ({} recv attempts, {} packets received)", 
                                recv_attempts, packet_count);
                            last_heartbeat = now;
                        }

                        match pcap.next_ex() {
                            Ok(Some((hdr, packet_data))) => {
                                packet_count += 1;
                                let mut stats_guard = stats.lock().unwrap();
                                stats_guard.all_packets_received += 1;
                                drop(stats_guard);
                                
                                // Periodic status update every 100 packets or every 5 seconds
                                let now = std::time::Instant::now();
                                if packet_count % 100 == 0 || now.duration_since(last_status_time).as_secs() >= 5 {
                                    let stats_guard = stats.lock().unwrap();
                                    println!("Status: {} received, {} parsed, {} filtered", 
                                        stats_guard.all_packets_received,
                                        stats_guard.parsed_packets,
                                        stats_guard.total_packets);
                                    last_status_time = now;
                                    
                                    // Request repaint to update GUI stats
                                    if let Some(ref ctx) = ctx {
                                        ctx.request_repaint();
                                    }
                                }
                                
                                if let Some(packet_info) = parse_packet(&packet_data, hdr.ts) {
                                    let mut stats_guard = stats.lock().unwrap();
                                    stats_guard.parsed_packets += 1;
                                    drop(stats_guard);
                                    
                                    // Debug: print first few packets
                                    if packet_count <= 10 {
                                        println!("Packet {}: {} -> {} ({})", 
                                            packet_count, 
                                            packet_info.src_ip, 
                                            packet_info.dst_ip, 
                                            packet_info.protocol);
                                    }
                                    
                                    // Filter by network (if specified)
                                    let should_include = if network_filter.is_empty() {
                                        true // No filter - show all packets
                                    } else {
                                        is_in_network(&packet_info.src_ip, &network_filter) ||
                                        is_in_network(&packet_info.dst_ip, &network_filter)
                                    };
                                    
                                    if should_include {
                                        let mut packets_guard = packets.lock().unwrap();
                                        packets_guard.push(packet_info);
                                        
                                        // Keep only last 10000 packets
                                        if packets_guard.len() > 10000 {
                                            packets_guard.remove(0);
                                        }

                                        let mut stats_guard = stats.lock().unwrap();
                                        stats_guard.total_packets += 1;
                                        stats_guard.bytes_received += hdr.caplen as u64;
                                        
                                        // Request GUI repaint when new packet arrives
                                        if let Some(ref ctx) = ctx {
                                            ctx.request_repaint();
                                        }
                                    } else if packet_count <= 10 {
                                        // Debug: Show packets that don't match the filter
                                        println!("Packet {} filtered out: {} -> {} (not in 192.168.0.0/24)", 
                                            packet_count, packet_info.src_ip, packet_info.dst_ip);
                                    }
                                } else {
                                    // Debug parse failures
                                    if packet_count <= 10 {
                                        println!("Packet {}: Failed to parse (size: {})", packet_count, packet_data.len());
                                        if packet_data.len() >= 14 {
                                            println!("  First 20 bytes: {:02x?}", &packet_data[..packet_data.len().min(20)]);
                                        }
                                    }
                                }
                            }
                            Ok(None) => {
                                thread::sleep(std::time::Duration::from_millis(10));
                            }
                            Err(PCAP_ERROR_BREAK) => {
                                break;
                            }
                            Err(_) => {
                                thread::sleep(std::time::Duration::from_millis(100));
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to start capture: {}", e);
                    *error_message.lock().unwrap() = Some(e);
                    *active.lock().unwrap() = false;
                    // Request repaint to show error
                    if let Some(ref ctx) = ctx {
                        ctx.request_repaint();
                    }
                }
            }
        });
    }

    fn stop_capture(&self) {
        *self.capture_active.lock().unwrap() = false;
    }
}

impl eframe::App for NetworkCatcherApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Request continuous repaint while capture is active to show stats updates
        let is_active = *self.capture_active.lock().unwrap();
        if is_active {
            ctx.request_repaint();
        }
        
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Network Traffic Catcher - 192.168.0.0/24 Network");

            // Error message display
            if let Some(error) = self.error_message.lock().unwrap().as_ref() {
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.colored_label(egui::Color32::from_rgb(255, 100, 100), "⚠ Error");
                            // Display multi-line error messages properly
                            for line in error.lines() {
                                ui.label(line);
                            }
                        });
                        if ui.button("✕").clicked() {
                            *self.error_message.lock().unwrap() = None;
                        }
                    });
                });
                ui.separator();
            }

            // Get capture status
            let is_active = *self.capture_active.lock().unwrap();

            // Control panel
            ui.horizontal(|ui| {
                if ui.button(if is_active { "Stop Capture" } else { "Start Capture" }).clicked() {
                    if is_active {
                        self.stop_capture();
                    } else {
                        self.start_capture();
                    }
                }

                if ui.button("Clear").clicked() {
                    self.packets.lock().unwrap().clear();
                    self.selected_packet = None;
                }

                ui.separator();

                // Stats display
                let stats = self.stats.lock().unwrap();
                ui.label(format!("Filtered Packets: {}", stats.total_packets));
                ui.label(format!("All Received: {}", stats.all_packets_received));
                ui.label(format!("Parsed: {}", stats.parsed_packets));
                ui.label(format!("Bytes: {} KB", stats.bytes_received / 1024));
            });

            ui.separator();

            // Network filter input
            ui.horizontal(|ui| {
                ui.label("Network Filter:");
                ui.text_edit_singleline(&mut self.network_filter);
                if ui.button("Clear Network Filter").clicked() {
                    self.network_filter.clear();
                }
                ui.label("(e.g., 192.168.0.0/24 or leave empty for all)");
            });

            // Text filter input
            ui.horizontal(|ui| {
                ui.label("Text Filter:");
                ui.text_edit_singleline(&mut self.filter_text);
            });

            ui.separator();

            // Packet list
            let packets = self.packets.lock().unwrap();
            let filtered_packets: Vec<(usize, &PacketInfo)> = if self.filter_text.is_empty() {
                packets.iter().enumerate().collect()
            } else {
                packets.iter()
                    .enumerate()
                    .filter(|(_, p)| {
                        p.src_ip.contains(&self.filter_text) ||
                        p.dst_ip.contains(&self.filter_text) ||
                        p.protocol.contains(&self.filter_text)
                    })
                    .collect()
            };

            // Show status message if no packets
            if filtered_packets.is_empty() && is_active {
                let stats = self.stats.lock().unwrap();
                if stats.all_packets_received == 0 {
                    ui.vertical_centered(|ui| {
                        ui.add_space(20.0);
                        ui.label("Waiting for packets...");
                        ui.label("On Windows, raw sockets can only capture:");
                        ui.label("  • Outgoing packets from this machine");
                        ui.label("  • Incoming packets NOT destined for this machine");
                        ui.add_space(10.0);
                        ui.label("Try: Opening a website, pinging a server, or generating network traffic");
                    });
                } else {
                    ui.vertical_centered(|ui| {
                        ui.add_space(20.0);
                        if self.network_filter.is_empty() {
                            ui.label(format!("Received {} packets, but none are being displayed", stats.all_packets_received));
                        } else {
                            ui.label(format!("Received {} packets, but none match the {} filter", stats.all_packets_received, self.network_filter));
                        }
                        ui.label("Check the terminal for packet details");
                    });
                }
            }

            egui::ScrollArea::vertical()
                .auto_shrink([false; 2])
                .show_rows(ui, 20.0, filtered_packets.len(), |ui, row_range| {
                    egui::Grid::new("packet_grid")
                        .num_columns(5)
                        .spacing([4.0, 2.0])
                        .show(ui, |ui| {
                            // Header
                            ui.strong("Time");
                            ui.strong("Source IP");
                            ui.strong("Dest IP");
                            ui.strong("Protocol");
                            ui.strong("Size");
                            ui.end_row();

                            // Rows
                            for (orig_idx, packet) in row_range.map(|i| &filtered_packets[i]) {
                                let is_selected = self.selected_packet == Some(*orig_idx);
                                
                                let response = ui.selectable_label(
                                    is_selected,
                                    format_packet_time(&packet.timestamp)
                                );
                                if response.clicked() {
                                    self.selected_packet = Some(*orig_idx);
                                }

                                ui.label(&packet.src_ip);
                                ui.label(&packet.dst_ip);
                                ui.label(&packet.protocol);
                                ui.label(format!("{} B", packet.size));
                                ui.end_row();
                            }
                        });
                });

            ui.separator();

            // Packet details
            if let Some(selected_idx) = self.selected_packet {
                if let Some(packet) = packets.get(selected_idx) {
                    ui.group(|ui| {
                        ui.heading("Packet Details");
                        ui.label(format!("Timestamp: {:?}", packet.timestamp));
                        ui.label(format!("Source IP: {}", packet.src_ip));
                        ui.label(format!("Destination IP: {}", packet.dst_ip));
                        ui.label(format!("Protocol: {}", packet.protocol));
                        ui.label(format!("Size: {} bytes", packet.size));
                        
                        ui.separator();
                        ui.label("Raw Data (Hex):");
                        egui::ScrollArea::vertical()
                            .max_height(200.0)
                            .show(ui, |ui| {
                                let hex_str = packet.raw_data.iter()
                                    .map(|b| format!("{:02x}", b))
                                    .collect::<Vec<_>>()
                                    .chunks(16)
                                    .map(|chunk| chunk.join(" "))
                                    .collect::<Vec<_>>()
                                    .join("\n");
                                ui.monospace(hex_str);
                            });
                    });
                }
            }
        });
    }
}

fn format_packet_time(time: &SystemTime) -> String {
    if let Ok(duration) = time.duration_since(SystemTime::UNIX_EPOCH) {
        let secs = duration.as_secs();
        let millis = duration.subsec_millis();
        format!("{:02}:{:02}:{:02}.{:03}", 
            (secs / 3600) % 24,
            (secs / 60) % 60,
            secs % 60,
            millis)
    } else {
        "00:00:00.000".to_string()
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 800.0])
            .with_title("Network Traffic Catcher"),
        ..Default::default()
    };

    eframe::run_native(
        "Network Traffic Catcher",
        options,
        Box::new(|cc| Box::new(NetworkCatcherApp::new(cc))),
    )
}

