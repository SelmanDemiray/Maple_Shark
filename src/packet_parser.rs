use std::net::IpAddr;
use std::time::SystemTime;

#[derive(Clone, Debug)]
pub struct PacketInfo {
    pub timestamp: SystemTime,
    pub src_ip: String,
    pub dst_ip: String,
    pub protocol: String,
    pub size: u32,
    pub raw_data: Vec<u8>,
}

pub fn parse_packet(data: &[u8], timestamp: SystemTime) -> Option<PacketInfo> {
    if data.len() < 14 {
        return None; // Too short for Ethernet header
    }

    // Check Ethernet type (offset 12-13)
    let eth_type = u16::from_be_bytes([data[12], data[13]]);
    
    // 0x0800 = IPv4
    if eth_type != 0x0800 {
        return None;
    }

    if data.len() < 34 {
        return None; // Too short for IP header
    }

    // Parse IP header (starts at offset 14)
    let ip_header = &data[14..];
    
    // IP version and header length (first byte)
    let version_and_ihl = ip_header[0];
    let version = (version_and_ihl >> 4) & 0x0F;
    
    if version != 4 {
        return None; // Not IPv4
    }

    let ihl = (version_and_ihl & 0x0F) as usize * 4;
    if ip_header.len() < ihl {
        return None;
    }

    // Protocol (offset 9 in IP header)
    let protocol = ip_header[9];
    let protocol_name = match protocol {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        47 => "GRE",
        50 => "ESP",
        51 => "AH",
        _ => "Unknown",
    };

    // Source IP (offset 12-15 in IP header)
    let src_ip = IpAddr::V4(std::net::Ipv4Addr::new(
        ip_header[12],
        ip_header[13],
        ip_header[14],
        ip_header[15],
    ));

    // Destination IP (offset 16-19 in IP header)
    let dst_ip = IpAddr::V4(std::net::Ipv4Addr::new(
        ip_header[16],
        ip_header[17],
        ip_header[18],
        ip_header[19],
    ));

    Some(PacketInfo {
        timestamp,
        src_ip: src_ip.to_string(),
        dst_ip: dst_ip.to_string(),
        protocol: protocol_name.to_string(),
        size: data.len() as u32,
        raw_data: data.to_vec(),
    })
}

pub fn is_in_network(ip_str: &str, network: &str) -> bool {
    // Parse network like "192.168.0.0/24"
    if let Some((network_ip, prefix_len)) = network.split_once('/') {
        if let (Ok(ip), Ok(prefix)) = (network_ip.parse::<IpAddr>(), prefix_len.parse::<u8>()) {
            if let Ok(parsed_ip) = ip_str.parse::<IpAddr>() {
                if let (IpAddr::V4(ip), IpAddr::V4(network_ip)) = (parsed_ip, ip) {
                    let mask = !((1u32 << (32 - prefix)) - 1);
                    let ip_u32 = u32::from_be_bytes(ip.octets());
                    let network_u32 = u32::from_be_bytes(network_ip.octets());
                    return (ip_u32 & mask) == (network_u32 & mask);
                }
            }
        }
    }
    false
}

