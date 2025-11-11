// Homemade Rust implementation of libpcap
// No third-party dependencies - uses only standard library and direct syscalls
// Supports both Linux and Windows using native system APIs
// Optimized for performance and efficiency

#[allow(dead_code)]
#[allow(unused_imports)]

use std::fs::File;
use std::io::{self, Read, Write};
use std::mem;
use std::ptr;
use std::slice;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH, Duration};

#[cfg(target_os = "linux")]
use std::os::unix::io::RawFd;

// Windows type definitions and FFI declarations
#[cfg(target_os = "windows")]
mod windows_ffi {
    // Type aliases
    pub type SOCKET = usize;
    pub type DWORD = u32;
    pub type HANDLE = *mut u8;
    pub type WORD = u16;
    pub type ULONG = u32;
    pub type ULONG64 = u64;
    pub type BOOL = i32;

    // Constants
    pub const INVALID_SOCKET: SOCKET = !0;
    pub const SOCKET_ERROR: i32 = -1;
    pub const AF_INET: i32 = 2;
    pub const SOCK_RAW: i32 = 3;
    pub const IPPROTO_IP: i32 = 0;
    pub const FIONBIO: u32 = 0x8004667E;
    pub const SIO_RCVALL: u32 = 0x98000001;
    pub const RCVALL_ON: u32 = 1;
    pub const RCVALL_OFF: u32 = 0;
    pub const TOKEN_QUERY: u32 = 0x0008;
    pub const TokenElevation: u32 = 20;
    pub const INADDR_ANY: u32 = 0;
    pub const GAA_FLAG_INCLUDE_PREFIX: u32 = 0x0010;
    pub const AF_UNSPEC: u32 = 0;
    pub const IF_OPER_STATUS_UP: u32 = 1;

    // WSADATA structure
    #[repr(C)]
    pub struct WSADATA {
        pub wVersion: WORD,
        pub wHighVersion: WORD,
        pub szDescription: [u8; 257],
        pub szSystemStatus: [u8; 129],
        pub iMaxSockets: u16,
        pub iMaxUdpDg: u16,
        pub lpVendorInfo: *mut i8,
    }

    // SOCKADDR structure
    #[repr(C)]
    pub struct SOCKADDR {
        pub sa_family: u16,
        pub sa_data: [u8; 14],
    }

    // SOCKADDR_IN structure
    #[repr(C)]
    pub struct SOCKADDR_IN {
        pub sin_family: u16,
        pub sin_port: u16,
        pub sin_addr: u32, // in_addr as u32 (S_un.S_addr)
        pub sin_zero: [u8; 8],
    }

    // in_addr (simplified - just u32 for S_un.S_addr)
    pub type in_addr = u32;

    // SOCKET_ADDRESS structure
    #[repr(C)]
    pub struct SOCKET_ADDRESS {
        pub lpSockaddr: *mut SOCKADDR,
        pub iSockaddrLength: i32,
    }

    // IP_ADAPTER_UNICAST_ADDRESS structure
    #[repr(C)]
    pub struct IP_ADAPTER_UNICAST_ADDRESS {
        pub Length: ULONG,
        pub Flags: u32,
        pub Next: *mut IP_ADAPTER_UNICAST_ADDRESS,
        pub Address: SOCKET_ADDRESS,
        pub PrefixOrigin: u32,
        pub SuffixOrigin: u32,
        pub DadState: u32,
        pub ValidLifetime: ULONG,
        pub PreferredLifetime: ULONG,
        pub LeaseLifetime: ULONG,
        pub OnLinkPrefixLength: u8,
    }

    // IP_ADAPTER_ADDRESSES structure
    #[repr(C)]
    pub struct IP_ADAPTER_ADDRESSES {
        pub Length: ULONG,
        pub IfIndex: u32,
        pub Next: *mut IP_ADAPTER_ADDRESSES,
        pub AdapterName: *mut i8,
        pub FirstUnicastAddress: *mut IP_ADAPTER_UNICAST_ADDRESS,
        pub FirstAnycastAddress: *mut u8, // Not used, but needed for alignment
        pub FirstMulticastAddress: *mut u8, // Not used, but needed for alignment
        pub FirstDnsServerAddress: *mut u8, // Not used, but needed for alignment
        pub DnsSuffix: *mut u16,
        pub Description: *mut u16,
        pub FriendlyName: *mut u16,
        pub PhysicalAddress: [u8; 8],
        pub PhysicalAddressLength: ULONG,
        pub Flags: ULONG,
        pub Mtu: ULONG,
        pub IfType: u32,
        pub OperStatus: u32,
        pub Ipv6IfIndex: u32,
        pub ZoneIndices: [ULONG; 16],
        pub FirstPrefix: *mut u8, // Not used, but needed for alignment
    }

    // TOKEN_ELEVATION structure
    #[repr(C)]
    pub struct TOKEN_ELEVATION {
        pub TokenIsElevated: u32,
    }

    // Winsock2 functions (ws2_32.dll)
    #[link(name = "ws2_32")]
    extern "system" {
        pub fn WSAStartup(wVersionRequested: WORD, lpWSAData: *mut WSADATA) -> i32;
        pub fn WSACleanup() -> i32;
        pub fn WSAGetLastError() -> i32;
        pub fn socket(af: i32, socket_type: i32, protocol: i32) -> SOCKET;
        pub fn recv(s: SOCKET, buf: *mut i8, len: i32, flags: i32) -> i32;
        pub fn bind(s: SOCKET, name: *const SOCKADDR, namelen: i32) -> i32;
        pub fn closesocket(s: SOCKET) -> i32;
        pub fn ioctlsocket(s: SOCKET, cmd: u32, argp: *mut u32) -> i32;
        pub fn WSAIoctl(
            s: SOCKET,
            dwIoControlCode: u32,
            lpvInBuffer: *mut u8,
            cbInBuffer: u32,
            lpvOutBuffer: *mut u8,
            cbOutBuffer: u32,
            lpcbBytesReturned: *mut u32,
            lpOverlapped: *mut u8,
            lpCompletionRoutine: *mut u8, // LPWSAOVERLAPPED_COMPLETION_ROUTINE (function pointer or null)
        ) -> i32;
    }

    // IP Helper API functions (iphlpapi.dll)
    #[link(name = "iphlpapi")]
    extern "system" {
        pub fn GetAdaptersAddresses(
            Family: ULONG,
            Flags: ULONG,
            Reserved: *mut u8,
            AdapterAddresses: *mut IP_ADAPTER_ADDRESSES,
            SizePointer: *mut ULONG,
        ) -> u32;
    }

    // Security API functions (advapi32.dll)
    #[link(name = "advapi32")]
    extern "system" {
        pub fn OpenProcessToken(
            ProcessHandle: HANDLE,
            DesiredAccess: u32,
            TokenHandle: *mut HANDLE,
        ) -> BOOL;
        pub fn GetTokenInformation(
            TokenHandle: HANDLE,
            TokenInformationClass: u32,
            TokenInformation: *mut u8,
            TokenInformationLength: u32,
            ReturnLength: *mut u32,
        ) -> BOOL;
    }

    // Kernel32 functions (kernel32.dll)
    #[link(name = "kernel32")]
    extern "system" {
        pub fn GetCurrentProcess() -> HANDLE;
        pub fn CloseHandle(hObject: HANDLE) -> BOOL;
    }
}

#[cfg(target_os = "windows")]
use windows_ffi::*;

// Windows IP protocol constants (additional ones not in windows_ffi)
#[cfg(target_os = "windows")]
const IPPROTO_ICMP: i32 = 1;
#[cfg(target_os = "windows")]
const IPPROTO_TCP: i32 = 6;
#[cfg(target_os = "windows")]
const IPPROTO_UDP: i32 = 17;

// Constants from pcap.h
const PCAP_VERSION_MAJOR: u16 = 2;
const PCAP_VERSION_MINOR: u16 = 4;
const PCAP_ERRBUF_SIZE: usize = 256;
const PCAP_MAGIC: u32 = 0xa1b2c3d4;
const PCAP_MAGIC_SWAPPED: u32 = 0xd4c3b2a1;

// Link types (DLT_*)
const DLT_NULL: i32 = 0;
const DLT_EN10MB: i32 = 1;  // Ethernet
const DLT_RAW: i32 = 101;

// Error codes
pub const PCAP_ERROR: i32 = -1;
pub const PCAP_ERROR_BREAK: i32 = -2;
pub const PCAP_ERROR_NOT_ACTIVATED: i32 = -3;
pub const PCAP_ERROR_PERM_DENIED: i32 = -8;
pub const PCAP_ERROR_NO_SUCH_DEVICE: i32 = -5;

// Linux socket constants
#[cfg(target_os = "linux")]
const AF_PACKET: i32 = 17;
#[cfg(target_os = "linux")]
const SOCK_RAW: i32 = 3;
#[cfg(target_os = "linux")]
const SOCK_DGRAM: i32 = 2;
#[cfg(target_os = "linux")]
const ETH_P_ALL: u16 = 0x0003;
#[cfg(target_os = "linux")]
const SOL_PACKET: i32 = 263;
#[cfg(target_os = "linux")]
const PACKET_ADD_MEMBERSHIP: i32 = 1;
#[cfg(target_os = "linux")]
const PACKET_MR_PROMISC: i32 = 1;
#[cfg(target_os = "linux")]
const SIOCGIFINDEX: u64 = 0x8933;
#[cfg(target_os = "linux")]
const SOL_SOCKET: i32 = 1;
#[cfg(target_os = "linux")]
const SO_ERROR: i32 = 4;

// Windows constants are now defined in windows_ffi module

// BPF instruction structure
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct BpfInstruction {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

// BPF program
#[derive(Clone)]
pub struct BpfProgram {
    instructions: Vec<BpfInstruction>,
}

impl BpfProgram {
    pub fn new() -> Self {
        Self {
            instructions: Vec::new(),
        }
    }

    pub fn matches(&self, packet: &[u8]) -> bool {
        if self.instructions.is_empty() {
            return true;
        }

        let mut accumulator: u32 = 0;
        let mut _x: u32 = 0;
        let _mem: [u32; 16] = [0; 16];
        let mut pc = 0;

        while pc < self.instructions.len() {
            let insn = self.instructions[pc];
            let code = insn.code;
            let k = insn.k as usize;

            match code {
                0x00 => return false,
                0x04 => return true,
                0x15 => {
                    if accumulator == insn.k {
                        pc = if insn.jt != 0 { pc + insn.jt as usize } else { pc + 1 };
                    } else {
                        pc = if insn.jf != 0 { pc + insn.jf as usize } else { pc + 1 };
                    }
                    continue;
                }
                0x20 => {
                    if k < packet.len() {
                        accumulator = packet[k] as u32;
                    } else {
                        return false;
                    }
                }
                0x21 => {
                    if k < packet.len() {
                        _x = packet[k] as u32;
                    } else {
                        return false;
                    }
                }
                0x28 => accumulator &= insn.k,
                0x30 => accumulator <<= insn.k,
                0x34 => accumulator >>= insn.k,
                0x40 => accumulator += insn.k,
                0x50 => {
                    if accumulator > insn.k {
                        pc = if insn.jt != 0 { pc + insn.jt as usize } else { pc + 1 };
                        continue;
                    } else {
                        pc = if insn.jf != 0 { pc + insn.jf as usize } else { pc + 1 };
                        continue;
                    }
                }
                _ => return true,
            }
            pc += 1;
        }
        true
    }
}

// Packet header
#[derive(Clone, Debug)]
pub struct PcapPkthdr {
    pub ts: SystemTime,
    pub caplen: u32,
    pub len: u32,
}

// Pcap statistics
#[derive(Default, Clone, Debug)]
pub struct PcapStat {
    pub ps_recv: u32,
    pub ps_drop: u32,
    pub ps_ifdrop: u32,
}

// Platform-specific socket type
#[cfg(target_os = "linux")]
type PlatformSocket = RawFd;

#[cfg(target_os = "windows")]
type PlatformSocket = SOCKET;

// Main pcap handle
pub struct Pcap {
    #[cfg(target_os = "linux")]
    socket: Option<RawFd>,
    #[cfg(target_os = "windows")]
    socket: Option<SOCKET>,
    device: String,
    snaplen: i32,
    promisc: bool,
    timeout_ms: i32,
    linktype: i32,
    activated: bool,
    filter: Option<BpfProgram>,
    stats: PcapStat,
    errbuf: String,
    break_loop: AtomicBool,
    packet_buf: Vec<u8>, // Reusable buffer for efficiency
    #[cfg(target_os = "windows")]
    wsa_initialized: bool,
}

#[cfg(target_os = "linux")]
#[repr(C, packed)]
struct SockaddrLl {
    sll_family: u16,
    sll_protocol: u16,
    sll_ifindex: i32,
    sll_hatype: u16,
    sll_pkttype: u8,
    sll_halen: u8,
    sll_addr: [u8; 8],
}

#[cfg(target_os = "linux")]
#[repr(C, packed)]
struct PacketMreq {
    mr_ifindex: i32,
    mr_type: u16,
    mr_alen: u16,
    mr_address: [u8; 8],
}

// Check if running as administrator on Windows
#[cfg(target_os = "windows")]
fn is_running_as_admin() -> bool {
    unsafe {
        let mut token: HANDLE = ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        
        let mut elevation: TOKEN_ELEVATION = mem::zeroed();
        let mut return_length: u32 = 0;
        
        let result = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut u8,
            mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_length,
        );
        
        CloseHandle(token);
        
        result != 0 && elevation.TokenIsElevated != 0
    }
}

#[cfg(target_os = "linux")]
#[repr(C, packed)]
struct Ifreq {
    ifr_name: [u8; 16],
    ifr_ifindex: i32,
}

impl Pcap {
    pub fn create(device: &str) -> Result<Self, String> {
        Ok(Self {
            socket: None,
            device: device.to_string(),
            snaplen: 65535,
            promisc: false,
            timeout_ms: 1000,
            linktype: DLT_EN10MB,
            activated: false,
            filter: None,
            stats: PcapStat::default(),
            errbuf: String::new(),
            break_loop: AtomicBool::new(false),
            packet_buf: Vec::with_capacity(65535),
            #[cfg(target_os = "windows")]
            wsa_initialized: false,
        })
    }

    pub fn set_snaplen(&mut self, snaplen: i32) -> Result<(), String> {
        if self.activated {
            return Err("Cannot set snaplen after activation".to_string());
        }
        if snaplen <= 0 || snaplen > 65535 {
            return Err("Invalid snaplen".to_string());
        }
        self.snaplen = snaplen;
        self.packet_buf = Vec::with_capacity(snaplen as usize);
        Ok(())
    }

    pub fn set_promisc(&mut self, promisc: bool) -> Result<(), String> {
        if self.activated {
            return Err("Cannot set promisc after activation".to_string());
        }
        self.promisc = promisc;
        Ok(())
    }

    pub fn set_timeout(&mut self, timeout_ms: i32) -> Result<(), String> {
        if self.activated {
            return Err("Cannot set timeout after activation".to_string());
        }
        self.timeout_ms = timeout_ms;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn get_ifindex(&self, _fd: RawFd, device: &str) -> Result<i32, String> {
        if device == "any" {
            return Ok(0);
        }

        // Create a control socket for ioctl
        let ctrl_fd = unsafe { sys_socket(2, 1, 0) }; // AF_INET, SOCK_DGRAM
        if ctrl_fd < 0 {
            return Err("Failed to create control socket".to_string());
        }

        let mut ifr = Ifreq {
            ifr_name: [0; 16],
            ifr_ifindex: 0,
        };

        let name_bytes = device.as_bytes();
        if name_bytes.len() >= 16 {
            unsafe { sys_close(ctrl_fd); }
            return Err("Device name too long".to_string());
        }

        ifr.ifr_name[..name_bytes.len()].copy_from_slice(name_bytes);

        let result = unsafe {
            sys_ioctl(ctrl_fd, SIOCGIFINDEX, &mut ifr as *mut _ as *const u8)
        };

        unsafe { sys_close(ctrl_fd); }

        if result < 0 {
            let err = io::Error::last_os_error();
            return Err(format!("Failed to get interface index for {}: {}", device, err));
        }
        Ok(ifr.ifr_ifindex)
    }

    #[cfg(target_os = "windows")]
    fn get_local_ip(&self) -> Result<u32, String> {
        // Get the first valid IP address
        let ips = self.get_all_local_ips()?;
        if ips.is_empty() {
            return Err("No valid network adapter found".to_string());
        }
        Ok(ips[0])
    }

    #[cfg(target_os = "windows")]
    fn get_all_local_ips(&self) -> Result<Vec<u32>, String> {
        // Get all non-loopback IPv4 addresses from operational adapters
        unsafe {
            let mut buffer_size: u32 = 15000; // Start with 15KB
            let mut buffer: Vec<u8> = Vec::new();
            let mut result: u32;
            
            loop {
                buffer.resize(buffer_size as usize, 0);
                let adapter_addresses = buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES;
                result = GetAdaptersAddresses(
                    AF_UNSPEC,
                    GAA_FLAG_INCLUDE_PREFIX,
                    ptr::null_mut(),
                    adapter_addresses,
                    &mut buffer_size,
                );
                
                if result == 0 {
                    break; // Success
                } else if result == 111 { // ERROR_BUFFER_OVERFLOW
                    continue; // Try again with larger buffer
                } else {
                    return Err(format!("Failed to get adapter addresses: error {}", result));
                }
            }
            
            // Separate vectors for priority ordering
            let mut priority1: Vec<u32> = Vec::new(); // Operational adapters in 192.168.0.0/24
            let mut priority2: Vec<u32> = Vec::new(); // Operational adapters in other networks
            let mut priority3: Vec<u32> = Vec::new(); // Non-operational adapters in 192.168.0.0/24
            let mut priority4: Vec<u32> = Vec::new(); // Other non-operational adapters
            
            // Walk through adapters (buffer is valid here)
            let mut adapter = buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES;
            while !adapter.is_null() {
                let adapter_ref = &*adapter;
                
                // Check if adapter is operational (up and connected)
                // IfOperStatusUp = 1 means the interface is up
                let is_operational = adapter_ref.OperStatus == IF_OPER_STATUS_UP;
                
                // Walk through unicast addresses
                let mut address = adapter_ref.FirstUnicastAddress;
                while !address.is_null() {
                    let addr_ref = &*address;
                    let sockaddr = addr_ref.Address.lpSockaddr;
                    
                    if !sockaddr.is_null() {
                        let sockaddr_ref = &*sockaddr;
                        if sockaddr_ref.sa_family == AF_INET as u16 {
                            let sockaddr_in = sockaddr as *const SOCKADDR_IN;
                            let sockaddr_in_ref = &*sockaddr_in;
                            // Access in_addr as u32 (sin_addr is already u32)
                            // The value is in network byte order (big-endian)
                            let ip: u32 = sockaddr_in_ref.sin_addr;
                            
                            // Skip loopback (127.0.0.1) and INADDR_ANY - IP is in network byte order
                            // 127.0.0.1 = 0x7f000001 in network byte order
                            if ip != 0x7f000001 && ip != INADDR_ANY {
                                // Check if IP is in 192.168.0.0/24 network (preferred for capture)
                                // 192.168.0.0 = 0xC0A80000 in network byte order
                                // Mask for /24 = 0xFFFFFF00
                                let is_192_168_0 = (ip & 0xFFFFFF00) == 0xC0A80000;
                                
                                // Categorize by priority
                                if is_operational && is_192_168_0 {
                                    priority1.push(ip);
                                } else if is_operational {
                                    priority2.push(ip);
                                } else if is_192_168_0 {
                                    priority3.push(ip);
                                } else {
                                    priority4.push(ip);
                                }
                            }
                        }
                    }
                    
                    address = addr_ref.Next;
                }
                
                adapter = adapter_ref.Next;
            }
            
            // Combine in priority order
            let mut valid_ips = priority1;
            valid_ips.extend(priority2);
            valid_ips.extend(priority3);
            valid_ips.extend(priority4);
            
            if valid_ips.is_empty() {
                return Err("No valid network adapter found".to_string());
            }
            
            Ok(valid_ips)
        }
    }

    #[cfg(target_os = "windows")]
    fn get_ifindex(&self, _fd: SOCKET, _device: &str) -> Result<i32, String> {
        // On Windows, we don't need interface index for raw sockets
        Ok(0)
    }

    #[cfg(target_os = "linux")]
    fn bind_socket(&self, fd: RawFd, ifindex: i32) -> Result<(), String> {
        let mut sll = SockaddrLl {
            sll_family: AF_PACKET as u16,
            sll_protocol: (ETH_P_ALL as u16).to_be(),
            sll_ifindex: ifindex,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };

        let result = unsafe {
            sys_bind(fd, &sll as *const _ as *const u8, mem::size_of::<SockaddrLl>())
        };

        if result < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(19) { // ENODEV
                return Err("No such device".to_string());
            }
            return Err(format!("Failed to bind socket: {}", err));
        }

        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn bind_socket(&self, _fd: SOCKET, _ifindex: i32) -> Result<(), String> {
        // Binding is done in activate() for Windows
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn set_promisc_mode(&self, fd: RawFd, ifindex: i32) -> Result<(), String> {
        if !self.promisc || ifindex == 0 {
            return Ok(());
        }

        let mr = PacketMreq {
            mr_ifindex: ifindex,
            mr_type: PACKET_MR_PROMISC as u16,
            mr_alen: 0,
            mr_address: [0; 8],
        };

        let result = unsafe {
            sys_setsockopt(
                fd,
                SOL_PACKET,
                PACKET_ADD_MEMBERSHIP,
                &mr as *const _ as *const u8,
                mem::size_of::<PacketMreq>(),
            )
        };

        if result < 0 {
            return Err("Failed to set promiscuous mode".to_string());
        }

        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn set_promisc_mode(&self, fd: SOCKET, _ifindex: i32) -> Result<(), String> {
        if !self.promisc {
            return Ok(());
        }

        unsafe {
            let mut bytes_returned: u32 = 0;
            let mut option: u32 = RCVALL_ON;
            
            let result = WSAIoctl(
                fd,
                SIO_RCVALL,
                &mut option as *mut _ as *mut u8,
                mem::size_of::<u32>() as u32,
                ptr::null_mut(),
                0,
                &mut bytes_returned,
                ptr::null_mut(),
                ptr::null_mut(),
            );

            if result == SOCKET_ERROR {
                let err = WSAGetLastError();
                // Error 10022 (WSAEINVAL) can occur if the interface doesn't support
                // promiscuous mode or if there are system restrictions.
                // We'll continue without promiscuous mode - the socket will still
                // receive packets destined for this machine.
                if err == 10022 {
                    eprintln!("Warning: Promiscuous mode not available (error 10022). Continuing with normal capture mode.");
                    eprintln!("Note: You may only see packets destined for this machine.");
                    return Ok(()); // Continue without promiscuous mode
                }
                return Err(format!("Failed to set promiscuous mode: error {}", err));
            } else {
                eprintln!("Promiscuous mode enabled successfully (SIO_RCVALL)");
            }
        }

        Ok(())
    }

    pub fn activate(&mut self) -> Result<(), String> {
        if self.activated {
            return Err("Already activated".to_string());
        }

        #[cfg(target_os = "linux")]
        {
            let is_any = self.device == "any";
            let socket_type = if is_any { SOCK_DGRAM } else { SOCK_RAW };
            
            let fd = unsafe {
                sys_socket(AF_PACKET, socket_type, (ETH_P_ALL as u16).to_be() as i32)
            };
            
            if fd < 0 {
                let err = io::Error::last_os_error();
                return Err(format!("Failed to create socket: {} (try running as root)", err));
            }

            let ifindex = self.get_ifindex(fd, &self.device)?;
            self.bind_socket(fd, ifindex)?;
            self.set_promisc_mode(fd, ifindex)?;

            if self.timeout_ms == 0 {
                let flags = unsafe { sys_fcntl(fd, 3, 0) };
                if flags >= 0 {
                    unsafe {
                        sys_fcntl(fd, 4, flags | 0x800);
                    }
                }
            }

            self.socket = Some(fd);
            self.activated = true;
            Ok(())
        }

        #[cfg(target_os = "windows")]
        {
            unsafe {
                // Initialize Winsock
                let mut wsa_data: WSADATA = mem::zeroed();
                let result = WSAStartup(0x0202, &mut wsa_data);
                if result != 0 {
                    return Err(format!("Failed to initialize Winsock: error {}", result));
                }
                self.wsa_initialized = true;

                // Create raw socket to receive all IP packets
                // On Windows, we use IPPROTO_IP to receive all IP packets
                let fd = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
                if fd == INVALID_SOCKET {
                    let err = WSAGetLastError();
                    WSACleanup();
                    self.wsa_initialized = false;
                    
                    // Error 10013 is WSAEACCES - Access denied (requires administrator)
                    let is_admin = is_running_as_admin();
                    if err == 10013 {
                        if !is_admin {
                            return Err(format!(
                                "Permission denied (error 10013): Raw socket creation requires Administrator privileges.\n\n\
                                To fix this:\n\
                                1. Close this application\n\
                                2. Right-click on the executable\n\
                                3. Select 'Run as administrator'\n\n\
                                Alternatively, you can run from an elevated PowerShell or Command Prompt."
                            ));
                        } else {
                            return Err(format!(
                                "Permission denied (error 10013): Raw socket creation failed even with Administrator privileges.\n\
                                This may indicate a system policy restriction or firewall blocking raw socket access."
                            ));
                        }
                    }
                    return Err(format!("Failed to create raw socket: Windows error {} (try running as administrator)", err));
                }

                // Set socket to non-blocking mode
                let mut mode: u32 = 1;
                let ioctl_result = ioctlsocket(fd, FIONBIO, &mut mode);
                if ioctl_result == SOCKET_ERROR {
                    let err = WSAGetLastError();
                    closesocket(fd);
                    WSACleanup();
                    self.wsa_initialized = false;
                    return Err(format!("Failed to set non-blocking mode: error {}", err));
                }

                // Note: IP_HDRINCL is only for sending raw packets, not receiving
                // For receiving, we don't need to set this option

                // Get all local IP addresses for binding (required for SIO_RCVALL to work)
                // On Windows, raw sockets cannot bind to INADDR_ANY, so we must try each IP
                let local_ips = match self.get_all_local_ips() {
                    Ok(ips) => ips,
                    Err(e) => {
                        closesocket(fd);
                        WSACleanup();
                        self.wsa_initialized = false;
                        return Err(format!("Failed to get local IP addresses: {}. Make sure you have an active network adapter.", e));
                    }
                };

                // Try to bind to each IP address until one works
                let mut local_ip: Option<u32> = None;
                let mut bind_error: Option<i32> = None;
                
                for ip in &local_ips {
                    let mut addr: SOCKADDR_IN = mem::zeroed();
                    addr.sin_family = AF_INET as u16;
                    // Set in_addr from u32 (sin_addr is already u32)
                    addr.sin_addr = *ip;
                    addr.sin_port = 0;

                    let bind_result = bind(
                        fd,
                        &addr as *const _ as *const SOCKADDR,
                        mem::size_of::<SOCKADDR_IN>() as i32,
                    );
                    
                    if bind_result != SOCKET_ERROR {
                        local_ip = Some(*ip);
                        break; // Success!
                    } else {
                        let err = WSAGetLastError();
                        bind_error = Some(err);
                        // Error 10049 (WSAEADDRNOTAVAIL) means this IP is not valid
                        // Continue trying other IPs
                        if err != 10049 {
                            // For other errors, stop trying
                            closesocket(fd);
                            WSACleanup();
                            self.wsa_initialized = false;
                            let ip_bytes = ip.to_be_bytes();
                            return Err(format!("Failed to bind socket to {}.{}.{}.{}: error {}",
                                ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3], err));
                        }
                    }
                }
                
                // Check if we successfully bound to an IP
                let bound_ip = match local_ip {
                    Some(ip) => ip,
                    None => {
                        closesocket(fd);
                        WSACleanup();
                        self.wsa_initialized = false;
                        let error_msg = match bind_error {
                            Some(10049) => {
                                format!("Failed to bind socket: error 10049 (address not available). \
                                    Tried {} IP address(es) but none were valid. \
                                    This usually means:\n\
                                    1. The network adapter is disconnected or disabled\n\
                                    2. The IP address is no longer assigned to the adapter\n\
                                    3. There are no active network adapters\n\n\
                                    Please check your network adapters and ensure at least one is connected and has a valid IP address.",
                                    local_ips.len())
                            },
                            Some(err) => format!("Failed to bind socket: error {}", err),
                            None => "Failed to bind socket: unknown error".to_string(),
                        };
                        return Err(error_msg);
                    }
                };
                
                // Log which IP we bound to
                // IP is in network byte order (big-endian), but on little-endian systems
                // it's stored swapped in memory. Use swap_bytes() to get correct byte order.
                let ip_bytes = bound_ip.swap_bytes().to_be_bytes();
                eprintln!("Bound socket to {}.{}.{}.{}", ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);

                // Enable promiscuous mode to receive all packets
                let ifindex = self.get_ifindex(fd, &self.device)?;
                self.set_promisc_mode(fd, ifindex)?;

                self.socket = Some(fd);
                self.activated = true;
                Ok(())
            }
        }
    }

    pub fn setfilter(&mut self, program: BpfProgram) -> Result<(), String> {
        self.filter = Some(program);
        Ok(())
    }

    pub fn next_ex(&mut self) -> Result<Option<(PcapPkthdr, Vec<u8>)>, i32> {
        if !self.activated {
            return Err(PCAP_ERROR_NOT_ACTIVATED);
        }

        if self.break_loop.load(Ordering::Relaxed) {
            self.break_loop.store(false, Ordering::Relaxed);
            return Err(PCAP_ERROR_BREAK);
        }

        if let Some(fd) = self.socket {
            #[cfg(target_os = "linux")]
            {
                self.packet_buf.resize(self.snaplen as usize, 0);
                
                let n = unsafe {
                    sys_recvfrom(
                        fd,
                        self.packet_buf.as_mut_ptr(),
                        self.packet_buf.len(),
                        0,
                        ptr::null_mut(),
                        ptr::null_mut(),
                    )
                };

                if n < 0 {
                    let err = io::Error::last_os_error();
                    let errno = err.raw_os_error().unwrap_or(0);
                    if errno == 11 || errno == 35 {
                        return Ok(None);
                    }
                    return Err(PCAP_ERROR);
                }

                if n == 0 {
                    return Ok(None);
                }

                let packet = &self.packet_buf[..n as usize];

                if let Some(ref filter) = self.filter {
                    if !filter.matches(packet) {
                        return self.next_ex();
                    }
                }

                let now = SystemTime::now();
                let hdr = PcapPkthdr {
                    ts: now,
                    caplen: n as u32,
                    len: n as u32,
                };

                self.stats.ps_recv += 1;
                return Ok(Some((hdr, packet.to_vec())));
            }

            #[cfg(target_os = "windows")]
            {
                self.packet_buf.resize(self.snaplen as usize, 0);
                
                unsafe {
                    let n = recv(
                        fd,
                        self.packet_buf.as_mut_ptr() as *mut i8,
                        self.packet_buf.len() as i32,
                        0,
                    );

                    if n == SOCKET_ERROR {
                        let err = WSAGetLastError();
                        // WSAEWOULDBLOCK = 10035, WSAETIMEDOUT = 10060
                        // These are expected for non-blocking sockets
                        if err == 10035 || err == 10060 {
                            return Ok(None);
                        }
                        // Log unexpected errors for debugging
                        eprintln!("recv() error: {} (unexpected)", err);
                        return Err(PCAP_ERROR);
                    }

                    if n == 0 {
                        return Ok(None);
                    }

                    // On Windows, raw sockets receive IP packets without Ethernet header
                    // We need to prepend a fake Ethernet header for compatibility
                    let ip_packet = &self.packet_buf[..n as usize];
                    
                    // Validate IP packet minimum size
                    if ip_packet.len() < 20 {
                        return Ok(None);
                    }
                    
                    // Create Ethernet header + IP packet
                    let mut ethernet_packet = Vec::with_capacity(14 + ip_packet.len());
                    ethernet_packet.extend_from_slice(&[0u8; 12]); // Dummy MAC addresses
                    ethernet_packet.extend_from_slice(&[0x08, 0x00]); // IPv4 EtherType
                    ethernet_packet.extend_from_slice(ip_packet);

                    let packet = &ethernet_packet;

                    if let Some(ref filter) = self.filter {
                        if !filter.matches(packet) {
                            return self.next_ex();
                        }
                    }

                    let now = SystemTime::now();
                    let hdr = PcapPkthdr {
                        ts: now,
                        caplen: packet.len() as u32,
                        len: packet.len() as u32,
                    };

                    self.stats.ps_recv += 1;
                    return Ok(Some((hdr, packet.to_vec())));
                }
            }
        }

        Ok(None)
    }

    pub fn breakloop(&self) {
        self.break_loop.store(true, Ordering::Relaxed);
    }

    pub fn stats(&self) -> Result<PcapStat, String> {
        Ok(self.stats.clone())
    }

    pub fn geterr(&self) -> &str {
        &self.errbuf
    }

    pub fn datalink(&self) -> i32 {
        self.linktype
    }

    pub fn snapshot(&self) -> i32 {
        self.snaplen
    }
}

impl Drop for Pcap {
    fn drop(&mut self) {
        if let Some(fd) = self.socket {
            #[cfg(target_os = "linux")]
            unsafe {
                sys_close(fd);
            }
            #[cfg(target_os = "windows")]
            unsafe {
                closesocket(fd);
                if self.wsa_initialized {
                    WSACleanup();
                }
            }
        }
    }
}

// File operations
pub struct PcapFile {
    file: File,
    swapped: bool,
    linktype: i32,
    snaplen: u32,
}

#[repr(C, packed)]
struct PcapFileHeader {
    magic: u32,
    version_major: u16,
    version_minor: u16,
    thiszone: i32,
    sigfigs: u32,
    snaplen: u32,
    linktype: u32,
}

#[repr(C, packed)]
struct PcapPacketHeader {
    ts_sec: u32,
    ts_usec: u32,
    caplen: u32,
    len: u32,
}

impl PcapFile {
    pub fn open_offline(filename: &str) -> Result<Self, String> {
        let mut file = File::open(filename)
            .map_err(|e| format!("Failed to open file: {}", e))?;

        let mut header_buf = [0u8; mem::size_of::<PcapFileHeader>()];
        file.read_exact(&mut header_buf)
            .map_err(|e| format!("Failed to read header: {}", e))?;

        let header = unsafe {
            ptr::read(header_buf.as_ptr() as *const PcapFileHeader)
        };

        let swapped = header.magic == PCAP_MAGIC_SWAPPED;
        let magic = if swapped {
            u32::from_be(header.magic)
        } else {
            header.magic
        };

        if magic != PCAP_MAGIC {
            return Err("Invalid pcap file format".to_string());
        }

        let snaplen = if swapped {
            u32::from_be(header.snaplen)
        } else {
            header.snaplen
        };

        let linktype = if swapped {
            u32::from_be(header.linktype) as i32
        } else {
            header.linktype as i32
        };

        Ok(Self {
            file,
            swapped,
            linktype,
            snaplen,
        })
    }

    pub fn next_ex(&mut self) -> Result<Option<(PcapPkthdr, Vec<u8>)>, String> {
        let mut hdr_buf = [0u8; mem::size_of::<PcapPacketHeader>()];
        match self.file.read_exact(&mut hdr_buf) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(format!("Failed to read packet header: {}", e)),
        }

        let hdr = unsafe {
            ptr::read(hdr_buf.as_ptr() as *const PcapPacketHeader)
        };

        let caplen = if self.swapped {
            u32::from_be(hdr.caplen)
        } else {
            hdr.caplen
        };

        let len = if self.swapped {
            u32::from_be(hdr.len)
        } else {
            hdr.len
        };

        let ts_sec = if self.swapped {
            u32::from_be(hdr.ts_sec)
        } else {
            hdr.ts_sec
        };

        let ts_usec = if self.swapped {
            u32::from_be(hdr.ts_usec)
        } else {
            hdr.ts_usec
        };

        let mut packet = vec![0u8; caplen as usize];
        self.file.read_exact(&mut packet)
            .map_err(|e| format!("Failed to read packet data: {}", e))?;

        let ts = UNIX_EPOCH + Duration::new(ts_sec as u64, ts_usec * 1000);

        let pkthdr = PcapPkthdr {
            ts: SystemTime::from(ts),
            caplen,
            len,
        };

        Ok(Some((pkthdr, packet)))
    }

    pub fn datalink(&self) -> i32 {
        self.linktype
    }
}

// Dumper
pub struct PcapDumper {
    file: File,
    snaplen: u32,
    linktype: u32,
}

impl PcapDumper {
    pub fn open(pcap: &Pcap, filename: &str) -> Result<Self, String> {
        let mut file = File::create(filename)
            .map_err(|e| format!("Failed to create file: {}", e))?;

        let header = PcapFileHeader {
            magic: PCAP_MAGIC,
            version_major: PCAP_VERSION_MAJOR,
            version_minor: PCAP_VERSION_MINOR,
            thiszone: 0,
            sigfigs: 0,
            snaplen: pcap.snaplen as u32,
            linktype: pcap.linktype as u32,
        };

        let header_bytes = unsafe {
            slice::from_raw_parts(
                &header as *const _ as *const u8,
                mem::size_of::<PcapFileHeader>(),
            )
        };

        file.write_all(header_bytes)
            .map_err(|e| format!("Failed to write header: {}", e))?;

        Ok(Self {
            file,
            snaplen: pcap.snaplen as u32,
            linktype: pcap.linktype as u32,
        })
    }

    pub fn dump(&mut self, hdr: &PcapPkthdr, packet: &[u8]) -> Result<(), String> {
        let ts = hdr.ts.duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO);

        let pkt_hdr = PcapPacketHeader {
            ts_sec: ts.as_secs() as u32,
            ts_usec: ts.subsec_micros(),
            caplen: hdr.caplen,
            len: hdr.len,
        };

        let hdr_bytes = unsafe {
            slice::from_raw_parts(
                &pkt_hdr as *const _ as *const u8,
                mem::size_of::<PcapPacketHeader>(),
            )
        };

        self.file.write_all(hdr_bytes)
            .map_err(|e| format!("Failed to write packet header: {}", e))?;
        self.file.write_all(packet)
            .map_err(|e| format!("Failed to write packet data: {}", e))?;

        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), String> {
        self.file.flush()
            .map_err(|e| format!("Failed to flush: {}", e))
    }
}

pub fn compile_filter(_expr: &str) -> Result<BpfProgram, String> {
    Ok(BpfProgram::new())
}

pub fn open_live(device: &str, snaplen: i32, promisc: bool, timeout_ms: i32) -> Result<Pcap, String> {
    let mut pcap = Pcap::create(device)?;
    pcap.set_snaplen(snaplen)?;
    pcap.set_promisc(promisc)?;
    pcap.set_timeout(timeout_ms)?;
    pcap.activate()?;
    Ok(pcap)
}

pub fn open_offline(filename: &str) -> Result<PcapFile, String> {
    PcapFile::open_offline(filename)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bpf_program() {
        let program = BpfProgram::new();
        let packet = vec![0u8; 100];
        assert!(program.matches(&packet));
    }

    #[test]
    fn test_pcap_create() {
        let pcap = Pcap::create("eth0");
        assert!(pcap.is_ok());
    }
}

// Direct Linux syscalls
#[cfg(target_os = "linux")]
#[cfg(target_arch = "x86_64")]
mod syscalls {
    use super::*;

    const SYS_SOCKET: i64 = 41;
    const SYS_BIND: i64 = 49;
    const SYS_SETSOCKOPT: i64 = 54;
    const SYS_RECVFROM: i64 = 45;
    const SYS_CLOSE: i64 = 3;
    const SYS_FCNTL: i64 = 72;
    const SYS_IOCTL: i64 = 16;

    #[inline(always)]
    pub unsafe fn sys_socket(domain: i32, socket_type: i32, protocol: i32) -> RawFd {
        let result: i64;
        core::arch::asm!(
            "syscall",
            in("rax") SYS_SOCKET,
            in("rdi") domain as i64,
            in("rsi") socket_type as i64,
            in("rdx") protocol as i64,
            lateout("rax") result,
            options(nostack, preserves_flags)
        );
        result as RawFd
    }

    #[inline(always)]
    pub unsafe fn sys_bind(fd: RawFd, addr: *const u8, addrlen: usize) -> i32 {
        let result: i64;
        core::arch::asm!(
            "syscall",
            in("rax") SYS_BIND,
            in("rdi") fd as i64,
            in("rsi") addr as i64,
            in("rdx") addrlen as i64,
            lateout("rax") result,
            options(nostack, preserves_flags)
        );
        result as i32
    }

    #[inline(always)]
    pub unsafe fn sys_setsockopt(fd: RawFd, level: i32, optname: i32, optval: *const u8, optlen: usize) -> i32 {
        let result: i64;
        core::arch::asm!(
            "syscall",
            in("rax") SYS_SETSOCKOPT,
            in("rdi") fd as i64,
            in("rsi") level as i64,
            in("rdx") optname as i64,
            in("r10") optval as i64,
            in("r8") optlen as i64,
            lateout("rax") result,
            options(nostack, preserves_flags)
        );
        result as i32
    }

    #[inline(always)]
    pub unsafe fn sys_recvfrom(fd: RawFd, buf: *mut u8, len: usize, flags: i32, src_addr: *const u8, addrlen: *const u8) -> isize {
        let result: i64;
        core::arch::asm!(
            "syscall",
            in("rax") SYS_RECVFROM,
            in("rdi") fd as i64,
            in("rsi") buf as i64,
            in("rdx") len as i64,
            in("r10") flags as i64,
            in("r8") src_addr as i64,
            in("r9") addrlen as i64,
            lateout("rax") result,
            options(nostack, preserves_flags)
        );
        result as isize
    }

    #[inline(always)]
    pub unsafe fn sys_close(fd: RawFd) -> i32 {
        let result: i64;
        core::arch::asm!(
            "syscall",
            in("rax") SYS_CLOSE,
            in("rdi") fd as i64,
            lateout("rax") result,
            options(nostack, preserves_flags)
        );
        result as i32
    }

    #[inline(always)]
    pub unsafe fn sys_fcntl(fd: RawFd, cmd: i32, arg: i32) -> i32 {
        let result: i64;
        core::arch::asm!(
            "syscall",
            in("rax") SYS_FCNTL,
            in("rdi") fd as i64,
            in("rsi") cmd as i64,
            in("rdx") arg as i64,
            lateout("rax") result,
            options(nostack, preserves_flags)
        );
        result as i32
    }

    #[inline(always)]
    pub unsafe fn sys_ioctl(fd: RawFd, request: u64, argp: *const u8) -> i32 {
        let result: i64;
        core::arch::asm!(
            "syscall",
            in("rax") 16i64, // SYS_IOCTL
            in("rdi") fd as i64,
            in("rsi") request as i64,
            in("rdx") argp as i64,
            lateout("rax") result,
            options(nostack, preserves_flags)
        );
        result as i32
    }
}

#[cfg(target_os = "linux")]
#[cfg(not(target_arch = "x86_64"))]
mod syscalls {
    use super::*;
    pub unsafe fn sys_socket(_domain: i32, _socket_type: i32, _protocol: i32) -> RawFd { -1 }
    pub unsafe fn sys_bind(_fd: RawFd, _addr: *const u8, _addrlen: usize) -> i32 { -1 }
    pub unsafe fn sys_setsockopt(_fd: RawFd, _level: i32, _optname: i32, _optval: *const u8, _optlen: usize) -> i32 { -1 }
    pub unsafe fn sys_recvfrom(_fd: RawFd, _buf: *mut u8, _len: usize, _flags: i32, _src_addr: *const u8, _addrlen: *const u8) -> isize { -1 }
    pub unsafe fn sys_close(_fd: RawFd) -> i32 { -1 }
    pub unsafe fn sys_fcntl(_fd: RawFd, _cmd: i32, _arg: i32) -> i32 { -1 }
    pub unsafe fn sys_ioctl(_fd: RawFd, _request: u64, _argp: *const u8) -> i32 { -1 }
}

#[cfg(target_os = "linux")]
use syscalls::*;
