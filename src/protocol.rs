//! Protocol messages for TCP relay server communication
//!
//! The relay server uses JSON messages over TCP (newline-delimited)
//! 
//! Protocol flow:
//! 1. Client -> Server: register
//! 2. Server -> Client: registered
//! 3. Server -> Client: peer_info (when both peers connected)
//! 4. Client -> Server: ready (when prepared for hole punch)
//! 5. Server -> Client: go (synchronized start time)

use serde::{Deserialize, Serialize};
use crate::hole_punch::PeerAddress;

/// Client registration message to relay server
#[derive(Debug, Clone, Serialize)]
pub struct RegisterMessage {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub session_id: String,
    pub role: String,
    pub local_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_ip: Option<String>,
}

impl RegisterMessage {
    pub fn new(session_id: &str, role: &str, local_port: u16) -> Self {
        Self {
            msg_type: "register".to_string(),
            session_id: session_id.to_string(),
            role: role.to_string(),
            local_port,
            private_ip: get_private_ip(),
        }
    }
}

/// Get private/local IP address for LAN detection
fn get_private_ip() -> Option<String> {
    // Try to get local IP by connecting to a public address (doesn't actually send data)
    use std::net::UdpSocket;
    
    if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
        // Connect to Google DNS (doesn't send data, just sets up routing)
        if socket.connect("8.8.8.8:80").is_ok() {
            if let Ok(addr) = socket.local_addr() {
                return Some(addr.ip().to_string());
            }
        }
    }
    None
}

/// Ready message - sent when client is prepared for hole punch
#[derive(Debug, Clone, Serialize)]
pub struct ReadyMessage {
    #[serde(rename = "type")]
    pub msg_type: String,
}

impl Default for ReadyMessage {
    fn default() -> Self {
        Self {
            msg_type: "ready".to_string(),
        }
    }
}

/// Keepalive message
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize)]
pub struct KeepaliveMessage {
    #[serde(rename = "type")]
    pub msg_type: String,
}

impl Default for KeepaliveMessage {
    fn default() -> Self {
        Self {
            msg_type: "keepalive".to_string(),
        }
    }
}

/// Punch result report
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize)]
pub struct PunchResultMessage {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub success: bool,
}

#[allow(dead_code)]
impl PunchResultMessage {
    pub fn new(success: bool) -> Self {
        Self {
            msg_type: "punch_result".to_string(),
            success,
        }
    }
}

/// Peer address info from server
#[derive(Debug, Clone, Deserialize)]
pub struct PeerAddressInfo {
    pub ip: String,
    pub port: u16,
    #[serde(rename = "type")]
    pub addr_type: String,
    #[allow(dead_code)]
    #[serde(default)]
    pub priority: Option<i32>,
    #[allow(dead_code)]
    #[serde(default)]
    pub confidence: Option<f64>,
}

/// NAT Analysis from server - Focus on PORT RANGE!
#[derive(Debug, Clone, Deserialize, Default)]
pub struct NATAnalysis {
    #[allow(dead_code)]
    #[serde(default)]
    pub probed_ports: Vec<u16>,
    #[allow(dead_code)]
    #[serde(default)]
    pub local_ports: Vec<u16>,
    
    // KEY METRICS
    #[allow(dead_code)]
    #[serde(default)]
    pub min_port: u16,
    #[allow(dead_code)]
    #[serde(default)]
    pub max_port: u16,
    #[serde(default)]
    pub port_range: u16,
    
    // Classification
    #[serde(default)]
    pub pattern_type: String,
    #[serde(default)]
    pub needs_scan: bool,
    #[serde(default)]
    pub scan_start: u16,
    #[serde(default)]
    pub scan_end: u16,
}

impl NATAnalysis {
    /// Get friendly description of NAT type
    pub fn description(&self) -> &'static str {
        match self.pattern_type.as_str() {
            "port_preserved" => "Port-preserving NAT (easy)",
            "constant_delta" => "Constant delta NAT (easy)",
            "small_delta_range" => "Small delta range NAT (should work)",
            "medium_delta_range" => "Medium delta range NAT (may work)",
            "large_delta_range" => "Large delta range NAT (difficult)",
            "random_like" => "Random-like NAT (very difficult)",
            "constant" => "Constant port NAT (easy)",
            "small_range" => "Small range NAT (should work)",
            "medium_range" => "Medium range NAT (may work)",
            "large_range" => "Large range NAT (difficult)",
            "random" => "Random NAT (very difficult)",
            "insufficient_data" => "Unknown (no probe data)",
            _ => "Unknown NAT type",
        }
    }
    
    /// Get number of ports to scan
    pub fn scan_count(&self) -> u32 {
        if self.needs_scan && self.scan_end >= self.scan_start {
            (self.scan_end - self.scan_start + 1) as u32
        } else {
            0
        }
    }
}

/// Probe message for NAT analysis
#[derive(Debug, Clone, Serialize)]
pub struct ProbeMessage {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub session_id: String,
    pub local_port: u16,
    pub probe_num: u32,
}

impl ProbeMessage {
    pub fn new(session_id: &str, local_port: u16, probe_num: u32) -> Self {
        Self {
            msg_type: "probe".to_string(),
            session_id: session_id.to_string(),
            local_port,
            probe_num,
        }
    }
}

/// Probes complete message
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize)]
pub struct ProbesCompleteMessage {
    #[serde(rename = "type")]
    pub msg_type: String,
}

impl Default for ProbesCompleteMessage {
    fn default() -> Self {
        Self {
            msg_type: "probes_complete".to_string(),
        }
    }
}

impl From<PeerAddressInfo> for PeerAddress {
    fn from(info: PeerAddressInfo) -> Self {
        PeerAddress {
            ip: info.ip,
            port: info.port,
            addr_type: info.addr_type,
        }
    }
}

/// Generic server message
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum RelayMessage {
    #[serde(rename = "registered")]
    Registered {
        your_public_addr: Vec<serde_json::Value>,
        your_role: String,
        session_id: String,
        #[serde(default)]
        server_time: Option<f64>,  // Server timestamp for clock sync
        #[serde(default)]
        #[allow(dead_code)]
        initial_delta: Option<i32>,  // NAT port delta
        #[serde(default)]
        #[allow(dead_code)]
        port_preserved: Option<bool>,  // Is port preserved?
        #[serde(default)]
        probe_port: Option<u16>,  // Port for NAT probing
        #[serde(default)]
        needs_probing: Option<bool>,  // Does this peer need NAT probing?
    },
    
    #[serde(rename = "peer_info")]
    PeerInfo {
        peer_public_addr: Vec<serde_json::Value>,
        peer_local_port: u16,
        peer_addresses: Vec<PeerAddressInfo>,
        #[allow(dead_code)]
        your_role: String,
        same_network: bool,
        #[serde(default)]
        peer_nat_analysis: Option<NATAnalysis>,
    },
    
    #[serde(rename = "go")]
    Go {
        start_at: f64,
        #[serde(default)]
        message: String,
    },
    
    #[serde(rename = "ping")]
    Ping {},
    
    #[serde(rename = "keepalive_ack")]
    KeepaliveAck {},
    
    #[serde(rename = "error")]
    Error {
        message: String,
    },
}

impl RelayMessage {
    /// Parse peer address from JSON array [ip, port]
    pub fn parse_addr(addr: &[serde_json::Value]) -> Option<(String, u16)> {
        if addr.len() != 2 {
            return None;
        }
        let ip = addr[0].as_str()?.to_string();
        let port = addr[1].as_u64()? as u16;
        Some((ip, port))
    }
}

/// File transfer protocol messages (binary, over the direct TCP connection)
#[allow(dead_code)]
pub mod transfer {
    use bytes::{Buf, BufMut, Bytes, BytesMut};

    /// Message types for file transfer
    #[repr(u8)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum MessageType {
        Hello = 1,       // Initial handshake
        FileInfo = 2,    // File metadata
        FileInfoAck = 3, // Acknowledge file info
        Data = 4,        // File data chunk (reserved for future use)
        Done = 5,        // Transfer complete
        Ack = 6,         // Final acknowledgment
        Error = 7,       // Error message (reserved for future use)
    }

    impl MessageType {
        pub fn from_u8(v: u8) -> Option<Self> {
            match v {
                1 => Some(Self::Hello),
                2 => Some(Self::FileInfo),
                3 => Some(Self::FileInfoAck),
                4 => Some(Self::Data),
                5 => Some(Self::Done),
                6 => Some(Self::Ack),
                7 => Some(Self::Error),
                _ => None,
            }
        }
    }

    /// Hello message for initial handshake after hole punch
    #[derive(Debug, Clone)]
    pub struct HelloMessage {
        pub role: String, // "sender" or "receiver"
    }

    impl HelloMessage {
        pub fn encode(&self) -> BytesMut {
            let role_bytes = self.role.as_bytes();
            let mut buf = BytesMut::with_capacity(5 + role_bytes.len());
            buf.put_u8(MessageType::Hello as u8);
            buf.put_u32(role_bytes.len() as u32);
            buf.put_slice(role_bytes);
            buf
        }

        pub fn decode(data: &[u8]) -> Option<Self> {
            if data.len() < 5 {
                return None;
            }
            let mut cursor = &data[1..];
            let len = cursor.get_u32() as usize;
            if data.len() < 5 + len {
                return None;
            }
            let role = String::from_utf8(data[5..5 + len].to_vec()).ok()?;
            Some(Self { role })
        }
    }

    /// File info message
    #[derive(Debug, Clone)]
    pub struct FileInfoMessage {
        pub filename: String,
        pub file_size: u64,
        pub sha256: [u8; 32],
    }

    impl FileInfoMessage {
        /// Encode: type(1) + name_len(4) + size(8) + name(n) + sha256(32)
        pub fn encode(&self) -> BytesMut {
            let name_bytes = self.filename.as_bytes();
            let mut buf = BytesMut::with_capacity(1 + 4 + 8 + name_bytes.len() + 32);
            buf.put_u8(MessageType::FileInfo as u8);
            buf.put_u32(name_bytes.len() as u32);
            buf.put_u64(self.file_size);
            buf.put_slice(name_bytes);
            buf.put_slice(&self.sha256);
            buf
        }

        pub fn decode(data: &[u8]) -> Option<Self> {
            if data.len() < 13 {
                return None;
            }
            let mut cursor = &data[1..];
            let name_len = cursor.get_u32() as usize;
            let file_size = cursor.get_u64();
            
            if data.len() < 13 + name_len + 32 {
                return None;
            }
            
            let filename = String::from_utf8(data[13..13 + name_len].to_vec()).ok()?;
            let mut sha256 = [0u8; 32];
            sha256.copy_from_slice(&data[13 + name_len..13 + name_len + 32]);
            
            Some(Self {
                filename,
                file_size,
                sha256,
            })
        }
    }

    /// Simple acknowledgment messages
    pub fn encode_simple(msg_type: MessageType) -> Bytes {
        Bytes::from(vec![msg_type as u8])
    }

    /// Parse message type from first byte
    pub fn parse_type(data: &[u8]) -> Option<MessageType> {
        if data.is_empty() {
            return None;
        }
        MessageType::from_u8(data[0])
    }
}
