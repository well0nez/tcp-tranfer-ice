//! TCP Hole Punching Implementation v2.0
//!
//! TCP hole punching requires "simultaneous open" - both peers must try to 
//! connect at EXACTLY the same time. This is achieved by:
//!
//! 1. Both peers bind to a known local port
//! 2. Both peers wait for a synchronized "GO" signal from relay server
//! 3. At the exact same moment, both peers:
//!    - Listen for incoming connections on their local port
//!    - Attempt outgoing connections to peer's address
//! 4. The outgoing connections use SO_REUSEADDR/SO_REUSEPORT to share the port
//! 5. One of the connection attempts will succeed
//!
//! Critical: The OUTGOING connection must come from the SAME PORT as the listener!
//! This is what creates the NAT mapping that allows the peer's packets through.

use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::{TcpListener, TcpStream};
use socket2::{Socket, Domain, Type, Protocol, SockAddr};
use anyhow::{Result, anyhow};
use tracing::{info, debug, warn, error};

/// Result of hole punch attempt
pub enum HolePunchResult {
    /// Successfully established connection
    Success(TcpStream),
    /// Timed out without connection
    Timeout,
}

/// Peer address to try
#[derive(Debug, Clone)]
pub struct PeerAddress {
    pub ip: String,
    pub port: u16,
    #[allow(dead_code)]
    pub addr_type: String,
}

impl PeerAddress {
    pub fn to_socket_addr(&self) -> Result<SocketAddr> {
        let addr_str = format!("{}:{}", self.ip, self.port);
        addr_str.parse().map_err(|e| anyhow!("Invalid address {}: {}", addr_str, e))
    }
}

/// Configuration for hole punching
pub struct HolePunchConfig {
    /// Local port to bind to (MUST match what we told the relay!)
    pub local_port: u16,
    /// Primary peer address (public IP:port)
    pub peer_primary_addr: SocketAddr,
    /// All peer addresses to try (including predicted ports)
    pub peer_addresses: Vec<PeerAddress>,
    /// Synchronized start time (Unix timestamp from SERVER)
    pub start_at: f64,
    /// How long to try after start_at before giving up
    pub timeout: Duration,
    /// Are we on the same network as peer?
    #[allow(dead_code)]
    pub same_network: bool,
    /// Time offset: local_time + offset = server_time
    /// (positive = our clock is behind server, negative = ahead)
    pub time_offset: f64,
}

impl Default for HolePunchConfig {
    fn default() -> Self {
        Self {
            local_port: 0,
            peer_primary_addr: "0.0.0.0:0".parse().unwrap(),
            peer_addresses: vec![],
            start_at: 0.0,
            timeout: Duration::from_secs(30),
            same_network: false,
            time_offset: 0.0,
        }
    }
}

/// Get current Unix timestamp
fn current_timestamp() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}

/// Create a TCP socket with proper options for hole punching
fn create_hole_punch_socket() -> Result<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    
    // CRITICAL: Enable address reuse so multiple sockets can bind to same port
    socket.set_reuse_address(true)?;
    
    // CRITICAL on Unix: Enable port reuse for true simultaneous bind
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    
    // Disable Nagle for faster small packet transmission
    socket.set_nodelay(true)?;
    
    // Set linger to ensure clean socket closure
    socket.set_linger(Some(Duration::from_secs(0)))?;
    
    Ok(socket)
}

/// Bind a socket to the specified local port
fn bind_to_port(socket: &Socket, port: u16) -> Result<()> {
    let addr: SocketAddr = format!("0.0.0.0:{}", port).parse()?;
    socket.bind(&SockAddr::from(addr))?;
    Ok(())
}

/// Perform TCP hole punching with proper synchronization
///
/// This is the main entry point for hole punching. It:
/// 1. Waits until start_at timestamp (adjusted for clock offset)
/// 2. Starts listener and connector simultaneously
/// 3. Connector binds to same local port as listener (critical!)
/// 4. Tries multiple peer addresses in parallel
pub async fn do_hole_punch(config: HolePunchConfig) -> Result<HolePunchResult> {
    // Calculate wait time with clock offset compensation
    // start_at is in SERVER time, we need to convert to local time
    // local_time + offset = server_time
    // so: local_start_at = start_at - offset
    let local_start_at = config.start_at - config.time_offset;
    let now = current_timestamp();
    let wait_time = local_start_at - now;
    
    // Log clock sync info
    if config.time_offset.abs() > 0.1 {
        info!("⏱️ Clock offset: {:.3}s (local {} server)", 
            config.time_offset,
            if config.time_offset > 0.0 { "behind" } else { "ahead of" });
    }
    
    if wait_time > 0.0 {
        info!("Waiting {:.2}s until synchronized start time...", wait_time);
        tokio::time::sleep(Duration::from_secs_f64(wait_time)).await;
    } else if wait_time < -5.0 {
        warn!("Start time was {:.2}s in the past! Clock sync issue?", -wait_time);
    }
    
    let start = Instant::now();
    
    info!("🚀 Starting TCP hole punch from port {}...", config.local_port);
    
    // Collect all addresses to try
    let mut addresses: Vec<SocketAddr> = vec![config.peer_primary_addr];
    for pa in &config.peer_addresses {
        if let Ok(addr) = pa.to_socket_addr() {
            if !addresses.contains(&addr) {
                addresses.push(addr);
            }
        }
    }
    
    info!("Will try {} unique addresses", addresses.len());
    
    // Run the hole punch
    let result = run_hole_punch(config.local_port, addresses, config.timeout).await;
    
    match &result {
        Ok(HolePunchResult::Success(_)) => {
            info!("✅ Hole punch succeeded! (took {:?})", start.elapsed());
        }
        Ok(HolePunchResult::Timeout) => {
            warn!("⏱️ Hole punch timed out after {:?}", start.elapsed());
        }
        Err(e) => {
            error!("❌ Hole punch error: {}", e);
        }
    }
    
    result
}

/// Run the actual hole punch with listener and connector
async fn run_hole_punch(
    local_port: u16,
    peer_addresses: Vec<SocketAddr>,
    timeout: Duration,
) -> Result<HolePunchResult> {
    
    // Create and set up the listener socket
    let listener_socket = create_hole_punch_socket()?;
    bind_to_port(&listener_socket, local_port)?;
    listener_socket.listen(128)?;
    
    let std_listener: std::net::TcpListener = listener_socket.into();
    std_listener.set_nonblocking(true)?;
    let listener = TcpListener::from_std(std_listener)?;
    
    let actual_port = listener.local_addr()?.port();
    info!("Listener ready on port {} (requested: {})", actual_port, local_port);
    
    // Use a channel to communicate success
    let (tx, mut rx) = tokio::sync::mpsc::channel::<TcpStream>(1);
    
    // Spawn listener task
    let listener_tx = tx.clone();
    let listener_handle = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    info!("📥 Accepted connection from {}", peer_addr);
                    if let Err(_) = stream.set_nodelay(true) {
                        warn!("Failed to set nodelay");
                    }
                    let _ = listener_tx.send(stream).await;
                    break;
                }
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::WouldBlock {
                        debug!("Accept error: {}", e);
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    });
    
    // Spawn connector tasks for each address
    let total_ports = peer_addresses.len();
    let connector_handles: Vec<_> = peer_addresses.iter().enumerate().map(|(idx, &peer_addr)| {
        let connector_tx = tx.clone();
        let local_port = local_port;
        let port_num = idx + 1;
        
        tokio::spawn(async move {
            // Stagger start slightly to avoid overwhelming the network
            if idx > 0 {
                tokio::time::sleep(Duration::from_millis(50 * idx as u64)).await;
            }
            
            let mut attempt = 0;
            let connector_timeout = timeout;
            let connector_start = Instant::now();
            
            while connector_start.elapsed() < connector_timeout {
                attempt += 1;
                
                // Create a new socket for each attempt, bound to our local port
                let socket = match create_hole_punch_socket() {
                    Ok(s) => s,
                    Err(e) => {
                        debug!("Failed to create socket: {}", e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                
                // CRITICAL: Bind to our local port!
                if let Err(e) = bind_to_port(&socket, local_port) {
                    debug!("Failed to bind to port {}: {}", local_port, e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
                
                // Set non-blocking for async operation
                if let Err(e) = socket.set_nonblocking(true) {
                    debug!("Failed to set nonblocking: {}", e);
                    continue;
                }
                
                // Try to connect
                let connect_result = socket.connect(&SockAddr::from(peer_addr));
                
                match connect_result {
                    Ok(()) => {
                        // Immediate success (unlikely but possible)
                        let std_stream: std::net::TcpStream = socket.into();
                        match TcpStream::from_std(std_stream) {
                            Ok(stream) => {
                                info!("📤 Connected to {} (port {}/{} found it!)", peer_addr, port_num, total_ports);
                                let _ = connector_tx.send(stream).await;
                                return;
                            }
                            Err(e) => {
                                debug!("Failed to convert stream: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        // Check if it's "in progress" (expected for non-blocking)
                        #[cfg(unix)]
                        let is_in_progress = e.raw_os_error() == Some(libc::EINPROGRESS)
                            || e.kind() == std::io::ErrorKind::WouldBlock;
                        #[cfg(not(unix))]
                        let is_in_progress = e.kind() == std::io::ErrorKind::WouldBlock;
                        
                        if is_in_progress {
                            // Wait for connection to complete
                            let std_stream: std::net::TcpStream = socket.into();
                            
                            match wait_for_connect(std_stream, Duration::from_millis(500)).await {
                                Ok(stream) => {
                                    info!("📤 Connected to {} (port {}/{} found it!)", peer_addr, port_num, total_ports);
                                    let _ = connector_tx.send(stream).await;
                                    return;
                                }
                                Err(_) => {
                                    // Connection failed, try again
                                }
                            }
                        } else {
                            // Real error
                            if attempt % 20 == 0 {
                                debug!("[{}] Connect attempt {} to {} failed: {}", 
                                    idx, attempt, peer_addr, e);
                            }
                        }
                    }
                }
                
                // Small delay between attempts
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            
            debug!("[{}] Connector to {} timed out after {} attempts", idx, peer_addr, attempt);
        })
    }).collect();
    
    // Drop our sender so the channel closes when all tasks are done
    drop(tx);
    
    // Wait for success or timeout
    let timeout_duration = timeout + Duration::from_secs(1);
    
    tokio::select! {
        Some(stream) = rx.recv() => {
            // Success! Cancel other tasks
            listener_handle.abort();
            for h in connector_handles {
                h.abort();
            }
            return Ok(HolePunchResult::Success(stream));
        }
        _ = tokio::time::sleep(timeout_duration) => {
            // Timeout - cancel all tasks
            listener_handle.abort();
            for h in connector_handles {
                h.abort();
            }
            return Ok(HolePunchResult::Timeout);
        }
    }
}

/// Wait for a non-blocking connect to complete
async fn wait_for_connect(stream: std::net::TcpStream, timeout: Duration) -> Result<TcpStream> {
    use tokio::io::Interest;
    
    let stream = TcpStream::from_std(stream)?;
    
    // Wait for the socket to become writable (connection complete)
    match tokio::time::timeout(timeout, stream.ready(Interest::WRITABLE)).await {
        Ok(Ok(_)) => {
            // Check if there was a connection error
            match stream.peer_addr() {
                Ok(_) => {
                    stream.set_nodelay(true)?;
                    Ok(stream)
                }
                Err(e) => Err(anyhow!("Connection failed: {}", e))
            }
        }
        Ok(Err(e)) => Err(anyhow!("Ready check failed: {}", e)),
        Err(_) => Err(anyhow!("Connection timeout")),
    }
}

/// Simple test connection (no hole punch, just direct connect)
/// Useful for testing on same machine or when hole punch not needed
#[allow(dead_code)]
pub async fn direct_connect(addr: SocketAddr, timeout: Duration) -> Result<TcpStream> {
    info!("Attempting direct connection to {}...", addr);
    
    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => {
            stream.set_nodelay(true)?;
            info!("✅ Direct connection successful!");
            Ok(stream)
        }
        Ok(Err(e)) => Err(anyhow!("Connection failed: {}", e)),
        Err(_) => Err(anyhow!("Connection timeout")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_create_socket() {
        let socket = create_hole_punch_socket().unwrap();
        bind_to_port(&socket, 0).unwrap();
        let addr = socket.local_addr().unwrap();
        println!("Bound to: {:?}", addr);
    }
    
    #[tokio::test]
    async fn test_local_loopback() {
        // Test that we can connect to ourselves (basic sanity check)
        let socket = create_hole_punch_socket().unwrap();
        bind_to_port(&socket, 0).unwrap();
        socket.listen(1).unwrap();
        
        let listener: std::net::TcpListener = socket.into();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let listener = TcpListener::from_std(listener).unwrap();
        
        let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
        
        let accept_task = tokio::spawn(async move {
            listener.accept().await
        });
        
        let connect_task = tokio::spawn(async move {
            TcpStream::connect(addr).await
        });
        
        let (accept_result, connect_result) = tokio::join!(accept_task, connect_task);
        
        assert!(accept_result.unwrap().is_ok());
        assert!(connect_result.unwrap().is_ok());
    }
}
