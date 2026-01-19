//! TCP File Transfer Client with NAT Traversal
//!
//! This client uses TCP hole punching to establish direct peer-to-peer
//! connections through NAT, then transfers files using TCP streams.
//!
//! Protocol flow:
//! 1. Connect to relay server and register with session ID + role
//! 2. Wait for peer_info (when other peer connects)
//! 3. Send "ready" to signal we're prepared
//! 4. Wait for synchronized "go" signal with start_at timestamp
//! 5. At start_at, begin simultaneous hole punch
//! 6. Transfer file over established connection
//!
//! Usage:
//!   Receive: tcp-transfer -s relay:port -i SESSION_ID -m receive
//!   Send:    tcp-transfer -s relay:port -i SESSION_ID -m send -f file.mp4

use std::collections::HashSet;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;
use clap::{Parser, ValueEnum};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use socket2::{Socket, Domain, Type, Protocol, SockAddr};
use anyhow::{Result, anyhow};
use tracing::{info, error, warn, Level, debug};
use tracing_subscriber::FmtSubscriber;

mod protocol;
mod hole_punch;
mod transfer;

use protocol::{RegisterMessage, ReadyMessage, RelayMessage, ProbeMessage};
use hole_punch::{HolePunchConfig, HolePunchResult, PeerAddress, do_hole_punch};
use transfer::{TcpSender, TcpReceiver, calculate_sha256, set_chunk_size};

/// Number of NAT probes to send
const DEFAULT_NAT_PROBE_COUNT: u32 = 10;
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Mode {
    Send,
    Receive,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum PredictionMode {
    Delta,
    External,
}

impl PredictionMode {
    fn as_str(self) -> &'static str {
        match self {
            PredictionMode::Delta => "delta",
            PredictionMode::External => "external",
        }
    }
}

#[derive(Parser, Debug)]
#[command(name = "tcp-transfer")]
#[command(author = "TCP Transfer Team")]
#[command(version)]
#[command(about = "TCP file transfer with NAT traversal (hole punching)")]
struct Args {
    /// Relay server address (host:port)
    #[arg(short, long)]
    server: String,
    
    /// Session ID (both sender and receiver must use the same ID)
    #[arg(short = 'i', long)]
    session_id: String,
    
    /// Mode: send or receive
    #[arg(short, long, value_enum)]
    mode: Mode,
    
    /// File to send (sender mode only)
    #[arg(short, long)]
    file: Option<String>,
    
    /// Hole punch timeout in seconds
    #[arg(long, default_value = "30")]
    timeout: u64,

    /// Number of NAT probes to send (higher can improve symmetric/random NAT success)
    #[arg(long, default_value_t = DEFAULT_NAT_PROBE_COUNT)]
    probe_count: u32,

    /// Run probe-only debug mode and print observed ports
    #[arg(long)]
    probe_debug: bool,

    /// NAT prediction mode: delta or external
    #[arg(long, value_enum, default_value_t = PredictionMode::Delta)]
    prediction_mode: PredictionMode,

    /// Expand prediction scan range by percentage (applies to delta and external)
    #[arg(long, default_value_t = 0.0)]
    prediction_range_extra_pct: f64,
    
    /// Enable debug logging
    #[arg(long)]
    debug: bool,
    
    /// Chunk size for transfer (e.g., 512KB, 1MB, 2MB)
    #[arg(long, default_value = "1MB")]
    chunk: String,
}

/// Parse chunk size from string (e.g., "512KB", "1MB", "2MB")
fn parse_chunk_size(s: &str) -> Result<usize> {
    let s = s.trim().to_uppercase();
    
    if s.ends_with("MB") {
        let num: f64 = s.trim_end_matches("MB").trim().parse()
            .map_err(|_| anyhow!("Invalid chunk size: {}", s))?;
        Ok((num * 1024.0 * 1024.0) as usize)
    } else if s.ends_with("KB") {
        let num: f64 = s.trim_end_matches("KB").trim().parse()
            .map_err(|_| anyhow!("Invalid chunk size: {}", s))?;
        Ok((num * 1024.0) as usize)
    } else if s.ends_with("B") {
        let num: usize = s.trim_end_matches("B").trim().parse()
            .map_err(|_| anyhow!("Invalid chunk size: {}", s))?;
        Ok(num)
    } else {
        // Try parsing as bytes
        s.parse::<usize>()
            .map_err(|_| anyhow!("Invalid chunk size: {}. Use format like 512KB, 1MB, 2MB", s))
    }
}

/// Session state for hole punch coordination
struct Session {
    peer_public_addr: Option<SocketAddr>,
    peer_addresses: Vec<PeerAddress>,
    same_network: bool,
    start_at: Option<f64>,
    /// Time offset for clock sync: local_time + offset = server_time
    time_offset: f64,
    /// Our own public port as seen by server
    our_public_port: Option<u16>,
    /// Our port delta: public_port - local_port
    our_delta: i32,
    /// Port preservation: true if our_delta == 0
    port_preserved: bool,
}

fn parse_host_port(input: &str) -> Result<(String, u16)> {
    let input = input.trim();
    if input.starts_with('[') {
        let end = input.find(']').ok_or_else(|| anyhow!("Invalid address '{}': missing closing ']'", input))?;
        let host = &input[1..end];
        let rest = &input[end + 1..];
        if !rest.starts_with(':') {
            return Err(anyhow!("Invalid address '{}': expected [host]:port", input));
        }
        let port_str = &rest[1..];
        if host.is_empty() || port_str.is_empty() {
            return Err(anyhow!("Invalid address '{}': expected [host]:port", input));
        }
        let port = port_str.parse::<u16>()
            .map_err(|_| anyhow!("Invalid port in address '{}'", input))?;
        return Ok((host.to_string(), port));
    }

    let idx = input.rfind(':')
        .ok_or_else(|| anyhow!("Invalid address '{}': expected host:port", input))?;
    let host = &input[..idx];
    let port_str = &input[idx + 1..];
    if host.is_empty() || port_str.is_empty() {
        return Err(anyhow!("Invalid address '{}': expected host:port", input));
    }
    if host.contains(':') {
        return Err(anyhow!("Invalid address '{}': IPv6 must be in [addr]:port format", input));
    }
    let port = port_str.parse::<u16>()
        .map_err(|_| anyhow!("Invalid port in address '{}'", input))?;
    Ok((host.to_string(), port))
}

fn resolve_host_port(host: &str, port: u16) -> Result<SocketAddr> {
    let mut addrs = (host, port).to_socket_addrs()
        .map_err(|e| anyhow!("Failed to resolve '{}': {}", host, e))?;
    addrs.next()
        .ok_or_else(|| anyhow!("Failed to resolve '{}': no addresses found", host))
}

fn resolve_socket_addr(input: &str) -> Result<SocketAddr> {
    let (host, port) = parse_host_port(input)?;
    resolve_host_port(&host, port)
}

/// Do NAT probing - send multiple connections to probe server to determine port range
async fn do_nat_probing(probe_addr: SocketAddr, session_id: &str, count: u32) -> Result<()> {
    info!("🔍 Starting NAT probing ({} connections to {})...", count, probe_addr);
    
    let mut successful = 0;
    
    for i in 0..count {
        // Each probe uses a NEW local port to get different NAT mapping
        match TcpStream::connect(probe_addr).await {
            Ok(stream) => {
                let local_port = stream.local_addr().map(|a| a.port()).unwrap_or(0);
                
                // Send probe message
                let probe = ProbeMessage::new(session_id, local_port, i);
                let msg = serde_json::to_string(&probe).unwrap_or_default() + "\n";
                
                // Use split to send
                let (_, mut writer) = stream.into_split();
                if let Ok(_) = tokio::io::AsyncWriteExt::write_all(&mut writer, msg.as_bytes()).await {
                    successful += 1;
                    debug!("  Probe #{}: local port {}", i, local_port);
                }
            }
            Err(e) => {
                warn!("  Probe #{} failed: {}", i, e);
            }
        }
        
        // Small delay between probes
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    
    if successful >= 5 {
        info!("  ✓ Sent {}/{} probes successfully", successful, count);
        Ok(())
    } else {
        warn!("  ⚠️ Only {}/{} probes succeeded - NAT analysis may be incomplete", successful, count);
        Ok(()) // Continue anyway
    }
}

/// Get a free local port by binding temporarily
fn get_free_port() -> Result<u16> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    
    let addr: SocketAddr = "0.0.0.0:0".parse()?;
    socket.bind(&addr.into())?;
    
    let local_addr = socket.local_addr()?;
    let port = local_addr.as_socket().ok_or_else(|| anyhow!("No socket address"))?.port();
    
    // Socket is dropped here, freeing the port but we remember it
    Ok(port)
}

/// Create a TCP socket bound to a specific local port
fn create_bound_socket(local_port: u16) -> Result<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    
    // CRITICAL: Enable address reuse so we can reuse this port for hole punching
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    
    // Disable Nagle for faster small packet transmission
    socket.set_nodelay(true)?;
    
    // Bind to the specific local port
    let local_addr: SocketAddr = format!("0.0.0.0:{}", local_port).parse()?;
    socket.bind(&SockAddr::from(local_addr))?;
    
    Ok(socket)
}

/// Connect to relay server and handle the full protocol
async fn run_relay_protocol(
    server_addr: &str,
    session_id: &str,
    role: &str,
    local_port: u16,
    _timeout: Duration,
    probe_count: u32,
    prediction_mode: PredictionMode,
    prediction_range_extra_pct: f64,
) -> Result<(TcpStream, Session)> {
    info!("Connecting to relay server: {}", server_addr);
    
    // CRITICAL FIX: Connect FROM the local_port so NAT mapping matches hole punch!
    let server_sock_addr = resolve_socket_addr(server_addr)?;
    
    let socket = create_bound_socket(local_port)?;
    socket.set_nonblocking(true)?;
    
    // Start async connect
    let _ = socket.connect(&SockAddr::from(server_sock_addr));
    
    let std_stream: std::net::TcpStream = socket.into();
    let stream = TcpStream::from_std(std_stream)?;
    
    // Wait for connection to complete
    stream.writable().await?;
    
    // Check for connection errors
    if let Err(e) = stream.peer_addr() {
        return Err(anyhow!("Failed to connect to relay server: {}", e));
    }
    
    info!("Connected from local port {} to {}", local_port, server_addr);
    
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    
    // Send registration
    let register = RegisterMessage::new(
        session_id,
        role,
        local_port,
        Some(prediction_mode.as_str().to_string()),
        Some(prediction_range_extra_pct),
    );
    let msg = serde_json::to_string(&register)? + "\n";
    writer.write_all(msg.as_bytes()).await?;
    writer.flush().await?;
    
    info!("Registered as {} for session {} (local_port={})", role, session_id, local_port);
    
    // Track timing for clock offset calculation
    let register_sent_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    
    let mut session = Session {
        peer_public_addr: None,
        peer_addresses: vec![],
        same_network: false,
        start_at: None,
        time_offset: 0.0,
        our_public_port: None,
        our_delta: 0,
        port_preserved: true,
    };
    
    // Read messages from server until we get the GO signal
    loop {
        let mut line = String::new();
        let n = tokio::time::timeout(Duration::from_secs(120), reader.read_line(&mut line)).await
            .map_err(|_| anyhow!("Timeout waiting for server response"))??;
        
        if n == 0 {
            return Err(anyhow!("Server closed connection"));
        }
        
        debug!("Server message: {}", line.trim());
        
        let msg: RelayMessage = serde_json::from_str(&line)
            .map_err(|e| anyhow!("Failed to parse server message: {} - {}", e, line.trim()))?;
        
        match msg {
            RelayMessage::Registered { your_public_addr, your_role, session_id: sess_id, server_time, probe_port, needs_probing, .. } => {
                if let Some((ip, port)) = RelayMessage::parse_addr(&your_public_addr) {
                    // Store our public port and calculate delta
                    let public_port = port;
                    session.our_public_port = Some(public_port);
                    session.our_delta = public_port as i32 - local_port as i32;
                    session.port_preserved = session.our_delta == 0;
                    
                    info!("✓ Registered! Public address: {}:{}", ip, port);
                    info!("  Role: {}, Session: {}", your_role, sess_id);
                    info!("  Local port: {} → NAT port: {}", local_port, public_port);
                    
                    // Show port delta analysis
                    let needs_probe = needs_probing.unwrap_or(false);
                    if session.port_preserved {
                        info!("  ✅ Port Preserved! (delta=0) - NAT is friendly");
                    } else {
                        warn!("  ⚠️ Port Changed! Delta = {} (NAT may be Symmetric)", session.our_delta);
                        if needs_probe {
                            info!("     Will do NAT probing to determine port range...");
                        }
                    }
                    
                    // Calculate clock offset if server_time is provided
                    if let Some(srv_time) = server_time {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs_f64();
                        let rtt = now - register_sent_at;
                        session.time_offset = srv_time - (register_sent_at + rtt / 2.0);
                        
                        if session.time_offset.abs() > 0.1 {
                            info!("⏱️ Clock offset: {:.3}s (local {} server)", 
                                session.time_offset,
                                if session.time_offset > 0.0 { "behind" } else { "ahead of" });
                        }
                        if session.time_offset.abs() > 60.0 {
                            warn!("⚠️ Large clock offset detected! Consider syncing system time.");
                        }
                    }
                    
                    // Do NAT probing if server provided probe_port AND needs_probing is true
                    if needs_probe {
                        if let Some(pp) = probe_port {
                            // Build probe server address using the relay server IP
                            let probe_addr = SocketAddr::new(server_sock_addr.ip(), pp);
                            if let Err(e) = do_nat_probing(probe_addr, session_id, probe_count).await {
                                warn!("NAT probing failed: {} - continuing anyway", e);
                            }
                        }
                    }
                    
                    // Send probes_complete message to server
                    info!("Sending probes_complete...");
                    let probes_complete_msg = r#"{"type":"probes_complete"}"#.to_string() + "\n";
                    writer.write_all(probes_complete_msg.as_bytes()).await?;
                    writer.flush().await?;
                    info!("✓ Probes complete sent");
                } else {
                    warn!("Could not parse public address");
                }
            }
            
            RelayMessage::PeerInfo { peer_public_addr, peer_local_port, peer_addresses, your_role: _, same_network, peer_nat_analysis } => {
                if let Some((ip, port)) = RelayMessage::parse_addr(&peer_public_addr) {
                    let addr: SocketAddr = format!("{}:{}", ip, port).parse()?;
                    session.peer_public_addr = Some(addr);
                    session.peer_addresses = peer_addresses.into_iter()
                        .map(|pa| pa.into())
                        .collect();
                    session.same_network = same_network;
                    
                    let addr_count = session.peer_addresses.len();
                    
                    info!("✓ Peer info received!");
                    info!("  Peer: {} (local port {})", addr, peer_local_port);
                    
                    // Show peer's NAT analysis
                    if let Some(nat) = &peer_nat_analysis {
                        info!("  NAT: {} | Range: {} ports", nat.description(), nat.port_range);
                        if nat.needs_scan {
                            info!("  🔍 Will scan {} ports ({}..{})", nat.scan_count(), nat.scan_start, nat.scan_end);
                        }
                    } else if addr_count == 1 {
                        info!("  NAT: ✅ Port-Preserving (single address)");
                    }
                    
                    // Send READY signal
                    let ready = ReadyMessage::default();
                    let msg = serde_json::to_string(&ready)? + "\n";
                    writer.write_all(msg.as_bytes()).await?;
                    writer.flush().await?;
                    info!("✓ READY sent, waiting for GO...");
                }
            }
            
            RelayMessage::Go { start_at, message } => {
                session.start_at = Some(start_at);
                info!("✓ GO signal received!");
                info!("  Start at: {} (in {:.2}s)", start_at, start_at - std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs_f64());
                if !message.is_empty() {
                    info!("  Message: {}", message);
                }
                
                // Reunite the stream for returning
                let stream = reader.into_inner().reunite(writer)?;
                return Ok((stream, session));
            }
            
            RelayMessage::Ping {} => {
                // Respond with keepalive
                let msg = r#"{"type":"keepalive"}"# .to_string() + "\n";
                writer.write_all(msg.as_bytes()).await?;
                writer.flush().await?;
                debug!("Responded to ping");
            }
            
            RelayMessage::KeepaliveAck {} => {
                debug!("Keepalive acknowledged");
            }
            
            RelayMessage::Error { message } => {
                return Err(anyhow!("Server error: {}", message));
            }
        }
    }
}

/// Run the sender
async fn run_sender(
    server_addr: &str,
    session_id: &str,
    file_path: &str,
    timeout: Duration,
    probe_count: u32,
    prediction_mode: PredictionMode,
    prediction_range_extra_pct: f64,
) -> Result<()> {
    // FIRST: Calculate SHA256 BEFORE connecting to relay
    // This can take a long time for large files, and we don't want to
    // block the other peer or timeout while hashing
    info!("Calculating SHA256 hash (this may take a while for large files)...");
    let (sha256, file_size) = calculate_sha256(file_path).await?;
    info!("SHA256: {}", transfer::sha256_to_hex(&sha256));
    info!("File size: {:.2} MB", file_size as f64 / (1024.0 * 1024.0));
    info!("");
    
    // Get local port for hole punching
    let local_port = get_free_port()?;
    info!("Using local port: {}", local_port);
    
    // Run relay protocol to get peer info and GO signal
    let (_relay_stream, session) = run_relay_protocol(
        server_addr,
        session_id,
        "sender",
        local_port,
        timeout,
        probe_count,
        prediction_mode,
        prediction_range_extra_pct,
    ).await?;
    
    // We can close relay connection now - we have all the info we need
    // (The relay keeps the connection open but we don't need it anymore)
    
    let peer_addr = session.peer_public_addr
        .ok_or_else(|| anyhow!("No peer address received"))?;
    let start_at = session.start_at
        .ok_or_else(|| anyhow!("No start_at received"))?;
    
    // Perform hole punch with clock offset compensation
    let config = HolePunchConfig {
        local_port,
        peer_primary_addr: peer_addr,
        peer_addresses: session.peer_addresses,
        start_at,
        timeout,
        same_network: session.same_network,
        time_offset: session.time_offset,
    };
    
    let stream = match do_hole_punch(config).await? {
        HolePunchResult::Success(stream) => stream,
        HolePunchResult::Timeout => {
            return Err(anyhow!("Hole punch timed out - could not establish connection"));
        }
    };
    
    info!("✅ Direct P2P connection established!");
    info!("   Local:  {}", stream.local_addr()?);
    info!("   Remote: {}", stream.peer_addr()?);
    
    // Start file transfer with pre-calculated hash
    let mut sender = TcpSender::new_with_hash(stream, file_path, file_size, sha256);
    sender.run().await
}

/// Run the receiver
async fn run_receiver(
    server_addr: &str,
    session_id: &str,
    timeout: Duration,
    probe_count: u32,
    prediction_mode: PredictionMode,
    prediction_range_extra_pct: f64,
) -> Result<()> {
    // Get local port for hole punching
    let local_port = get_free_port()?;
    info!("Using local port: {}", local_port);
    
    // Run relay protocol to get peer info and GO signal
    let (_relay_stream, session) = run_relay_protocol(
        server_addr,
        session_id,
        "receiver",
        local_port,
        timeout,
        probe_count,
        prediction_mode,
        prediction_range_extra_pct,
    ).await?;
    
    let peer_addr = session.peer_public_addr
        .ok_or_else(|| anyhow!("No peer address received"))?;
    let start_at = session.start_at
        .ok_or_else(|| anyhow!("No start_at received"))?;
    
    // Perform hole punch with clock offset compensation
    let config = HolePunchConfig {
        local_port,
        peer_primary_addr: peer_addr,
        peer_addresses: session.peer_addresses,
        start_at,
        timeout,
        same_network: session.same_network,
        time_offset: session.time_offset,
    };
    
    let stream = match do_hole_punch(config).await? {
        HolePunchResult::Success(stream) => stream,
        HolePunchResult::Timeout => {
            return Err(anyhow!("Hole punch timed out - could not establish connection"));
        }
    };
    
    info!("✅ Direct P2P connection established!");
    info!("   Local:  {}", stream.local_addr()?);
    info!("   Remote: {}", stream.peer_addr()?);
    
    // Start file transfer
    let mut receiver = TcpReceiver::new(stream);
    receiver.run().await
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    
    // Set up logging
    let level = if args.debug { Level::DEBUG } else { Level::INFO };
    let _subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .init();

    if args.probe_debug {
        run_probe_debug(&args.server, &args.session_id, args.probe_count).await?;
        return Ok(());
    }
    
    // Parse and set chunk size
    let chunk_size = parse_chunk_size(&args.chunk)?;
    if chunk_size < 64 * 1024 {
        return Err(anyhow!("Chunk size must be at least 64KB"));
    }
    if chunk_size > 16 * 1024 * 1024 {
        return Err(anyhow!("Chunk size must be at most 16MB"));
    }
    set_chunk_size(chunk_size);
    
    info!("TCP File Transfer Client v{} (ICE)", APP_VERSION);
    info!("===================================");
    debug!("Chunk: {} KB | Buffer: 8MB | TCP Buffer: 16MB", chunk_size / 1024);
    
    // Validate arguments
    if matches!(args.mode, Mode::Send) && args.file.is_none() {
        return Err(anyhow!("--file required for send mode"));
    }
    
    let timeout = Duration::from_secs(args.timeout);
    
    // Handle Ctrl+C
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        error!("🛑 Ctrl+C received, exiting...");
        std::process::exit(1);
    });
    
    // Run based on mode
    match args.mode {
        Mode::Send => {
            let file_path = args.file.as_ref().unwrap();
            
            // Check file exists
            if !std::path::Path::new(file_path).exists() {
                return Err(anyhow!("File not found: {}", file_path));
            }
            
            info!("Mode: SEND");
            info!("File: {}", file_path);
            info!("Session: {}", args.session_id);
            info!("");
            
            run_sender(
                &args.server,
                &args.session_id,
                file_path,
                timeout,
                args.probe_count,
                args.prediction_mode,
                args.prediction_range_extra_pct,
            ).await
        }
        Mode::Receive => {
            info!("Mode: RECEIVE");
            info!("Session: {}", args.session_id);
            info!("");
            
            run_receiver(
                &args.server,
                &args.session_id,
                timeout,
                args.probe_count,
                args.prediction_mode,
                args.prediction_range_extra_pct,
            ).await
        }
    }
}

async fn run_probe_debug(server_addr: &str, session_id: &str, count: u32) -> Result<()> {
    let probe_addr = derive_probe_addr(server_addr)?;

    println!("PROBE DEBUG MODE");
    println!("Server: {}", server_addr);
    println!("Probe:  {}", probe_addr);
    println!("Session: {}", session_id);
    println!("Count: {}", count);
    println!();

    if count == 0 {
        println!("No probes requested.");
        return Ok(());
    }

    struct ProbeSample {
        idx: u32,
        local_port: u16,
        nat_port: u16,
        delta: i32,
    }

    let mut samples: Vec<ProbeSample> = Vec::new();
    let mut failures = 0u32;

    for i in 0..count {
        match TcpStream::connect(probe_addr).await {
            Ok(stream) => {
                let local_port = stream.local_addr().map(|a| a.port()).unwrap_or(0);
                let (reader, mut writer) = stream.into_split();
                let mut reader = BufReader::new(reader);

                let probe = ProbeMessage::new(session_id, local_port, i);
                let msg = serde_json::to_string(&probe)? + "\n";
                if writer.write_all(msg.as_bytes()).await.is_err() {
                    failures += 1;
                    continue;
                }
                let _ = writer.flush().await;

                let mut line = String::new();
                match tokio::time::timeout(Duration::from_secs(3), reader.read_line(&mut line)).await {
                    Ok(Ok(0)) => {
                        failures += 1;
                    }
                    Ok(Ok(_n)) => {
                        let v: serde_json::Value = serde_json::from_str(&line)
                            .map_err(|e| anyhow!("Failed to parse probe_ack: {}", e))?;
                        let nat_port = v.get("your_nat_port").and_then(|p| p.as_u64())
                            .ok_or_else(|| anyhow!("probe_ack missing your_nat_port"))? as u16;
                        let delta = nat_port as i32 - local_port as i32;
                        samples.push(ProbeSample { idx: i, local_port, nat_port, delta });
                    }
                    _ => {
                        failures += 1;
                    }
                }
            }
            Err(_) => {
                failures += 1;
            }
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    if samples.is_empty() {
        println!("No probe acknowledgements received.");
        return Ok(());
    }

    println!("{:<4} {:>6} {:>6} {:>7}", "#", "local", "nat", "delta");
    println!("{:-<4} {:-<6} {:-<6} {:-<7}", "", "", "", "");
    for s in &samples {
        println!("{:<4} {:>6} {:>6} {:+7}", s.idx, s.local_port, s.nat_port, s.delta);
    }
    println!();

    let mut nat_ports: Vec<u16> = samples.iter().map(|s| s.nat_port).collect();
    let mut deltas: Vec<i32> = samples.iter().map(|s| s.delta).collect();

    let min_nat = *nat_ports.iter().min().unwrap();
    let max_nat = *nat_ports.iter().max().unwrap();
    let range_nat = max_nat - min_nat;

    let min_delta = *deltas.iter().min().unwrap();
    let max_delta = *deltas.iter().max().unwrap();
    let median_delta = median_i32(&mut deltas);
    let mean_delta = deltas.iter().map(|d| *d as f64).sum::<f64>() / deltas.len() as f64;
    let var_delta = deltas.iter().map(|d| {
        let diff = *d as f64 - mean_delta;
        diff * diff
    }).sum::<f64>() / deltas.len() as f64;
    let stdev_delta = var_delta.sqrt();

    let unique_nat: HashSet<u16> = nat_ports.iter().cloned().collect();
    nat_ports.sort_unstable();

    println!("NAT ports: min={} max={} range={} unique={}", min_nat, max_nat, range_nat, unique_nat.len());
    println!("Delta: min={} max={} median={:.1} stdev={:.2}", min_delta, max_delta, median_delta, stdev_delta);
    let max_dev = deltas.iter()
        .map(|d| ((*d as f64) - median_delta).abs())
        .fold(0.0, f64::max);
    let jitter = (stdev_delta * 2.0).round().max(2.0);
    let error_range = (max_dev + jitter).round() as i32;
    let delta_spread = max_delta - min_delta;
    let port_preserved = samples.iter().all(|s| s.delta == 0);
    let nat_type = if port_preserved {
        "port_preserved"
    } else if delta_spread == 0 {
        "constant_delta"
    } else if error_range <= 5 {
        "small_delta_range"
    } else if error_range <= 30 {
        "medium_delta_range"
    } else if error_range <= 100 {
        "large_delta_range"
    } else {
        "random_like"
    };
    println!("Estimated NAT type: {}", nat_type);
    println!();

    let mut deltas_sorted = deltas;
    deltas_sorted.sort_unstable();
    let delta_list = deltas_sorted.iter().map(|d| d.to_string()).collect::<Vec<_>>().join(", ");

    println!("Delta (sorted): {}", delta_list);
    println!();
    if failures > 0 {
        println!("Probe failures: {}/{}", failures, count);
    }

    Ok(())
}

fn derive_probe_addr(server_addr: &str) -> Result<SocketAddr> {
    let (host, port) = parse_host_port(server_addr)?;
    if port <= 1 {
        return Err(anyhow!("Server port {} is too low to derive probe port", port));
    }
    let resolved = resolve_host_port(&host, port)?;
    Ok(SocketAddr::new(resolved.ip(), port - 1))
}

fn median_i32(values: &mut Vec<i32>) -> f64 {
    values.sort_unstable();
    let len = values.len();
    if len == 0 {
        return 0.0;
    }
    if len % 2 == 1 {
        values[len / 2] as f64
    } else {
        let a = values[(len / 2) - 1] as f64;
        let b = values[len / 2] as f64;
        (a + b) / 2.0
    }
}
