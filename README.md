# TCP File Transfer Client

High-performance TCP file transfer with NAT traversal (hole punching).

## Features

- **TCP Hole Punching**: Establishes direct peer-to-peer TCP connections through NAT
- **NAT Probing + Prediction**: Uses a probe port to narrow candidate external ports
- **SHA256 Verification**: Ensures file integrity after transfer
- **Progress Bar**: Real-time transfer progress with speed display
- **Session-Based**: Both peers connect using a shared session ID

## How It Works

1. Both sender and receiver connect to the relay server with the same session ID
2. The relay server probes NAT behavior (if needed) and exchanges peer addresses
3. Both peers attempt TCP hole punching simultaneously
4. Once connected, the file is transferred directly peer-to-peer
5. SHA256 verification ensures file integrity

## Usage

### Prerequisites

Start the relay server:
```bash
python3 tcp_server_ice_NEW.py --port 9999 --probe-port 9998
```
Ensure both ports are reachable from the public Internet.

### Receiver (start first)

```bash
./tcp-transfer -s relay-server:9999 -i my-session -m receive
```

### Sender

```bash
./tcp-transfer -s relay-server:9999 -i my-session -m send -f myfile.mp4
```

### Options

```
Options:
  -s, --server <SERVER>      Relay server address (host:port)
  -i, --session-id <ID>      Session ID (both peers must use the same)
  -m, --mode <MODE>          Mode: send or receive
  -f, --file <FILE>          File to send (sender mode only)
      --timeout <SECONDS>    Hole punch timeout [default: 30]
      --debug                Enable debug logging
  -h, --help                 Print help
  -V, --version              Print version
```

## Building

```bash
cargo build --release
```

The binary will be at `target/release/tcp-transfer`.

## Protocol

### Relay Server Protocol (JSON over TCP)

1. **Registration**: Client sends `{"type": "register", "session_id": "...", "role": "sender|receiver", "local_port": 12345}`
2. **Registered**: Server responds `{"type": "registered", "your_public_addr": ["ip", port], "needs_probing": true|false, "probe_port": 9998}`
3. **Peer Info**: When both peers are connected, server sends `{"type": "peer_info", "peer_public_addr": ["ip", port], "peer_addresses": [...], "peer_nat_analysis": {...}}`

### File Transfer Protocol (Binary over direct TCP)

1. **HELLO**: Both peers exchange `[type=1][len][role]`
2. **FILE_INFO**: Sender sends `[type=2][name_len][size][filename][sha256]`
3. **FILE_INFO_ACK**: Receiver acknowledges `[type=3]`
4. **Data Stream**: Raw file bytes (TCP handles reliability)
5. **DONE**: Sender signals completion `[type=5]`
6. **ACK**: Receiver confirms SHA256 verified `[type=6]`

## Comparison with UDP Version

| Feature | UDP Transfer | TCP Transfer |
|---------|-------------|--------------|
| Protocol | Custom reliable UDP | TCP (built-in reliability) |
| Window Management | Yes (complex) | No (TCP handles it) |
| ACK Messages | Every 100ms | Only for handshake |
| Retransmission | Manual | TCP handles it |
| Congestion Control | AIMD | TCP's built-in |
| Code Complexity | High | Low |
| Speed | Potentially faster | Reliable, consistent |

## Troubleshooting

### Hole punch fails

TCP hole punching is more difficult than UDP and may not work with all NAT types:
- **Full Cone NAT**: Usually works
- **Restricted Cone NAT**: Usually works
- **Port Restricted Cone NAT**: May work
- **Symmetric NAT**: Unlikely to work

If hole punching fails, consider:
1. Using a TURN-style relay fallback
2. Using the UDP version which has better NAT traversal

### Connection timeout

Increase the timeout: `--timeout 60`

### Debug mode

Use `--debug` for detailed logging.

## License

MIT
