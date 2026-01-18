# TCP File Transfer Client

High-performance TCP file transfer with NAT traversal (hole punching).

## Features

- **TCP Hole Punching**: Establishes direct peer-to-peer TCP connections through NAT
- **NAT Probing + Prediction**: Uses a probe port to predict a NAT port range and build a capped scan list
- **SHA256 Verification**: Ensures file integrity after transfer
- **Progress Bar**: Real-time transfer progress with speed display
- **Session-Based**: Both peers connect using a shared session ID

## How It Works

1. Both sender and receiver connect to the relay server with the same session ID
2. The relay server probes NAT behavior (if needed) and exchanges peer addresses
3. Both peers attempt TCP hole punching simultaneously
4. Once connected, the file is transferred directly peer-to-peer
5. SHA256 verification ensures file integrity

## Port Prediction and Scan Method

The relay server runs a short NAT probing phase when a peer does not preserve ports:

- The client opens several quick probe connections to `--probe-port` (server waits for at least 5).
- The server records `(local_port, observed_public_port, timestamp)` and computes a prediction model:
  - delta = public_port - local_port
  - predicted_port = local_port + median(delta)
  - error_range = max deviation + jitter (2 * stdev, min 2)
  - For progressing symmetric NATs, estimate a port allocation rate and shift the prediction forward
    (`port_rate * prediction_delay * RATE_DAMPING`, capped by `MAX_RATE_SHIFT`).
- The server classifies the pattern (`port_preserved`, `constant_delta`, `small/medium/large_delta_range`,
  `random_like`) and builds a bounded candidate list:
  - For non-random patterns, use a contiguous window around `predicted_port` and cap to `MAX_SCAN_PORTS`.
  - For `random_like`, use the observed min/max range and build a sparse list:
    `predicted_port`, `min_port+1..+5`, plus evenly spaced samples, capped to `MAX_SCAN_PORTS`.
- The server sends `peer_info` with the prioritized candidate list; the client tries only those candidates.

These additions (rate-based forward shift and sparse random-like sampling) extend the standard delta-only
prediction and reduce the number of attempts without a full port sweep.

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

## References

These papers and implementations informed the NAT probing and prediction approach:

- Kazuhiro Tobe, Akihiro Shimoda, Shigeki Goto. "Extended UDP Multiple Hole Punching Method to Traverse Large Scale NATs." https://pdfs.semanticscholar.org/953d/438516e9b2eb2bf35528de3e1fb0e9b164f8.pdf
- Daniel Maier, Oliver Haase, Juergen Waesch, Marcel Waldvogel. "NAT Hole Punching Revisited." Technical Report No. KN-2011-DiSy-02. https://kops.uni-konstanz.de/server/api/core/bitstreams/29a35a1d-40f1-4290-9d03-dae21f2b9c36/content
- Simon Keller, Tobias Hossfeld, Sebastian von Mammen. "Edge-Case Integration into Established NAT Traversal Techniques." IEEE ICCE 2022. https://downloads.hci.informatik.uni-wuerzburg.de/2022-icce-keller.pdf
- Chongyc/natblaster (GitHub). https://github.com/chongyc/natblaster

## License

MIT
