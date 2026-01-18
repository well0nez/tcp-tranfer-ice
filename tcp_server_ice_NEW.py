#!/usr/bin/env python3
"""
TCP Hole Punch Relay Server v3.0 - ICE-Lite Edition

Enhanced with NAT Probing phase for port pattern detection.

New Protocol Flow:
1. Peers connect and register
2. Server sends "probe_request" - client makes multiple quick connections
3. Server collects NAT ports and analyzes pattern
4. Server sends "peer_info" with NAT analysis to help prediction
5. Normal ready/go handshake
6. Hole punch with predicted ports

NAT Pattern Types:
- port_preserved: Public port = Local port (easy!)
- sequential: Ports increment by 1 or constant delta
- random: No pattern detected (hard to punch)
"""

import asyncio
import json
import logging
import argparse
import time
import statistics
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Tuple

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

MIN_PORT = 1024
MAX_PORT = 65535
MAX_SCAN_PORTS = 128
PREDICTION_DELAY_SEC = 2.0
RATE_DAMPING = 0.5
MAX_RATE_SHIFT = 32


@dataclass
class NATAnalysis:
    """Analysis of NAT port allocation behavior - Focus on PORT RANGE not delta!"""
    probed_ports: List[int] = field(default_factory=list)  # NAT ports seen
    local_ports: List[int] = field(default_factory=list)   # Local ports used
    
    # KEY METRICS - Range is what matters!
    min_port: int = 0          # Minimum NAT port seen
    max_port: int = 0          # Maximum NAT port seen
    port_range: int = 0        # max - min (THIS IS KEY!)

    # Delta metrics (nat_port - local_port)
    delta_min: int = 0
    delta_max: int = 0
    delta_median: float = 0.0
    delta_stdev: float = 0.0
    predicted_port: int = 0
    error_range: int = 0
    port_rate: float = 0.0
    prediction_delay: float = 0.0
    predicted_shift: int = 0
    
    # Classification
    pattern_type: str = "unknown"  # port_preserved, small_range, large_range, random
    needs_scan: bool = False       # Do we need port range scanning?
    scan_start: int = 0            # Start port for scanning
    scan_end: int = 0              # End port for scanning
    
    def to_dict(self) -> dict:
        return {
            'probed_ports': self.probed_ports,
            'local_ports': self.local_ports,
            'min_port': self.min_port,
            'max_port': self.max_port,
            'port_range': self.port_range,
            'delta_min': self.delta_min,
            'delta_max': self.delta_max,
            'delta_median': self.delta_median,
            'delta_stdev': self.delta_stdev,
            'predicted_port': self.predicted_port,
            'error_range': self.error_range,
            'port_rate': self.port_rate,
            'prediction_delay': self.prediction_delay,
            'predicted_shift': self.predicted_shift,
            'pattern_type': self.pattern_type,
            'needs_scan': self.needs_scan,
            'scan_start': self.scan_start,
            'scan_end': self.scan_end,
        }


@dataclass
class Peer:
    """Represents a connected peer"""
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    public_addr: tuple  # (ip, port) as seen by server
    local_port: int     # Port the client will use for hole punch
    role: str           # 'sender' or 'receiver'
    session_id: str
    ready: bool = False
    private_ip: Optional[str] = None
    nat_analysis: Optional[NATAnalysis] = None
    probe_ports: List[Tuple[int, int]] = field(default_factory=list)  # [(local, nat), ...]
    probes_done: bool = False  # True when probing phase complete
    needs_probing: bool = False  # True if NAT port changed (not preserved)


class TCPRelayServerICE:
    """TCP Hole Punch Relay Server with NAT Probing"""
    
    def __init__(self, host: str = '0.0.0.0', port: int = 9999, probe_port: int = 9998):
        self.host = host
        self.port = port
        self.probe_port = probe_port
        self.sessions: Dict[str, Dict[str, Peer]] = {}
        self.session_locks: Dict[str, asyncio.Lock] = {}
        # Probe connections waiting to be claimed
        self.pending_probes: Dict[str, List[Tuple[str, int, int, float]]] = {}  # session_id -> [(ip, nat_port, local_port, ts), ...]
        # Track if peer_info was already sent for a session
        self.peer_info_sent: Dict[str, bool] = {}
    
    async def start(self):
        """Start both main server and probe server"""
        # Main server
        main_server = await asyncio.start_server(
            self.handle_client,
            self.host,
            self.port
        )
        
        # Probe server (for NAT analysis)
        probe_server = await asyncio.start_server(
            self.handle_probe,
            self.host,
            self.probe_port
        )
        
        logger.info(f"TCP Relay Server v3.0 (ICE-Lite) listening on {self.host}:{self.port}")
        logger.info(f"NAT Probe Server listening on {self.host}:{self.probe_port}")
        logger.info("Features: NAT Probing, Pattern Detection, Port Prediction")
        
        await asyncio.gather(
            main_server.serve_forever(),
            probe_server.serve_forever()
        )
    
    async def handle_probe(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle a probe connection (for NAT analysis)"""
        addr = writer.get_extra_info('peername')
        
        try:
            # Quick read of probe info
            data = await asyncio.wait_for(reader.readline(), timeout=5.0)
            if not data:
                return
            
            msg = json.loads(data.decode())
            if msg.get('type') != 'probe':
                return
            
            session_id = msg.get('session_id')
            local_port = msg.get('local_port', 0)
            probe_num = msg.get('probe_num', 0)
            
            if not session_id:
                return
            
            # Record this probe
            ip, nat_port = addr
            ts = time.time()
            logger.debug(f"Probe #{probe_num} from {session_id}: local={local_port} nat={nat_port}")
            
            if session_id not in self.pending_probes:
                self.pending_probes[session_id] = []
            self.pending_probes[session_id].append((ip, nat_port, local_port, ts))
            
            # Send ACK with observed port
            await self.send_message(writer, {
                'type': 'probe_ack',
                'probe_num': probe_num,
                'your_nat_port': nat_port
            })
            
        except Exception as e:
            logger.debug(f"Probe error: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
    
    def get_session_lock(self, session_id: str) -> asyncio.Lock:
        if session_id not in self.session_locks:
            self.session_locks[session_id] = asyncio.Lock()
        return self.session_locks[session_id]
    
    def analyze_nat(self, probes: List[Tuple[str, int, int, float]], target_local_port: int) -> NATAnalysis:
        """Analyze NAT behavior and predict the peer-facing port range."""
        analysis = NATAnalysis()

        if len(probes) < 2 or target_local_port <= 0:
            analysis.pattern_type = "insufficient_data"
            return analysis

        # Extract ports
        for ip, nat_port, local_port, _ts in probes:
            analysis.probed_ports.append(nat_port)
            analysis.local_ports.append(local_port)

        # Key metrics
        analysis.min_port = min(analysis.probed_ports)
        analysis.max_port = max(analysis.probed_ports)
        analysis.port_range = analysis.max_port - analysis.min_port

        # Port preservation
        preserved = all(
            nat == local
            for nat, local in zip(analysis.probed_ports, analysis.local_ports)
        )

        if preserved:
            analysis.pattern_type = "port_preserved"
            analysis.needs_scan = False
            analysis.predicted_port = max(MIN_PORT, min(MAX_PORT, target_local_port))
            analysis.scan_start = analysis.predicted_port
            analysis.scan_end = analysis.predicted_port
            logger.info("NAT Analysis: port preserved (no scan needed)")
            return analysis

        # Delta-based prediction (nat_port - local_port)
        deltas = [
            nat - local
            for nat, local in zip(analysis.probed_ports, analysis.local_ports)
            if local > 0
        ]
        if not deltas:
            analysis.pattern_type = "insufficient_data"
            return analysis

        analysis.delta_min = min(deltas)
        analysis.delta_max = max(deltas)
        analysis.delta_median = statistics.median(deltas)
        analysis.delta_stdev = statistics.pstdev(deltas) if len(deltas) > 1 else 0.0

        predicted = int(round(target_local_port + analysis.delta_median))
        analysis.predicted_port = max(MIN_PORT, min(MAX_PORT, predicted))

        max_dev = max(abs(d - analysis.delta_median) for d in deltas)
        jitter = max(2, int(round(analysis.delta_stdev * 2)))
        analysis.error_range = int(round(max_dev + jitter))

        analysis.prediction_delay = PREDICTION_DELAY_SEC
        analysis.port_rate = 0.0
        analysis.predicted_shift = 0

        sorted_probes = sorted(probes, key=lambda p: p[3])
        if len(sorted_probes) >= 2:
            times = [p[3] for p in sorted_probes]
            ports = [p[1] for p in sorted_probes]
            time_span = times[-1] - times[0]
            if time_span > 0:
                diffs = [ports[i] - ports[i - 1] for i in range(1, len(ports))]
                pos_diffs = [d for d in diffs if d > 0]
                pos_ratio = len(pos_diffs) / len(diffs) if diffs else 0.0
                if pos_ratio >= 0.6:
                    port_span = sum(pos_diffs)
                    if port_span > 0:
                        analysis.port_rate = port_span / time_span

        if analysis.port_rate > 0.0:
            raw_shift = int(round(analysis.port_rate * analysis.prediction_delay * RATE_DAMPING))
            analysis.predicted_shift = max(0, min(MAX_RATE_SHIFT, raw_shift))
            if analysis.predicted_shift > 0:
                analysis.predicted_port = max(
                    MIN_PORT,
                    min(MAX_PORT, analysis.predicted_port + analysis.predicted_shift),
                )

        analysis.scan_start = max(MIN_PORT, analysis.predicted_port - analysis.error_range)
        analysis.scan_end = min(MAX_PORT, analysis.predicted_port + analysis.error_range)
        analysis.needs_scan = analysis.error_range > 0

        delta_spread = analysis.delta_max - analysis.delta_min
        if delta_spread == 0:
            analysis.pattern_type = "constant_delta"
            analysis.needs_scan = False
            analysis.error_range = 0
            analysis.scan_start = analysis.predicted_port
            analysis.scan_end = analysis.predicted_port
        elif analysis.error_range <= 5:
            analysis.pattern_type = "small_delta_range"
        elif analysis.error_range <= 30:
            analysis.pattern_type = "medium_delta_range"
        elif analysis.error_range <= 100:
            analysis.pattern_type = "large_delta_range"
        else:
            analysis.pattern_type = "random_like"
            analysis.scan_start = max(MIN_PORT, analysis.min_port)
            analysis.scan_end = min(MAX_PORT, analysis.max_port)
            analysis.needs_scan = True

        logger.info(
            "NAT Analysis: delta_range=%s predicted=%s range=%s-%s",
            delta_spread,
            analysis.predicted_port,
            analysis.scan_start,
            analysis.scan_end,
        )

        return analysis

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle a new client connection"""
        addr = writer.get_extra_info('peername')
        logger.info(f"New connection from {addr}")
        
        peer = None
        session_id = None
        
        try:
            data = await asyncio.wait_for(reader.readline(), timeout=300.0)
            if not data:
                return
            
            msg = json.loads(data.decode())
            
            if msg.get('type') != 'register':
                await self.send_error(writer, "Expected 'register' message")
                return
            
            session_id = msg['session_id']
            role = msg['role']
            local_port = msg.get('local_port', 0)
            private_ip = msg.get('private_ip')
            skip_probing = msg.get('skip_probing', False)  # For clients that don't support probing
            
            if role not in ('sender', 'receiver'):
                await self.send_error(writer, f"Invalid role: {role}")
                return
            
            peer = Peer(
                reader=reader,
                writer=writer,
                public_addr=addr,
                local_port=local_port,
                role=role,
                session_id=session_id,
                private_ip=private_ip
            )
            
            lock = self.get_session_lock(session_id)
            
            async with lock:
                if session_id not in self.sessions:
                    self.sessions[session_id] = {}
                
                session = self.sessions[session_id]
                
                if role in session:
                    await self.send_error(writer, f"Role '{role}' already taken")
                    return
                
                session[role] = peer
                logger.info(f"Registered {role} for session {session_id}: {addr}, local_port={local_port}")
            
            # Calculate initial delta
            initial_delta = addr[1] - local_port if local_port else 0
            port_preserved = (initial_delta == 0)
            
            # Determine if probing is needed
            peer.needs_probing = not skip_probing and not port_preserved
            peer.probes_done = not peer.needs_probing  # If no probing needed, mark done
            
            # Create basic NAT analysis for port-preserved case
            if port_preserved:
                predicted_port = max(MIN_PORT, min(MAX_PORT, local_port or addr[1]))
                peer.nat_analysis = NATAnalysis(
                    probed_ports=[addr[1]],
                    local_ports=[local_port],
                    min_port=addr[1],
                    max_port=addr[1],
                    port_range=0,
                    predicted_port=predicted_port,
                    error_range=0,
                    pattern_type="port_preserved",
                    needs_scan=False,
                    scan_start=predicted_port,
                    scan_end=predicted_port,
                )
            
            # Send registration ACK with needs_probing flag
            await self.send_message(writer, {
                'type': 'registered',
                'your_public_addr': list(addr),
                'your_role': role,
                'session_id': session_id,
                'server_time': time.time(),
                'initial_delta': initial_delta,
                'port_preserved': port_preserved,
                'needs_probing': peer.needs_probing,
                'probe_port': self.probe_port if peer.needs_probing else None
            })
            
            logger.info(f"Peer {role}: port_preserved={port_preserved}, needs_probing={peer.needs_probing}")
            
            # Try to start session (will wait for both probes_done)
            await self.try_start_session(session_id)
            
            # Wait for messages
            await self.wait_for_peer_messages(peer)
        
        except asyncio.TimeoutError:
            logger.warning(f"Client {addr} timed out")
        except Exception as e:
            logger.error(f"Error handling client {addr}: {e}", exc_info=True)
        finally:
            if session_id and peer:
                await self.cleanup_peer(session_id, peer)
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
    
    async def wait_for_probes(self, session_id: str, peer: Peer, timeout: float = 10.0):
        """Wait for probe connections from this peer"""
        probe_key = f"{session_id}_{peer.role}"
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            # Check for probes from this session
            if session_id in self.pending_probes:
                probes = self.pending_probes[session_id]
                # Filter probes from this peer's IP
                peer_probes = [(ip, nat, local, ts) for ip, nat, local, ts in probes
                               if ip == peer.public_addr[0]]
                
                if len(peer_probes) >= 5:  # Minimum probes needed
                    logger.info(f"Got {len(peer_probes)} probes from {peer.role}")
                    peer.nat_analysis = self.analyze_nat(peer_probes, peer.local_port)
                    # Clear used probes
                    self.pending_probes[session_id] = [
                        (ip, nat, local, ts) for ip, nat, local, ts in probes
                        if ip != peer.public_addr[0]
                    ]
                    return
            
            await asyncio.sleep(0.5)
        
        logger.warning(f"Probe timeout for {peer.role}, using basic analysis")
        # Create basic analysis from registration connection
        peer.nat_analysis = NATAnalysis(
            probed_ports=[peer.public_addr[1]],
            local_ports=[peer.local_port],
            min_port=peer.public_addr[1],
            max_port=peer.public_addr[1],
            port_range=0,
            predicted_port=peer.public_addr[1],
            error_range=0,
            pattern_type="insufficient_data",
            needs_scan=False,
            scan_start=peer.public_addr[1],
            scan_end=peer.public_addr[1],
        )
    
    async def wait_for_peer_messages(self, peer: Peer):
        """Wait for messages from peer"""
        while True:
            try:
                data = await asyncio.wait_for(peer.reader.readline(), timeout=300.0)
                if not data:
                    break
                
                msg = json.loads(data.decode())
                msg_type = msg.get('type')
                
                if msg_type == 'ready':
                    peer.ready = True
                    logger.info(f"Peer {peer.role} is READY")
                    await self.try_send_go(peer.session_id)
                
                elif msg_type == 'keepalive':
                    await self.send_message(peer.writer, {'type': 'keepalive_ack'})
                
                elif msg_type == 'probes_complete':
                    # Client finished sending probes - analyze and mark done
                    logger.info(f"Peer {peer.role} sent probes_complete")
                    await self.handle_probes_complete(peer)
                
            except asyncio.TimeoutError:
                try:
                    await self.send_message(peer.writer, {'type': 'ping'})
                except:
                    break
            except Exception as e:
                logger.debug(f"Error reading from {peer.role}: {e}")
                break
    
    async def handle_probes_complete(self, peer: Peer):
        """Handle probes_complete message from client"""
        session_id = peer.session_id
        
        # Analyze probes if we have them
        if session_id in self.pending_probes:
            probes = self.pending_probes[session_id]
            peer_probes = [(ip, nat, local, ts) for ip, nat, local, ts in probes
                           if ip == peer.public_addr[0]]
            
            if peer_probes:
                logger.info(f"Analyzing {len(peer_probes)} probes from {peer.role}")
                peer.nat_analysis = self.analyze_nat(peer_probes, peer.local_port)
                # Clear used probes
                self.pending_probes[session_id] = [
                    (ip, nat, local, ts) for ip, nat, local, ts in probes
                    if ip != peer.public_addr[0]
                ]
            else:
                logger.warning(f"No probes received from {peer.role}")
                # Create basic analysis from registration
                peer.nat_analysis = NATAnalysis(
                    probed_ports=[peer.public_addr[1]],
                    local_ports=[peer.local_port],
                    min_port=peer.public_addr[1],
                    max_port=peer.public_addr[1],
                    port_range=0,
                    predicted_port=peer.public_addr[1],
                    error_range=0,
                    pattern_type="insufficient_data",
                    needs_scan=False,
                    scan_start=peer.public_addr[1],
                    scan_end=peer.public_addr[1],
                )
        
        # Mark probing done
        peer.probes_done = True
        logger.info(f"Peer {peer.role} probes_done=True")
        
        # Try to send peer_info if both are done
        await self.try_send_peer_info(session_id)
    
    async def try_start_session(self, session_id: str):
        """Check if session can start (both peers connected)"""
        lock = self.get_session_lock(session_id)
        
        async with lock:
            session = self.sessions.get(session_id)
            if not session:
                return
            
            sender = session.get('sender')
            receiver = session.get('receiver')
            
            if not sender or not receiver:
                return
            
            logger.info(f"Session {session_id}: Both peers connected!")
            logger.info(f"  Sender probes_done={sender.probes_done}, Receiver probes_done={receiver.probes_done}")
        
        # Try to send peer_info (checks probes_done)
        await self.try_send_peer_info(session_id)
    
    async def try_send_peer_info(self, session_id: str):
        """Send peer_info when both peers have completed probing"""
        lock = self.get_session_lock(session_id)
        
        async with lock:
            # Check if already sent
            if self.peer_info_sent.get(session_id, False):
                return
            
            session = self.sessions.get(session_id)
            if not session:
                return
            
            sender = session.get('sender')
            receiver = session.get('receiver')
            
            if not sender or not receiver:
                return
            
            # Check if BOTH have completed probing
            if not sender.probes_done or not receiver.probes_done:
                logger.debug(f"Session {session_id}: Waiting for probes "
                           f"(sender={sender.probes_done}, receiver={receiver.probes_done})")
                return
            
            # Mark as sent BEFORE sending to prevent race
            self.peer_info_sent[session_id] = True
            
            logger.info(f"Session {session_id}: Both probes complete, sending peer_info!")
            
            # Build peer addresses with NAT analysis
            sender_addrs = self.get_peer_addresses_with_prediction(sender, receiver)
            receiver_addrs = self.get_peer_addresses_with_prediction(receiver, sender)
            
            # Send to sender
            msg_to_sender = {
                'type': 'peer_info',
                'peer_public_addr': list(receiver.public_addr),
                'peer_local_port': receiver.local_port,
                'peer_addresses': receiver_addrs,
                'your_role': 'sender',
                'same_network': False,
                'peer_nat_analysis': receiver.nat_analysis.to_dict() if receiver.nat_analysis else None
            }
            await self.send_message(sender.writer, msg_to_sender)
            
            # Send to receiver
            msg_to_receiver = {
                'type': 'peer_info',
                'peer_public_addr': list(sender.public_addr),
                'peer_local_port': sender.local_port,
                'peer_addresses': sender_addrs,
                'your_role': 'receiver',
                'same_network': False,
                'peer_nat_analysis': sender.nat_analysis.to_dict() if sender.nat_analysis else None
            }
            await self.send_message(receiver.writer, msg_to_receiver)
            
            logger.info(f"Session {session_id}: peer_info with NAT analysis sent!")

    def build_candidate_ports(self, analysis: NATAnalysis) -> List[int]:
        if not analysis or not analysis.needs_scan:
            return []
        if analysis.scan_start <= 0 or analysis.scan_end <= 0:
            return []
        if analysis.scan_end < analysis.scan_start:
            return []

        if analysis.pattern_type == "random_like":
            ports = []
            seen = set()

            def add_port(port: int):
                if port < analysis.scan_start or port > analysis.scan_end:
                    return
                if port in seen:
                    return
                seen.add(port)
                ports.append(port)

            if analysis.predicted_port:
                add_port(analysis.predicted_port)

            base = analysis.min_port
            for delta in (1, 2, 3, 4, 5):
                add_port(base + delta)

            remaining = MAX_SCAN_PORTS - len(ports)
            if remaining > 0:
                span = analysis.scan_end - analysis.scan_start
                step = max(1, span // remaining) if span > 0 else 1
                p = analysis.scan_start
                while p <= analysis.scan_end and len(ports) < MAX_SCAN_PORTS:
                    add_port(p)
                    p += step

            return ports

        total = analysis.scan_end - analysis.scan_start + 1
        if total <= MAX_SCAN_PORTS:
            return list(range(analysis.scan_start, analysis.scan_end + 1))

        predicted = analysis.predicted_port or ((analysis.scan_start + analysis.scan_end) // 2)
        half = MAX_SCAN_PORTS // 2
        window_start = max(analysis.scan_start, predicted - half)
        window_end = window_start + MAX_SCAN_PORTS - 1
        if window_end > analysis.scan_end:
            window_end = analysis.scan_end
            window_start = max(analysis.scan_start, window_end - MAX_SCAN_PORTS + 1)
        return list(range(window_start, window_end + 1))
    
    def get_peer_addresses_with_prediction(self, peer: Peer, other: Peer) -> List[Dict]:
        """Get addresses including scan range from NAT analysis"""
        addresses = []
        seen = set()

        def add_address(ip: str, port: int, addr_type: str, priority: int):
            key = (ip, port)
            if key in seen:
                return
            seen.add(key)
            addresses.append({
                'ip': ip,
                'port': port,
                'type': addr_type,
                'priority': priority
            })
        
        # 1. Primary public address
        add_address(peer.public_addr[0], peer.public_addr[1], 'public', 1)

        # 2. Predicted port (delta-based)
        if peer.nat_analysis and peer.nat_analysis.predicted_port:
            add_address(peer.public_addr[0], peer.nat_analysis.predicted_port, 'predicted', 2)

        # 3. Public IP + local port (if different)
        if peer.local_port and peer.local_port != peer.public_addr[1]:
            add_address(peer.public_addr[0], peer.local_port, 'public_local_port', 3)

        # 4. Predicted range from NAT analysis (capped)
        if peer.nat_analysis and peer.nat_analysis.needs_scan:
            scan_ports = self.build_candidate_ports(peer.nat_analysis)
            for i, port in enumerate(scan_ports):
                add_address(peer.public_addr[0], port, 'predicted_range', 10 + i)
        
        # Sort by priority
        addresses.sort(key=lambda x: x.get('priority', 999))
        
        return addresses
    
    def same_network(self, peer1: Peer, peer2: Peer) -> bool:
        return peer1.public_addr[0] == peer2.public_addr[0]
    
    async def try_send_go(self, session_id: str):
        """Send GO signal when both ready"""
        lock = self.get_session_lock(session_id)
        
        async with lock:
            session = self.sessions.get(session_id)
            if not session:
                return
            
            sender = session.get('sender')
            receiver = session.get('receiver')
            
            if not sender or not receiver or not sender.ready or not receiver.ready:
                return
            
            start_at = time.time() + 1.5
            
            go_msg = {
                'type': 'go',
                'start_at': start_at,
                'message': 'Start hole punch at start_at timestamp'
            }
            
            await self.send_message(sender.writer, go_msg)
            await self.send_message(receiver.writer, go_msg)
            
            logger.info(f"Session {session_id}: GO sent! Start at {start_at:.3f}")
    
    async def cleanup_peer(self, session_id: str, peer: Peer):
        lock = self.get_session_lock(session_id)
        async with lock:
            session = self.sessions.get(session_id)
            if session and peer.role in session:
                if session[peer.role] is peer:
                    del session[peer.role]
                if not session:
                    del self.sessions[session_id]
                    if session_id in self.pending_probes:
                        del self.pending_probes[session_id]
                    if session_id in self.peer_info_sent:
                        del self.peer_info_sent[session_id]
    
    async def send_message(self, writer: asyncio.StreamWriter, msg: dict):
        data = json.dumps(msg) + '\n'
        writer.write(data.encode())
        await writer.drain()
    
    async def send_error(self, writer: asyncio.StreamWriter, message: str):
        await self.send_message(writer, {'type': 'error', 'message': message})


async def main():
    parser = argparse.ArgumentParser(description='TCP Relay Server v3.0 (ICE-Lite)')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=9999, help='Main port')
    parser.add_argument('--probe-port', type=int, default=9998, help='Probe port for NAT analysis')
    args = parser.parse_args()
    
    server = TCPRelayServerICE(args.host, args.port, args.probe_port)
    await server.start()


if __name__ == '__main__':
    asyncio.run(main())
