# ingestion/packet_sniffer.py
"""
Data Ingestion Layer - Packet Sniffer
Captures network packets using Scapy, extracts metadata,
and feeds sliding-window buffers to the analytics engine.
"""

import time
import threading
from datetime import datetime
from collections import deque, defaultdict

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, Raw
except ImportError:
    # Graceful fallback if scapy not available
    pass


class PacketMetadata:
    """Extracted packet metadata for analysis."""

    def __init__(self, timestamp, src_ip, dst_ip, protocol, src_port=None,
                 dst_port=None, flags=None, payload_size=0, raw_size=0):
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = protocol
        self.src_port = src_port
        self.dst_port = dst_port
        self.flags = flags
        self.payload_size = payload_size
        self.raw_size = raw_size

    def to_dict(self):
        return {
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.protocol,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "flags": self.flags,
            "payload_size": self.payload_size,
            "raw_size": self.raw_size
        }


class SlidingWindowBuffer:
    """
    Sliding window buffer for network flow statistics.
    Tracks packet rates, byte rates, and connection counts
    within a configurable time window.
    """

    def __init__(self, window_sec=30, max_size=10000):
        self.window_sec = window_sec
        self.packets = deque(maxlen=max_size)
        self.flow_stats = defaultdict(lambda: {
            "packet_count": 0,
            "byte_count": 0,
            "first_seen": None,
            "last_seen": None,
            "ports": set()
        })
        self._lock = threading.Lock()

    def add(self, meta):
        with self._lock:
            self.packets.append(meta)
            flow_key = (meta.src_ip, meta.dst_ip)
            stats = self.flow_stats[flow_key]
            stats["packet_count"] += 1
            stats["byte_count"] += meta.raw_size
            now = meta.timestamp
            if stats["first_seen"] is None:
                stats["first_seen"] = now
            stats["last_seen"] = now
            if meta.dst_port:
                stats["ports"].add(meta.dst_port)

    def get_window_stats(self):
        """Get statistics for the current time window."""
        now = time.time()
        cutoff = now - self.window_sec

        with self._lock:
            # Clean old packets
            while self.packets and self.packets[0].timestamp < cutoff:
                self.packets.popleft()

            total_packets = len(self.packets)
            total_bytes = sum(p.raw_size for p in self.packets)
            unique_src = len(set(p.src_ip for p in self.packets))
            unique_dst = len(set(p.dst_ip for p in self.packets))

            protocol_counts = defaultdict(int)
            for p in self.packets:
                protocol_counts[p.protocol] += 1

        return {
            "window_sec": self.window_sec,
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "packets_per_sec": total_packets / self.window_sec if self.window_sec else 0,
            "bytes_per_sec": total_bytes / self.window_sec if self.window_sec else 0,
            "unique_sources": unique_src,
            "unique_destinations": unique_dst,
            "protocol_distribution": dict(protocol_counts)
        }

    def get_flow_stats(self):
        """Get per-flow statistics."""
        with self._lock:
            result = {}
            for key, stats in self.flow_stats.items():
                result[f"{key[0]}->{key[1]}"] = {
                    "src": key[0],
                    "dst": key[1],
                    "packet_count": stats["packet_count"],
                    "byte_count": stats["byte_count"],
                    "ports": list(stats["ports"])
                }
            return result


class DTARFPacketSniffer:
    """
    Packet sniffer that captures network traffic using Scapy,
    extracts metadata, and feeds it to the analytics pipeline.
    """

    def __init__(self, config, packet_queue):
        self.config = config
        self.packet_queue = packet_queue
        self.buffer = SlidingWindowBuffer(
            window_sec=config.get("sliding_window_sec", 30),
            max_size=config.get("buffer_size", 10000)
        )
        self.bpf_filter = config.get("bpf_filter", "ip or arp or icmp")
        self.promiscuous = config.get("promiscuous", True)
        self._stop_event = threading.Event()
        self._thread = None
        self._stats = {
            "total_captured": 0,
            "errors": 0,
            "started_at": None,
        }

    def start(self):
        self._stats["started_at"] = datetime.now().isoformat()
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)

    def get_stats(self):
        return dict(self._stats)

    def get_window_stats(self):
        return self.buffer.get_window_stats()

    def _sniff_loop(self):
        try:
            sniff(
                prn=self._packet_callback,
                filter=self.bpf_filter,
                store=0,
                promisc=self.promiscuous,
                stop_filter=lambda p: self._stop_event.is_set()
            )
        except Exception:
            self._stats["errors"] += 1

    def _packet_callback(self, pkt):
        try:
            now = time.time()

            if ARP in pkt:
                meta = PacketMetadata(
                    timestamp=now,
                    src_ip=pkt[ARP].psrc,
                    dst_ip=pkt[ARP].pdst,
                    protocol="ARP",
                    raw_size=len(pkt)
                )
                self.buffer.add(meta)
                self.packet_queue.append(("arp", pkt, meta))
                self._stats["total_captured"] += 1
                return

            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                raw_size = len(pkt)
                payload_size = len(pkt[Raw].load) if Raw in pkt else 0

                if TCP in pkt:
                    meta = PacketMetadata(
                        timestamp=now,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        protocol="TCP",
                        src_port=pkt[TCP].sport,
                        dst_port=pkt[TCP].dport,
                        flags=str(pkt[TCP].flags),
                        payload_size=payload_size,
                        raw_size=raw_size
                    )
                elif UDP in pkt:
                    meta = PacketMetadata(
                        timestamp=now,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        protocol="UDP",
                        src_port=pkt[UDP].sport,
                        dst_port=pkt[UDP].dport,
                        payload_size=payload_size,
                        raw_size=raw_size
                    )
                elif ICMP in pkt:
                    meta = PacketMetadata(
                        timestamp=now,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        protocol="ICMP",
                        raw_size=raw_size
                    )
                else:
                    meta = PacketMetadata(
                        timestamp=now,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        protocol="OTHER",
                        raw_size=raw_size
                    )

                self.buffer.add(meta)
                self.packet_queue.append(("ip", pkt, meta))
                self._stats["total_captured"] += 1

        except Exception:
            self._stats["errors"] += 1
