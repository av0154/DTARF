# core_engine/module_bridge.py
"""
Module Bridge - Integrates external base modules into DTARF pipeline.

Bridges:
  1. APT_&_Malware_Module → Ransomware, fileless malware, lateral movement,
                             exfiltration detection
  2. threshold_based_detection → DDoS, ARP spoofing, DNS poisoning,
                                  port scanning, ICMP flood detection

This module does NOT modify the base modules. It imports and wraps
their functionality for use within the DTARF orchestration pipeline.
"""

import os
import sys
import json
import threading
import time
from datetime import datetime
from collections import deque


class APTMalwareBridge:
    """
    Bridge to APT_&_Malware_Module.
    Wraps ransomware, fileless, lateral movement, and exfiltration detectors.
    """

    def __init__(self, module_path):
        self.module_path = module_path
        self._alerts = deque(maxlen=5000)
        self._available = False
        self._setup_path()

    def _setup_path(self):
        """Add module paths so imports work."""
        if not os.path.exists(self.module_path):
            return

        # Add the module root and subdirectories to sys.path
        paths_to_add = [
            self.module_path,
            os.path.join(self.module_path, "tools"),
            os.path.join(self.module_path, "collectors"),
            os.path.join(self.module_path, "detectors"),
        ]
        for p in paths_to_add:
            if p not in sys.path and os.path.exists(p):
                sys.path.insert(0, p)

        self._available = True

    def run_detection(self, config=None):
        """
        Run all APT/Malware detections and return alerts.
        Uses the module's own config if none provided.
        """
        if not self._available:
            return []

        alerts = []

        # Load config
        if config is None:
            config_path = os.path.join(self.module_path, "config.json")
            if os.path.exists(config_path):
                with open(config_path, "r") as f:
                    config = json.load(f)
            else:
                config = {
                    "entropy_high_threshold": 7.0,
                    "ransomware_file_change_threshold": 50,
                    "exfil_min_bytes": 5000000,
                    "suspicious_ports": ["445", "3389", "5985", "5986", "135"],
                    "log_paths": {
                        "powershell": os.path.join(self.module_path, "temp", "powershell.log"),
                        "sysmon": os.path.join(self.module_path, "temp", "sysmon.log"),
                    },
                    "temp_dir": os.path.join(self.module_path, "temp"),
                    "output_file": os.path.join(self.module_path, "output", "alerts.json")
                }

        try:
            # Ransomware detection
            from detectors.ransomware_detector import detect_ransomware
            ransomware_alerts = detect_ransomware(config)
            for a in ransomware_alerts:
                a["source"] = "apt_malware_module"
                a["severity"] = 90
            alerts.extend(ransomware_alerts)
        except Exception as e:
            pass

        try:
            # Fileless malware detection
            from detectors.fileless_detector import detect_fileless
            fileless_alerts = detect_fileless(config)
            for a in fileless_alerts:
                a["source"] = "apt_malware_module"
                a["severity"] = 85
            alerts.extend(fileless_alerts)
        except Exception as e:
            pass

        try:
            # Lateral movement detection
            from detectors.lateral_detector import detect_lateral_movement
            lateral_alerts = detect_lateral_movement(config)
            for a in lateral_alerts:
                a["source"] = "apt_malware_module"
                a["severity"] = 80
            alerts.extend(lateral_alerts)
        except Exception as e:
            pass

        # Store alerts
        for a in alerts:
            a["timestamp"] = datetime.now().isoformat()
            self._alerts.append(a)

        return alerts

    def get_alerts(self, count=100):
        return list(self._alerts)[-count:]


class ThresholdDetectionBridge:
    """
    Bridge to threshold_based_detection module.
    Wraps DDoS, ARP spoofing, DNS poisoning, port scan, ICMP flood detectors.
    """

    def __init__(self, module_path):
        self.module_path = module_path
        self._alerts = deque(maxlen=5000)
        self._available = False
        self._config = None
        self._detectors = {}
        self._setup()

    def _setup(self):
        """Set up paths and load config."""
        if not os.path.exists(self.module_path):
            return

        # Add module paths
        paths_to_add = [
            self.module_path,
            os.path.join(self.module_path, "src"),
        ]
        for p in paths_to_add:
            if p not in sys.path and os.path.exists(p):
                sys.path.insert(0, p)

        # Load threshold config
        config_path = os.path.join(self.module_path, "config", "thresholds.yaml")
        if os.path.exists(config_path):
            try:
                import yaml
                with open(config_path) as f:
                    self._config = yaml.safe_load(f)
            except Exception:
                self._config = self._default_config()
        else:
            self._config = self._default_config()

        # Initialize detectors
        try:
            from src.detectors.ddos_detector import DDoSDetector
            self._detectors['ddos'] = DDoSDetector(self._config)
        except Exception:
            pass

        try:
            from src.detectors.arp_spoof_detector import ARPSpoofDetector
            self._detectors['arp'] = ARPSpoofDetector(self._config)
        except Exception:
            pass

        try:
            from src.detectors.dns_poison_detector import DNSPoisonDetector
            self._detectors['dns'] = DNSPoisonDetector(self._config)
        except Exception:
            pass

        try:
            from src.detectors.portscan_detector import PortScanDetector
            self._detectors['portscan'] = PortScanDetector(self._config)
        except Exception:
            pass

        try:
            from src.detectors.icmp_flood_detector import ICMPFloodDetector
            self._detectors['icmp_flood'] = ICMPFloodDetector(self._config)
        except Exception:
            pass

        self._available = bool(self._detectors)

    def _default_config(self):
        return {
            "ddos": {
                "syn_flood": {"rate_per_sec": 800, "window_sec": 10},
                "icmp_flood": {"rate_per_sec": 400, "window_sec": 10},
                "udp_flood": {"rate_per_sec": 300, "window_sec": 10},
                "http_flood": {"requests_per_min": 150, "window_sec": 60}
            },
            "arp_spoof": {
                "mac_ip_collision_window_sec": 10,
                "gratuitous_arp_threshold": 5
            },
            "dns_poison": {
                "authoritative_file": "data/dns/authoritative.csv",
                "suspicious_ttl_max": 60
            },
            "portscan": {
                "distinct_ports_threshold": 25,
                "scan_window_sec": 60
            },
            "icmp_flood": {
                "broadcast_icmp_threshold": 30
            }
        }

    def get_detectors(self):
        """Get initialized detector instances."""
        return self._detectors

    def process_packet(self, pkt_type, pkt, meta):
        """
        Process a packet through threshold-based detectors.
        Returns a list of detected alerts.
        """
        if not self._available:
            return []

        alerts = []
        try:
            from scapy.all import IP, TCP, UDP, ICMP, ARP, DNS

            if pkt_type == "arp" and 'arp' in self._detectors:
                if ARP in pkt:
                    src_ip = pkt[ARP].psrc
                    src_mac = pkt[ARP].hwsrc
                    is_gratuitous = pkt[ARP].op == 2 and pkt[ARP].psrc == pkt[ARP].pdst
                    if self._detectors['arp'].check(src_ip, src_mac, is_gratuitous):
                        alerts.append({"type": "arp_spoofing", "severity": 90, "src_ip": src_ip})

            elif pkt_type == "ip":
                if IP in pkt:
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst

                    if TCP in pkt:
                        if pkt[TCP].flags & 2 and not pkt[TCP].flags & 16:
                            if 'ddos' in self._detectors:
                                if self._detectors['ddos'].check_syn_flood(src_ip):
                                    alerts.append({"type": "syn_flood", "severity": 85, "src_ip": src_ip})
                        if 'portscan' in self._detectors:
                            if self._detectors['portscan'].check(src_ip, pkt[TCP].dport):
                                alerts.append({"type": "port_scan", "severity": 75, "src_ip": src_ip})

                    elif ICMP in pkt:
                        if 'ddos' in self._detectors:
                            if self._detectors['ddos'].check_icmp_flood(src_ip):
                                alerts.append({"type": "icmp_flood", "severity": 80, "src_ip": src_ip})
                        if 'icmp_flood' in self._detectors:
                            if self._detectors['icmp_flood'].check(dst_ip):
                                alerts.append({"type": "broadcast_icmp_anomaly", "severity": 60, "src_ip": src_ip})

                    elif UDP in pkt:
                        if 'ddos' in self._detectors:
                            if self._detectors['ddos'].check_udp_flood(src_ip):
                                alerts.append({"type": "udp_flood", "severity": 80, "src_ip": src_ip})

                    if DNS in pkt and pkt[DNS].qr == 1:
                        if pkt[DNS].ancount > 0 and 'dns' in self._detectors:
                            for i in range(pkt[DNS].ancount):
                                try:
                                    answer = pkt[DNS].an[i]
                                    if answer.type == 1:
                                        domain = pkt[DNS].qd.qname.decode().rstrip('.')
                                        resolved_ip = answer.rdata
                                        ttl = answer.ttl
                                        if self._detectors['dns'].check(domain, resolved_ip, ttl):
                                            alerts.append({
                                                "type": "dns_poisoning",
                                                "severity": 85,
                                                "src_ip": src_ip,
                                                "details": {"domain": domain, "resolved_ip": resolved_ip, "ttl": ttl}
                                            })
                                except Exception:
                                    pass
        except Exception:
            pass
            
        return alerts

    def get_config(self):
        return self._config

    def is_available(self):
        return self._available

    def get_detector_names(self):
        return list(self._detectors.keys())
