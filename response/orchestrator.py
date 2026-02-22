# response/orchestrator.py
"""
Detection & Response Orchestration Layer
Implements:
  - Response Orchestrator (Alert Prioritization, Playbook Selection, Policy Mapping)
  - Action Executor (Firewall Rules, Container Isolation, IP Blacklisting)
"""

import os
import json
import time
import subprocess
import threading
from datetime import datetime
from collections import deque, defaultdict


class Alert:
    """Standardized alert format used across the framework."""

    SEVERITY_LABELS = {
        (90, 100): "CRITICAL",
        (70, 89): "HIGH",
        (40, 69): "MEDIUM",
        (10, 39): "LOW",
        (0, 9): "INFO"
    }

    def __init__(self, alert_type, severity, source, details,
                 src_ip=None, dst_ip=None, timestamp=None):
        self.id = f"DTARF-{int(time.time() * 1000)}-{id(self) % 10000:04d}"
        self.type = alert_type
        self.severity = min(100, max(0, severity))
        self.severity_label = self._get_label(self.severity)
        self.source = source
        self.details = details
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.timestamp = timestamp or datetime.now().isoformat()
        self.status = "new"  # new, acknowledged, responding, resolved, false_positive
        self.response_actions = []
        self.forensic_evidence = []
        self.enrichment = {}
        self.response_time_ms = None

    def _get_label(self, severity):
        for (low, high), label in self.SEVERITY_LABELS.items():
            if low <= severity <= high:
                return label
        return "INFO"

    def to_dict(self):
        return {
            "id": self.id,
            "type": self.type,
            "severity": self.severity,
            "severity_label": self.severity_label,
            "source": self.source,
            "details": self.details,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "timestamp": self.timestamp,
            "status": self.status,
            "response_actions": self.response_actions,
            "forensic_evidence": self.forensic_evidence,
            "enrichment": self.enrichment,
            "response_time_ms": self.response_time_ms
        }


class ActionExecutor:
    """
    Executes response actions:
    - Firewall rules (Windows Firewall / iptables)
    - IP blacklisting
    - Rate limiting
    - Network isolation
    """

    def __init__(self, config):
        self.backend = config.get("firewall_backend", "windows_firewall")
        self.blacklist_file = config.get("blacklist_file", "data/blacklisted_ips.json")
        self.whitelist_file = config.get("whitelist_file", "data/whitelisted_ips.json")
        self.max_duration = config.get("max_blacklist_duration_sec", 86400)
        self._blacklist = {}
        self._whitelist = set()
        self._action_log = deque(maxlen=5000)
        self._lock = threading.Lock()
        self._load_lists()

    def _load_lists(self):
        try:
            if os.path.exists(self.blacklist_file):
                with open(self.blacklist_file, "r") as f:
                    self._blacklist = json.load(f)
        except Exception:
            pass

        try:
            if os.path.exists(self.whitelist_file):
                with open(self.whitelist_file, "r") as f:
                    self._whitelist = set(json.load(f))
        except Exception:
            pass

    def _save_blacklist(self):
        try:
            os.makedirs(os.path.dirname(self.blacklist_file), exist_ok=True)
            with open(self.blacklist_file, "w") as f:
                json.dump(self._blacklist, f, indent=2)
        except Exception:
            pass

    def execute(self, action_type, params):
        """
        Execute a response action.
        Returns action result dict.
        """
        start_time = time.time()

        ip = params.get("ip", "")

        # Never block whitelisted IPs
        if ip and ip in self._whitelist:
            return {
                "action": action_type,
                "status": "skipped",
                "reason": "whitelisted",
                "ip": ip,
                "timestamp": datetime.now().isoformat()
            }

        result = {
            "action": action_type,
            "params": params,
            "status": "pending",
            "timestamp": datetime.now().isoformat()
        }

        try:
            if action_type == "ip_blacklist":
                result = self._blacklist_ip(ip, params.get("reason", ""))
            elif action_type == "rate_limit":
                result = self._rate_limit(ip, params.get("rate", 10))
            elif action_type == "network_isolate":
                result = self._network_isolate(ip)
            elif action_type == "quarantine":
                result = self._quarantine(params.get("path", ""))
            elif action_type == "alert":
                result = self._send_alert(params)
            elif action_type == "evidence_collect":
                result = {"action": "evidence_collect", "status": "delegated",
                          "timestamp": datetime.now().isoformat()}
            else:
                result["status"] = "unknown_action"
        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)

        result["execution_time_ms"] = round((time.time() - start_time) * 1000, 2)

        with self._lock:
            self._action_log.append(result)

        return result

    def _blacklist_ip(self, ip, reason=""):
        """Add IP to blacklist and create firewall rule."""
        with self._lock:
            self._blacklist[ip] = {
                "reason": reason,
                "blocked_at": datetime.now().isoformat(),
                "expires_at": time.time() + self.max_duration
            }
            self._save_blacklist()

        # Create firewall rule
        rule_name = f"DTARF_Block_{ip.replace('.', '_')}"

        if self.backend == "windows_firewall":
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=in", "action=block",
                f"remoteip={ip}",
                "enable=yes"
            ]
        else:
            cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]

        try:
            subprocess.run(cmd, capture_output=True, timeout=10)
            status = "executed"
        except Exception as e:
            status = f"firewall_error: {e}"

        return {
            "action": "ip_blacklist",
            "ip": ip,
            "rule_name": rule_name,
            "reason": reason,
            "status": status,
            "timestamp": datetime.now().isoformat()
        }

    def _rate_limit(self, ip, max_rate):
        """Apply rate limiting (logged only - actual rate limiting done at app level)."""
        return {
            "action": "rate_limit",
            "ip": ip,
            "max_rate_per_sec": max_rate,
            "status": "applied",
            "timestamp": datetime.now().isoformat()
        }

    def _network_isolate(self, ip):
        """Block all traffic to/from an IP (full isolation)."""
        rule_name = f"DTARF_Isolate_{ip.replace('.', '_')}"

        if self.backend == "windows_firewall":
            # Block both inbound and outbound
            for direction in ["in", "out"]:
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}_{direction}",
                    f"dir={direction}", "action=block",
                    f"remoteip={ip}",
                    "enable=yes"
                ]
                try:
                    subprocess.run(cmd, capture_output=True, timeout=10)
                except Exception:
                    pass

        return {
            "action": "network_isolate",
            "ip": ip,
            "status": "executed",
            "timestamp": datetime.now().isoformat()
        }

    def _quarantine(self, file_path):
        """Move a suspicious file to quarantine directory."""
        quarantine_dir = "evidence/quarantine"
        os.makedirs(quarantine_dir, exist_ok=True)

        if not os.path.exists(file_path):
            return {"action": "quarantine", "status": "file_not_found", "path": file_path}

        import shutil
        quarantine_name = f"{int(time.time())}_{os.path.basename(file_path)}"
        dest = os.path.join(quarantine_dir, quarantine_name)
        try:
            shutil.move(file_path, dest)
            return {
                "action": "quarantine",
                "original_path": file_path,
                "quarantine_path": dest,
                "status": "quarantined",
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            return {"action": "quarantine", "status": "error", "error": str(e)}

    def _send_alert(self, params):
        """Log an alert (extensible to email/webhook/SIEM)."""
        return {
            "action": "alert",
            "status": "sent",
            "details": params,
            "timestamp": datetime.now().isoformat()
        }

    def remove_blacklist(self, ip):
        """Remove an IP from the blacklist."""
        with self._lock:
            if ip in self._blacklist:
                del self._blacklist[ip]
                self._save_blacklist()

        rule_name = f"DTARF_Block_{ip.replace('.', '_')}"
        if self.backend == "windows_firewall":
            cmd = [
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={rule_name}"
            ]
            try:
                subprocess.run(cmd, capture_output=True, timeout=10)
            except Exception:
                pass

        return {"action": "unblock", "ip": ip, "status": "removed"}

    def get_blacklist(self):
        with self._lock:
            return dict(self._blacklist)

    def get_action_log(self, count=100):
        with self._lock:
            return list(self._action_log)[-count:]


class ResponseOrchestrator:
    """
    Response Orchestrator - coordinates alert handling:
    1. Alert Prioritization (severity-based queue)
    2. Playbook Selection (match alert type to response playbook)
    3. Policy Mapping (determine allowed actions)
    4. Action Execution (delegate to ActionExecutor)
    """

    def __init__(self, config, action_executor, forensic_engine=None):
        orch_config = config.get("orchestrator", {})
        self.enabled = orch_config.get("enabled", True)
        self.auto_threshold = orch_config.get("auto_response_threshold", 70)
        self.cooldown_sec = orch_config.get("cooldown_sec", 300)

        self.playbooks = config.get("playbooks", {})
        self.executor = action_executor
        self.forensic_engine = forensic_engine

        self._alert_queue = deque(maxlen=10000)
        self._processed = deque(maxlen=10000)
        self._history_file = config.get("history_file", "data/alert_history.json")
        self._cooldown_tracker = {}  # ip -> last_action_time
        self._lock = threading.Lock()
        self._stats = {
            "total_received": 0,
            "total_processed": 0,
            "total_auto_responded": 0,
            "total_manual_review": 0,
            "avg_response_time_ms": 0,
            "response_times": deque(maxlen=1000)
        }
        self._load_history()

    def _load_history(self):
        """Load alert history from disk."""
        try:
            if os.path.exists(self._history_file):
                with open(self._history_file, "r") as f:
                    history = json.load(f)
                    for h in history:
                        try:
                            a = Alert(
                                h.get('type', 'unknown'), 
                                h.get('severity', 50), 
                                h.get('source', 'unknown'), 
                                h.get('details', {}),
                                h.get('src_ip'), 
                                h.get('dst_ip'), 
                                h.get('timestamp')
                            )
                            a.id = h.get('id', a.id)
                            a.status = h.get('status', 'new')
                            a.response_actions = h.get('response_actions', [])
                            a.forensic_evidence = h.get('forensic_evidence', [])
                            a.enrichment = h.get('enrichment', {})
                            a.response_time_ms = h.get('response_time_ms')
                            self._processed.append(a)
                        except Exception as item_err:
                            print(f"  ⚠ Skipping invalid alert in history: {item_err}")
                print(f"  ✓ Loaded {len(self._processed)} alerts from history")
        except Exception as e:
            print(f"  ⚠ Error loading alert history: {e}")

    def _save_history(self):
        """Save alert history to disk."""
        try:
            os.makedirs(os.path.dirname(self._history_file), exist_ok=True)
            with self._lock:
                history = [a.to_dict() for a in self._processed]
            with open(self._history_file, "w") as f:
                json.dump(history, f, indent=2)
            # print(f"  [DEBUG] Saved {len(history)} alerts to history")
        except Exception as e:
            print(f"  ⚠ Error saving alert history: {e}")

    def receive_alert(self, alert):
        """
        Receive and process an alert.
        Determines if auto-response should be triggered or
        if manual review is required.
        """
        if not self.enabled:
            return

        start_time = time.time()
        self._stats["total_received"] += 1

        # Create standardized Alert object if raw dict
        if isinstance(alert, dict):
            alert_obj = Alert(
                alert_type=alert.get("type", "unknown"),
                severity=alert.get("severity", 50),
                source=alert.get("source", "unknown"),
                details=alert,
                src_ip=alert.get("src_ip") or alert.get("ip"),
                dst_ip=alert.get("dst_ip"),
                timestamp=alert.get("timestamp")
            )
        else:
            alert_obj = alert

        with self._lock:
            self._alert_queue.append(alert_obj)

        # Check cooldown
        if alert_obj.src_ip:
            last_action = self._cooldown_tracker.get(alert_obj.src_ip, 0)
            if time.time() - last_action < self.cooldown_sec:
                alert_obj.status = "cooldown"
                return alert_obj

        # Auto-response for high severity
        if alert_obj.severity >= self.auto_threshold:
            self._auto_respond(alert_obj)
            self._stats["total_auto_responded"] += 1
        else:
            alert_obj.status = "pending_review"
            self._stats["total_manual_review"] += 1

        # Track response time
        response_ms = (time.time() - start_time) * 1000
        alert_obj.response_time_ms = round(response_ms, 2)
        self._stats["response_times"].append(response_ms)
        self._stats["total_processed"] += 1

        # Update average
        times = list(self._stats["response_times"])
        if times:
            self._stats["avg_response_time_ms"] = round(sum(times) / len(times), 2)

        with self._lock:
            self._processed.append(alert_obj)

        self._save_history()

        return alert_obj

    def _auto_respond(self, alert):
        """Execute automatic response based on playbook matching."""
        alert.status = "responding"

        # Find matching playbook
        playbook = self._match_playbook(alert.type)

        if playbook:
            actions = playbook.get("actions", [])
            for action_type in actions:
                params = {
                    "ip": alert.src_ip,
                    "reason": f"Auto-response to {alert.type} (severity: {alert.severity})",
                    "alert_id": alert.id
                }
                result = self.executor.execute(action_type, params)
                alert.response_actions.append(result)

                # Trigger forensic evidence collection if action includes it
                if action_type == "evidence_collect" and self.forensic_engine:
                    evidence = self.forensic_engine.collect_evidence(alert)
                    alert.forensic_evidence.append(evidence)

        else:
            # Default response for unmatched alerts
            if alert.src_ip:
                result = self.executor.execute("ip_blacklist", {
                    "ip": alert.src_ip,
                    "reason": f"Default response to {alert.type}"
                })
                alert.response_actions.append(result)

        # Update cooldown
        if alert.src_ip:
            self._cooldown_tracker[alert.src_ip] = time.time()

        alert.status = "responded"

    def _match_playbook(self, alert_type):
        """Match an alert type to a response playbook."""
        # Direct mapping
        type_to_playbook = {
            "syn_flood": "ddos_mitigation",
            "udp_flood": "ddos_mitigation",
            "icmp_flood": "ddos_mitigation",
            "http_flood": "ddos_mitigation",
            "high_packet_rate": "ddos_mitigation",
            "port_scan": "port_scan_response",
            "arp_spoofing": "arp_spoof_response",
            "ransomware": "malware_response",
            "ransomware_suspected": "malware_response",
            "ransomware_high_entropy": "malware_response",
            "fileless_malware": "malware_response",
            "brute_force": "brute_force_response",
            "credential_stuffing": "brute_force_response",
            "data_exfiltration": "data_exfil_response",
            "external_connection": "data_exfil_response",
            "malicious_ip_detected": "ddos_mitigation",
            "lateral_tool_usage": "malware_response",
            "suspicious_smb_rdp": "malware_response",
        }

        playbook_name = type_to_playbook.get(alert_type)
        if playbook_name:
            return self.playbooks.get(playbook_name)

        return None

    def get_alerts(self, status=None, count=100):
        """Get alerts, optionally filtered by status."""
        with self._lock:
            alerts = list(self._processed)[-count:]
            if status:
                alerts = [a for a in alerts if a.status == status]
            return [a.to_dict() for a in alerts]

    def update_alert_status(self, alert_id, status):
        """Update an alert's status and save history."""
        with self._lock:
            for a in self._processed:
                if a.id == alert_id:
                    a.status = status
                    break
        self._save_history()

    def get_stats(self):
        return {
            "total_received": self._stats["total_received"],
            "total_processed": self._stats["total_processed"],
            "total_auto_responded": self._stats["total_auto_responded"],
            "total_manual_review": self._stats["total_manual_review"],
            "avg_response_time_ms": self._stats["avg_response_time_ms"],
            "queue_size": len(self._alert_queue),
            "blacklisted_ips": len(self.executor.get_blacklist()),
            "active_playbooks": len(self.playbooks)
        }
