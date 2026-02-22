# forensics/evidence_collector.py
"""
Forensic Evidence & Audit Layer - Evidence Collector
Collects and preserves:
  - Memory artifacts
  - Network captures (log snapshots)
  - Log snapshots
  - Process snapshots
"""

import os
import json
import time
import shutil
import psutil
import subprocess
from datetime import datetime


class EvidenceCollector:
    """
    Collects forensic evidence upon alert triggers.
    Captures memory artifacts, network state, log snapshots,
    and system state at the time of the incident.
    """

    def __init__(self, config):
        self.capture_memory = config.get("capture_memory_artifacts", True)
        self.capture_network = config.get("capture_network", True)
        self.capture_logs = config.get("capture_logs", True)
        self.min_severity = config.get("capture_on_alert_severity", 70)
        self.max_pcap_mb = config.get("max_pcap_size_mb", 50)
        self.retention_days = config.get("retention_days", 90)
        self.evidence_dir = "evidence/artifacts"
        os.makedirs(self.evidence_dir, exist_ok=True)

    def collect_evidence(self, alert):
        """
        Collect all relevant forensic evidence for an alert.
        Returns evidence package metadata.
        """
        alert_data = alert if isinstance(alert, dict) else alert.to_dict()

        if alert_data.get("severity", 0) < self.min_severity:
            return {"status": "skipped", "reason": "below_severity_threshold"}

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        alert_id = alert_data.get("id", f"unknown_{timestamp}")
        evidence_path = os.path.join(self.evidence_dir, f"{alert_id}_{timestamp}")
        os.makedirs(evidence_path, exist_ok=True)

        evidence_package = {
            "alert_id": alert_id,
            "collection_started": datetime.now().isoformat(),
            "evidence_path": evidence_path,
            "artifacts": []
        }

        # 1. Save alert details
        alert_file = os.path.join(evidence_path, "alert_details.json")
        with open(alert_file, "w") as f:
            json.dump(alert_data, f, indent=2, default=str)
        evidence_package["artifacts"].append({
            "type": "alert_details",
            "file": alert_file,
            "timestamp": datetime.now().isoformat()
        })

        # 2. Capture memory artifacts (process list, connections)
        if self.capture_memory:
            mem_artifact = self._capture_memory_artifacts(evidence_path)
            if mem_artifact:
                evidence_package["artifacts"].append(mem_artifact)

        # 3. Capture network state
        if self.capture_network:
            net_artifact = self._capture_network_state(evidence_path)
            if net_artifact:
                evidence_package["artifacts"].append(net_artifact)

        # 4. Capture log snapshots
        if self.capture_logs:
            log_artifact = self._capture_log_snapshot(evidence_path)
            if log_artifact:
                evidence_package["artifacts"].append(log_artifact)

        # 5. Capture system state
        sys_artifact = self._capture_system_state(evidence_path)
        if sys_artifact:
            evidence_package["artifacts"].append(sys_artifact)

        evidence_package["collection_completed"] = datetime.now().isoformat()
        evidence_package["artifact_count"] = len(evidence_package["artifacts"])

        # Save evidence manifest
        manifest_file = os.path.join(evidence_path, "evidence_manifest.json")
        with open(manifest_file, "w") as f:
            json.dump(evidence_package, f, indent=2)

        return evidence_package

    def _capture_memory_artifacts(self, evidence_path):
        """Capture running processes and their details."""
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'username',
                                              'cpu_percent', 'memory_percent',
                                              'create_time', 'status']):
                try:
                    info = proc.info
                    info['create_time'] = datetime.fromtimestamp(
                        info.get('create_time', 0)
                    ).isoformat()

                    # Get command line if possible
                    try:
                        info['cmdline'] = proc.cmdline()
                    except (psutil.AccessDenied, psutil.ZombieProcess):
                        info['cmdline'] = []

                    # Get open files if possible
                    try:
                        info['open_files'] = [f.path for f in proc.open_files()]
                    except (psutil.AccessDenied, psutil.ZombieProcess):
                        info['open_files'] = []

                    processes.append(info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            file_path = os.path.join(evidence_path, "memory_artifacts.json")
            with open(file_path, "w") as f:
                json.dump({
                    "capture_time": datetime.now().isoformat(),
                    "total_processes": len(processes),
                    "processes": processes
                }, f, indent=2, default=str)

            return {
                "type": "memory_artifacts",
                "file": file_path,
                "process_count": len(processes),
                "timestamp": datetime.now().isoformat()
            }

        except Exception as e:
            return {"type": "memory_artifacts", "error": str(e)}

    def _capture_network_state(self, evidence_path):
        """Capture current network connections and interface state."""
        try:
            # Active network connections
            connections = []
            try:
                for conn in psutil.net_connections(kind='inet'):
                    connections.append({
                        "fd": conn.fd,
                        "family": str(conn.family),
                        "type": str(conn.type),
                        "laddr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                        "raddr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                        "status": conn.status,
                        "pid": conn.pid
                    })
            except (psutil.AccessDenied, OSError):
                pass

            # Network interface stats
            interfaces = {}
            try:
                for name, addrs in psutil.net_if_addrs().items():
                    interfaces[name] = [
                        {"family": str(a.family), "address": a.address}
                        for a in addrs
                    ]
            except Exception:
                pass

            # Network I/O counters
            net_io = {}
            try:
                counters = psutil.net_io_counters(pernic=True)
                for name, c in counters.items():
                    net_io[name] = {
                        "bytes_sent": c.bytes_sent,
                        "bytes_recv": c.bytes_recv,
                        "packets_sent": c.packets_sent,
                        "packets_recv": c.packets_recv,
                        "errin": c.errin,
                        "errout": c.errout
                    }
            except Exception:
                pass

            file_path = os.path.join(evidence_path, "network_captures.json")
            with open(file_path, "w") as f:
                json.dump({
                    "capture_time": datetime.now().isoformat(),
                    "connections": connections,
                    "interfaces": interfaces,
                    "io_counters": net_io
                }, f, indent=2, default=str)

            return {
                "type": "network_captures",
                "file": file_path,
                "connection_count": len(connections),
                "timestamp": datetime.now().isoformat()
            }

        except Exception as e:
            return {"type": "network_captures", "error": str(e)}

    def _capture_log_snapshot(self, evidence_path):
        """Snapshot current log files."""
        try:
            log_sources = [
                "logs/alerts.log",
                "logs/access.log",
                "logs/dtarf.log"
            ]

            copied_logs = []
            log_dest_dir = os.path.join(evidence_path, "log_snapshots")
            os.makedirs(log_dest_dir, exist_ok=True)

            for log_src in log_sources:
                if os.path.exists(log_src):
                    dest = os.path.join(log_dest_dir, os.path.basename(log_src))
                    shutil.copy2(log_src, dest)
                    copied_logs.append({
                        "source": log_src,
                        "destination": dest,
                        "size_bytes": os.path.getsize(dest)
                    })

            return {
                "type": "log_snapshots",
                "directory": log_dest_dir,
                "logs_captured": len(copied_logs),
                "details": copied_logs,
                "timestamp": datetime.now().isoformat()
            }

        except Exception as e:
            return {"type": "log_snapshots", "error": str(e)}

    def _capture_system_state(self, evidence_path):
        """Capture system state: CPU, memory, disk, uptime."""
        try:
            import platform

            state = {
                "capture_time": datetime.now().isoformat(),
                "system": {
                    "platform": platform.platform(),
                    "hostname": platform.node(),
                    "architecture": platform.machine(),
                    "python_version": platform.python_version()
                },
                "cpu": {
                    "count": psutil.cpu_count(),
                    "percent": psutil.cpu_percent(interval=0.5),
                    "freq": psutil.cpu_freq()._asdict() if psutil.cpu_freq() else {}
                },
                "memory": {
                    "total_mb": round(psutil.virtual_memory().total / 1024 / 1024, 2),
                    "used_mb": round(psutil.virtual_memory().used / 1024 / 1024, 2),
                    "percent": psutil.virtual_memory().percent
                },
                "disk": {},
                "boot_time": datetime.fromtimestamp(psutil.boot_time()).isoformat()
            }

            # Disk usage
            try:
                for part in psutil.disk_partitions():
                    usage = psutil.disk_usage(part.mountpoint)
                    state["disk"][part.mountpoint] = {
                        "total_gb": round(usage.total / 1024 / 1024 / 1024, 2),
                        "used_gb": round(usage.used / 1024 / 1024 / 1024, 2),
                        "percent": usage.percent
                    }
            except Exception:
                pass

            file_path = os.path.join(evidence_path, "system_state.json")
            with open(file_path, "w") as f:
                json.dump(state, f, indent=2, default=str)

            return {
                "type": "system_state",
                "file": file_path,
                "timestamp": datetime.now().isoformat()
            }

        except Exception as e:
            return {"type": "system_state", "error": str(e)}
