# ingestion/system_telemetry.py
"""
Data Ingestion Layer - System Telemetry Collector
Collects CPU, memory, disk I/O, active processes, network connections,
and syscall-level information for the analytics engine.
"""

import time
import threading
import psutil
from datetime import datetime
from collections import deque


class TelemetrySnapshot:
    """A single telemetry reading."""

    def __init__(self):
        self.timestamp = datetime.now().isoformat()
        self.cpu_percent = 0.0
        self.memory_percent = 0.0
        self.memory_used_mb = 0.0
        self.disk_read_bytes = 0
        self.disk_write_bytes = 0
        self.active_processes = 0
        self.network_connections = 0
        self.network_bytes_sent = 0
        self.network_bytes_recv = 0
        self.suspicious_processes = []

    def to_dict(self):
        return {
            "timestamp": self.timestamp,
            "cpu_percent": self.cpu_percent,
            "memory_percent": self.memory_percent,
            "memory_used_mb": self.memory_used_mb,
            "disk_read_bytes": self.disk_read_bytes,
            "disk_write_bytes": self.disk_write_bytes,
            "active_processes": self.active_processes,
            "network_connections": self.network_connections,
            "network_bytes_sent": self.network_bytes_sent,
            "network_bytes_recv": self.network_bytes_recv,
            "suspicious_processes": self.suspicious_processes
        }


# Known suspicious process names
SUSPICIOUS_PROCESS_NAMES = {
    "mimikatz", "psexec", "wmic", "ncat", "netcat", "nc",
    "powershell_ise", "mshta", "regsvr32", "rundll32",
    "certutil", "bitsadmin", "msiexec", "csc", "installutil"
}


class SystemTelemetry:
    """
    Periodically collects system telemetry metrics and
    stores them in a sliding window buffer.
    """

    def __init__(self, config, telemetry_queue):
        self.enabled = config.get("enabled", True)
        self.interval = config.get("collect_interval_sec", 5)
        self.telemetry_queue = telemetry_queue
        self._history = deque(maxlen=1000)
        self._stop_event = threading.Event()
        self._thread = None
        self._baseline = None
        self._prev_disk = None
        self._prev_net = None

    def start(self):
        if not self.enabled:
            return
        self._thread = threading.Thread(target=self._collect_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)

    def get_latest(self):
        if self._history:
            return self._history[-1]
        return None

    def get_history(self, count=100):
        return list(self._history)[-count:]

    def get_baseline(self):
        """Calculate baseline from history for anomaly detection."""
        if len(self._history) < 10:
            return None

        history = list(self._history)
        cpu_vals = [s.cpu_percent for s in history]
        mem_vals = [s.memory_percent for s in history]
        conn_vals = [s.network_connections for s in history]

        def avg(lst):
            return sum(lst) / len(lst) if lst else 0

        def std(lst):
            m = avg(lst)
            return (sum((x - m) ** 2 for x in lst) / len(lst)) ** 0.5 if lst else 0

        return {
            "cpu": {"mean": avg(cpu_vals), "std": std(cpu_vals)},
            "memory": {"mean": avg(mem_vals), "std": std(mem_vals)},
            "connections": {"mean": avg(conn_vals), "std": std(conn_vals)},
            "sample_count": len(history)
        }

    def _collect_loop(self):
        # Initial reads for delta calculation
        try:
            self._prev_disk = psutil.disk_io_counters()
            self._prev_net = psutil.net_io_counters()
        except Exception:
            pass

        while not self._stop_event.is_set():
            try:
                snapshot = self._collect_snapshot()
                self._history.append(snapshot)
                self.telemetry_queue.append(snapshot)
            except Exception:
                pass
            time.sleep(self.interval)

    def _collect_snapshot(self):
        snap = TelemetrySnapshot()

        # CPU
        snap.cpu_percent = psutil.cpu_percent(interval=0.5)

        # Memory
        mem = psutil.virtual_memory()
        snap.memory_percent = mem.percent
        snap.memory_used_mb = round(mem.used / (1024 * 1024), 2)

        # Disk I/O (delta since last read)
        try:
            disk = psutil.disk_io_counters()
            if self._prev_disk:
                snap.disk_read_bytes = disk.read_bytes - self._prev_disk.read_bytes
                snap.disk_write_bytes = disk.write_bytes - self._prev_disk.write_bytes
            self._prev_disk = disk
        except Exception:
            pass

        # Active processes
        try:
            procs = list(psutil.process_iter(['name', 'pid', 'cpu_percent']))
            snap.active_processes = len(procs)

            # Check for suspicious processes
            for p in procs:
                try:
                    pname = (p.info.get('name') or '').lower()
                    if pname.replace('.exe', '') in SUSPICIOUS_PROCESS_NAMES:
                        snap.suspicious_processes.append({
                            "pid": p.info['pid'],
                            "name": p.info['name'],
                            "cpu": p.info.get('cpu_percent', 0)
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            pass

        # Network connections
        try:
            conns = psutil.net_connections(kind='inet')
            snap.network_connections = len(conns)
        except (psutil.AccessDenied, OSError):
            snap.network_connections = -1

        # Network I/O (delta)
        try:
            net = psutil.net_io_counters()
            if self._prev_net:
                snap.network_bytes_sent = net.bytes_sent - self._prev_net.bytes_sent
                snap.network_bytes_recv = net.bytes_recv - self._prev_net.bytes_recv
            self._prev_net = net
        except Exception:
            pass

        return snap
