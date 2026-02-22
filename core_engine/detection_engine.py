# core_engine/detection_engine.py
"""
DTARF Core Analytics Engine - Detection Engine
Implements:
  - Shannon Entropy (Hash-based) analysis
  - Statistical Anomaly Detection (Z-Score)
  - Sliding-Window Network Analysis
"""

import math
import time
import threading
from collections import Counter, defaultdict, deque
from datetime import datetime


class ShannonEntropyAnalyzer:
    """
    Shannon Entropy analyzer for detecting encrypted/packed content.
    High entropy may indicate: ransomware-encrypted files, packed malware,
    encrypted C2 communications, or steganography.
    """

    def __init__(self, config):
        self.high_threshold = config.get("high_threshold", 7.0)
        self.medium_threshold = config.get("medium_threshold", 5.0)
        self.block_size = config.get("block_size", 1024)

    def calculate(self, data):
        """Calculate Shannon entropy of byte data."""
        if not data:
            return 0.0
        freq = Counter(data)
        length = len(data)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 4)

    def classify(self, entropy):
        """Classify entropy level."""
        if entropy >= self.high_threshold:
            return "HIGH"
        elif entropy >= self.medium_threshold:
            return "MEDIUM"
        else:
            return "LOW"

    def analyze_data(self, data):
        """Full entropy analysis of data block."""
        entropy = self.calculate(data)
        classification = self.classify(entropy)

        # Block-level analysis for large payloads
        blocks = []
        if len(data) > self.block_size:
            for i in range(0, len(data), self.block_size):
                block = data[i:i + self.block_size]
                block_ent = self.calculate(block)
                blocks.append({
                    "offset": i,
                    "size": len(block),
                    "entropy": block_ent,
                    "classification": self.classify(block_ent)
                })

        return {
            "overall_entropy": entropy,
            "classification": classification,
            "data_size": len(data),
            "blocks": blocks,
            "is_suspicious": classification == "HIGH"
        }


class StatisticalAnomalyDetector:
    """
    Z-Score based anomaly detection.
    Maintains rolling baselines for network metrics and
    flags deviations that exceed the configured threshold.
    """

    def __init__(self, config):
        self.z_threshold = config.get("z_score_threshold", 3.0)
        self.baseline_window = config.get("baseline_window_sec", 300)
        self.min_samples = config.get("min_samples", 50)
        self._metrics = defaultdict(lambda: deque(maxlen=5000))
        self._lock = threading.Lock()

    def add_sample(self, metric_name, value):
        """Add a data point to the metric's history."""
        with self._lock:
            self._metrics[metric_name].append({
                "value": value,
                "timestamp": time.time()
            })

    def check_anomaly(self, metric_name, current_value):
        """
        Check if the current value is anomalous based on
        the historical baseline using Z-Score.
        """
        with self._lock:
            samples = self._metrics.get(metric_name, deque())

            if len(samples) < self.min_samples:
                return {
                    "metric": metric_name,
                    "value": current_value,
                    "is_anomaly": False,
                    "reason": "insufficient_baseline",
                    "sample_count": len(samples)
                }

            # Filter to baseline window
            now = time.time()
            cutoff = now - self.baseline_window
            window_values = [s["value"] for s in samples if s["timestamp"] >= cutoff]

            if len(window_values) < self.min_samples:
                window_values = [s["value"] for s in samples]

            mean = sum(window_values) / len(window_values)
            variance = sum((x - mean) ** 2 for x in window_values) / len(window_values)
            std_dev = variance ** 0.5

            if std_dev == 0:
                z_score = 0
            else:
                z_score = (current_value - mean) / std_dev

            is_anomaly = abs(z_score) > self.z_threshold

        return {
            "metric": metric_name,
            "value": current_value,
            "mean": round(mean, 4),
            "std_dev": round(std_dev, 4),
            "z_score": round(z_score, 4),
            "threshold": self.z_threshold,
            "is_anomaly": is_anomaly,
            "direction": "above" if z_score > 0 else "below",
            "sample_count": len(window_values)
        }

    def get_baselines(self):
        """Get current baselines for all tracked metrics."""
        baselines = {}
        with self._lock:
            for name, samples in self._metrics.items():
                if not samples:
                    continue
                values = [s["value"] for s in samples]
                mean = sum(values) / len(values)
                std = (sum((x - mean) ** 2 for x in values) / len(values)) ** 0.5
                baselines[name] = {
                    "mean": round(mean, 4),
                    "std_dev": round(std, 4),
                    "sample_count": len(values)
                }
        return baselines


class SlidingWindowAnalyzer:
    """
    Sliding-window network traffic analysis.
    Detects anomalies in packet rate, byte rate, and
    connection patterns within configurable windows.
    """

    def __init__(self, config):
        self.window_size = config.get("window_size_sec", 30)
        self.step_size = config.get("step_size_sec", 5)
        self.pkt_threshold = config.get("packet_rate_threshold", 1000)
        self.byte_threshold = config.get("byte_rate_threshold", 10_000_000)
        self.conn_threshold = config.get("connection_rate_threshold", 100)
        self._windows = deque(maxlen=100)
        self._current_window = {
            "start_time": time.time(),
            "packets": 0,
            "bytes": 0,
            "connections": set(),
            "sources": defaultdict(int),
            "protocols": defaultdict(int)
        }
        self._lock = threading.Lock()

    def add_packet(self, meta):
        """Process a packet metadata object."""
        now = time.time()
        with self._lock:
            # Check if window has expired
            if now - self._current_window["start_time"] >= self.step_size:
                self._rotate_window(now)

            self._current_window["packets"] += 1
            self._current_window["bytes"] += meta.raw_size
            self._current_window["connections"].add(
                (meta.src_ip, meta.dst_ip, meta.dst_port)
            )
            self._current_window["sources"][meta.src_ip] += 1
            self._current_window["protocols"][meta.protocol] += 1

    def _rotate_window(self, now):
        """Finalize current window and start a new one."""
        w = self._current_window
        snapshot = {
            "start_time": w["start_time"],
            "end_time": now,
            "duration": now - w["start_time"],
            "packets": w["packets"],
            "bytes": w["bytes"],
            "unique_connections": len(w["connections"]),
            "top_sources": dict(
                sorted(w["sources"].items(), key=lambda x: x[1], reverse=True)[:10]
            ),
            "protocols": dict(w["protocols"])
        }
        self._windows.append(snapshot)

        # Reset
        self._current_window = {
            "start_time": now,
            "packets": 0,
            "bytes": 0,
            "connections": set(),
            "sources": defaultdict(int),
            "protocols": defaultdict(int)
        }

    def analyze(self):
        """Analyze recent windows for anomalies."""
        alerts = []
        with self._lock:
            if not self._windows:
                return alerts

            latest = self._windows[-1]
            duration = latest["duration"] if latest["duration"] > 0 else 1

            pkt_rate = latest["packets"] / duration
            byte_rate = latest["bytes"] / duration
            conn_rate = latest["unique_connections"] / duration

            if pkt_rate > self.pkt_threshold:
                alerts.append({
                    "type": "high_packet_rate",
                    "severity": 80,
                    "value": round(pkt_rate, 2),
                    "threshold": self.pkt_threshold,
                    "timestamp": datetime.now().isoformat(),
                    "top_sources": latest.get("top_sources", {})
                })

            if byte_rate > self.byte_threshold:
                alerts.append({
                    "type": "high_byte_rate",
                    "severity": 75,
                    "value": round(byte_rate, 2),
                    "threshold": self.byte_threshold,
                    "timestamp": datetime.now().isoformat()
                })

            if conn_rate > self.conn_threshold:
                alerts.append({
                    "type": "high_connection_rate",
                    "severity": 70,
                    "value": round(conn_rate, 2),
                    "threshold": self.conn_threshold,
                    "timestamp": datetime.now().isoformat()
                })

        return alerts

    def get_history(self, count=20):
        """Get recent window snapshots."""
        with self._lock:
            return list(self._windows)[-count:]


class DetectionEngine:
    """
    Unified detection engine combining all analysis methods.
    """

    def __init__(self, config):
        de_config = config.get("detection_engine", {})
        self.entropy = ShannonEntropyAnalyzer(de_config.get("shannon_entropy", {}))
        self.anomaly = StatisticalAnomalyDetector(de_config.get("statistical_anomaly", {}))
        self.sliding_window = SlidingWindowAnalyzer(de_config.get("sliding_window", {}))
        self._alerts = deque(maxlen=10000)
        self._lock = threading.Lock()

    def process_packet(self, meta):
        """Process a packet through all analyzers."""
        # Feed to sliding window
        self.sliding_window.add_packet(meta)

        # Feed metrics to anomaly detector
        self.anomaly.add_sample("packet_size", meta.raw_size)
        if meta.payload_size > 0:
            self.anomaly.add_sample("payload_size", meta.payload_size)

    def check_payload_entropy(self, data, context=""):
        """Analyze payload entropy for suspicious content."""
        result = self.entropy.analyze_data(data)
        if result["is_suspicious"]:
            alert = {
                "type": "high_entropy_payload",
                "severity": 65,
                "context": context,
                "entropy": result["overall_entropy"],
                "data_size": result["data_size"],
                "timestamp": datetime.now().isoformat()
            }
            self._add_alert(alert)
            return alert
        return None

    def run_analysis_cycle(self):
        """Run a complete analysis cycle and return any alerts."""
        alerts = []

        # Sliding window analysis
        sw_alerts = self.sliding_window.analyze()
        alerts.extend(sw_alerts)

        # Anomaly checks on recent metrics
        for metric in ["packet_size", "payload_size"]:
            samples = self.anomaly._metrics.get(metric, deque())
            if samples:
                latest = samples[-1]["value"]
                result = self.anomaly.check_anomaly(metric, latest)
                if result["is_anomaly"]:
                    alerts.append({
                        "type": f"anomaly_{metric}",
                        "severity": 60,
                        "details": result,
                        "timestamp": datetime.now().isoformat()
                    })

        for a in alerts:
            self._add_alert(a)

        return alerts

    def _add_alert(self, alert):
        with self._lock:
            self._alerts.append(alert)

    def get_alerts(self, count=100):
        with self._lock:
            return list(self._alerts)[-count:]

    def get_stats(self):
        return {
            "total_alerts": len(self._alerts),
            "baselines": self.anomaly.get_baselines(),
            "window_history": self.sliding_window.get_history(10)
        }
