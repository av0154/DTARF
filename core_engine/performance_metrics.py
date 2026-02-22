# core_engine/performance_metrics.py
"""
Performance Metrics & Benchmarking Module
Tracks:
  - Detection Accuracy
  - Mean Time To Respond (MTTR)
  - False Positive Rate
  - System throughput and latency
  
Provides comparison baseline against traditional systems.
"""

import time
import threading
from datetime import datetime
from collections import deque


class PerformanceMetrics:
    """
    Tracks and reports framework performance metrics.
    Target benchmarks from the architecture:
      - Detection Accuracy: 96.8%
      - MTTR: 87ms
      - Low False Positives
    """

    def __init__(self, config):
        self.enabled = config.get("enable_metrics", True)
        self.window_sec = config.get("metrics_window_sec", 3600)
        self.target_accuracy = config.get("target_accuracy", 0.968)
        self.target_mttr_ms = config.get("target_mttr_ms", 87)
        self.export_interval = config.get("export_interval_sec", 60)

        # Tracking containers
        self._detections = deque(maxlen=50000)
        self._response_times = deque(maxlen=50000)
        self._false_positives = deque(maxlen=50000)
        self._true_positives = deque(maxlen=50000)
        self._throughput = deque(maxlen=10000)
        self._lock = threading.Lock()

        self._start_time = time.time()

    def record_detection(self, alert_type, severity, is_true_positive=True):
        """Record a detection event."""
        with self._lock:
            entry = {
                "timestamp": time.time(),
                "type": alert_type,
                "severity": severity,
                "is_true_positive": is_true_positive
            }
            self._detections.append(entry)
            if is_true_positive:
                self._true_positives.append(entry)
            else:
                self._false_positives.append(entry)

    def record_response_time(self, response_time_ms):
        """Record a response time in milliseconds."""
        with self._lock:
            self._response_times.append({
                "timestamp": time.time(),
                "response_time_ms": response_time_ms
            })

    def record_throughput(self, events_per_sec):
        """Record throughput measurement."""
        with self._lock:
            self._throughput.append({
                "timestamp": time.time(),
                "events_per_sec": events_per_sec
            })

    def mark_false_positive(self, alert_id):
        """Mark an alert as a false positive after manual review."""
        with self._lock:
            self._false_positives.append({
                "timestamp": time.time(),
                "alert_id": alert_id,
                "is_true_positive": False
            })

    def get_metrics(self):
        """Get current performance metrics."""
        now = time.time()
        cutoff = now - self.window_sec

        with self._lock:
            # Filter to current window
            window_detections = [d for d in self._detections if d["timestamp"] >= cutoff]
            window_tp = [d for d in self._true_positives if d["timestamp"] >= cutoff]
            window_fp = [d for d in self._false_positives if d["timestamp"] >= cutoff]
            window_rt = [r for r in self._response_times if r["timestamp"] >= cutoff]

        total_detections = len(window_detections)
        true_positives = len(window_tp)
        false_positives = len(window_fp)

        # Detection Accuracy
        if total_detections > 0:
            accuracy = true_positives / total_detections
        else:
            accuracy = 1.0  # No detections = no errors

        # False Positive Rate
        if total_detections > 0:
            fpr = false_positives / total_detections
        else:
            fpr = 0.0

        # MTTR (Mean Time to Respond)
        if window_rt:
            response_times = [r["response_time_ms"] for r in window_rt]
            mttr = sum(response_times) / len(response_times)
            min_rt = min(response_times)
            max_rt = max(response_times)
            p95_rt = sorted(response_times)[int(len(response_times) * 0.95)] if len(response_times) > 20 else max_rt
        else:
            mttr = 0
            min_rt = 0
            max_rt = 0
            p95_rt = 0

        # Uptime
        uptime_sec = now - self._start_time

        return {
            "timestamp": datetime.now().isoformat(),
            "window_sec": self.window_sec,
            "uptime_sec": round(uptime_sec, 2),
            "detection": {
                "total_detections": total_detections,
                "true_positives": true_positives,
                "false_positives": false_positives,
                "accuracy": round(accuracy, 4),
                "accuracy_pct": f"{accuracy * 100:.1f}%",
                "target_accuracy": self.target_accuracy,
                "meets_target": accuracy >= self.target_accuracy,
                "false_positive_rate": round(fpr, 4)
            },
            "response": {
                "mttr_ms": round(mttr, 2),
                "min_response_ms": round(min_rt, 2),
                "max_response_ms": round(max_rt, 2),
                "p95_response_ms": round(p95_rt, 2),
                "target_mttr_ms": self.target_mttr_ms,
                "meets_target": mttr <= self.target_mttr_ms if mttr > 0 else True,
                "total_responses": len(window_rt)
            },
            "severity_distribution": self._get_severity_distribution(window_detections)
        }

    def _get_severity_distribution(self, detections):
        """Categorize detections by severity level."""
        dist = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for d in detections:
            sev = d.get("severity", 0)
            if sev >= 90:
                dist["CRITICAL"] += 1
            elif sev >= 70:
                dist["HIGH"] += 1
            elif sev >= 40:
                dist["MEDIUM"] += 1
            elif sev >= 10:
                dist["LOW"] += 1
            else:
                dist["INFO"] += 1
        return dist

    def get_baseline_comparison(self):
        """
        Compare DTARF performance against traditional systems.
        Baseline data from the architecture diagram.
        """
        current = self.get_metrics()

        return {
            "framework": "DTARF",
            "comparison_timestamp": datetime.now().isoformat(),
            "metrics": {
                "detection_accuracy": {
                    "dtarf": current["detection"]["accuracy_pct"],
                    "multi_layered_sem": "78.5%",
                    "elk_siem": "82.3%",
                    "snort_nids": "85.1%",
                    "target": f"{self.target_accuracy * 100:.1f}%"
                },
                "mttr_ms": {
                    "dtarf": current["response"]["mttr_ms"],
                    "multi_layered_sem": 2500,
                    "elk_siem": 1800,
                    "snort_nids": 950,
                    "target": self.target_mttr_ms
                },
                "false_positive_rate": {
                    "dtarf": current["detection"]["false_positive_rate"],
                    "multi_layered_sem": 0.15,
                    "elk_siem": 0.12,
                    "snort_nids": 0.18,
                    "target": 0.05
                },
                "forensic_readiness": {
                    "dtarf": "SHA-256 chain of custody with immutable ledger",
                    "multi_layered_sem": "Basic log storage",
                    "elk_siem": "Elasticsearch indices (mutable)",
                    "snort_nids": "PCAP files only"
                },
                "threat_intelligence": {
                    "dtarf": "Multi-feed IOC correlation (AbuseIPDB, OTX)",
                    "multi_layered_sem": "Manual IOC lookup",
                    "elk_siem": "Threat Intel plugin (limited)",
                    "snort_nids": "Rule-based signatures only"
                },
                "response_automation": {
                    "dtarf": "Playbook-based autonomous response",
                    "multi_layered_sem": "Manual response",
                    "elk_siem": "Limited webhook actions",
                    "snort_nids": "Inline blocking only"
                }
            }
        }
