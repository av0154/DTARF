# main.py
"""
DTARF - Distributed Threat Analysis & Response Framework
Main Entry Point

Architecture:
┌─────────────────────────┐
│ Data Ingestion Layer    │ → Log Collector, System Telemetry, Packet Sniffer
├─────────────────────────┤
│ Core Analytics Engine   │ → Detection Engine, Threat Intelligence
├─────────────────────────┤
│ Response Orchestration  │ → Orchestrator, Action Executor
├─────────────────────────┤
│ Forensic Evidence Layer │ → Evidence Collector, Chain of Custody
├─────────────────────────┤
│ Dashboard               │ → Flask Web UI with JWT Auth
└─────────────────────────┘
"""

import os
import sys
import time
import yaml
import signal
import threading
from datetime import datetime
from collections import deque
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.resolve()
sys.path.insert(0, str(PROJECT_ROOT))

# --- Configuration ---

def load_config():
    config_path = os.path.join(PROJECT_ROOT, "config", "dtarf_config.yaml")
    if os.path.exists(config_path):
        with open(config_path, "r") as f:
            return yaml.safe_load(f)
    else:
        print(f"[!] Config not found at {config_path}, using defaults")
        return {}


class DTARFEngine:
    """
    Central DTARF Engine - orchestrates all components.
    """

    def __init__(self, config):
        self.config = config
        self._running = False

        # --- Shared queues ---
        self.event_queue = deque(maxlen=50000)      # Log events
        self.telemetry_queue = deque(maxlen=10000)   # Telemetry snapshots
        self.packet_queue = deque(maxlen=50000)      # Packet metadata
        self.alert_queue = deque(maxlen=10000)       # Alerts

        # Ensure directories exist
        for d in ["logs", "data", "evidence", "evidence/artifacts",
                   "evidence/chain_of_custody", "evidence/chain_of_custody/reports"]:
            os.makedirs(os.path.join(PROJECT_ROOT, d), exist_ok=True)

        print("[*] Initializing DTARF components...")

        # --- 1. Data Ingestion Layer ---
        from ingestion.log_collector import LogCollector
        from ingestion.system_telemetry import SystemTelemetry
        from ingestion.packet_sniffer import DTARFPacketSniffer

        ingestion_config = config.get("ingestion", {})
        self.log_collector = LogCollector(
            ingestion_config.get("log_collector", {}),
            self.event_queue
        )
        self.telemetry = SystemTelemetry(
            ingestion_config.get("system_telemetry", {}),
            self.telemetry_queue
        )
        self.sniffer = DTARFPacketSniffer(
            ingestion_config.get("packet_sniffer", {}),
            self.packet_queue
        )
        print("  ✓ Data Ingestion Layer initialized")

        # --- 2. Core Analytics Engine ---
        from core_engine.detection_engine import DetectionEngine
        from core_engine.threat_intelligence import ThreatIntelligenceEngine
        from core_engine.performance_metrics import PerformanceMetrics

        analytics_config = config.get("analytics", {})
        self.detection = DetectionEngine(analytics_config)
        self.ti_engine = ThreatIntelligenceEngine(analytics_config)
        self.metrics = PerformanceMetrics(config.get("performance", {}))
        print("  ✓ Core Analytics Engine initialized")

        # --- 3. Response Orchestration ---
        from response.orchestrator import ActionExecutor, ResponseOrchestrator

        response_config = config.get("response", {})
        self.action_executor = ActionExecutor(
            response_config.get("action_executor", {})
        )

        # --- 4. Forensic Evidence Layer ---
        from forensics.evidence_collector import EvidenceCollector
        from forensics.chain_of_custody import ChainOfCustody

        forensics_config = config.get("forensics", {})
        self.evidence_collector = EvidenceCollector(
            forensics_config.get("evidence_collector", {})
        )
        self.custody = ChainOfCustody(
            forensics_config.get("chain_of_custody", {})
        )
        print("  ✓ Forensic Evidence Layer initialized")

        # Initialize orchestrator (needs forensic engine reference)
        self.orchestrator = ResponseOrchestrator(
            response_config,
            self.action_executor,
            self.evidence_collector
        )
        print("  ✓ Response Orchestration initialized")

        # --- 5. Module Bridges ---
        from core_engine.module_bridge import APTMalwareBridge, ThresholdDetectionBridge

        ext_config = config.get("external_modules", {})
        self.apt_bridge = APTMalwareBridge(
            ext_config.get("apt_malware_module", "")
        )
        self.threshold_bridge = ThresholdDetectionBridge(
            ext_config.get("threshold_detection_module", "")
        )
        print(f"  ✓ Module Bridges initialized "
              f"(Threshold detectors: {self.threshold_bridge.get_detector_names()})")

        # --- Processing thread ---
        self._process_thread = None
        self._analysis_thread = None
        self._stop_event = threading.Event()
        self._packet_counter = 0
        self._apt_counter = 0

    def start(self):
        """Start all DTARF components."""
        self._running = True
        print("\n[*] Starting DTARF Engine...")

        # Start ingestion
        self.log_collector.start()
        self.telemetry.start()

        try:
            self.sniffer.start()
            print("  ✓ Packet sniffer started")
        except Exception as e:
            print(f"  ⚠ Packet sniffer requires admin privileges: {e}")

        # Start processing threads
        self._process_thread = threading.Thread(
            target=self._packet_processing_loop, daemon=True
        )
        self._process_thread.start()

        self._analysis_thread = threading.Thread(
            target=self._analysis_loop, daemon=True
        )
        self._analysis_thread.start()

        print("  ✓ Processing pipelines active")
        print("  ✓ DTARF Engine is running!\n")

    def stop(self):
        """Gracefully stop all components."""
        print("\n[*] Stopping DTARF Engine...")
        self._running = False
        self._stop_event.set()

        self.log_collector.stop()
        self.telemetry.stop()
        self.sniffer.stop()

        if self._process_thread:
            self._process_thread.join(timeout=5)
        if self._analysis_thread:
            self._analysis_thread.join(timeout=5)

        print("[*] DTARF Engine stopped.")

    def _packet_processing_loop(self):
        """Continuously process packets from the queue."""
        while not self._stop_event.is_set():
            try:
                while self.packet_queue:
                    pkt_type, pkt, meta = self.packet_queue.popleft()
                    self._packet_counter += 1

                    # Feed to detection engine
                    self.detection.process_packet(meta)

                    # Feed to threshold-based detectors and get alerts
                    bridge_alerts = self.threshold_bridge.process_packet(pkt_type, pkt, meta)
                    for a in bridge_alerts:
                        self.orchestrator.receive_alert(a)

                    # Immediate TI check for source/dest IPs
                    for ip in [meta.src_ip, meta.dst_ip]:
                        if ip:
                            intel = self.ti_engine.correlate_ip(ip)
                            # correlate_ip appends to ti_engine._alerts if malicious
                
                # Check for TI-generated alerts periodically
                if self._packet_counter % 100 == 0:
                    ti_alerts = self.ti_engine.get_alerts()
                    for ta in ti_alerts:
                        # Avoid duplicates
                        self.orchestrator.receive_alert(ta)

                time.sleep(0.01)
            except IndexError:
                time.sleep(0.05)
            except Exception:
                time.sleep(0.1)

    def _analysis_loop(self):
        """Periodic analysis cycle - runs detection and generates alerts."""
        while not self._stop_event.is_set():
            try:
                # Run detection engine analysis
                detection_alerts = self.detection.run_analysis_cycle()
                for alert in detection_alerts:
                    # Enrich with TI
                    enriched = self.ti_engine.enrich_alert(alert)
                    # Send to orchestrator
                    processed = self.orchestrator.receive_alert(enriched)

                    # Record metrics
                    if processed:
                        self.metrics.record_detection(
                            alert.get("type", "unknown"),
                            alert.get("severity", 50)
                        )
                        if processed.response_time_ms:
                            self.metrics.record_response_time(processed.response_time_ms)

                        # Collect forensic evidence for high-severity alerts
                        if alert.get("severity", 0) >= 70:
                            evidence = self.evidence_collector.collect_evidence(alert)
                            if evidence and evidence.get("evidence_path"):
                                self.custody.register_evidence(
                                    evidence["evidence_path"],
                                    alert_id=processed.id,
                                    collector="dtarf_engine",
                                    description=f"Auto-collected for {alert.get('type')}",
                                    evidence_type="incident_package"
                                )

                # Run APT module detection periodically
                # (less frequent as it scans files/logs)
                if hasattr(self, '_apt_counter'):
                    self._apt_counter += 1
                else:
                    self._apt_counter = 0

                if self._apt_counter % 12 == 0:  # Every ~60 seconds
                    apt_alerts = self.apt_bridge.run_detection()
                    for alert in apt_alerts:
                        self.orchestrator.receive_alert(alert)

            except Exception as e:
                pass

            time.sleep(1)  # High performance analysis - every 1 second

    # --- Summary methods for dashboard ---

    def get_alert_summary(self):
        alerts = self.orchestrator.get_alerts(count=2000)
        by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        by_status = {}
        unacknowledged = 0
        
        for a in alerts:
            lbl = a.get("severity_label", "INFO")
            by_severity[lbl] = by_severity.get(lbl, 0) + 1
            st = a.get("status", "new")
            by_status[st] = by_status.get(st, 0) + 1
            if st in ["new", "pending_review", "responding"]:
                unacknowledged += 1

        return {
            "total": len(alerts),
            "unacknowledged_count": unacknowledged,
            "by_severity": by_severity,
            "by_status": by_status,
            "recent": alerts[-10:] if alerts else []
        }

    def get_system_summary(self):
        latest = self.telemetry.get_latest()
        return {
            "telemetry": latest.to_dict() if latest else {},
            "sniffer": self.sniffer.get_stats(),
            "log_collector": self.log_collector.get_stats()
        }

    def get_performance_summary(self):
        return self.metrics.get_metrics()

    def get_ti_summary(self):
        return self.ti_engine.get_stats()

    def get_forensics_summary(self):
        return self.custody.get_stats()


def main():
    print("=" * 60)
    print("  DTARF - Distributed Threat Analysis & Response Framework")
    print("  Version 1.0.0")
    print("=" * 60)
    print()

    # Load config
    config = load_config()

    # Create engine
    engine = DTARFEngine(config)

    # Create dashboard
    from dashboard.app import create_app
    dash_config = config.get("dashboard", {})
    app = create_app(dtarf_engine=engine, config=dash_config)

    # Start engine
    engine.start()

    # Handle graceful shutdown
    def shutdown_handler(sig, frame):
        engine.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    # Start dashboard
    host = dash_config.get("host", "0.0.0.0")
    port = dash_config.get("port", 8080)

    print(f"  🌐 Dashboard: http://localhost:{port}")
    print(f"  📡 API: http://localhost:{port}/api")
    print(f"  🔑 Default login: admin / admin123")
    print(f"\n  Press Ctrl+C to stop\n")

    app.run(host=host, port=port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
