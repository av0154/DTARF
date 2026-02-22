# DTARF - Distributed Threat Analysis & Response Framework

## Architecture

```
┌────────────────────────────┐   ┌──────────────────────────────┐
│  Data Ingestion & Monitor  │   │    Threat Sources             │
│  ├─ Log Collector          │──▶│    (External/Internal)        │
│  ├─ System Telemetry       │   └──────────────────────────────┘
│  └─ Packet Sniffer (Scapy) │
└────────────┬───────────────┘
             │
             ▼
┌────────────────────────────────────────────────┐
│         DTARF Core Analytics Engine            │
│  ├─ Detection Engine                           │
│  │  ├─ Shannon Entropy (Hash)                  │
│  │  ├─ Statistical Anomaly Detection           │
│  │  └─ Sliding-Window Network Analysis         │
│  └─ Threat Intelligence Engine                 │
│     ├─ IOC Correlation                         │
│     ├─ MISP Feed Integration                   │
│     └─ Context Enrichment                      │
└──────────┬────────────┬────────────────────────┘
           │            │
   Detection Output     │
   ├─ Threat Scores     │
   ├─ Alerts            │
   └─ Event Class.      │
           │            │
           ▼            ▼
┌──────────────────────────────────┐  ┌──────────────────────────┐
│  Detection & Response Orch.     │  │  Forensic Evidence &     │
│  ├─ Response Orchestrator       │  │  Audit Layer             │
│  │  ├─ Alert Prioritization     │  │  ├─ Evidence Collector   │
│  │  ├─ Playbook Selection       │  │  │  ├─ Memory Artifacts  │
│  │  └─ Policy Mapping           │  │  │  ├─ Network Captures  │
│  └─ Action Executor             │  │  │  └─ Log Snapshots     │
│     ├─ Firewall Rules           │  │  └─ Chain of Custody     │
│     ├─ Container Isolation      │  │     ├─ SHA-256 Hashing   │
│     └─ IP Blacklisting          │  │     └─ Immutable Records │
└──────────────────────────────────┘  └──────────────────────────┘
```

## Modules

| Module | Description |
|--------|-------------|
| `ingestion/` | Data ingestion - log collection, system telemetry, packet sniffing |
| `core_engine/` | Detection engine + Threat intelligence engine |
| `response/` | Response orchestration + Action execution |
| `forensics/` | Evidence collection + Chain of custody (SHA-256) |
| `dashboard/` | Flask web dashboard with real-time monitoring |
| `config/` | Configuration files |
| `data/` | Threat intel feeds, IOC databases |

## External Base Modules (Not Modified)

- `e:\APT_&_Malware_Module` - APT & Malware detection (ransomware, fileless, lateral movement, exfiltration)
- `e:\threshold_based_detection` - Threshold-based network attack detection (DDoS, ARP spoofing, DNS poisoning, port scanning, ICMP flood)

## Quick Start

```bash
cd DTARF
pip install -r requirements.txt
python main.py
```

Dashboard: http://localhost:8080
