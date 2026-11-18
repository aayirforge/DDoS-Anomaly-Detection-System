# DDoS Anomaly Detection System (`ddos_ads`)

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests Passing](https://img.shields.io/badge/tests-63%20passed-brightgreen.svg)](#test-suite)

An enterprise-grade, dual-path Network Security and Machine Learning system engineered to detect, benchmark, and monitor Distributed Denial-of-Service (DDoS) traffic across both offline flow-based benchmark modeling and live packet-level streaming detection.

---

## 🏛️ System Architecture

```text
                               +-----------------------------+
                               |     Raw Network Ingress     |
                               | (Wire dumpcap / PCAP Replay)|
                               +--------------+--------------+
                                              |
                       +----------------------+----------------------+
                       |                                             |
                       v (Path 1: Sub-Second)                        v (Path 2: Statistical Flow)
         +---------------------------+                 +---------------------------+
         | Packet-Level Engine       |                 | Flow Extraction & ML      |
         | - Stateful Handshake Track|                 | - SimpleFlowMeterV4       |
         | - 2.0s Incomplete Timeout |                 | - Robust 14-Feature Subset|
         | - Conditions A & B        |                 | - Random Forest (0.999 AUC|
         | - Port Scan Classifier    |                 | - KNN Boundary Classifier |
         | - Stateless SYN Arrival   |                 | - PyTorch Sequence LSTM   |
         | - Per-Destination UDP Rate|                 |                           |
         +-------------+-------------+                 +-------------+-------------+
                       |                                             |
                       +----------------------+----------------------+
                                              |
                                              v
         +-------------------------------------------------------------------------+
         |                         Operational Interfaces                          |
         |                                                                         |
         |  +-------------------------+   +-------------------------------------+  |
         |  |   Streaming Supervisor  |   |    Streamlit Read-Only Dashboard    |  |
         |  |  - Asynchronous Queue   |   |   - Strict `mode=ro` SQLite URI     |  |
         |  |  - 0.50 ms State Recover|   |   - WAL Concurrency (Zero Lockouts) |  |
         |  |  - 42k-84k pps Offline  |   |   - Real-Time Attack Telemetry      |  |
         |  |  - Passive Alert-Only   |   |   - Automated DETECTOR BLIND Banner |  |
         |  +-------------------------+   +-------------------------------------+  |
         +-------------------------------------------------------------------------+
```

---

## 🛡️ Safety & Mitigation Boundaries

1. **Passive Sensor Default (Alert-Only):** The streaming engine operates strictly in **ALERT-ONLY** mode by default. Packet filtering via `nftables` or `iptables` is disabled and configured strictly for dry-run logging. No firewall modifications or host routing table alterations occur.
2. **Read-Only Dashboard Isolation:** The Streamlit dashboard accesses telemetry databases via `file:...mode=ro` SQLite URIs. It contains zero subprocess execution, zero database write queries, and zero active defense triggers.
3. **Internal Lab Isolation:** All live replay and network generation testing is conducted inside isolated private network subnets (`172.20.0.0/16`). Traffic generators are only aimed at the isolated 172.20.0.0/16 network, never at public or third-party systems.
4. **Scope Note on Reflection Amplification:** Reflection amplification scenario: pre-registered in the Session 3 plan but not run. The reflector container named in the plan was never provisioned in docker-compose.yml (a planning error), and the traffic generator implements no reflection logic. The scenario would have run on the internal-only lab network. Source: lab/docker-compose.yml and the 'not run' rows of results/tables/table_s3_b_per_repeat.md. Status: NOT RUN.

---

## 📦 Setup & Installation

### Requirements
- Linux (Ubuntu/Debian, Kali, Arch, or Fedora on x86_64)
- Python 3.10+ (tested on Python 3.11 and 3.13)
- `tshark` / `dumpcap` (Wireshark packet capture CLI)
- SQLite 3 (with WAL support)

### Installation Steps
```bash
# 1. Clone repository and enter directory
cd ddos-anomaly-detection-system

# 2. Set up virtual environment and install dependencies
make setup

# 3. Run full verification test suite (63 unit and integration tests)
make test
```

---

## 📊 How to Regenerate Tables & Audit Manifest

All benchmark and empirical evaluation tables in `results/tables/*.md` are generated directly from primary JSON artifacts (`results/metrics.json` and `results/session3_evaluation.json`) and verified by a strict per-cell validator.

```bash
# 1. Regenerate all authoritative results tables
make report

# 2. Or regenerate individually via standalone scripts:
.venv/bin/python3 scripts/render_session3_tables.py
.venv/bin/python3 scripts/render_phase7_tables.py
.venv/bin/python3 scripts/render_all_verbatim_tables.py
.venv/bin/python3 scripts/build_claims_table.py
```

### Table Consistency & Anti-Tamper Enforcement
Running `make report` executes `ddos_ads.table_validator`. If any cell in `results/tables/*.md` or `results/session3_evaluation.json` is modified by even 0.001 s, `make report` immediately halts with an `AssertionError` identifying the exact mismatched cell and JSON key.

---

## 🔄 How to Replay Captures & Evaluate Traffic

Empirical evaluation captures recorded during Session 3 are located in `lab/captures/session3/`.

### 1. Offline Engine Parity Evaluation
To re-evaluate all 40 captures against frozen reference ground truth:
```bash
.venv/bin/python3 scripts/evaluate_phase7_parity.py
```
*Expected: 40/40 passed, 0 failed, maximum delay difference &le; 0.25 s, alerted-second difference = 0 s.*

### 2. Live PCAP Replay Through Streaming Detector
To replay an individual capture through the live packet detector:
```bash
# Example: Replay a 200 pps TCP SYN Flood
.venv/bin/python3 scripts/replay_pcap_live.py \
    --pcap lab/captures/session3/session3_tcp_syn_flood_200pps_rep1.pcap \
    --db data/detection_events.db \
    --rate-multiplier 1.0

# Example: Replay a 50 pps Volumetric UDP Flood
.venv/bin/python3 scripts/replay_pcap_live.py \
    --pcap lab/captures/session3/session3_udp_flood_50pps_rep1.pcap \
    --db data/detection_events.db \
    --rate-multiplier 1.0

# Example: Replay a 30 pps TCP Port Scan
.venv/bin/python3 scripts/replay_pcap_live.py \
    --pcap lab/captures/session3/session3_tcp_port_scan_30pps.pcap \
    --db data/detection_events.db \
    --rate-multiplier 1.0
```

---

## 🖥️ How to Run the Monitoring Dashboard

Launch the interactive web telemetry interface:
```bash
make dashboard
# Or run directly via Streamlit:
.venv/bin/streamlit run src/ddos_ads/dashboard.py --server.port 8501
```

Access the dashboard in your browser at `http://localhost:8501`.
Features:
- **Live Threat Telemetry:** Real-time timelines of incomplete handshakes, arrival rates, and UDP volume.
- **Threat State Indicator:** Instant visual alerts for `NORMAL`, `ALERT_SYN_FLOOD`, `ALERT_UDP_FLOOD`, and `ALERT_SCAN`.
- **DETECTOR BLIND Watchdog:** Prominent full-screen banner alerting operators if the capture supervisor stops emitting heartbeats for >5.0 seconds.
- **Read-Only Guarantee:** Concurrently viewable while replay or live detection is active with zero database lockups.

---

## 📑 Comprehensive Reports & Documentation

- **Academic Report (PDF):** `results/report.pdf` (27 pages, publication-formatted with embedded figures)
- **Academic Report (Word):** `results/report.docx`
- **Presentation Slide Deck:** `results/presentation_slides.pdf` (11 widescreen vector slides)
- **Presentation Deck Markdown:** `results/presentation_slides.md`
- **Claim-to-Evidence Audit:** `results/tables/table_claims.md` (19 verified empirical claims, 2 explicitly disclosed unrun scenarios)
- **Demonstration Script & Screen Recording Plan:** `demo/demo_script.md`

---

## ⚖️ Ethics & Legal Disclaimer

```text
================================================================================
                    ETHICAL & LEGAL COMPLIANCE NOTICE
This software is intended strictly for educational, defensive, and authorized
security research on networks and systems you own or have explicit written
permission to audit. Unauthorized sniffing, interception, or disruption of
network communications violates international computer crime laws.
================================================================================
```
