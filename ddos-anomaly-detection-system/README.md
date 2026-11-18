# DDoS Anomaly Detection System (`ddos_ads`)

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests Passing](https://img.shields.io/badge/tests-63%20passed-brightgreen.svg)](#test-suite)
[![Architecture: Hybrid Dual-Path](https://img.shields.io/badge/architecture-hybrid%20dual--path-orange.svg)](#why-this-architecture)

An enterprise-grade, dual-path Network Security and Machine Learning system engineered to detect, benchmark, and monitor Distributed Denial-of-Service (DDoS) traffic across both offline flow-based benchmark modeling and live packet-level streaming detection.

---

## 📖 1. Project Explanation & Executive Overview

### The Problem: Academic Benchmarks vs. Real-World Failure
In academic network security literature, supervised Machine Learning (ML) models trained on flow-based benchmark datasets (such as **CIC-DDoS2019**) routinely report near-perfect classification metrics, frequently boasting ROC-AUC and PR-AUC scores above $0.999$. However, when these models are deployed in live production networks or transferred into empirical traffic environments, they suffer catastrophic failures:
1. **The Single-Packet Flow Blind Spot:** Traditional flow extractors (e.g., CICFlowMeter, Argus, Zeek) aggregate packets into bidirectional flows keyed on the 5-tuple `(Source IP, Source Port, Destination IP, Destination Port, Protocol)`. When an attacker launches a spoofed TCP SYN flood or randomized UDP flood, each packet uses a distinct source IP and ephemeral port. Standard extractors classify each packet as an independent, uncompleted flow and **hold it in memory for up to 120 seconds** awaiting flow termination or an inactivity timeout before exporting statistical features. By the time the flow is exported and scored by an ML model, server kernel connection tables are saturated and services have collapsed.
2. **Cross-Day Distribution Shift:** Operating thresholds calibrated on Day 1 training data collapse when applied to Day 2 traffic, causing false positive rates (FPR) to spike from $<0.02\%$ to over **$43\%$** across uncalibrated models.
3. **Extractor Vulnerabilities & Artifacts:** Statistical features derived from third-party flow extractors frequently contain subtle implementation bugs (e.g., packet payload truncation, microsecond vs. millisecond scaling inconsistencies, and flag-column alignment shifts) that mislead classifiers.

### The Solution: An Empirical Dual-Path Architecture
This project resolves the operational gap by implementing a **hybrid dual-path architecture**:
- **Fast Path (Packet-Level Streaming Engine):** Directly inspects raw wire datagrams with sub-microsecond latency. Tracks stateful TCP connection handshakes, enforces single-destination volumetric rate limits, monitors stateless SYN arrival counters, and detects multi-port reconnaissance scans in real time.
- **Deep Path (Statistical Flow Analytics):** Extracts bidirectional flow vectors across a robust 14-feature invariant subset, enabling forensic analysis, traffic profiling, and secondary machine learning classification without delaying immediate mitigation.

---

## 🛠️ 2. Technology Stack & Technical Choices

| Component / Layer | Technology | Primary Role & Architectural Rationale |
| :--- | :--- | :--- |
| **Core Language** | **Python 3.10+** (tested on 3.11 & 3.13) | Standardized runtime for rapid algorithm iteration, scikit-learn integration, PyTorch modeling, and asynchronous streaming concurrency. |
| **Deep Sequence Modeling** | **PyTorch 2.15** | Implements the Long Short-Term Memory (LSTM) sequence classifier with custom temporal window generators (`Length=10, Step=5`) and BCEWithLogits loss. |
| **Tabular ML & Analytics** | **Scikit-Learn 1.9** & **NumPy / Pandas** | Powers Random Forest ensembles with balanced class weighting, K-Nearest Neighbors (KNN), data cleaning, chronological time-splits, and ROC/PR metric computation. |
| **Packet Capture & Dissection** | **`tshark` / `dumpcap` & Scapy 2.8** | Low-overhead wire capture via standard pipes and Scapy dissectors for packet-level header analysis (TCP flags, timestamps, port distributions). |
| **Flow Feature Extractor** | **SimpleFlowMeterV4 / Java CICFlowMeter** | Custom-audited flow extraction engine. Rectified upstream payload truncation and Backward IAT scaling bugs to ensure absolute feature consistency. |
| **Operational Telemetry UI** | **Streamlit 1.67** | Zero-lockout monitoring dashboard connected via read-only SQLite URIs (`mode=ro`) with WAL concurrency, timeline charts, and watchdog alerts. |
| **Embedded Database** | **SQLite 3 (WAL Mode)** | High-throughput, concurrent append-only event logging with sub-millisecond query recovery and zero database locking during active replays. |
| **API Serving Layer** | **FastAPI & Uvicorn** | Asynchronous REST API providing `/health`, `/score`, and `/alerts` endpoints with 503 circuit-breaker guards when models are unloaded. |
| **Verification & Testing** | **Pytest 9.2 & Typeguard** | 63 automated tests covering model training smoke tests, chronological leakage guards, streaming parity, and dashboard read-only enforcement. |
| **Document Generation** | **LibreOffice (Headless) & Matplotlib** | Generates verified, reproducible 27-page academic reports (PDF & DOCX) and 11 widescreen vector presentation slides with zero external cloud dependencies. |

---

## 🏛️ 3. Why I Made This Architecture: Design Rationale & Deep Dive

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

### 3.1 The Fast Path: Packet-Level Streaming Rules
Because single-packet floods cannot wait for flow aggregation, the system implements dedicated packet heuristics:
1. **Stateful TCP Handshake Tracking:**
   - Tracks incoming connection states `(Source IP, Source Port, Destination IP, Destination Port)`.
   - Pure SYNs enter an `INCOMPLETE` state. Completing SYN-ACK or ACK transitions the state to `COMPLETED` and purges it from the table.
   - If no completing handshake packet arrives within **2.0 seconds** (calibrated against empirical RTT $<200\text{ ms}$), the entry transitions to `TIMEOUT_EXPIRED`.
   - **Condition A (Volumetric Flood):** Triggers if unacknowledged expired handshakes in a 1.0 s sliding window $> 100$.
   - **Condition B (Low-Rate / Mixed Exhaustion):** Triggers if expired handshakes $> 20$ AND incomplete-to-total ratio $> 0.80$.
2. **Reconnaissance Port Scan Classifier:**
   - Detects when a single source IP contacts $\ge 15$ distinct destination ports within 1.0 s with incomplete handshakes, classifying the event as `ALERT_SCAN` rather than misidentifying it as a SYN flood.
3. **Stateless Volumetric UDP Rule:**
   - Connectionless UDP cannot track handshakes. The detector monitors per-destination packet arrival rates in a 1.0 s window, triggering at **$> 40\text{ pps}$** (calibrated against benign bursts of $6.2\text{ pps}$, providing a $6\times$ safety margin).
4. **Stateless SYN Arrival Rate Rule (`ALERT_SYN_RATE`):**
   - Resolves state-table starvation under high-rate floods ($\ge 20,000\text{ pps}$). Evaluates raw SYN arrival volume without allocating table entries:
     - Multi-Source: $>150\text{ unacked SYNs/s}$ with $\ge 3$ distinct sources.
     - Single-Source: $>1,500\text{ unacked SYNs/s}$ from a single source.
     - Per-Source ACK Credit: Completing ACKs only credit the specific source IP's SYN count, preventing benign traffic from masking concurrent floods.
     - Keep-First Semantics: Table entries retain the timestamp of the first SYN, preventing port collisions from resetting expiration timers.

### 3.2 The Deep Path: Flow Modeling & Sequence Ablation
- **Robust 14-Feature Invariant Subset:** All single-bit transport flag headers (FIN, SYN, RST, PSH, ACK, URG) were eliminated from model inputs due to extractor alignment bugs. The models rely strictly on conserved physical invariants (packet lengths, flow duration, inter-arrival times, and segment sizes).
- **Sequence Order Invariance (Shuffle Test):** Ablation testing proved that shuffling flow order within 10-flow LSTM windows yielded an ROC-AUC of $0.9996$ vs $0.9997$ ordered ($\Delta < 0.0002$). This demonstrated that recurrent models act as multivariant pooling smoothers rather than sequence decoders, enabling low-cost window-summary MLP baselines to match LSTM performance.

### 3.3 Safety & Operational Boundaries
1. **Passive Sensor Default (Alert-Only):** The streaming engine operates strictly in **ALERT-ONLY** mode by default. Packet filtering via `nftables` or `iptables` is disabled and hardcoded strictly for dry-run logging. Zero routing modifications or packet drops occur on host interfaces.
2. **Read-Only Dashboard Isolation:** The Streamlit dashboard accesses telemetry databases via `file:...mode=ro` SQLite URIs. It contains zero subprocess execution, zero database write queries, and zero active defense triggers.
3. **Isolated Lab Subnets:** All live replay and network generation testing is conducted inside isolated private network subnets (`172.20.0.0/16`). Traffic generators are only aimed at the isolated `172.20.0.0/16` network, never at public or third-party systems.
4. **Scope Note on Reflection Amplification:** Reflection amplification scenario: pre-registered in the Session 3 plan but not run. The reflector container named in the plan was never provisioned in `docker-compose.yml` (a planning error), and the traffic generator implements no reflection logic. The scenario would have run on the internal-only lab network. Source: `lab/docker-compose.yml` and the "not run" rows of `results/tables/table_s3_b_per_repeat.md`. Status: **NOT RUN**.

---

## 🚀 4. How to Use This System: Step-by-Step Guide

### 4.1 Prerequisites & Installation
Ensure you have Linux (x86_64), Python 3.10+, and Wireshark/tshark installed:

```bash
# Ubuntu / Debian prerequisites
sudo apt-get update && sudo apt-get install -y tshark sqlite3 libreoffice

# Clone the repository
cd ddos-anomaly-detection-system

# Create virtualenv and install all dependencies
make setup
```

### 4.2 Running the Full Verification Test Suite
Execute the comprehensive 63-test suite covering unit logic, feature alignment, read-only safety, and streaming parity:

```bash
make test
# Or directly via pytest:
.venv/bin/pytest tests/
```

### 4.3 Data Preprocessing & Leakage Guards
Cleans raw CIC-DDoS2019 CSVs, purges 88.4% duplicate records, removes network identifiers (IPs/ports), applies chronological time-splits, fits `StandardScaler` strictly on Train, and builds sliding sequence windows:

```bash
make preprocess
```

### 4.4 Model Training
Train all supervised models sequentially or individually:

```bash
# Train Random Forest, KNN, and LSTM models
make train

# Or train individually:
make train_rf    # Outputs models/rf.joblib
make train_knn   # Outputs models/knn.joblib
make train_lstm  # Outputs models/lstm.pt
```

### 4.5 Offline Benchmark Evaluation
Evaluates trained models across same-day holdout and unseen cross-day partitions, searching for operating thresholds meeting target FPR ($\le 1\%$):

```bash
make evaluate
```
*Outputs: `results/metrics.json`, `results/roc_curves.png`, `results/pr_curves.png`, and `results/cross_day_roc.png`.*

### 4.6 Authoritative Table Generation & Anti-Tamper Enforcement
Generates all authoritative benchmark tables in `results/tables/*.md` and asserts exact per-cell numerical grounding:

```bash
make report
```
*If any cell in `results/tables/*.md` or `results/session3_evaluation.json` differs by even 0.001 s, `make report` immediately halts with an `AssertionError` naming the modified cell.*

### 4.7 Real-Time Streaming Detection & Live Replay
Empirical evaluation captures recorded during Session 3 are located in `lab/captures/session3/`.

#### Replay Parity Verification
Verify streaming engine parity across all 40 captures against frozen ground truth:
```bash
.venv/bin/python3 scripts/evaluate_phase7_parity.py
```
*Expected: 40/40 passed (0 failed), max delay diff $\le 0.25\text{ s}$, alerted-second diff $= 0\text{ s}$.*

#### Live Replay Examples
Replay individual attack PCAPs through the streaming supervisor:

```bash
# Method A: Direct module invocation (built-in)
.venv/bin/python3 -m ddos_ads.live_packet_detector \
    --replay-pcap lab/captures/session3/session3_tcp_syn_flood_200pps_rep1.pcap \
    --pace 1.0

# Method B: Convenience script wrapper
# 1. Replay a 200 pps TCP SYN Flood
.venv/bin/python3 scripts/replay_pcap_live.py \
    --pcap lab/captures/session3/session3_tcp_syn_flood_200pps_rep1.pcap \
    --pace 1.0

# 2. Replay a 50 pps Volumetric UDP Flood
.venv/bin/python3 scripts/replay_pcap_live.py \
    --pcap lab/captures/session3/session3_udp_flood_random_ports_50pps_rep1.pcap \
    --pace 1.0

# 3. Replay a 30 pps Reconnaissance Port Scan
.venv/bin/python3 scripts/replay_pcap_live.py \
    --pcap lab/captures/session3/session3_reconnaissance_port_scan_30pps_rep1.pcap \
    --pace 1.0
```

### 4.8 Interactive Monitoring Dashboard
Launch the Streamlit web dashboard to observe real-time telemetry, threat gauges, and watchdog banners:

```bash
make dashboard
# Or run directly:
.venv/bin/streamlit run src/ddos_ads/dashboard.py --server.port 8501
```
Open your browser at `http://localhost:8501`.
- **Live Threat Telemetry:** Real-time timelines of incomplete handshakes, arrival rates, and UDP volume.
- **Threat State Indicator:** Instant visual alerts for `NORMAL`, `ALERT_SYN_FLOOD`, `ALERT_UDP_FLOOD`, and `ALERT_SCAN`.
- **DETECTOR BLIND Watchdog:** Full-screen red banner alerting operators if the capture supervisor stalls for $>5.0$ seconds.

### 4.9 REST API Inference Service
Start the FastAPI batch-inference service:

```bash
make api
```
- `GET /health`: Health status and loaded model confirmation.
- `POST /score`: Submit flow batches for immediate inference (returns 503 if models are not loaded).
- `GET /alerts`: Query recent alert records from the SQLite database.

### 4.10 Generating Comprehensive Reports and Slide Decks
Regenerate the publication-grade 27-page academic report and widescreen presentation slide deck:

```bash
# Generate results/report.pdf and results/report.docx
.venv/bin/python3 scripts/generate_final_report.py

# Generate results/presentation_slides.pdf (11 vector slides)
.venv/bin/python3 scripts/generate_slides.py
```

---

## 📊 5. Empirical Evaluation Results Summary

Across 40 independent evaluation captures recorded during Session 3:

| Attack Scenario | Offered Rates Evaluated | Target Criteria | Empirical Recall | Mean Detection Latency | Ground Truth Validation |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **TCP SYN Floods** | 50, 200, 1000, 5000 pps | Recall 100%, Delay $\le 5.0\text{ s}$ | **12 / 12 (100%)** | **2.13 s** (max: 2.42 s at 50 pps) | Verified (`table_s3_b_per_repeat.md`) |
| **Volumetric UDP Floods** | 50 to 20,000 pps | Recall 100%, Delay $\le 1.0\text{ s}$ | **24 / 24 (100%)** | **0.28 s** (max: 0.80 s at 50 pps) | Verified (`table_s3_b_per_repeat.md`) |
| **TCP Port Scans** | 10, 30, 100 pps | Classified as `ALERT_SCAN` | **3 / 3 (100%)** | **2.44 s** | Verified (`table_s3_b_per_repeat.md`) |
| **Benign Baseline** | Concurrent HTTP, DNS, NTP, RTP stream | FPR $\le 0.1\%$ | **0 False Alarms** | **0.00% empirical FPR** (95% CI bound: 0.33%) | Verified across 900 s baseline |

---

## 📂 6. Repository Layout & File Index

```text
ddos-anomaly-detection-system/
├── checksums.sha256                    # Authoritative SHA-256 release manifest (112 assets)
├── Makefile                            # Top-level automation targets (setup, test, report, live)
├── pyproject.toml / requirements.txt   # Python dependency specifications
├── config.yaml                         # Global system configuration (thresholds, paths, database)
├── src/ddos_ads/                       # Production detection engine & application source
│   ├── rule_engine.py                  # Core packet streaming rules (TCP handshake & UDP counters)
│   ├── live_packet_detector.py         # Asynchronous supervisor loop and circular packet buffer
│   ├── dashboard.py                    # Streamlit read-only monitoring interface
│   ├── mitigation.py                   # Hardcoded dry-run firewall response manager
│   ├── report.py & table_validator.py  # Report generator and per-cell table consistency validator
│   ├── features.py                     # 25-feature and robust 14-feature invariant definitions
│   └── models.py                       # Random Forest, KNN, and PyTorch LSTM architectures
├── results/                            # Authoritative benchmarks and generated publications
│   ├── report.pdf                      # Comprehensive 27-page academic evaluation report
│   ├── report.docx                     # Editable Word version of the final report
│   ├── presentation_slides.pdf         # 11-slide widescreen presentation deck
│   ├── metrics.json                    # Primary frozen benchmark evaluation ground truth
│   ├── session3_evaluation.json        # Primary frozen empirical capture ground truth
│   ├── figures/                        # Dashboard verification screenshots & figure manifests
│   └── tables/                         # Script-generated markdown benchmark tables
│       ├── table_claims.md             # Full claim-to-evidence traceability audit (21 claims)
│       └── table_s3_b_per_repeat.md    # Exhaustive per-run empirical evaluation results
├── lab/                                # Empirical evaluation environment and captures
│   ├── docker-compose.yml              # Lab container topology (victim, client, bridge network)
│   └── captures/session3/              # 40 canonical evaluation PCAPs and session3_pcaps.sha256
├── demo/                               # Demonstration script & screen recording storyboard
│   └── demo_script.md                  # Replay walkthrough, tamper test demo, and screen plan
├── scripts/                            # Standalone reproduction and report rendering utilities
│   ├── generate_final_report.py        # Programmatic builder for report.pdf and report.docx
│   ├── generate_slides.py              # Programmatic builder for presentation_slides.pdf
│   ├── build_claims_table.py           # Programmatic builder for table_claims.md
│   ├── evaluate_phase7_parity.py       # Replay parity evaluator across 40 Session 3 PCAPs
│   └── run_parity_mutations.py         # 5 parameter mutation sensitivity tests
└── tests/                              # Comprehensive test suite (63 unit & integration tests)
    ├── test_dashboard_readonly.py      # Verifies strict read-only SQLite URI and zero write queries
    ├── test_live_packet_detector_parity.py # Verifies parity against session3_evaluation.json
    └── test_table_cell_grounding.py    # Verifies table cells match exact JSON keys
```

---

## ⚖️ 7. Ethics & Legal Compliance Notice

```text
================================================================================
                    ETHICAL & LEGAL COMPLIANCE NOTICE
This software is intended strictly for educational, defensive, and authorized
security research on networks and systems you own or have explicit written
permission to audit. Unauthorized sniffing, packet injection, or disruption of
network communications violates international computer crime laws.
================================================================================
```
