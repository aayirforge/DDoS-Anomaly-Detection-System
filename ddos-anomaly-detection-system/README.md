# DDoS Anomaly Detection System (`ddos_ads`)

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests: 71 Passed](https://img.shields.io/badge/tests-71%20passed-brightgreen.svg)](#option-3-run-the-71-safety-checks-automated-tests)
[![Architecture: Hybrid Dual-Path](https://img.shields.io/badge/architecture-hybrid%20dual--path-orange.svg)](#8-behind-the-scenes-how-the-pieces-fit-together)
[![UI: Wireshark Stream](https://img.shields.io/badge/ui-wireshark%20live%20packet%20stream-blueviolet.svg)](#option-2-web-browser-mode-visual-dashboard)

An enterprise-grade, dual-path Network Security and Machine Learning system engineered to detect, benchmark, and monitor Distributed Denial-of-Service (DDoS) traffic across both offline flow-based modeling and live packet-level streaming detection.

---

## 📑 Table of Contents
1. [What is DDoS ADS? (The 60-Second Explanation)](#1-what-is-ddos-ads-the-60-second-explanation)
2. [Why DDoS ADS is Special (Why It's Better & Unique)](#2-why-ddos-ads-is-special-why-its-better--unique)
3. [Simple Comparison: Traditional Flow Meters vs. Naive ML vs. DDoS ADS](#3-simple-comparison-traditional-flow-meters-vs-naive-ml-classifiers-vs-ddos-ads)
4. [How Does It Work? (Real-World Analogies)](#4-how-does-it-work-real-world-analogies)
5. [How to Run It Right Now (Step-by-Step Guide)](#5-how-to-run-it-right-now-step-by-step-guide)
   - [Step 1: Setup It Up (Takes 5 Seconds)](#step-1-setup-it-up-takes-5-seconds)
   - [Option 1: Terminal Mode (Live Detector in the Shell)](#option-1-terminal-mode-live-detector-in-the-shell)
   - [Option 2: Web Browser Mode (Visual Dashboard)](#option-2-web-browser-mode-visual-dashboard)
   - [Option 3: Run the 71 Safety Checks (Automated Tests)](#option-3-run-the-71-safety-checks-automated-tests)
   - [Option 4: Run the Speed Tests (Benchmarks & Latency Evaluations)](#option-4-run-the-speed-tests-benchmarks--latency-evaluations)
   - [Option 5: Run the 1-Minute Automated Demo](#option-5-run-the-1-minute-automated-demo)
6. [Try It Yourself: 30-Second Hands-On Example](#6-try-it-yourself-30-second-hands-on-example)
7. [How Fast is It? (Real-World Numbers)](#7-how-fast-is-it-real-world-numbers)
8. [Behind the Scenes: How the Pieces Fit Together](#8-behind-the-scenes-how-the-pieces-fit-together)
9. [Detailed Guides for Developers & Engineers](#9-detailed-guides-for-developers--engineers)

---

## 1. What is DDoS ADS? (The 60-Second Explanation)

**DDoS ADS (Anomaly Detection System)** is a real-time cybersecurity defense framework designed to catch Distributed Denial-of-Service attacks as they hit the wire, without choking server resources or suffering from false alarms.

### The Problem: Why Academic AI Fails in the Real World
In academic research papers, Machine Learning (ML) models trained on benchmark datasets (such as **CIC-DDoS2019**) boast near-perfect accuracy ($>99.9\%$). But when deployed onto live production servers, they almost immediately fail:
1. **The 120-Second Flow Trap:** Traditional network tools (like CICFlowMeter or Zeek) bundle packets into bidirectional "flows" identified by `(Source IP, Source Port, Destination IP, Destination Port, Protocol)`. When an attacker sends spoofed TCP SYN or UDP floods with randomized ports, each packet is treated as a brand new conversation and **held in memory for up to 120 seconds** waiting for the connection to finish. By the time the flow is exported and analyzed by an AI model, the server's connection tables are saturated and the server has crashed.
2. **The 43% False Alarm Collapse:** Models trained on Monday's network traffic often experience a catastrophic spike in False Positive Rates (jumping from $<0.02\%$ to over **$43\%$**) when applied to Tuesday's normal traffic due to subtle network timing variations.
3. **Extractor Vulnerabilities:** Misaligned protocol flags in flow calculators mislead classification algorithms.

### The Solution: A Hybrid Dual-Path Architecture
DDoS ADS solves this by splitting detection into two complementary paths:
- **Fast Path (Live Packet Wire Engine):** Evaluates raw datagrams directly in microseconds. Tracks stateful TCP connection handshakes in a 2.0-second sliding window, counts volumetric UDP arrival surges, and flags port scans without waiting for flow completion.
- **Deep Path (Statistical Flow Analytics):** Uses a robust 14-feature invariant subset to extract bidirectional flows for forensic reporting, behavioral analysis, and secondary machine learning classification (Random Forest, KNN, and PyTorch LSTM).

---

## 2. Why DDoS ADS is Special (Why It's Better & Unique)

- ⚡ **Sub-Second Live Detection (0.28s – 2.13s):** While traditional flow tools wait up to 120 seconds, DDoS ADS triggers alerts within seconds of attack onset.
- 🎯 **Zero Single-Packet Blind Spots:** Tracks incomplete TCP handshakes and stateless arrival bursts at the packet layer, catching single-packet spoofed attacks instantly.
- 🔍 **DDoS vs. Port Scan Disambiguation:** Accurately separates multi-port reconnaissance scanning (`ALERT_SCAN`) from volumetric SYN floods (`ALERT_SYN_FLOOD`).
- 🛡️ **Robust 14-Feature Invariant Set:** Throws away fragile single-bit header flags (SYN/FIN/RST/ACK) that get corrupted across different extractors, relying strictly on robust physical invariants (byte lengths, duration, segment sizes, inter-arrival times).
- 🦈 **Built-In Wireshark-Style Live Packet Monitor:** A Streamlit web dashboard featuring an authentic Wireshark-like packet stream with live display filtering (`tcp`, `udp`, IP), a real-time status bar, and click-to-inspect packet header trees.
- 🔒 **Safe & Non-Destructive by Design:** Operates in strictly **ALERT-ONLY** mode by default (no unintended iptables firewall changes), reads SQLite via `mode=ro` URIs, and strictly sandboxes subprocess calls with argument lists (never `shell=True`).
- 🚨 **Self-Aware DETECTOR BLIND Watchdog:** If packet volumes exceed kernel buffer capacity or the capture supervisor stalls, the system displays a prominent `DETECTOR BLIND` warning so security teams never mistake an overloaded sensor for calm traffic.

---

## 3. Simple Comparison: Traditional Flow Meters vs. Naive ML Classifiers vs. DDoS ADS

| Capability / Metric | Traditional Flow Meters (e.g., CICFlowMeter) | Naive Academic ML Classifiers | DDoS ADS (Hybrid Dual-Path) |
| :--- | :--- | :--- | :--- |
| **Detection Latency** | 60 – 120 seconds (flow timeout delay) | Post-hoc / batch scoring | **0.28s – 2.13s (Real-Time)** |
| **Single-Packet Spoofed Floods** | **Blind** (unexported flows held in RAM) | Severe latency or missed attacks | **100% Empirical Recall** |
| **TCP Handshake Tracking** | None (only statistical duration/bytes) | Blind to individual state transitions | **Stateful 2.0s Incomplete Table** |
| **Port Scan Recognition** | Aggregated into thousands of tiny flows | Often misclassified as volumetric flood | **Dedicated `ALERT_SCAN` Classifier** |
| **Flash Crowd Resilience** | High false positive rate on surges | Vulnerable to distribution shift (>43% FPR) | **0 False Alarms** (Table S7-I validated) |
| **Sensor Overload Awareness** | Silent packet dropping | Ignores kernel buffer health | **Automated `DETECTOR BLIND` Alert** |
| **Live Operator Interface** | Raw CSV dumps or CLI logs | Jupyter Notebook graphs | **Interactive Wireshark Web Dashboard** |

---

## 4. How Does It Work? (Real-World Analogies)

### Analogy 1: The Bouncer vs. The Accountant (Fast Path vs. Deep Path)
Imagine a busy nightclub:
- **The Bouncer (Fast Path):** Stands at the front door. If someone knocks (SYN) but runs away when greeted (no ACK), or if a suspicious group tries 50 different back doors at once (port scan), the bouncer flags them immediately. He doesn't wait 2 hours to see what happens.
- **The Accountant (Deep Path):** Sits in the back office the next morning. She analyzes the guest register, computing average stay duration, party sizes, and spending trends using statistical models and machine learning.

### Analogy 2: The Two-Way Radio Handshake (Stateful TCP Tracking)
In TCP networking, establishing a connection is like a 3-way radio check:
1. Client: *"Base, do you copy?"* (`SYN`)
2. Server: *"Copy Client, loud and clear."* (`SYN-ACK`)
3. Client: *"Roger that."* (`ACK`)

When an attacker launches a SYN flood, they send thousands of *"Base, do you copy?"* calls using fake callsigns and **never** reply with *"Roger that"*. DDoS ADS keeps a lightweight table of active handshakes. If a conversation is abandoned for more than 2.0 seconds, it transitions to expired. If expired conversations cross calibrated thresholds, an instant alert triggers.

### Analogy 3: The Security Guard's Watchdog (Detector Blind Alert)
If someone throws a smoke grenade into the guard booth, an ordinary sensor might fail silently and report "zero intruders detected." DDoS ADS has a watchdog: if packet arrival rates overwhelm kernel buffers and packets get dropped (`tshark_drops > 0`), it immediately signals `DETECTOR BLIND`. Security teams are explicitly warned that traffic was too intense to inspect cleanly.

---

## 5. How to Run It Right Now (Step-by-Step Guide)

<a id="section-41-prerequisites--installation"></a>
### Step 1: Setup It Up (Takes 5 Seconds)

Ensure Linux (Ubuntu/Debian or Kali), Python 3.10+, and capture tools are installed:

```bash
# 1. Install system prerequisites
sudo apt-get update && sudo apt-get install -y tshark sqlite3 libreoffice

# 2. Enter repository directory
cd ddos-anomaly-detection-system

# 3. Create virtual environment and install dependencies
make setup
```

> **Note on Evaluation Captures:** Large binary packet captures (`lab/captures/session3/*.pcap`) are stored in the lab archive or generated locally using `python lab/scripts/run_session3_suite.py`. On a clean repository clone without binary PCAPs, capture-dependent tests automatically skip with an informative notice while all 60 core logic, safety, and model tests continue to pass.

---

### Option 1: Terminal Mode (Live Detector in the Shell)

Replay real-world attack captures through the live streaming detector directly in your terminal:

```bash
# Replay a 200 pps TCP SYN Flood
.venv/bin/python3 scripts/replay_pcap_live.py \
  --pcap lab/captures/session3/session3_tcp_syn_flood_200pps_rep1.pcap \
  --pace 1.0

# Replay a 50 pps Volumetric UDP Flood
.venv/bin/python3 scripts/replay_pcap_live.py \
  --pcap lab/captures/session3/session3_udp_flood_random_ports_50pps_rep1.pcap \
  --pace 1.0

# Replay a 30 pps Reconnaissance Port Scan
.venv/bin/python3 scripts/replay_pcap_live.py \
  --pcap lab/captures/session3/session3_reconnaissance_port_scan_30pps_rep1.pcap \
  --pace 1.0
```

---

### Option 2: Web Browser Mode (Visual Dashboard)

Launch the interactive Streamlit monitoring dashboard:

```bash
make dashboard
# Or launch directly:
.venv/bin/streamlit run src/ddos_ads/dashboard.py --server.port 8501
```

Open your browser at **`http://localhost:8501`**. The dashboard includes two specialized views:
1. **Traffic Analysis UI:** Upload PCAP/PCAPNG files (up to 500 MB) or capture live traffic via `dumpcap`. Generates automatic threat verdicts, rate timelines, and downloadable PDF/HTML/DOCX reports.
2. **Advanced Real-Time Incident Monitor (Wireshark-Style):**
   - **Wireshark Live Packet Table:** Real-time stream showing `No.`, `Time (s)`, `Source`, `Destination`, `Protocol`, `Length`, and `Info`.
   - **Interactive Click-to-Inspect:** Click any packet row to instantly view its protocol layers (`Frame`, `Ethernet II`, `IPv4`, `TCP/UDP`, and `DDoS ADS Alert Details`) in the tree inspector below.
   - **Real-Time Display Filter:** Search instantly by protocol (`tcp`, `udp`), IP address (`172.20.0.2`), or attack type (`syn_flood`, `scan`).
   - **Wireshark Status Bar:** Live counter displaying total captured vs. displayed packets.

---

### Option 3: Run the 71 Safety Checks (Automated Tests)

Run the automated test suite covering unit logic, feature consistency, UI sandboxing, and leakage guards:

```bash
make test
# Or run directly via pytest:
.venv/bin/pytest tests/
```

- **71 / 71 passed** when evaluation PCAPs are present.
- **60 passed, 11 skipped, 0 failed** on a clean clone without binary captures.

---

### Option 4: Run the Speed Tests (Benchmarks & Latency Evaluations)

Validate empirical replay parity across all 40 Session 3 attack captures against frozen ground truth:

```bash
.venv/bin/python3 scripts/evaluate_phase7_parity.py
```
*Expected Result: 40/40 passed (0 failed), maximum detection delay difference $\le 0.25\text{ s}$, alerted-second difference $= 0\text{ s}$.*

---

### Option 5: Run the 1-Minute Automated Demo

Follow the complete demonstration storyboard in [`demo/demo_script.md`](demo/demo_script.md) to showcase live attack replay, tamper resistance verification, and report generation in under 60 seconds.

---

## 6. Try It Yourself: 30-Second Hands-On Example

Want to see the detection engine trigger an alert in pure Python? Open a Python shell:

```python
from ddos_ads.rule_engine import RuleEngine

# Initialize engine with frozen detection thresholds
engine = RuleEngine()

# Simulate 25 incomplete TCP SYN packets arriving within 1 second
alerts = []
for i in range(25):
    pkt = {
        "timestamp": 1000.0 + (i * 0.02),
        "src_ip": f"192.168.1.{i + 10}",
        "dst_ip": "172.20.0.2",
        "src_port": 10000 + i,
        "dst_port": 80,
        "flags": {"SYN": True, "ACK": False, "RST": False, "FIN": False},
        "protocol": "TCP",
    }
    alert = engine.process_packet(pkt)
    if alert:
        alerts.append(alert)

print(f"Alerts Triggered: {len(alerts)}")
if alerts:
    print(f"First Alert: {alerts[0]['alert_type']} at {alerts[0]['timestamp']}s")
```

**Output:**
```text
Alerts Triggered: 5
First Alert: ALERT_SYN_FLOOD at 1002.0s
```

---

## 7. How Fast is It? (Real-World Numbers)

Evaluated across **40 independent evaluation captures** in an isolated Docker container topology (`172.20.0.0/16`):

| Attack Scenario | Offered Rates Evaluated | Target Criteria | Empirical Recall | Mean Detection Delay | Ground Truth Verification |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **TCP SYN Floods** | 50, 200, 1,000, 5,000 pps | Recall 100%, Delay $\le 5.0\text{ s}$ | **12 / 12 (100%)** | **2.13 s** (max: 2.42s at 50 pps) | Verified (`table_s3_b_per_repeat.md`) |
| **Volumetric UDP Floods** | 50 to 20,000 pps | Recall 100%, Delay $\le 1.0\text{ s}$ | **24 / 24 (100%)** | **0.28 s** (max: 0.80s at 50 pps) | Verified (`table_s3_b_per_repeat.md`) |
| **TCP Port Scans** | 10, 30, 100 pps | Classified as `ALERT_SCAN` | **3 / 3 (100%)** | **2.44 s** | Verified (`table_s3_b_per_repeat.md`) |
| **Benign Baseline** | HTTP, DNS, NTP, RTP mix | FPR $\le 0.1\%$ | **0 False Alarms** | **0.00% empirical FPR** (95% CI: 0.33%) | Verified across 900 s baseline |

### Flash Crowd & Table Saturation Finding (Table S7-I)
Stress-testing under completing legitimate handshakes (200 ms RTT, 1,000-entry table) produced:
- **0 arrival alerts** at 500 conn/s
- **1, 2, and 2 arrival alerts** at 1,000, 2,000, and 5,000 conn/s due to brief in-flight SYN accumulation.
- Across all rates, the **stateful rule produced 0 false alarms** (even under 9,802 capacity evictions at 5,000 conn/s), and the 3-window sustained variant produced 0 false alarms with ~3 s delay.
- Streaming engine offline throughput: **42,000 to 84,000 packets per second**.

---

## 8. Behind the Scenes: How the Pieces Fit Together

```text
                               +-----------------------------+
                               |     Raw Network Ingress     |
                               | (Wire dumpcap / PCAP Replay)|
                               +--------------+--------------+
                                              |
                       +----------------------+----------------------+
                       |                                             |
                       v (Fast Path: Sub-Second)                     v (Deep Path: Statistical Flow)
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
         |  |   Streaming Supervisor  |   |    Streamlit UI (Analysis & Monitor)|  |
         |  |  - Asynchronous Queue   |   |   - Analysis Page (runs dumpcap)    |  |
         |  |  - 0.50 ms State Recover|   |   - Wireshark Table & Click Inspect |  |
         |  |  - 42k-84k pps Offline  |   |   - Advanced Page: SQLite `mode=ro` |  |
         |  |  - Passive Alert-Only   |   |   - Automated DETECTOR BLIND Banner |  |
         |  +-------------------------+   +-------------------------------------+  |
         +-------------------------------------------------------------------------+
```

### Component Breakdown
1. **Packet-Level Rule Engine (`rule_engine.py`):**
   - **Condition A (Volumetric Flood):** Expired unacknowledged handshakes in 1.0s window $> 100$.
   - **Condition B (Low-Rate / Exhaustion):** Expired handshakes $> 20$ AND incomplete-to-total ratio $> 0.80$.
   - **Port Scan Rule:** Single source contacting $\ge 15$ distinct ports with incomplete handshakes.
   - **Volumetric UDP Rule:** $>40\text{ pps}$ to a single destination ($6\times$ safety margin above benign bursts).
   - **Stateless SYN Arrival Rule:** $>150\text{ unacked SYNs/s}$ multi-source, $>1,500\text{ unacked SYNs/s}$ single-source.
2. **Streaming Supervisor (`live_packet_detector.py`):** Multi-threaded ring buffer pulling packets from `dumpcap` or PCAPs, feeding the rule engine, and persisting alerts to SQLite.
3. **Database Layer (`SQLite WAL Mode`):** Concurrent write-ahead logging ensuring zero lock contention between detector writes and UI dashboard queries.
4. **Machine Learning Pipeline (`models.py` & `features.py`):** Scikit-learn Random Forest, KNN, and PyTorch LSTM operating on the robust 14-feature invariant subset.

---

## 9. Detailed Guides for Developers & Engineers

### Data Preprocessing & Leakage Guards
Cleans raw CIC-DDoS2019 CSVs, purges 88.4% duplicate records, removes network identifiers (IPs/ports), applies chronological time-splits, fits `StandardScaler` strictly on Train, and builds sliding sequence windows:
```bash
make preprocess
```

### Model Training
Train all supervised models sequentially or individually:
```bash
# Train Random Forest, KNN, and LSTM models
make train

# Or train individually:
make train_rf    # Outputs models/rf.joblib
make train_knn   # Outputs models/knn.joblib
make train_lstm  # Outputs models/lstm.pt
```

### Authoritative Table & Report Generation
Generates the authoritative 27-page academic report, widescreen slides, and markdown benchmark tables with strict anti-tamper per-cell grounding checks:
```bash
# Generate report and assert exact numerical grounding against JSON ground truth
make report

# Or generate presentation slides (11 vector slides):
.venv/bin/python3 scripts/generate_slides.py
```

### REST API Inference Service
Start the FastAPI batch-inference service:
```bash
make api
```
- `GET /health`: Health status and loaded model confirmation.
- `POST /score`: Submit flow batches for immediate inference (returns 503 if models are not loaded).
- `GET /alerts`: Query recent alert records from the SQLite database.

### Repository Layout & File Index
```text
ddos-anomaly-detection-system/
├── checksums.sha256                    # Authoritative SHA-256 release manifest (112 assets)
├── Makefile                            # Top-level automation targets (setup, test, report, live)
├── pyproject.toml / requirements.txt   # Python dependency specifications
├── config.yaml                         # Global system configuration (thresholds, paths, database)
├── src/ddos_ads/                       # Production detection engine & application source
│   ├── rule_engine.py                  # Core packet streaming rules (TCP handshake & UDP counters)
│   ├── live_packet_detector.py         # Asynchronous supervisor loop and circular packet buffer
│   ├── dashboard.py                    # Streamlit analysis UI and read-only telemetry interface
│   ├── ui_capture.py                   # Isolated subprocess wrapper for dumpcap/tshark (argument lists only)
│   ├── ui_analyzer.py                  # Pcap upload validation, streaming evaluator, and tamper digest
│   ├── ui_report.py                    # Programmatic HTML/PDF/DOCX report generator from analysis.json
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
│   ├── ui_runs/                        # Ephemeral UI run artifacts (.gitignore; clean via make clean_ui_runs)
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
│   ├── rewrite_pcaps.py                # Subnet address rewriter (172.20.0.0/16 -> 10.50.0.0/16)
│   ├── generate_unrelated_captures.py  # Synthesizes 4 unrelated traffic captures
│   └── run_parity_mutations.py         # 5 parameter mutation sensitivity tests
└── tests/                              # Comprehensive test suite (unit, safety & integration tests)
    ├── test_dashboard_readonly.py      # Verifies UI AST safety, subprocess containment, and mode=ro
    ├── test_phase10_ui.py              # Verifies upload security, command template, tamper digests, and generality
    ├── test_live_packet_detector_parity.py # Verifies parity against session3_evaluation.json
    └── test_table_cell_grounding.py    # Verifies table cells match exact JSON keys
```

---
