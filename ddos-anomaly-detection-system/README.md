# DDoS Anomaly Detection System (`ddos_ads`)

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests Passing](https://img.shields.io/badge/tests-29%20passed-brightgreen.svg)](#test-suite)

An enterprise-grade Machine Learning and Network Security system designed to detect, benchmark, and mitigate Distributed Denial-of-Service (DDoS) traffic using the **CIC-DDoS2019** dataset across three complementary architectures:
- **Random Forest** (Tree ensemble with balanced class weights)
- **K-Nearest Neighbors (KNN)** (Distance-weighted memory-efficient local boundary classifier)
- **Long Short-Term Memory (LSTM)** (Deep sequence model capturing temporal window dynamics in PyTorch)

---

## 🏛️ System Architecture

```text
                               +-----------------------------+
                               |     Raw Network Traffic     |
                               | (CIC-DDoS2019 CSV / tshark) |
                               +--------------+--------------+
                                              |
                                              v
+-----------------------------------------------------------------------------------------+
|                                Data Processing & Alignment                              |
|                                                                                         |
|  +--------------------+    +--------------------+    +-------------------------------+  |
|  | Chunked Ingestion  | -> | Column Alignment & | -> | Leakage Guards & Chronological|  |
|  | & Inf/NaN Cleaning |    | Zero-Fill Mapping  |    | Train/Val/Test Splits         |  |
|  +--------------------+    +--------------------+    +-------------------------------+  |
+---------------------------------------------+-------------------------------------------+
                                              |
                       +----------------------+----------------------+
                       |                                             |
                       v                                             v
         +---------------------------+                 +---------------------------+
         |     Tabular Modeling      |                 |     Sequence Modeling     |
         |  - StandardScaler Fit     |                 |  - Sliding Windows (N=10) |
         |  - Correlation Pruning    |                 |  - Temporal Isolation     |
         |  - RF Top-25 Selection    |                 |  - PyTorch TensorDatasets |
         +-------------+-------------+                 +-------------+-------------+
                       |                                             |
         +-------------+-------------+                               |
         |                           |                               |
         v                           v                               v
+-----------------+         +-----------------+             +-----------------+
|  Random Forest  |         |   KNN Tuning    |             |  PyTorch LSTM   |
| (Class-Weighted)|         | (Val F1 Search) |             |(BCEWithLogits)  |
+--------+--------+         +--------+--------+             +--------+--------+
         |                           |                               |
         +---------------------------+-------------------------------+
                                     |
                                     v
+------------------------------------+----------------------------------------------------+
|                               Operational Interfaces                                    |
|                                                                                         |
|  +-------------------------+   +-------------------------+   +-----------------------+  |
|  |     FastAPI Service     |   |   Live Detector Loop    |   |  Streamlit Dashboard  |  |
|  |  GET /health            |   |  - Passive Alert-Only   |   |  - Real-Time Timeline |  |
|  |  POST /score (503 Guard)|   |  - Opt-In nftables Drop |   |  - Metric Comparisons |  |
|  |  GET /alerts            |   |  - Whitelist Protection |   |  - Audit Event Tables |  |
|  +-------------------------+   +-------------------------+   +-----------------------+  |
+-----------------------------------------------------------------------------------------+
```

---

## 🛡️ Safety & Mitigation Philosophy

1. **Passive Sensor Default**: The live engine operates strictly in **ALERT-ONLY** mode by default. Packet filtering via `nftables` remains simulated (dry-run mode).
2. **Whitelist Alerting Integrity**: The whitelist **only suppresses active packet dropping**; it never suppresses logging or alerting. Suspicious activity from internal infrastructure is always recorded to `logs/detections.csv` and `logs/detections.db`.
3. **Mandatory Infrastructure Protection**: Localhost (`127.0.0.1`, `::1`), default gateways, and system DNS resolvers (`/etc/resolv.conf`) are dynamically resolved and protected from accidental blocking.
4. **RFC 1918 Exemption Toggle**: Private subnet exemptions (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) are controlled via `mitigation.exempt_rfc1918` (default: `false`).
5. **Kernel Rule Auto-Expiration**: All dropped IP rules are applied as dynamic set elements with kernel timeouts (default: `3600s`) to prevent indefinite isolation.
6. **Graceful Teardown**: Interruption via `SIGINT` (Ctrl+C) automatically flushes all temporary `nftables` chains and tables.

---

## 📦 Quickstart & Installation

### Requirements
- Linux (Ubuntu/Debian, Fedora, Kali, or Arch)
- Python 3.10+
- `tshark` (Wireshark packet capture CLI)
- `nftables` (Linux kernel firewall, optional for active mitigation)

```bash
# Clone the repository
cd ddos-anomaly-detection-system

# Create virtualenv and install dependencies
make setup

# Run the complete test suite (29 unit & integration tests)
make test

# Verify all model trainers on isolated synthetic data
make smoke
```

---

## 💾 Dataset Acquisition (CIC-DDoS2019)

The project utilizes the [UNB Canadian Institute for Cybersecurity DDoS 2019 dataset](https://www.unb.ca/cic/datasets/ddos-2019.html).

### Method A: Manual Download (Official Source)
1. Register and request access at the official UNB portal:
   `https://www.unb.ca/cic/datasets/ddos-2019.html`
2. Download the Day 1 (`01-12`) and Day 2 (`03-11`) CSV flow files.
3. Place the CSVs into `data/raw/`.
4. Validate and generate `manifest.json`:
   ```bash
   make download
   ```

### Method B: Kaggle API / Mirror
1. Configure your Kaggle credentials (`~/.kaggle/kaggle.json` or `KAGGLE_USERNAME` / `KAGGLE_KEY`).
2. Update the `download.kaggle_dataset_slug` in `config.yaml` with your verified mirror.
3. Run:
   ```bash
   python -m ddos_ads.download_data --source kaggle
   ```

*Note: The uncompressed dataset requires approximately 10–15 GB of disk space.*

---

## 🚀 Execution Pipeline

### 1. Preprocessing & Leakage Guards
Cleans infinite values, normalizes labels, removes 5-tuple identifier features, performs correlation pruning (> 0.95), ranks features with Random Forest (top 25), applies chronological time-splits, fits `StandardScaler` strictly on Train, and builds LSTM windows:
```bash
make preprocess
```

### 2. Model Training
Train all three models sequentially or individually:
```bash
# Train all models
make train

# Or train individually:
make train_rf    # Outputs models/rf.joblib
make train_knn   # Outputs models/knn.joblib
make train_lstm  # Outputs models/lstm.pt
```
*Note: Any script can be tested without data via `--smoke-test`.*

### 3. Comprehensive Evaluation
Evaluates all trained models on same-day and cross-day test splits, searches for operating thresholds meeting target FPR ($\le 1\%$), and generates publication-quality plots:
```bash
make evaluate
```
Outputs:
- `results/metrics.csv` & `results/metrics.json`
- `results/roc_curves.png`
- `results/pr_curves.png`
- `results/model_comparison.png`

### 4. Real-Time Detection & Mitigation
Capture traffic on an interface (e.g., `eth0`), convert to flows, and score in real time:
```bash
# Run in default passive alert-only mode
make live

# Run with dry-run mitigation simulation
python -m ddos_ads.live_detector --interface eth0 --dry-run

# Run live monitor (alert-only, dry-run simulated mitigation)
python -m ddos_ads.live_detector --interface eth0
```

### 5. Serving REST API
Start the FastAPI inference service:
```bash
make api
```
Endpoints:
- `GET /health`: Health status and loaded model confirmation.
- `POST /score`: Submit flow batches for immediate inference (returns 503 if models are not trained).
- `GET /alerts`: Fetch recent detection records from the SQLite database.

### 6. Interactive Monitoring Dashboard
Launch the Streamlit web dashboard:
```bash
make dashboard
```
Accessible at `http://localhost:8501`. Displays live flow rate timelines, anomaly probability distributions against decision thresholds, blocked IP tables, and offline benchmark comparisons.

---

## ⚠️ System Limitations & Research Caveats

- **Domain Gap & Dataset Age**: CIC-DDoS2019 was collected in a controlled testbed in 2019. Modern multi-vector DDoS attacks (e.g., encrypted HTTPS/QUIC floods, carpet-bombing, reflective DNS/NTP with randomized payload structures) may exhibit distribution shifts.
- **Tooling Differences**: CICFlowMeter flow generation algorithms may exhibit slight statistical differences across operating systems or Java/Python versions. The system includes an automated fuzzy alignment and zero-fill mapper to mitigate schema discrepancies.
- **Lab Testing**: It is strongly recommended to test active mitigation in a staged virtual network or testbed prior to deployment on production networks.

---

## ⚖️ Ethics & Legal Disclaimer

```text
================================================================================
                    ETHICAL & LEGAL COMPLIANCE NOTICE
This software is intended strictly for educational, defensive, and authorized
security testing purposes on networks and systems you own or have explicit
written permission to audit. Unauthorized sniffing, interception, or disruption
of network communications violates international computer crime laws.
================================================================================
```
