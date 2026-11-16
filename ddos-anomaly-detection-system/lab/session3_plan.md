# Session 3 Test Plan: Multi-Protocol Live Validation & Benchmark

## 1. Objectives & Scope
Session 3 evaluates detection performance under diverse, realistic multi-protocol benign traffic alongside controlled SYN and UDP flood attacks in the isolated Docker container lab. No models will be retrained; all evaluation strictly utilizes existing model checkpoints and calibration protocols.

---

## 2. Methodology & Protocols

### 2.1 Flow Extraction & Normalization
- **Primary Extractor:** Official Java CICFlowMeter v4 (offline CLI execution via `cic.cs.unb.ca.ifm.Cmd`).
- **Feature Schema & Alignment:**
  - Microsecond IAT features preserved natively without re-scaling.
  - Flag counts binarized to $\{0.0, 1.0\}$ matching `train.parquet`.
  - **Direction Inversion Rule:** Enforced for server-to-client flows (`Source IP == 172.20.0.2` or `Source Port in {80, 443}`) to ensure client-initiated orientation for bidirectional features.
  - Payload length calculation preserved (0B forward payload for pure SYN attacks).

### 2.2 Models & Detection Rules Evaluated
Session 3 will evaluate and compare three distinct tiers of detectors on the unseen Session 3 holdout:
1. **Flow-Level Anomaly Classifiers (Step-Size 5 Windows):**
   - **Champion Pre-Registered Model:** KNN Robust 14 (Log1p + Clip [-5, 5]) (Window-Max, fixed threshold = 1.0000, 0.83% Benign FPR on Session 2).
   - **Robust Window-Stats Baseline:** Window-Stats Logistic Regression on Robust 28 features (fixed threshold = 0.6261).
   - **Frozen Day 1 Reference Baselines:**
     - Random Forest Full 25 (Window-Max threshold = 0.9094, Window-Mean threshold = 0.7563).
     - KNN Full 25 Frozen Baseline (Window-Max threshold = 1.0000, Window-Mean threshold = 0.6482).
     - PyTorch LSTM Full 25 (Window-level fixed threshold in logit space = +4.8078, corresponding to $p = 0.9919$).
   - Flow models report detection recall strictly where flow records are extracted by Java CICFlowMeter; per-second real-time attack coverage is monitored via the packet rules.
2. **Packet-Level Incomplete Handshake Rule (TCP Defense):**
   - Tracks client SYN attempts where no completing final ACK is observed within $N = 2.0\text{ seconds}$ (or connection refused with RST/ACK).
   - **Condition A (Multi-Source Distributed Flood):** $\ge 15$ incomplete handshakes/s **AND** $\ge 3$ distinct incomplete source IPs/s.
   - **Condition B (Volumetric Single-Source Flood):** $\ge 50$ incomplete handshakes/s (any source count).
   - Alert-only by default; real detection delay accounts for the 2.0s completion timeout ($\Delta t_{\text{real}} \le 2.50\text{ s}$).
3. **Packet-Level UDP Flood Rule (UDP Defense):**
   - Counts incoming UDP packets (`ip.proto == 17`) per destination IP and distinct source ports in 1-second bins.
   - **Threshold:** $\text{UDP packets/s} \ge 40$ per destination IP (or $\text{UDP packets/s} \ge 30$ with $\ge 5$ distinct source ports).
   - Frozen on Session 2 benign baseline ($0\text{ pkts/s}$, 0.0% FPR). Detects UDP floods at 50, 200, 500, and 1,000 pps. Alert-only.
4. **Lab-Trained Baselines:**
   - **(a) One-Class Model (Isolation Forest):** Trained strictly on Session 2 benign traffic to detect out-of-profile traffic without attack supervision.
   - **(b) Day 1 + Session 2 Lab-Trained Classifiers (Random Forest & Logistic Regression):** Trained on combined Day 1 training data plus Session 2 lab flows to adapt tree splits to lab network artifacts.

---

## 4. Session 3 Success Criteria (Pre-Registered)

Before initiating any Session 3 live capture, the following success criteria are pre-registered:

| Evaluation Dimension | Metric Target | Evaluation Basis |
| :--- | :---: | :--- |
| **Benign False Alarm Rate (FPR)** | **$\le 1.0\%$** per-bin FPR | Evaluated across all $\ge 15$ minutes of diverse multi-protocol benign traffic (1-second bins for packet rules, step-5 windows for flow models). |
| **High-Rate Attack Recall (200, 500, 1000 pps)** | **$\ge 95.0\%$** recall | Evaluated on TCP SYN floods, UDP floods, and UDP reflection attacks across all 3 repeats. |
| **Low-Rate Attack Recall (50 pps)** | **$\ge 80.0\%$** recall | Evaluated on 50 pps attack runs across all 3 repeats. |
| **Packet-Rule Real Detection Delay** | **$\le 2.5\text{ seconds}$** | Real detection delay including the 2.0s TCP handshake completion timeout for SYN floods; $\le 1.0\text{ s}$ for UDP floods. |
| **Flow-Model Detection Delay** | **$\le 5.0\text{ seconds}$** | From first attack packet arrival to the first window alert crossing where flows exist. |

### 2.3 Traffic Generation & Composition
- **Benign Traffic Profiles ($\ge 15$ minutes total):**
  - **DNS:** Continuous domain resolutions via local bind/unbound daemon.
  - **HTTP/REST:** Concurrent short GET requests, POST data payloads, and keep-alive sessions.
  - **SSH:** Scripted interactive shell sessions and automated SFTP file transfers.
  - **UDP Echo:** Bidirectional datagram exchange with randomized payloads.
  - **Bulk HTTP:** Multi-megabyte chunked file downloads.
  - **Ping / ICMP:** Periodic diagnostic echo requests.
- **BPF Filtering:** Strict capture filter applied to eliminate multicast/broadcast noise:
  ```text
  (ip or ip6) and not multicast and not broadcast and not port 1900 and not port 5353
  ```
- **ICMP Protocol Rule (Count and Alert Only, Strictly No Dropping):**
  - CIC-DDoS2019 features and classifiers are trained strictly on transport-layer flows with IP protocols TCP ($6$) and UDP ($17$).
  - ICMP packets ($Protocol = 1$) will be handled under a strict **count-and-alert-only** policy:
    - **No Dropping:** ICMP packets will **never** be dropped, blocked, or rate-limited.
    - **Counting & Alerting:** All ICMP packets are continuously counted and monitored per source and destination. Any burst exceeding baseline (> 10 ICMP echo requests/s) triggers an audit alert logged to `logs/icmp_audit.log` with timestamp, source IP, ICMP type/code, and alert status.

---

## 3. Attack Scenarios & Experimental Matrix

### 3.1 Attack Vectors & Rates (50, 200, 500, 1,000 pps)
Each attack vector is executed across four rate tiers (50, 200, 500, and 1,000 packets per second), all strictly confined to the internal network (`internal: true`):
1. **TCP SYN Floods with Randomized Source IPs:**
   - Source IP addresses randomized across internal subnet addresses (`172.20.0.100`–`172.20.0.250`).
   - Targets `victim-web:80`.
2. **UDP Floods with Randomized Destination Ports:**
   - Destination ports randomized across ephemeral range (`1024`–`65535`).
   - Targets `victim-web`.
3. **UDP Reflection-Style Amplification Attack (Internal Reflector Container):**
   - An internal reflector container (`reflector`, `172.20.0.5`) hosts a UDP echo/query service responding with enlarged amplification payloads (e.g., 512B–1024B responses for 64B request queries).
   - Traffic generator (`172.20.0.3`) sends query requests to `reflector:5353` with the spoofed source IP set to the victim (`172.20.0.2`), inducing the reflector to reflect amplified UDP datagrams toward `victim-web`.
   - Internal-only network: strictly zero external egress.

### 3.2 Repetition, Block-Bootstrap Intervals & Statistical Rigor
- **3 Independent Repeats per Rate:** Each attack rate (50, 200, 500, 1000 pps) is executed in 3 independent, chronologically isolated runs ($\ge 60$ seconds each) separated by quiescent benign baseline periods.
- **Block-Bootstrap Confidence Intervals:**
  - Because flow and packet time-series exhibit strong temporal autocorrelation and window dependency, standard i.i.d. bootstrapping is invalid.
  - A **moving-block bootstrap** (block size $B = 10\text{ seconds}$, 2,000 resamples) will be computed across the pooled repeat windows to construct non-parametric 95% confidence intervals for:
    - Benign False Positive Rate (FPR)
    - Attack Detection Recall
    - Per-second Alert Coverage Rate
    - Detection Delay (Time-to-first-alert $\Delta t$)

### 3.3 Latency & Detection Delay Measurement
- **Wall-Clock Detection Delay:**
  $$\Delta t_{\text{detect}} = t_{\text{alert}} - t_{\text{first\_attack\_pkt}}$$
  Measured by comparing the pcap packet arrival timestamp of the first attack packet against the wall-clock timestamp of the first triggered anomaly alert (flow-level, window-level, and packet-level handshake rules).
