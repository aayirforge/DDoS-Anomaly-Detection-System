# Session 3 Test Plan: Multi-Protocol Live Validation & Benchmark

## 1. Objectives & Scope
Session 3 evaluates detection performance under diverse, realistic multi-protocol benign traffic alongside controlled SYN and UDP flood attacks in the isolated Docker container lab. No models will be retrained; all evaluation strictly utilizes existing model checkpoints, frozen thresholds, and calibration protocols.

---

## 2. Methodology & Detection Architecture

### 2.1 Flow Extraction & Normalization
- **Primary Extractor:** Official Java CICFlowMeter v4 (offline CLI execution via `cic.cs.unb.ca.ifm.Cmd`).
- **Feature Schema & Alignment:**
  - Microsecond IAT features preserved natively without re-scaling.
  - Flag counts binarized to $\{0.0, 1.0\}$ matching `train.parquet`.
  - **Direction Inversion Rule:** Enforced for server-to-client flows (`Source IP == 172.20.0.2` or `Source Port in {80, 443}`) to ensure client-initiated orientation for bidirectional features.
  - Payload length calculation preserved (0B forward payload for pure SYN attacks).

### 2.2 Attack-to-Detector Mapping & Primary Detectors
Different attack vectors produce fundamentally different packet-level and flow-level footprints. Detectors are scored according to their design scope:

| Attack Vector | Primary Detector | Scored Detection Mechanism | Scope & Boundary Conditions |
| :--- | :--- | :--- | :--- |
| **TCP SYN Floods (50, 200, 500, 1000 pps)** | **Packet-Level Incomplete TCP Handshake Rule** | Real-time 1-second packet analysis | Evaluated across all rate tiers. Handshake rule handles single-packet connection requests where flows may not be completed. |
| **UDP Floods (Random Dst Ports)** | **Packet-Level Dual-Condition UDP Rule** | Real-time 1-second packet analysis | Evaluated across all rate tiers. Random destination ports disperse across ephemeral range. |
| **UDP Floods (Volumetric Service Target)** | **Packet-Level Dual-Condition UDP Rule** | Real-time 1-second packet analysis | Evaluated across all rate tiers against specific victim UDP services. |
| **UDP Reflection Amplification** | **Packet-Level Dual-Condition UDP Rule** | Real-time 1-second packet analysis | Detects amplified incoming reflection datagrams from internal reflector container. |
| **Multi-Packet / Application Attacks** | **KNN Robust 14 (Log1p+Clip) (Window-Max)** | Step-size 5 flow windows | **Scored ONLY where bidirectional flows with $\ge 2$ packets exist.** Flow classifiers require established bidirectional flow records to populate the 14 robust features; they are not scored on pure 1-packet control flood streams. |

### 2.3 Detector Specifications & Frozen Thresholds

1. **Packet-Level Incomplete TCP Handshake Rule (TCP Defense):**
   - Monitors incoming client TCP SYN attempts (`tcp.flags.syn == 1 && tcp.flags.ack == 0`) for which no completing final ACK arrives within timeout $N = 2.0\text{ seconds}$ (or connection refused with RST/ACK).
   - **Reconnaissance Scan Condition:**
     - If incomplete handshakes $\ge 15/\text{s}$ AND ($\text{distinct destination ports} \ge 3$ OR $\text{distinct destination IPs} \ge 3$):
     - Trigger **`ALERT_SCAN`** (Port Scan / Host Sweep).
   - **Denial-of-Service Flood Condition:**
     - Target-concentrated ($\le 2$ distinct destination ports and $\le 2$ distinct destination IPs):
     - **Condition A (Multi-Source Distributed / Spoofed Flood):** $\ge 15$ incomplete handshakes/s **AND** $\ge 3$ distinct incomplete source IPs/s.
     - **Condition B (Volumetric Single-Source Flood):** $\ge 50$ incomplete handshakes/s (any source count).
     - Trigger **`ALERT_SYN_FLOOD`**. Alert-only by default.

### 2. Primary Defense Detectors & Transfer Experiment Architecture

1. **Packet-Level Incomplete TCP Handshake Rule (Primary SYN Defense):**
   - Tracks incoming TCP SYN packets destined to the victim (`172.20.0.2`) across a **continuous sliding 1-second window**.
   - Handshake completion timeout: $N = 2.0\text{ s}$. If a SYN packet does not observe a completed 3-way handshake (SYN $\to$ SYN-ACK $\to$ ACK) within $2.000\text{ s}$, it is confirmed incomplete.
   - **Condition A (Distributed / Multi-Source Flood):** $\ge 15\text{ incomplete SYNs in sliding 1.0s}$ from $\ge 3\text{ distinct source IPs}$ (target-concentrated $\le 2$ ports/hosts) $\longrightarrow$ `ALERT_SYN_FLOOD`.
   - **Condition B (Concentrated Single-Source / Low-Rate Flood):** $\ge 20\text{ incomplete SYNs in sliding 1.0s window}$ (target-concentrated $\le 2$ ports/hosts) $\longrightarrow$ `ALERT_SYN_FLOOD`.
     - *Principle & Margin:* Formulated on Sessions 2 and 2b benign baselines, where the maximum concentrated incomplete SYN count is exactly 2. The threshold of 20 provides a safety margin of $+18$ incomplete SYNs (10x benign maximum) and guarantees detection delay $\le 2.5\text{ s}$ at 50 pps ($19/50\text{s} + 2.0\text{s} = 2.38\text{s}$).
   - **Reconnaissance Port / Host Scan Separation:** $\ge 15\text{ incomplete SYNs in sliding 1.0s}$ AND ($\ge 3\text{ distinct destination ports}$ OR $\ge 3\text{ distinct destination IPs}$) $\longrightarrow$ `ALERT_SCAN` (classified separately; zero flood false alarms).

2. **Packet-Level Dual-Condition UDP Rule (Primary UDP Defense — Frozen on Session 2c):**
   - Counts incoming UDP datagrams (`ip.proto == 17`) per destination IP across either a **continuous sliding 1-second window or non-overlapping 1-second bins**.
   - **ICMP Exclusion Protocol:** Naive packet filtering (e.g. Wireshark `udp`) matches ICMP payload-quoted headers (such as ICMP Type 3 Code 3 Port Unreachable errors returned by the victim). To ensure strict measurement integrity, packet counting **strictly excludes ICMP-quoted headers** (`ip.proto == 17 && !icmp`), verified by unit test `tests/test_udp_counting.py`.
   - **Real Detection Delay:** Measured identically to the TCP rule as the elapsed time from first attack packet arrival to the first alert trigger: $\Delta t_{\text{real}} = t_{\text{first\_alert}} - t_{\text{first\_attack\_pkt}}$.
   - Evaluated on Session 2c benchmark (benign multi-protocol peak = 25 pps including streaming RTP; 30, 80, 300 pps floods):
     - **Condition 1 (Volumetric UDP Flood):** $\ge 40\text{ UDP packets/s}$ per destination IP (any port distribution).
     - **Condition 2 (Random-Port UDP Flood):** $\ge 30\text{ UDP packets/s}$ per destination IP **AND** $\ge 10\text{ distinct destination ports/s}$.
   - **Safety Margin:** Provides $\ge 15\text{ pps}$ margin above benign peak rates (25 pps) while achieving 100% recall on floods $\ge 30\text{ pps}$ with 0.00% FPR. Alert-only.

3. **Flow-Level Anomaly Classifier (Transferability Diagnostic Only — NOT a Primary Detector):**
   - **Diagnostic Role:** Flow models (KNN Robust 14, Random Forest, LSTM) are evaluated strictly as an experimental transferability diagnostic to study cross-environment drift and feature stability on multi-packet flows ($\ge 2$ packets/flow).
   - **EXCLUSION FROM OR UNION:** Flow models are **NOT** primary defense detectors and are **NOT** included in the active defense logical OR union. The primary active defense system union counts packet rules only.
   - **Champion Transfer Candidate:** `KNN Robust 14 (Log1p + Clip [-5, 5]) (Window-Max)` at fixed threshold $1.0000$ (and calibrated threshold $0.8086$).
   - **Evaluation Boundary:** Scored strictly on extracted flow records with $\ge 2$ packets where flows exist.

---

## 3. Pre-Registered Session 3 Success Criteria

Before initiating any Session 3 live capture, the following success criteria are pre-registered:

| Evaluation Dimension | Metric Target | Evaluation Basis & Bin Definition |
| :--- | :---: | :--- |
| **Packet Rules Benign False Alarm Rate (FPR)** | **$\le 1.0\%$** per-detector FPR | 1-second non-overlapping bins across $\ge 15$ minutes of dedicated, separate benign-only traffic ($900\text{ s}$ total). Allowed false bins: **$\le 9\text{ seconds}$** per rule. |
| **Combined Active Defense False Alarm Rate** | **$\le 1.0\%$** combined FPR | **Logical OR union of PACKET RULES ONLY** (Incomplete Handshake Rule $\cup$ Dual UDP Rule). Allowed false bins: **$\le 9\text{ seconds}$ total** across the 900s separate benign-only baseline. Flow models are excluded from this union. |
| **Attack Detection Recall (All Rates: 50, 200, 500, 1000 pps)** | **$\ge 95.0\%$** recall | **Duration:** Floods run at least $120\text{ seconds}$ each ($\ge 120\text{ s}$), executed **concurrently over active benign background traffic**. <br>**Recall Definition:** Evaluated strictly as the **fraction of 1-second bins/windows alerted over the active attack period AFTER THE FIRST ALERT** ($t_{\text{alerted\_post\_first}} / t_{\text{attack\_active\_post\_first}}$). <br>**Separation of Delay:** Real detection delay is reported separately as an independent primary metric. |
| **Real Detection Delay (TCP SYN Floods: All Rates)** | **$\le 2.5\text{ seconds}$** | Measured as $\Delta t_{\text{real}} = t_{\text{first\_alert}} - t_{\text{first\_attack\_pkt}}$. **Physical Justification:** Under sliding Condition B (threshold 20 incomplete SYNs), transmitting 20 packets at 50 pps takes $(20-1)/50 = 0.38\text{ s}$. Adding the $N = 2.00\text{ s}$ completion timeout yields $\Delta t_{\text{real}} = 0.38 + 2.00 = 2.38\text{ s} \le 2.5\text{ s}$. At higher rates ($\ge 100$ pps), arrival offset is $\le 0.19\text{ s}$ ($\Delta t_{\text{real}} \le 2.19\text{ s}$). |
| **Real Detection Delay (UDP Floods: All Rates)** | **$\le 1.0\text{ second}$** | Measured identically as $\Delta t_{\text{real}} = t_{\text{first\_alert}} - t_{\text{first\_attack\_pkt}}$ across continuous sliding 1-second window or 1-second bin. Stateless packet threshold trigger. |
| **Port / Host Scan Evaluation (`ALERT_SCAN`)** | **$\ge 95.0\%$** scan recall, **$\le 1.0\%$** scan FPR | `ALERT_SCAN` is treated as a **true positive for scan traffic** ($\ge 3$ distinct destination ports/hosts at $\ge 15\text{ inc/s}$) and is reported separately from floods with its own scan recall and scan false alarm counts. Benign traffic in Session 3 contains no scanner-like multi-port bursts unless explicitly labeled as scans. |
| **Flow-Model Cross-Environment Transfer Experiment** | **Diagnostic Observation** | **ALL frozen candidates** (RF Full 25, RF Robust 14, KNN Full 25, KNN Robust 14, Window-Stats LR, LSTM) are evaluated on Session 3 strictly as an empirical transfer experiment with **no new model selection and no new thresholds**. Delay reported from first attack packet arrival to first step-5 window alert crossing where $\ge 2$-packet flows exist. |

> **STRICT FAILURE REPORTING POLICY:** Every attack run must report the **measured offered packet rate** extracted directly from pcap timestamps via tshark. If any pre-registered target is not met (FPR $> 1.0\%$, recall $< 95.0\%$, delay $> 2.5\text{ s}$), it must be reported unambiguously as a **FAILURE** in the evaluation summary. Post-hoc threshold changes or moving criteria after capture are prohibited.

---

## 4. Experimental Execution & Statistical Reporting Protocol

### 4.1 3 Independent Repeats per Attack Rate Over Benign Background Traffic
Each attack condition (vector $\times$ rate tier) is executed in **3 independent, chronologically isolated runs** ($\ge 120\text{ seconds}$ each) executed **concurrently over active benign background traffic** and separated by quiescent benign baseline periods:
- **Repeat 1, Repeat 2, and Repeat 3 must each be reported separately** with individual per-second recall rates (post-first-alert), true positives, and detection delays.
- Followed by the **pooled mean** across the 3 repeats.
- **Benign False Alarm Isolation:** Benign false alarms and benign FPR are evaluated exclusively from separate, dedicated benign-only recording periods ($\ge 15$ min baseline) to prevent cross-contamination.

### 4.2 Moving-Block Bootstrap Confidence Intervals
Because network traffic exhibits strong temporal autocorrelation, standard i.i.d. bootstrapping is invalid.
- A **moving-block bootstrap** ($B = 10\text{ seconds}$, 2,000 resamples) will be computed across the pooled repeat windows to construct non-parametric 95% confidence intervals for:
  - Benign False Positive Rate (FPR)
  - Attack Detection Recall
  - Per-second Alert Coverage Rate
  - Detection Delay ($\Delta t_{\text{real}}$)

### 4.3 Traffic Composition & Multi-Protocol Baseline ($\ge 15$ min)
- **DNS:** Continuous domain queries to `victim-web:53` (2–5 queries/s).
- **NTP:** Periodic time synchronization requests to `victim-web:123`.
- **UDP Echo:** Bidirectional datagram exchange with randomized payloads on `victim-web:7`.
- **Streaming UDP Flow:** Constant 15 pkts/s UDP stream to `victim-web:5004` (VoIP/RTP media emulation).
- **Bursty HTTP Clients:** Concurrent bursts of 5–15 requests to Web & REST endpoints separated by idle pauses.
- **Bulk Downloads:** Chunked multi-megabyte file transfers.
- **BPF Filtering:** Strict capture filter applied on capture interfaces:
  ```text
  (ip or ip6) and not multicast and not broadcast and not port 1900 and not port 5353
  ```
- **ICMP Policy:** Strict count-and-alert only; zero packet dropping or rate-limiting.
