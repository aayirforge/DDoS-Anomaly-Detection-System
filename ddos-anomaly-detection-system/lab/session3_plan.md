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

2. **Packet-Level Dual-Condition UDP Rule (UDP Defense — Frozen on Session 2c):**
   - Counts incoming UDP datagrams (`ip.proto == 17`) per destination IP in 1-second bins.
   - Evaluated on Session 2c benchmark (benign multi-protocol max = 25 pps including streaming RTP; 30, 80, 300 pps floods):
     - **Condition 1 (Volumetric UDP Flood):** $\ge 40\text{ UDP packets/s}$ per destination IP (any port distribution).
     - **Condition 2 (Random-Port UDP Flood):** $\ge 30\text{ UDP packets/s}$ per destination IP **AND** $\ge 10\text{ distinct destination ports/s}$.
   - **Safety Margin:** Provides $\ge 15\text{ pps}$ margin above benign peak rates (25 pps) while achieving 100% recall on floods $\ge 30\text{ pps}$ with 0.00% FPR. Alert-only.

3. **Flow-Level Anomaly Classifier (Step-Size 5 Windows):**
   - **Champion Pre-Registered Model:** `KNN Robust 14 (Log1p + Clip [-5, 5]) (Window-Max)`.
   - **Features (14):** Bwd Packets/s, Down/Up Ratio, Bwd Packet Length Mean, Bwd Packet Length Max, Total Length of Bwd Packets, Bwd Header Length, Flow Packets/s, Total Backward Packets, Bwd Packet Length Min, Flow Bytes/s, Total Length of Fwd Packets, Total Fwd Packets, Fwd Packet Length Max, Idle Std.
   - **Window Aggregation:** Window size 10 flows, step size 5 flows inside each capture stream.
   - **Fixed Threshold:** $1.0000$ (achieving 0.83% Benign FPR on Session 2 Java windows).
   - **Evaluation Boundary:** Scored strictly on extracted flow records with $\ge 2$ packets.

---

## 3. Pre-Registered Session 3 Success Criteria

Before initiating any Session 3 live capture, the following success criteria are pre-registered:

| Evaluation Dimension | Metric Target | Evaluation Basis & Bin Definition |
| :--- | :---: | :--- |
| **Benign False Alarm Rate (FPR)** | **$\le 1.0\%$** per-bin FPR | **Packet Rules:** 1-second non-overlapping bins across $\ge 15$ minutes of benign traffic ($900\text{ s}$ total). Allowed false bins: **$\le 9\text{ seconds}$**. <br>**Flow Models:** Step-size 5 windows. Allowed false bins: **$\le 1.0\%$ of total benign windows**. |
| **Combined Benign False Alarm Rate** | **$\le 1.0\%$** combined FPR | Logical OR union of alerted 1-second bins across all active detectors: **$\le 9\text{ false alarm seconds}$** total across the 900s benign baseline. |
| **High-Rate Attack Recall (200, 500, 1000 pps)** | **$\ge 95.0\%$** recall | Evaluated across 1-second bins during attack active duration across all 3 independent repeats. |
| **Low-Rate Attack Recall (50 pps)** | **$\ge 80.0\%$** recall | Evaluated across 1-second bins during 50 pps attack runs across all 3 independent repeats. |
| **Packet-Rule Real Detection Delay (High-Rate $\ge 100$ pps)** | **$\le 2.5\text{ seconds}$** | Wall-clock delay including completion timeout ($\Delta t_{\text{packet}} + N_{\text{timeout}}$) for TCP SYN floods; $\le 1.0\text{ s}$ for UDP floods. |
| **Packet-Rule Real Detection Delay (Low-Rate 50 pps)** | **$\le 3.5\text{ seconds}$** | **Mathematical Justification:** At 50 pps, transmitting the 50 packets required to reach the volumetric threshold takes $\Delta t_{\text{packet}} = 49 / 50 = 0.98\text{ s}$. Adding the mandatory $N = 2.00\text{ s}$ completion timeout yields $\Delta t_{\text{real}} = 0.98 + 2.00 = 2.98\text{ s} \approx 3.0\text{ s}$. A $\le 2.5\text{ s}$ threshold is physically impossible for single-source 50 pps floods. |
| **Flow-Model Detection Delay** | **$\le 5.0\text{ seconds}$** | From first attack packet arrival to the first step-5 window alert crossing where flows exist. |

---

## 4. Experimental Execution & Statistical Reporting Protocol

### 4.1 3 Independent Repeats per Attack Rate
Each attack condition (vector $\times$ rate tier) is executed in **3 independent, chronologically isolated runs** ($\ge 60$ seconds each) separated by quiescent benign baseline periods:
- **Repeat 1, Repeat 2, and Repeat 3 must each be reported separately** with individual per-second recall rates, true positives, and detection delays.
- Followed by the **pooled mean** across the 3 repeats.

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
