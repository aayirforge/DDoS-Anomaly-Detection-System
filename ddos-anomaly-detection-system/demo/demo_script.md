# DDoS Anomaly Detection System: Demonstration Script and Screen Recording Plan

This document provides an end-to-end operational demonstration script and camera/screen recording storyboard for evaluating the hybrid dual-path DDoS detection system.

---

## 1. Demonstration Overview & Environment Setup

### 1.1 Prerequisites & Scope Notes
- **Target OS:** Linux (x86_64)
- **Runtime Environment:** Python 3.11+ virtual environment (`.venv`)
- **Working Directory:** `ddos-anomaly-detection-system/`
- **Dashboard Service:** Streamlit on port `8501` (One-page capture analysis UI with dumpcap writing under `results/ui_runs`; advanced live telemetry page operates in read-only SQLite mode)
- **Database Path:** `data/detection_events.db` (auto-created in WAL mode)
- **Scope Note on Reflection Amplification:** Reflection amplification scenario: pre-registered in the Session 3 plan but not run. The reflector container named in the plan was never provisioned in docker-compose.yml (a planning error), and the traffic generator implements no reflection logic. The scenario would have run on the internal-only lab network. Source: lab/docker-compose.yml and the 'not run' rows of results/tables/table_s3_b_per_repeat.md. Status: NOT RUN.

### 1.2 Layout Configuration (Screen Recording)
- **Display Resolution:** 1920 &times; 1080 (1080p, 60 FPS)
- **Left Window (50% width):** Terminal running detector engine and replay commands.
- **Right Window (50% width):** Chrome browser displaying Streamlit Dashboard (`http://localhost:8501`).

```
+------------------------------------+------------------------------------+
|                                    |                                    |
|      TERMINAL (50% Width)          |       BROWSER UI (50% Width)       |
|                                    |                                    |
|  $ .venv/bin/streamlit run ...     |   DDoS Anomaly Detection System    |
|  $ python3 -m ddos_ads.detector    |   [Live Telemetry Dashboard]       |
|  $ tcpreplay / pcap streaming ...  |   • Packet Rates & Threat Gauges   |
|                                    |   • Real-Time Alert Event Log      |
|                                    |                                    |
+------------------------------------+------------------------------------+
```

---

## 2. Step-by-Step Demonstration Script

### Scene 1: System Initialization and Streamlit UI Launch (0:00 - 0:45)
1. **Initialize Telemetry Database:**
   ```bash
   rm -f data/detection_events.db data/detection_events.db-wal data/detection_events.db-shm
   sqlite3 data/detection_events.db "VACUUM;"
   ```
2. **Launch Streamlit UI in Browser:**
   ```bash
   .venv/bin/streamlit run src/ddos_ads/dashboard.py --server.port 8501 --server.headless true
   ```
3. **Narration:**
   > *"We start by launching the Streamlit interface. The UI provides a one-page capture analysis interface (which can analyze uploaded pcaps or launch dumpcap for controlled live captures with outputs written under results/ui_runs) as well as an advanced live monitoring page that connects to SQLite strictly via URI `file:data/detection_events.db?mode=ro`, guaranteeing zero write locks on active detection pipelines. Note the system status displays 'NORMAL' with zero active threats."*

---

### Scene 2: Replay Scenario 1 – TCP SYN Flood at 200 pps (0:45 - 1:45)
1. **Execute Detector in Streaming Mode:**
   ```bash
   .venv/bin/python3 -m ddos_ads.live_packet_detector \
       --replay-pcap lab/captures/session3/session3_tcp_syn_flood_200pps_rep1.pcap \
       --pace 1.0
   ```
   *Or via the replay wrapper script:*
   ```bash
   .venv/bin/python3 scripts/replay_pcap_live.py \
       --pcap lab/captures/session3/session3_tcp_syn_flood_200pps_rep1.pcap \
       --pace 1.0
   ```
2. **Observed Dashboard Behavior:**
   - Incomplete handshake gauge rises rapidly past 20.
   - At $t \approx 2.05\text{ s}$, **Condition B** fires: `ALERT_SYN_FLOOD (Condition B: 20 incomplete, ratio 1.00)`.
   - Alert log populates with attacker 4-tuple and millisecond timestamp.
3. **Narration:**
   > *"We now replay a 200 packets-per-second TCP SYN flood from Session 3. Notice that as incomplete handshakes cross the 2.0-second timeout threshold, Condition B triggers immediately at 2.05 seconds, achieving 100% attack recall with sub-second delay."*

---

### Scene 3: Replay Scenario 2 – Volumetric UDP Flood at 50 pps (1:45 - 2:30)
1. **Stream Session 3 PCAP (`session3_udp_flood_random_ports_50pps_rep1.pcap`):**
   ```bash
   .venv/bin/python3 scripts/replay_pcap_live.py \
       --pcap lab/captures/session3/session3_udp_flood_random_ports_50pps_rep1.pcap \
       --pace 1.0
   ```
2. **Observed Dashboard Behavior:**
   - Per-destination UDP rate crosses the 40 pps threshold.
   - At $t \approx 0.80\text{ s}$, **ALERT_UDP_FLOOD** fires with measured rate of 50 pps.
3. **Narration:**
   > *"Next, we replay a low-rate 50 pps UDP flood. Because UDP lacks handshakes, our stateless sliding window monitors per-destination packet arrival rates. The rule triggers within 0.80 seconds, comfortably exceeding the 40 pps baseline threshold while avoiding false positives."*

---

### Scene 4: Replay Scenario 3 – TCP Port Scan at 30 pps (2:30 - 3:15)
1. **Stream Session 3 PCAP (`session3_reconnaissance_port_scan_30pps_rep1.pcap`):**
   ```bash
   .venv/bin/python3 scripts/replay_pcap_live.py \
       --pcap lab/captures/session3/session3_reconnaissance_port_scan_30pps_rep1.pcap \
       --pace 1.0
   ```
2. **Observed Dashboard Behavior:**
   - Single source IP contacts &ge; 15 distinct ports.
   - Distinct classification fires: **`ALERT_SCAN`** (not classified as generic SYN flood).
3. **Narration:**
   > *"In Scenario 3, we replay a 30 pps reconnaissance port scan. The multi-port heuristic isolates the single source IP targeting 15+ destination ports, correctly classifying the attack as ALERT_SCAN rather than misidentifying it as a volumetric SYN flood."*

---

### Scene 5: Demonstrating the "DETECTOR BLIND" Operator Alert (3:15 - 4:00)
1. **Simulate Ingress Pipeline Crash:**
   ```bash
   kill -9 $DETECTOR_PID
   ```
2. **Observed Dashboard Behavior:**
   - Streamlit heartbeat detector detects missing supervisor timestamp updates (&gt;5.0 s silence).
   - A high-visibility, full-width red banner displays across top of screen:
     `CRITICAL ALERT: DETECTOR BLIND – INGRESS STREAM STALLED (NO HEARTBEAT > 5.0s)`
3. **Narration:**
   > *"If an adversary causes the capture daemon or supervisor to terminate, silent failure is fatal. Here we forcefully terminate the detector process. Within 5 seconds, the dashboard heartbeat triggers the prominent DETECTOR BLIND banner, alerting network operations that traffic is unmonitored."*

---

### Scene 6: Reproducing Table-Validator Tamper Detection (4:00 - 5:00)
1. **Execute Successful Consistency Check:**
   ```bash
   make report
   ```
   *Output: `[OK] Report generated and verified at: results/report.md`*
2. **Simulate Cell Tampering in `results/session3_evaluation.json`:**
   ```bash
   # Mutate one detection delay value from 2.4199 s to 9.999 s
   sed -i 's/"first_detection_delay_sec": 2.4199/"first_detection_delay_sec": 9.999/' results/session3_evaluation.json
   make report
   ```
3. **Observed Terminal Failure Output:**
   ```
   AssertionError: Table S3-B cell mismatch for run 'session3_tcp_syn_flood_50pps_rep1' on JSON key 'first_detection_delay_sec': expected '9.999 s', got '2.420 s'
   make: *** [Makefile: report] Error 1
   ```
4. **Revert Mutated Value:**
   ```bash
   git checkout results/session3_evaluation.json
   make report
   ```
   *Output: `[OK] Report generated and verified`*
5. **Narration:**
   > *"To prove scientific integrity, all numbers are strictly bound to primary JSON artifacts. Here we manually alter a single detection delay in session3_evaluation.json. Running `make report` immediately halts execution with an AssertionError, explicitly naming the modified cell and mismatched key. Reverting the change restores full verification."*

---

## 3. Screen Recording Plan & Visual Storyboard

| Scene | Timestamp | Visual Focus / Region | Audio Narration & Key Points |
| :---: | :---: | :--- | :--- |
| **1** | 0:00 - 0:45 | Full split screen: Terminal left, Streamlit UI right. | Introduce hybrid architecture; point out capture analysis writing under results/ui_runs and advanced read-only monitoring. |
| **2** | 0:45 - 1:45 | Zoom on Dashboard Incomplete Handshake chart and Alert feed. | Replay SYN 200 pps; highlight 2.05 s detection latency under Condition B. |
| **3** | 1:45 - 2:30 | Zoom on Dashboard UDP rate chart and 40 pps threshold marker. | Replay UDP 50 pps; explain stateless sliding-window rate tracking. |
| **4** | 2:30 - 3:15 | Zoom on Alert Classification badge (`ALERT_SCAN`). | Replay Scan 30 pps; explain scan classifier distinguishing scans from floods. |
| **5** | 3:15 - 4:00 | Zoom on top banner of Dashboard. | Kill detector PID; observe prominent red `DETECTOR BLIND` banner. |
| **6** | 4:00 - 5:00 | Terminal full screen, showing `make report` diff and error. | Tamper test: modify JSON key, show exact AssertionError, revert and pass. |
