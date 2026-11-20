# DDoS Anomaly Detection System: Technical Presentation Deck

> **Format:** 11 Widescreen Slides (16:9 Aspect Ratio)
> **Artifacts:** Verified against `results/metrics.json` and `results/session3_evaluation.json`.

---
## Slide 1: DDoS Anomaly Detection Architecture
*Bridging the Gap from Offline ML Benchmarks to Real-Time Streaming Detection*

- **The Operational Challenge:** Flow-based ML models report >0.999 AUC on benchmark datasets but suffer catastrophic failure in real-world deployments.
- **Core Problem:** High-rate single-packet floods (SYN & UDP) saturate targets before flow extractors export statistical summaries (120 s timeout).
- **Project Scope:** Rigorous empirical evaluation from offline benchmark modeling (CIC-DDoS2019) to live packet-level streaming detection.
- **Verification Standard:** 100% frozen reproducibility: every number verified by automated consistency scripts across 40 empirical PCAPs.

---
## Slide 2: Architectural Approach: Dual-Path Hybrid
*Decoupling Low-Latency Packet Mitigation from Deep Flow Analytics*

- **Path 1: Packet-Level Streaming Engine:** Processes wire datagrams with sub-microsecond latency. Tracks stateful TCP handshakes and stateless UDP/SYN arrival rates.
- **Path 2: Statistical Flow Analytics:** Extracts bidirectional flows over 14 robust features for forensic auditing and background pattern analysis.
- **Asynchronous Decoupling:** Capture ring buffers isolate network ingress from database logging, maintaining 42,000-84,000 pps offline throughput.
- **Safety & Observability:** Analysis UI launches dumpcap under results/ui_runs; only advanced page is read-only (mode=ro).

---
## Slide 3: Benchmark Modeling vs Generalization Collapse
*Why Benchmark AUC Masks Operational Fragility*

- **Same-Day Performance (Day 1):** RF AUC: 0.9987, FPR: 0.0105; KNN AUC: 0.9973, FPR: 0.0150; LSTM AUC: 1.0000, FPR: 0.0016.
- **Cross-Day Collapse (Day 2):** Uncalibrated zero-shot operating thresholds produced severe FPR spikes: 8.18% (RF) and 3.24% (KNN) at flow level (>43% window max).
- **Threshold Drift:** Decision thresholds drifted dramatically between days (RF: 0.1288 -> 0.6690; KNN: 0.1268 -> 0.8200).
- **Local Calibration Recovery:** Calibrating thresholds on target-environment benign traffic restored cross-day FPR to <0.004 while maintaining >91% recall.

---
## Slide 4: Sequence Ablation & Extractor Auditing
*Debunking Sequence Learning & Uncovering Extractor Bugs*

- **LSTM Order Invariance (Shuffle Test):** Shuffling flow order within 10-flow windows yielded AUC 0.9996 vs 0.9997 ordered (Delta < 0.0002). Models learned pooling, not sequence dynamics.
- **Window-Summary Baselines:** Static MLP trained on 50 window summary statistics matched LSTM sequence performance (AUC 0.9995).
- **CICFlowMeter Bug Fixes:** Rectified TCP payload truncation and a 1,000x Backward IAT scaling bug between millisecond and microsecond units.
- **Flag Column Anomaly:** Demonstrated in lab execution that compiled JAR shifted flag headers by one column; unproven for canonical dataset provenance.

---
## Slide 5: The Flow Extractor Blind Spot
*Why Flow-Based Machine Learning Cannot Stop Single-Packet Floods*

- **Degenerate Single-Packet Flows:** Spoofed TCP SYN floods and UDP floods generate unique 5-tuples per packet (random source IPs/ports).
- **Inactivity Timeout Delay:** Flow extractors hold unclosed connections for 120 seconds awaiting completing FIN/ACK or timeout.
- **Detection Failure:** Downstream ML models cannot classify the attack until two minutes after victim connection tables have collapsed.
- **Architectural Mandate:** Mitigating volumetric and state-exhaustion floods strictly requires wire-speed, packet-level inspection.

---
## Slide 6: Packet-Level Streaming Detection Engine
*Stateful Handshake Tracking & Calibrated Arrival Thresholds*

- **Stateful TCP Handshake Rule:** Tracks (SIP, SPort, DIP, DPort). Incomplete entries expire at 2.0 s. Condition A triggers at >100 unacked; Condition B at >20 unacked with >80% incomplete ratio.
- **Port Scan Classifier:** Distinguishes scans when a single source IP contacts >=15 distinct destination ports within 1.0 s.
- **Volumetric UDP Rule:** Monitors per-destination arrival rate in a 1.0 s sliding window; triggers at >40 pps (calibrated against 6.2 pps benign burst max).
- **Stateless SYN Arrival Rule (Post-Hoc):** ALERT_SYN_RATE monitors high-rate arrivals: >150 unacked SYNs/s (>=3 sources) or >1,500 unacked SYNs/s (single-source).

---
## Slide 7: Session 3 Empirical Lab Evaluation
*100% Attack Recall Across 40 Rigorous Captures*

- **TCP SYN Floods (12 Captures):** 12/12 detected (100% recall). Mean detection delay: 2.13 s (max: 2.42 s at 50 pps rep1), well within 5.0 s bound.
- **Volumetric UDP Floods (24 Captures):** 24/24 detected (100% recall). Mean detection delay: 0.28 s (max: 0.80 s at 50 pps rep1), well within 1.0 s bound.
- **TCP Port Scans (3 Captures):** 3/3 correctly classified as ALERT_SCAN (mean delay: 2.44 s; diagnostic evaluation).
- **Benign Baseline (900 s):** 0 false alarm seconds across 900 s of DNS, NTP, UDP echo, 15 pps RTP-like UDP, and bursty HTTP (0.00% empirical FPR; 95% bound: 0.33%).

---
## Slide 8: Adversarial Stress-Test Findings
*Uncovering and Resolving 5 Algorithmic Vulnerabilities*

- **State-Table Blind Spot:** Floods >=20k pps starved the 20,000-entry table (0 alerts). Resolved by stateless ALERT_SYN_RATE detector firing in <0.08 s.
- **Single-Source Gap:** Single IP floods at 40k pps bypassed multi-source rule. Resolved via 1,500/s single-source condition.
- **Benign ACK Masking:** Global ACK subtraction allowed busy web traffic to mask spoofed floods. Resolved via per-source ACK credit capped at source SYN count.
- **Timestamp Refresh Bug:** 4-tuple re-transmissions reset expiration timer. Resolved by preserving initial SYN timestamp (keep-first semantics).

---
## Slide 9: Operational Telemetry & Safety Architecture
*Analysis Page (Subprocess Under ui_runs), Read-Only Advanced Page, Zero Active Risk*

- **UI Safety Architecture:** Analysis page can launch dumpcap via argument lists under results/ui_runs; only the advanced monitoring page is read-only (SQLite mode=ro).
- **Supervisor Recovery:** Simulated supervisor crash restored state tracking and database reconnection in 0.50 ms.
- **DETECTOR BLIND Fixture:** Automated UI banners instantly alert operators if the capture daemon stalls or crashes.
- **Strict Safety Guarantees:** Active firewall mitigation hardcoded to dry-run logging; zero automated routing changes or packet-drop injections.

---
## Slide 10: Explicit Engineering Limitations
*Honest Empirical Boundaries (No Softening)*

- **Topology Constraints:** Evaluated in a single container bridge topology on a single Linux kernel; physical switch fabric and NIC offloading not tested.
- **Threshold Calibration:** Calibrated near 50 pps generator rates; sub-threshold distributed floods (<40 UDP pps, <20 unacked SYNs) will not trigger.
- **Protocol Bypasses:** Adversaries transmitting paired bare ACKs for every SYN cancel the arrival counter; legitimate flash crowds >750 conn/s risk false alerts.
- **Evaluation Scope:** Reflection amplification scenario: pre-registered in the Session 3 plan but not run. The reflector container named in the plan was never provisioned in docker-compose.yml (a planning error), and the traffic generator implements no reflection logic. The scenario would have run on the internal-only lab network. Source: lab/docker-compose.yml and the 'not run' rows of results/tables/table_s3_b_per_repeat.md. Status: NOT RUN.

---
## Slide 11: Future Roadmap & Project Conclusions
*Key Takeaways from the Empirical Investigation*

- **Finding 1: Benchmark Disconnect:** High benchmark AUC does not equal operational viability. Flow models fail against single-packet floods due to extraction delay.
- **Finding 2: The Dual-Path Imperative:** Production defense requires fast, stateless/stateful packet filters upfront, reserving flow ML for forensic analysis.
- **Finding 3: Stress-Testing is Essential:** Table caps, collision re-transmissions, and ACK credit rules were only exposed through aggressive adversarial replay.
- **Next Steps:** Provision a reflector container on the internal lab network and run the pre-registered scenario (DNS/NTP/Memcached-style reflection) as an exploratory session.
