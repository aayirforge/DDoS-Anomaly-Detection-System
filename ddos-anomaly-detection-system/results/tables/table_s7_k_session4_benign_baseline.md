### Table S7-K: Session 4 Benign Baseline & Per-Client Traffic Metrics (`results/phase7_round3_evaluation.json`)
*Specification: Internal lab baseline; 900.0s (15 min); 5 clients (172.20.0.4-8); services: HTTP, HTTPS, DNS, NTP, UDP echo*
| Metric / Traffic Scope | Max 1s SYN Rate (pkts/s) | Max Unacked Count (1s window) | Max Distinct Sources (1s window) | False Alarm Seconds | Rule Acceptance Status |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Overall Session 4 Baseline** | **101** | **1** | **5** | **0 seconds (0.00%)** | **PASS** |
| Client 1 (`172.20.0.4`) | 34 | 1 | 1 | 0 s | **PASS** |
| Client 2 (`172.20.0.5`) | 35 | 1 | 1 | 0 s | **PASS** |
| Client 3 (`172.20.0.6`) | 33 | 1 | 1 | 0 s | **PASS** |
| Client 4 (`172.20.0.7`) | 32 | 1 | 1 | 0 s | **PASS** |
| Client 5 (`172.20.0.8`) | 35 | 1 | 1 | 0 s | **PASS** |
| *TCP Incomplete Rule* | - | max incomplete = 0 | - | 0 s | **PASS** |
| *Dual-Condition UDP Rule* | - | max UDP/s = 5 | max dst ports = 1 | 0 s | **PASS** |
| *Stateless SYN Arrival Rule* | 101 | 1 | 5 | 0 s | **PASS** |
| **Session 3 Fired PCAPs (of 40)** | - | - | - | **0 of 40 fired** | **PASS (100% Frozen Parity Preserved)** |
