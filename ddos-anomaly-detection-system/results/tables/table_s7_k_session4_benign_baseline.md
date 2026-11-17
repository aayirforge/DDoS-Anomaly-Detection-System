### Table S7-K: Session 4 Multi-Client Benign Baseline Evaluation (`session4_benign_baseline_eval.json`)
*Capture Specification: Internal lab traffic only; duration >= 15 min (900s); 5 distinct clients; HTTP, HTTPS, DNS, NTP, UDP echo services; not used for any threshold calibration.*
| Evaluation Metric | Observed Result | Specification / Acceptance Criteria | Status |
| :--- | :---: | :--- | :---: |
| **Capture File** | `session4_benign_baseline_900s.pcap` | Internal lab pcap under `lab/captures/session4/` | **PASS** |
| **Capture Duration** | **900.0 s (15.0 min)** | $\ge$ 15 min requirement | **PASS** |
| **Distinct Benign Clients** | **5 clients** (`.4`, `.5`, `.6`, `.7`, `.8`) | $\ge$ 5 clients requirement | **PASS** |
| **Services Evaluated** | HTTP (80), HTTPS (443), DNS (53), NTP (123), UDP Stream (5004) | Several services requirement | **PASS** |
| **Total Evaluated Seconds** | **900 seconds** | Full baseline window | **PASS** |
| **TCP Incomplete Handshake Rule False Alarms** | **0 seconds (0 alerts)** | 0 false alarm seconds | **PASS** |
| **Dual-Condition UDP Rule False Alarms** | **0 seconds (0 alerts)** | 0 false alarm seconds | **PASS** |
| **Stateless SYN Arrival Rate Rule (ALERT_SYN_RATE)** | **0 seconds (0 alerts)** | 0 false alarm seconds | **PASS** |
| **Total Combined False-Alarm Seconds** | **0 seconds (0.00%)** | Zero false alarms across all rules | **PASS** |

