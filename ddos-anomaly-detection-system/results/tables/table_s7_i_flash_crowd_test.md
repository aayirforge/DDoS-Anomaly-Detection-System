### Table S7-I: Phase 7 Synthetic Replay Flash Crowd Evaluation (`results/phase7_round2_evaluation.json`)
*Classification: Synthetic Replay through RuleEngine (5 clients >= 3, 500 connections/s for 10.0s, Table Cap 1,000)*
| Evaluation Condition | Client Count | Offered Rate | Handshake Completion Status | Alerts Emitted | First Alert Delay (s) | Alert Class | Capacity Evictions | Evaluation Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Benign Flash Crowd** | 5 clients | 500 conn/s | Handshakes Completing (SYN+ACK) | **0 alerts** | None | None | 0 | **PASS (No False Alarm)** |
| **Unacknowledged SYN Burst** | 5 clients | 500 conn/s | No Completing ACKs (Pure SYNs) | **18 alerts** | 0.300000 s | `ALERT_SYN_RATE` | 0 | **PASS (Prompt Alert)** |

