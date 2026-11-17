### Table S7-G: Phase 7 Synthetic Replay Single-Source Flood Grid (`results/phase7_round2_evaluation.json`)
*Classification: Synthetic Replay through RuleEngine (Single source IP 172.20.0.3, randomized destination/source ports)*
| Table Capacity Cap | Packet Rate | First Alert Delay (s) | Alert Count (5s) | First Alert Class | Triggering Rule | Capacity Evictions | Timeout Expired Handshakes |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| 20,000 | 20,000 pps | **None (0 alerts)** | 0 | `None` | `None` | 52,646 | 0 |
| 20,000 | 40,000 pps | **None (0 alerts)** | 0 | `None` | `None` | 121,662 | 0 |
| 20,000 | 80,000 pps | **None (0 alerts)** | 0 | `None` | `None` | 259,670 | 0 |
| 160,000 | 20,000 pps | 2.001850 s | 3 | `ALERT_SYN_FLOOD` | `tcp_incomplete_handshake` | 0 | 32,328 |
| 160,000 | 40,000 pps | 2.001875 s | 3 | `ALERT_SYN_FLOOD` | `tcp_incomplete_handshake` | 0 | 34,745 |
| 160,000 | 80,000 pps | 2.003400 s | 3 | `ALERT_SYN_FLOOD` | `tcp_incomplete_handshake` | 0 | 20,096 |
