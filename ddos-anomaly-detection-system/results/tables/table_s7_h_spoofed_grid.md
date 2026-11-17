### Table S7-H: Phase 7 Synthetic Replay Spoofed Multi-Source Flood Grid (`results/phase7_round3_evaluation.json`)
*Classification: Synthetic Replay through RuleEngine (Randomized spoofed source IPs from internal lab subnet 172.20.0.0/16, window length: 5.0 s)*
| Table Capacity Cap | Packet Rate | First Alert Delay (s) | Alert Count (5s) | First Alert Class | Triggering Rule | Capacity Evictions | Timeout Expired Handshakes |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| 20,000 | 20,000 pps | **0.007500 s** | 5 | `ALERT_SYN_RATE` | `tcp_syn_arrival_rate` | 80,000 | 0 |
| 20,000 | 40,000 pps | **0.003750 s** | 5 | `ALERT_SYN_RATE` | `tcp_syn_arrival_rate` | 180,000 | 0 |
| 20,000 | 80,000 pps | **0.001875 s** | 5 | `ALERT_SYN_RATE` | `tcp_syn_arrival_rate` | 380,000 | 0 |
| 160,000 | 20,000 pps | **0.007500 s** | 8 | `ALERT_SYN_RATE` | `tcp_syn_arrival_rate` | 0 | 59,999 |
| 160,000 | 40,000 pps | **0.003750 s** | 8 | `ALERT_SYN_RATE` | `tcp_syn_arrival_rate` | 0 | 120,000 |
| 160,000 | 80,000 pps | **0.001875 s** | 8 | `ALERT_SYN_RATE` | `tcp_syn_arrival_rate` | 0 | 240,000 |
