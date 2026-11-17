### Table S7-G: Phase 7 Synthetic Replay Single-Source Flood Grid (`results/phase7_round3_evaluation.json`)
*Classification: Synthetic Replay through RuleEngine (Single source IP 172.20.0.3, single-source threshold = 1500 pkts/s)*
| Table Capacity Cap | Packet Rate | First Alert Delay (s) | Alert Count (5s) | First Alert Class | Triggering Rule | Capacity Evictions | Timeout Expired Handshakes |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| 20,000 | 20,000 pps | **0.075000 s** | 5 | `ALERT_SYN_RATE` | `tcp_syn_arrival_rate` | 80,000 | 0 |
| 20,000 | 40,000 pps | **0.037500 s** | 5 | `ALERT_SYN_RATE` | `tcp_syn_arrival_rate` | 180,000 | 0 |
| 20,000 | 80,000 pps | **0.018750 s** | 5 | `ALERT_SYN_RATE` | `tcp_syn_arrival_rate` | 380,000 | 0 |
| 160,000 | 20,000 pps | **0.075000 s** | 8 | `ALERT_SYN_RATE` | `tcp_syn_arrival_rate` | 0 | 59,999 |
| 160,000 | 40,000 pps | **0.037500 s** | 5 | `ALERT_SYN_RATE` | `tcp_syn_arrival_rate` | 0 | 0 |
| 160,000 | 80,000 pps | **0.018750 s** | 5 | `ALERT_SYN_RATE` | `tcp_syn_arrival_rate` | 0 | 0 |
