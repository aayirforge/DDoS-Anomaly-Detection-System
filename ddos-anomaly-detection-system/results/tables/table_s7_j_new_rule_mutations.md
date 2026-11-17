### Table S7-J: Phase 7 Mutation Sensitivity on Session 2b Capture (`results/phase7_round3_evaluation.json`)
*Evaluated directly on `lab/captures/session2b/lab_spoofed_syn_flood.pcap` (Internal lab spoofed SYN flood)*
| Configuration / Mutation | Detection Status | Alert Count | First Alert Delay (s) | First Alert Class | Triggering Rule | Differing First-Alert Field |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| Baseline (thresh=150, srcs=3, single=1500) | **DETECTED** | 22 | 0.774215 s | `ALERT_SYN_RATE` | `tcp_syn_arrival_rate` | Baseline reference |
| Mutation 1 (150 -> 200) | **NOT DETECTED** | 10 | 2.072268 s | `ALERT_SYN_FLOOD` | `tcp_incomplete_handshake` | alert_type (ALERT_SYN_FLOOD vs ALERT_SYN_RATE) |
| Mutation 2 (sources 3 -> 5) | **DETECTED** | 22 | 0.774215 s | `ALERT_SYN_RATE` | `tcp_syn_arrival_rate` | Identical first alert (high source entropy) |
| Mutation 3 (150 -> 100) | **DETECTED** | 22 | 0.515674 s | `ALERT_SYN_RATE` | `tcp_syn_arrival_rate` | packet_ts (1794816974.7899 vs 1794816975.0484, delta: -0.2585s) |
| Mutation 4 (single 1500 -> 2000) | **DETECTED** | 22 | 0.774215 s | `ALERT_SYN_RATE` | `tcp_syn_arrival_rate` | Identical first alert (high source entropy) |
| Mutation 5 (single 1500 -> 1000) | **DETECTED** | 22 | 0.774215 s | `ALERT_SYN_RATE` | `tcp_syn_arrival_rate` | Identical first alert (high source entropy) |
