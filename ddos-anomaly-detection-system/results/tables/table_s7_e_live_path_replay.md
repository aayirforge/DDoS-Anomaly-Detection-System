### Table S7-E: Phase 7 Full Live Path Replay Verification (`phase7_live_path_replay.json`)
| Evaluation Capture | Scenario | Packets | Live Replay First Alert Delay (s) | Offline Frozen Delay (s) | Signed Delay Diff (s) | Alerted Post-1st-Alert (s) | False Alarm (s) | Live Replay Status |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `session3_benign_baseline_900s.pcap` | Benign Multi-Protocol Baseline (900s) | 81,393 | None | None | 0.0000 | 0 (Offline: 0) | 0 | **PASS** |
| `session3_tcp_syn_flood_50pps_rep1.pcap` | TCP SYN Flood 50 pps (Rep 1) | 17,302 | 2.3802 | 2.4199 | -0.0397 | 118 (Offline: 118) | 0 | **PASS** |
| `session3_tcp_syn_flood_1000pps_rep1.pcap` | TCP SYN Flood 1,000 pps (Rep 1) | 132,530 | 2.0211 | 2.1076 | -0.0865 | 118 (Offline: 118) | 0 | **PASS** |
| `session3_udp_flood_random_ports_50pps_rep1.pcap` | UDP Random-Port Flood 50 pps (Rep 1) | 17,450 | 0.3999 | 0.5393 | -0.1394 | 120 (Offline: 120) | 0 | **PASS** |
| `session3_udp_flood_volumetric_port80_200pps_rep1.pcap` | UDP Volumetric Flood 200 pps Port 80 (Rep 1) | 35,185 | 0.1681 | 0.1681 | +0.0000 | 120 (Offline: 120) | 0 | **PASS** |
| `session3_reconnaissance_port_scan_30pps_rep1.pcap` | Port Scan 30 pps (Rep 1) | 18,569 | 2.4674 | 2.4674 | +0.0000 | 118 (Offline: 118) | 0 | **PASS** |

- **Alerted Seconds Evaluation Basis**: Evaluated post-first-alert over remaining attack seconds within the 120s window (matching `session3_evaluation.json`).
- **Maximum Absolute Delay Delta across Live Path Runs**: **0.1394 s** (Tolerance $\le 1.0$ s; signed offset is negative due to continuous sliding evaluation)
- **Operational Mode**: **Alert-Only Throughout** (Zero active packet dropping; `enable_blocking=False`).
- **Overall Verification Status**: **6/6 PASS**.

