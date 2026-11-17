### Table S7-A: Phase 7 Live Detector Replay Parity Evaluation on Session 3 Captures (`phase7_parity_eval.json`)
| PCAP File | Scenario / Evaluation Group | Rep | Live Replay Delay (s) | Ground Truth Delay (s) | Signed Delay Diff (s) | Live Alerted (s) | Ground Truth Alerted (s) | Parity Status |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `session3_benign_baseline_900s.pcap` | Benign Baseline (900S) | 1 | None | None | 0.0000 | 0 | 0 | **PASS** |
| `session3_tcp_syn_flood_50pps_rep1.pcap` | Tcp Syn Flood 50Pps | 1 | 2.3802 | 2.4199 | -0.0397 | 118 | 118 | **PASS** |
| `session3_tcp_syn_flood_50pps_rep2.pcap` | Tcp Syn Flood 50Pps | 2 | 2.3803 | 2.4417 | -0.0614 | 118 | 118 | **PASS** |
| `session3_tcp_syn_flood_50pps_rep3.pcap` | Tcp Syn Flood 50Pps | 3 | 2.3804 | 2.4811 | -0.1007 | 118 | 118 | **PASS** |
| `session3_tcp_syn_flood_200pps_rep1.pcap` | Tcp Syn Flood 200Pps | 1 | 2.0953 | 2.1443 | -0.0490 | 118 | 118 | **PASS** |
| `session3_tcp_syn_flood_200pps_rep2.pcap` | Tcp Syn Flood 200Pps | 2 | 2.0946 | 2.1557 | -0.0611 | 118 | 118 | **PASS** |
| `session3_tcp_syn_flood_200pps_rep3.pcap` | Tcp Syn Flood 200Pps | 3 | 2.0947 | 2.1407 | -0.0460 | 118 | 118 | **PASS** |
| `session3_tcp_syn_flood_500pps_rep1.pcap` | Tcp Syn Flood 500Pps | 1 | 2.0376 | 2.1046 | -0.0670 | 118 | 118 | **PASS** |
| `session3_tcp_syn_flood_500pps_rep2.pcap` | Tcp Syn Flood 500Pps | 2 | 2.0377 | 2.0813 | -0.0436 | 118 | 118 | **PASS** |
| `session3_tcp_syn_flood_500pps_rep3.pcap` | Tcp Syn Flood 500Pps | 3 | 2.0387 | 2.1550 | -0.1163 | 118 | 118 | **PASS** |
| `session3_tcp_syn_flood_1000pps_rep1.pcap` | Tcp Syn Flood 1000Pps | 1 | 2.0198 | 2.1076 | -0.0878 | 118 | 118 | **PASS** |
| `session3_tcp_syn_flood_1000pps_rep2.pcap` | Tcp Syn Flood 1000Pps | 2 | 2.0194 | 2.1618 | -0.1424 | 118 | 118 | **PASS** |
| `session3_tcp_syn_flood_1000pps_rep3.pcap` | Tcp Syn Flood 1000Pps | 3 | 2.0190 | 2.1099 | -0.0909 | 118 | 118 | **PASS** |
| `session3_udp_flood_random_ports_50pps_rep1.pcap` | Udp Flood Random Ports 50Pps | 1 | 0.3999 | 0.5393 | -0.1394 | 120 | 120 | **PASS** |
| `session3_udp_flood_random_ports_50pps_rep2.pcap` | Udp Flood Random Ports 50Pps | 2 | 0.3999 | 0.5405 | -0.1406 | 120 | 120 | **PASS** |
| `session3_udp_flood_random_ports_50pps_rep3.pcap` | Udp Flood Random Ports 50Pps | 3 | 0.3997 | 0.5535 | -0.1538 | 120 | 120 | **PASS** |
| `session3_udp_flood_random_ports_200pps_rep1.pcap` | Udp Flood Random Ports 200Pps | 1 | 0.1204 | 0.1651 | -0.0447 | 120 | 120 | **PASS** |
| `session3_udp_flood_random_ports_200pps_rep2.pcap` | Udp Flood Random Ports 200Pps | 2 | 0.1196 | 0.1637 | -0.0441 | 120 | 120 | **PASS** |
| `session3_udp_flood_random_ports_200pps_rep3.pcap` | Udp Flood Random Ports 200Pps | 3 | 0.1207 | 0.1650 | -0.0443 | 120 | 120 | **PASS** |
| `session3_udp_flood_random_ports_500pps_rep1.pcap` | Udp Flood Random Ports 500Pps | 1 | 0.0577 | 0.0707 | -0.0130 | 120 | 120 | **PASS** |
| `session3_udp_flood_random_ports_500pps_rep2.pcap` | Udp Flood Random Ports 500Pps | 2 | 0.0488 | 0.0685 | -0.0197 | 120 | 120 | **PASS** |
| `session3_udp_flood_random_ports_500pps_rep3.pcap` | Udp Flood Random Ports 500Pps | 3 | 0.0495 | 0.0690 | -0.0195 | 120 | 120 | **PASS** |
| `session3_udp_flood_random_ports_1000pps_rep1.pcap` | Udp Flood Random Ports 1000Pps | 1 | 0.0256 | 0.0355 | -0.0099 | 120 | 120 | **PASS** |
| `session3_udp_flood_random_ports_1000pps_rep2.pcap` | Udp Flood Random Ports 1000Pps | 2 | 0.0250 | 0.0352 | -0.0102 | 120 | 120 | **PASS** |
| `session3_udp_flood_random_ports_1000pps_rep3.pcap` | Udp Flood Random Ports 1000Pps | 3 | 0.0275 | 0.0343 | -0.0068 | 120 | 120 | **PASS** |
| `session3_udp_flood_volumetric_port80_50pps_rep1.pcap` | Udp Flood Volumetric Port80 50Pps | 1 | 0.5398 | 0.5398 | +0.0000 | 120 | 120 | **PASS** |
| `session3_udp_flood_volumetric_port80_50pps_rep2.pcap` | Udp Flood Volumetric Port80 50Pps | 2 | 0.5404 | 0.5404 | +0.0000 | 120 | 120 | **PASS** |
| `session3_udp_flood_volumetric_port80_50pps_rep3.pcap` | Udp Flood Volumetric Port80 50Pps | 3 | 0.5398 | 0.5398 | +0.0000 | 120 | 120 | **PASS** |
| `session3_udp_flood_volumetric_port80_200pps_rep1.pcap` | Udp Flood Volumetric Port80 200Pps | 1 | 0.1681 | 0.1681 | +0.0000 | 120 | 120 | **PASS** |
| `session3_udp_flood_volumetric_port80_200pps_rep2.pcap` | Udp Flood Volumetric Port80 200Pps | 2 | 0.1641 | 0.1641 | +0.0000 | 120 | 120 | **PASS** |
| `session3_udp_flood_volumetric_port80_200pps_rep3.pcap` | Udp Flood Volumetric Port80 200Pps | 3 | 0.1697 | 0.1697 | +0.0000 | 120 | 120 | **PASS** |
| `session3_udp_flood_volumetric_port80_500pps_rep1.pcap` | Udp Flood Volumetric Port80 500Pps | 1 | 0.0699 | 0.0699 | +0.0000 | 120 | 120 | **PASS** |
| `session3_udp_flood_volumetric_port80_500pps_rep2.pcap` | Udp Flood Volumetric Port80 500Pps | 2 | 0.0688 | 0.0688 | +0.0000 | 120 | 120 | **PASS** |
| `session3_udp_flood_volumetric_port80_500pps_rep3.pcap` | Udp Flood Volumetric Port80 500Pps | 3 | 0.0699 | 0.0699 | +0.0000 | 120 | 120 | **PASS** |
| `session3_udp_flood_volumetric_port80_1000pps_rep1.pcap` | Udp Flood Volumetric Port80 1000Pps | 1 | 0.0349 | 0.0349 | +0.0000 | 120 | 120 | **PASS** |
| `session3_udp_flood_volumetric_port80_1000pps_rep2.pcap` | Udp Flood Volumetric Port80 1000Pps | 2 | 0.0337 | 0.0337 | +0.0000 | 120 | 120 | **PASS** |
| `session3_udp_flood_volumetric_port80_1000pps_rep3.pcap` | Udp Flood Volumetric Port80 1000Pps | 3 | 0.0349 | 0.0349 | +0.0000 | 120 | 120 | **PASS** |
| `session3_reconnaissance_port_scan_30pps_rep1.pcap` | Reconnaissance Port Scan 30Pps | 1 | 2.4674 | 2.4674 | +0.0000 | 118 | 118 | **PASS** |
| `session3_reconnaissance_port_scan_30pps_rep2.pcap` | Reconnaissance Port Scan 30Pps | 2 | 2.4663 | 2.4663 | +0.0000 | 118 | 118 | **PASS** |
| `session3_reconnaissance_port_scan_30pps_rep3.pcap` | Reconnaissance Port Scan 30Pps | 3 | 2.4663 | 2.4663 | +0.0000 | 118 | 118 | **PASS** |

*Parity Acceptance Criteria: Replay first-alert delay tolerance = 0.25 s (observed max absolute delta = 0.1538 s); alerted seconds tolerance = 1 s (observed max delta = 0 s); benign baseline false alarm seconds = 0.*
*Consistent Negative Offset Explanation: Live streaming evaluates a continuous sliding window driven by instantaneous packet arrival timestamps, whereas offline ground truth evaluated discrete 1.0s calendar bins or updated batch arrays. This enables continuous streaming to detect threshold crossing slightly earlier (by -0.01s to -0.15s).*
*Overall Evaluation Result: **40/40 Passed (0 Failures, 100% Parity at 0.25s tolerance)**.*

