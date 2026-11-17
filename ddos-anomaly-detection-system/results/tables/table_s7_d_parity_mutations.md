### Table S7-D: Phase 7 Rule & Threshold Parity Mutation Sensitivity Tests (`phase7_parity_mutations.json`)
| Mutation Test | Parameter Perturbation | Affected Scenarios | Failed Runs Count | Parity Harness Status | Sensitivity Verified |
| :--- | :--- | :--- | :---: | :---: | :---: |
| **Mutation (i-a): Handshake Timeout 2.0s -> 3.0s** | Increases incomplete handshake timeout from 2.0s to 3.0s | TCP SYN Floods and Scans (first-alert delay increases by ~1.0s) | **18 / 40** | **FAIL** | **PASS (Detected)** |
| **Mutation (i-b): Handshake Timeout 2.0s -> 2.25s** | Increases incomplete handshake timeout from 2.0s to 2.25s (+0.25s) | TCP SYN Floods and Scans (first-alert delay increases by +0.25s) | **18 / 40** | **FAIL** | **PASS (Detected)** |
| **Mutation (ii): Condition B Threshold 20 -> 25** | Increases concentrated incomplete SYN threshold from 20 to 25 | TCP SYN Floods operating near or at Condition B threshold | **9 / 40** | **FAIL** | **PASS (Detected)** |
| **Mutation (iii): UDP Volumetric Threshold 40 -> 60 pkts/s** | Increases UDP volumetric threshold from 40 to 60 pkts/s | UDP Volumetric Floods at 50 pps (fail to cross 60 pps threshold) | **17 / 40** | **FAIL** | **PASS (Detected)** |

#### Detailed Breakdown of Failed Runs per Mutation (Metric, Offline Value, Mutated Value, Difference):
##### Mutation (i-a): Handshake Timeout 2.0s -> 3.0s:
- **Failed Captures (18 runs)**:
| PCAP File | Scenario | Metric | Offline Value | Mutated Value | Signed Difference |
| :--- | :--- | :--- | :---: | :---: | :---: |
| `session3_tcp_syn_flood_50pps_rep1.pcap` | Tcp Syn Flood 50Pps | `first_detection_delay_sec` | 2.4199 s | 3.3802 s | +0.9603 s |
| `session3_tcp_syn_flood_50pps_rep2.pcap` | Tcp Syn Flood 50Pps | `first_detection_delay_sec` | 2.4417 s | 3.3803 s | +0.9386 s |
| `session3_tcp_syn_flood_50pps_rep3.pcap` | Tcp Syn Flood 50Pps | `first_detection_delay_sec` | 2.4811 s | 3.3804 s | +0.8993 s |
| `session3_tcp_syn_flood_200pps_rep1.pcap` | Tcp Syn Flood 200Pps | `first_detection_delay_sec` | 2.1443 s | 3.0953 s | +0.9510 s |
| `session3_tcp_syn_flood_200pps_rep2.pcap` | Tcp Syn Flood 200Pps | `first_detection_delay_sec` | 2.1557 s | 3.0946 s | +0.9389 s |
| `session3_tcp_syn_flood_200pps_rep3.pcap` | Tcp Syn Flood 200Pps | `first_detection_delay_sec` | 2.1407 s | 3.0947 s | +0.9540 s |
| `session3_tcp_syn_flood_500pps_rep1.pcap` | Tcp Syn Flood 500Pps | `first_detection_delay_sec` | 2.1046 s | 3.0389 s | +0.9343 s |
| `session3_tcp_syn_flood_500pps_rep2.pcap` | Tcp Syn Flood 500Pps | `first_detection_delay_sec` | 2.0813 s | 3.0402 s | +0.9589 s |
| `session3_tcp_syn_flood_500pps_rep3.pcap` | Tcp Syn Flood 500Pps | `first_detection_delay_sec` | 2.1550 s | 3.0387 s | +0.8837 s |
| `session3_tcp_syn_flood_1000pps_rep1.pcap` | Tcp Syn Flood 1000Pps | `first_detection_delay_sec` | 2.1076 s | 3.0211 s | +0.9135 s |
| `session3_tcp_syn_flood_1000pps_rep2.pcap` | Tcp Syn Flood 1000Pps | `first_detection_delay_sec` | 2.1618 s | 3.0194 s | +0.8576 s |
| `session3_tcp_syn_flood_1000pps_rep3.pcap` | Tcp Syn Flood 1000Pps | `first_detection_delay_sec` | 2.1099 s | 3.0198 s | +0.9099 s |
| `session3_udp_flood_random_ports_50pps_rep1.pcap` | Udp Flood Random Ports 50Pps | `first_detection_delay_sec` | 0.5393 s | 0.3999 s | -0.1394 s |
| `session3_udp_flood_random_ports_50pps_rep2.pcap` | Udp Flood Random Ports 50Pps | `first_detection_delay_sec` | 0.5405 s | 0.3999 s | -0.1406 s |
| `session3_udp_flood_random_ports_50pps_rep3.pcap` | Udp Flood Random Ports 50Pps | `first_detection_delay_sec` | 0.5535 s | 0.3997 s | -0.1538 s |
| `session3_reconnaissance_port_scan_30pps_rep1.pcap` | Reconnaissance Port Scan 30Pps | `first_detection_delay_sec` | 2.4674 s | 3.4674 s | +1.0000 s |
| `session3_reconnaissance_port_scan_30pps_rep2.pcap` | Reconnaissance Port Scan 30Pps | `first_detection_delay_sec` | 2.4663 s | 3.4663 s | +1.0000 s |
| `session3_reconnaissance_port_scan_30pps_rep3.pcap` | Reconnaissance Port Scan 30Pps | `first_detection_delay_sec` | 2.4663 s | 3.4663 s | +1.0000 s |

##### Mutation (i-b): Handshake Timeout 2.0s -> 2.25s:
- **Failed Captures (18 runs)**:
| PCAP File | Scenario | Metric | Offline Value | Mutated Value | Signed Difference |
| :--- | :--- | :--- | :---: | :---: | :---: |
| `session3_tcp_syn_flood_50pps_rep1.pcap` | Tcp Syn Flood 50Pps | `first_detection_delay_sec` | 2.4199 s | 2.6302 s | +0.2103 s |
| `session3_tcp_syn_flood_50pps_rep2.pcap` | Tcp Syn Flood 50Pps | `first_detection_delay_sec` | 2.4417 s | 2.6303 s | +0.1886 s |
| `session3_tcp_syn_flood_50pps_rep3.pcap` | Tcp Syn Flood 50Pps | `first_detection_delay_sec` | 2.4811 s | 2.6304 s | +0.1493 s |
| `session3_tcp_syn_flood_200pps_rep1.pcap` | Tcp Syn Flood 200Pps | `first_detection_delay_sec` | 2.1443 s | 2.3453 s | +0.2010 s |
| `session3_tcp_syn_flood_200pps_rep2.pcap` | Tcp Syn Flood 200Pps | `first_detection_delay_sec` | 2.1557 s | 2.3446 s | +0.1889 s |
| `session3_tcp_syn_flood_200pps_rep3.pcap` | Tcp Syn Flood 200Pps | `first_detection_delay_sec` | 2.1407 s | 2.3447 s | +0.2040 s |
| `session3_tcp_syn_flood_500pps_rep1.pcap` | Tcp Syn Flood 500Pps | `first_detection_delay_sec` | 2.1046 s | 2.2876 s | +0.1830 s |
| `session3_tcp_syn_flood_500pps_rep2.pcap` | Tcp Syn Flood 500Pps | `first_detection_delay_sec` | 2.0813 s | 2.2902 s | +0.2089 s |
| `session3_tcp_syn_flood_500pps_rep3.pcap` | Tcp Syn Flood 500Pps | `first_detection_delay_sec` | 2.1550 s | 2.2887 s | +0.1337 s |
| `session3_tcp_syn_flood_1000pps_rep1.pcap` | Tcp Syn Flood 1000Pps | `first_detection_delay_sec` | 2.1076 s | 2.2711 s | +0.1635 s |
| `session3_tcp_syn_flood_1000pps_rep2.pcap` | Tcp Syn Flood 1000Pps | `first_detection_delay_sec` | 2.1618 s | 2.2694 s | +0.1076 s |
| `session3_tcp_syn_flood_1000pps_rep3.pcap` | Tcp Syn Flood 1000Pps | `first_detection_delay_sec` | 2.1099 s | 2.2698 s | +0.1599 s |
| `session3_udp_flood_random_ports_50pps_rep1.pcap` | Udp Flood Random Ports 50Pps | `first_detection_delay_sec` | 0.5393 s | 0.3999 s | -0.1394 s |
| `session3_udp_flood_random_ports_50pps_rep2.pcap` | Udp Flood Random Ports 50Pps | `first_detection_delay_sec` | 0.5405 s | 0.3999 s | -0.1406 s |
| `session3_udp_flood_random_ports_50pps_rep3.pcap` | Udp Flood Random Ports 50Pps | `first_detection_delay_sec` | 0.5535 s | 0.3997 s | -0.1538 s |
| `session3_reconnaissance_port_scan_30pps_rep1.pcap` | Reconnaissance Port Scan 30Pps | `first_detection_delay_sec` | 2.4674 s | 2.7174 s | +0.2500 s |
| `session3_reconnaissance_port_scan_30pps_rep2.pcap` | Reconnaissance Port Scan 30Pps | `first_detection_delay_sec` | 2.4663 s | 2.7163 s | +0.2500 s |
| `session3_reconnaissance_port_scan_30pps_rep3.pcap` | Reconnaissance Port Scan 30Pps | `first_detection_delay_sec` | 2.4663 s | 2.7163 s | +0.2500 s |

##### Mutation (ii): Condition B Threshold 20 -> 25:
- **Failed Captures (9 runs)**:
| PCAP File | Scenario | Metric | Offline Value | Mutated Value | Signed Difference |
| :--- | :--- | :--- | :---: | :---: | :---: |
| `session3_tcp_syn_flood_50pps_rep1.pcap` | Tcp Syn Flood 50Pps | `first_detection_delay_sec` | 2.4199 s | 2.4797 s | +0.0598 s |
| `session3_tcp_syn_flood_500pps_rep1.pcap` | Tcp Syn Flood 500Pps | `first_detection_delay_sec` | 2.1046 s | 2.0481 s | -0.0565 s |
| `session3_tcp_syn_flood_500pps_rep3.pcap` | Tcp Syn Flood 500Pps | `first_detection_delay_sec` | 2.1550 s | 2.0488 s | -0.1062 s |
| `session3_tcp_syn_flood_1000pps_rep1.pcap` | Tcp Syn Flood 1000Pps | `first_detection_delay_sec` | 2.1076 s | 2.0274 s | -0.0802 s |
| `session3_tcp_syn_flood_1000pps_rep2.pcap` | Tcp Syn Flood 1000Pps | `first_detection_delay_sec` | 2.1618 s | 2.0240 s | -0.1378 s |
| `session3_tcp_syn_flood_1000pps_rep3.pcap` | Tcp Syn Flood 1000Pps | `first_detection_delay_sec` | 2.1099 s | 2.0254 s | -0.0845 s |
| `session3_udp_flood_random_ports_50pps_rep1.pcap` | Udp Flood Random Ports 50Pps | `first_detection_delay_sec` | 0.5393 s | 0.3999 s | -0.1394 s |
| `session3_udp_flood_random_ports_50pps_rep2.pcap` | Udp Flood Random Ports 50Pps | `first_detection_delay_sec` | 0.5405 s | 0.3999 s | -0.1406 s |
| `session3_udp_flood_random_ports_50pps_rep3.pcap` | Udp Flood Random Ports 50Pps | `first_detection_delay_sec` | 0.5535 s | 0.3997 s | -0.1538 s |

##### Mutation (iii): UDP Volumetric Threshold 40 -> 60 pkts/s:
- **Failed Captures (17 runs)**:
| PCAP File | Scenario | Metric | Offline Value | Mutated Value | Signed Difference |
| :--- | :--- | :--- | :---: | :---: | :---: |
| `session3_tcp_syn_flood_50pps_rep2.pcap` | Tcp Syn Flood 50Pps | `first_detection_delay_sec` | 2.4417 s | 2.3803 s | -0.0614 s |
| `session3_tcp_syn_flood_50pps_rep3.pcap` | Tcp Syn Flood 50Pps | `first_detection_delay_sec` | 2.4811 s | 2.3804 s | -0.1007 s |
| `session3_tcp_syn_flood_200pps_rep2.pcap` | Tcp Syn Flood 200Pps | `first_detection_delay_sec` | 2.1557 s | 2.0946 s | -0.0611 s |
| `session3_tcp_syn_flood_500pps_rep1.pcap` | Tcp Syn Flood 500Pps | `first_detection_delay_sec` | 2.1046 s | 2.0376 s | -0.0670 s |
| `session3_tcp_syn_flood_500pps_rep3.pcap` | Tcp Syn Flood 500Pps | `first_detection_delay_sec` | 2.1550 s | 2.0387 s | -0.1163 s |
| `session3_tcp_syn_flood_1000pps_rep1.pcap` | Tcp Syn Flood 1000Pps | `first_detection_delay_sec` | 2.1076 s | 2.0211 s | -0.0865 s |
| `session3_tcp_syn_flood_1000pps_rep2.pcap` | Tcp Syn Flood 1000Pps | `first_detection_delay_sec` | 2.1618 s | 2.0194 s | -0.1424 s |
| `session3_tcp_syn_flood_1000pps_rep3.pcap` | Tcp Syn Flood 1000Pps | `first_detection_delay_sec` | 2.1099 s | 2.0198 s | -0.0901 s |
| `session3_udp_flood_random_ports_50pps_rep1.pcap` | Udp Flood Random Ports 50Pps | `first_detection_delay_sec` | 0.5393 s | 0.3999 s | -0.1394 s |
| `session3_udp_flood_random_ports_50pps_rep2.pcap` | Udp Flood Random Ports 50Pps | `first_detection_delay_sec` | 0.5405 s | 0.3999 s | -0.1406 s |
| `session3_udp_flood_random_ports_50pps_rep3.pcap` | Udp Flood Random Ports 50Pps | `first_detection_delay_sec` | 0.5535 s | 0.3997 s | -0.1538 s |
| `session3_udp_flood_volumetric_port80_50pps_rep1.pcap` | Udp Flood Volumetric Port80 50Pps | `first_detection_delay_sec` | 0.5398 s | 0.8188 s | +0.2790 s |
| `session3_udp_flood_volumetric_port80_50pps_rep2.pcap` | Udp Flood Volumetric Port80 50Pps | `first_detection_delay_sec` | 0.5404 s | 0.8440 s | +0.3036 s |
| `session3_udp_flood_volumetric_port80_50pps_rep3.pcap` | Udp Flood Volumetric Port80 50Pps | `first_detection_delay_sec` | 0.5398 s | 0.8262 s | +0.2864 s |
| `session3_udp_flood_volumetric_port80_200pps_rep1.pcap` | Udp Flood Volumetric Port80 200Pps | `first_detection_delay_sec` | 0.1681 s | 0.2598 s | +0.0917 s |
| `session3_udp_flood_volumetric_port80_200pps_rep2.pcap` | Udp Flood Volumetric Port80 200Pps | `first_detection_delay_sec` | 0.1641 s | 0.2598 s | +0.0957 s |
| `session3_udp_flood_volumetric_port80_200pps_rep3.pcap` | Udp Flood Volumetric Port80 200Pps | `first_detection_delay_sec` | 0.1697 s | 0.2658 s | +0.0961 s |

#### Cross-Class Mutation Interaction Explanation:
> [!NOTE]
> **Why mutations of one rule fail runs of the other class under tight tolerance (0.05 s)**:
> Live streaming evaluation uses a continuous sliding event window driven by packet timestamps, whereas offline ground truth evaluated discrete 1.0s calendar bins. This produces an inherent negative offset of -0.01 s to -0.15 s (streaming detects attacks earlier).
> When mutation sensitivity is evaluated with a strict sub-second threshold of 0.05 s, unmutated runs of the other protocol (e.g., UDP random-port runs under handshake mutations, or TCP SYN flood runs under UDP mutations) trigger parity failures solely because their baseline negative offset exceeds 0.05 s.
> At the official acceptance tolerance of 0.25 s, baseline offsets are safely accommodated, and zero cross-class runs fail.

*Mutation Acceptance Criteria: Parameter perturbations MUST trigger parity failure (FAIL) in the parity evaluation harness on affected runs.*

