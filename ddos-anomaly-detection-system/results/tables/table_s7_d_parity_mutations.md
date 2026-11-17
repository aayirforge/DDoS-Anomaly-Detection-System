### Table S7-D: Phase 7 Rule & Threshold Parity Mutation Sensitivity Tests (`phase7_parity_mutations.json`)
| Mutation Test | Parameter Perturbation | Affected Scenarios | Failed Runs | Unmutated Class Pass Rate | Status | Sensitivity Verified |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: |
| **Mutation (i-a): Handshake Timeout 2.0s -> 3.0s** | Increases incomplete handshake timeout from 2.0s to 3.0s | TCP SYN Floods and Scans (first-alert delay increases by ~1.0s) | **15 / 40** | **100% PASS** (UDP Floods & Baseline (25 runs)) | **FAIL** | **PASS (Detected)** |
| **Mutation (i-b): Handshake Timeout 2.0s -> 2.25s** | Increases incomplete handshake timeout from 2.0s to 2.25s (+0.25s) | TCP SYN Floods and Scans (first-alert delay increases by +0.25s) | **15 / 40** | **100% PASS** (UDP Floods & Baseline (25 runs)) | **FAIL** | **PASS (Detected)** |
| **Mutation (ii-a): Condition B Threshold 20 -> 25** | Increases concentrated incomplete SYN threshold from 20 to 25 | TCP SYN Floods triggering on Condition B | **12 / 40** | **100% PASS** (UDP Floods, Scans & Baseline (28 runs)) | **FAIL** | **PASS (Detected)** |
| **Mutation (ii-b): Condition B Threshold 20 -> 30** | Increases concentrated incomplete SYN threshold from 20 to 30 | TCP SYN Floods triggering on Condition B | **12 / 40** | **100% PASS** (UDP Floods, Scans & Baseline (28 runs)) | **FAIL** | **PASS (Detected)** |
| **Mutation (iii): UDP Volumetric Threshold 40 -> 60 pkts/s** | Increases UDP volumetric threshold from 40 to 60 pkts/s | UDP Volumetric Floods at 50 pps | **12 / 40** | **100% PASS** (TCP SYN Floods, Scans & Baseline (16 runs)) | **FAIL** | **PASS (Detected)** |

#### Detailed Breakdown of Failed Runs per Mutation (Field Differed, Streaming Baseline, Mutated Value):
##### Mutation (i-a): Handshake Timeout 2.0s -> 3.0s:
- **Failed Captures (15 runs)**:
| PCAP File | Scenario | Differing Field(s) | Streaming Baseline Value | Mutated Value | Signed Delay Diff |
| :--- | :--- | :--- | :---: | :---: | :---: |
| `session3_tcp_syn_flood_50pps_rep1.pcap` | Tcp Syn Flood 50Pps | `first_detection_delay_sec (2.3802s -> 3.3802s, diff=1.0s)<br>alert_seconds_set (120s -> 120s)` | 3.3802 s | 3.3802 s | +1.0000 s |
| `session3_tcp_syn_flood_50pps_rep2.pcap` | Tcp Syn Flood 50Pps | `first_detection_delay_sec (2.3803s -> 3.3803s, diff=1.0s)<br>alert_seconds_set (120s -> 120s)` | 3.3803 s | 3.3803 s | +1.0000 s |
| `session3_tcp_syn_flood_50pps_rep3.pcap` | Tcp Syn Flood 50Pps | `first_detection_delay_sec (2.3804s -> 3.3804s, diff=1.0s)<br>alert_seconds_set (120s -> 120s)` | 3.3804 s | 3.3804 s | +1.0000 s |
| `session3_tcp_syn_flood_200pps_rep1.pcap` | Tcp Syn Flood 200Pps | `first_detection_delay_sec (2.0953s -> 3.0953s, diff=1.0s)<br>alert_seconds_set (120s -> 120s)` | 3.0953 s | 3.0953 s | +1.0000 s |
| `session3_tcp_syn_flood_200pps_rep2.pcap` | Tcp Syn Flood 200Pps | `first_detection_delay_sec (2.0946s -> 3.0946s, diff=1.0s)<br>alert_seconds_set (120s -> 120s)` | 3.0946 s | 3.0946 s | +1.0000 s |
| `session3_tcp_syn_flood_200pps_rep3.pcap` | Tcp Syn Flood 200Pps | `first_detection_delay_sec (2.0947s -> 3.0947s, diff=1.0s)<br>alert_seconds_set (120s -> 120s)` | 3.0947 s | 3.0947 s | +1.0000 s |
| `session3_tcp_syn_flood_500pps_rep1.pcap` | Tcp Syn Flood 500Pps | `first_detection_delay_sec (2.0376s -> 3.0376s, diff=1.0s)<br>alert_seconds_set (120s -> 120s)` | 3.0376 s | 3.0376 s | +1.0000 s |
| `session3_tcp_syn_flood_500pps_rep2.pcap` | Tcp Syn Flood 500Pps | `first_detection_delay_sec (2.0377s -> 3.0377s, diff=1.0s)<br>alert_seconds_set (120s -> 120s)` | 3.0377 s | 3.0377 s | +1.0000 s |
| `session3_tcp_syn_flood_500pps_rep3.pcap` | Tcp Syn Flood 500Pps | `first_detection_delay_sec (2.0387s -> 3.0387s, diff=1.0s)<br>alert_seconds_set (120s -> 120s)` | 3.0387 s | 3.0387 s | +1.0000 s |
| `session3_tcp_syn_flood_1000pps_rep1.pcap` | Tcp Syn Flood 1000Pps | `first_detection_delay_sec (2.0198s -> 3.0198s, diff=1.0s)<br>alert_seconds_set (120s -> 120s)` | 3.0198 s | 3.0198 s | +1.0000 s |
| `session3_tcp_syn_flood_1000pps_rep2.pcap` | Tcp Syn Flood 1000Pps | `first_detection_delay_sec (2.0194s -> 3.0194s, diff=1.0s)<br>alert_seconds_set (120s -> 120s)` | 3.0194 s | 3.0194 s | +1.0000 s |
| `session3_tcp_syn_flood_1000pps_rep3.pcap` | Tcp Syn Flood 1000Pps | `first_detection_delay_sec (2.019s -> 3.019s, diff=1.0s)<br>alert_seconds_set (121s -> 121s)` | 3.0190 s | 3.0190 s | +1.0000 s |
| `session3_reconnaissance_port_scan_30pps_rep1.pcap` | Reconnaissance Port Scan 30Pps | `first_detection_delay_sec (2.4674s -> 3.4674s, diff=1.0s)<br>alert_seconds_set (121s -> 121s)` | 3.4674 s | 3.4674 s | +1.0000 s |
| `session3_reconnaissance_port_scan_30pps_rep2.pcap` | Reconnaissance Port Scan 30Pps | `first_detection_delay_sec (2.4663s -> 3.4663s, diff=1.0s)<br>alert_seconds_set (120s -> 120s)` | 3.4663 s | 3.4663 s | +1.0000 s |
| `session3_reconnaissance_port_scan_30pps_rep3.pcap` | Reconnaissance Port Scan 30Pps | `first_detection_delay_sec (2.4663s -> 3.4663s, diff=1.0s)<br>alert_seconds_set (121s -> 121s)` | 3.4663 s | 3.4663 s | +1.0000 s |

##### Mutation (i-b): Handshake Timeout 2.0s -> 2.25s:
- **Failed Captures (15 runs)**:
| PCAP File | Scenario | Differing Field(s) | Streaming Baseline Value | Mutated Value | Signed Delay Diff |
| :--- | :--- | :--- | :---: | :---: | :---: |
| `session3_tcp_syn_flood_50pps_rep1.pcap` | Tcp Syn Flood 50Pps | `first_detection_delay_sec (2.3802s -> 2.6302s, diff=0.25s)<br>alert_seconds_set (120s -> 121s)` | 2.6302 s | 2.6302 s | +0.2500 s |
| `session3_tcp_syn_flood_50pps_rep2.pcap` | Tcp Syn Flood 50Pps | `first_detection_delay_sec (2.3803s -> 2.6303s, diff=0.25s)<br>alert_seconds_set (120s -> 121s)` | 2.6303 s | 2.6303 s | +0.2500 s |
| `session3_tcp_syn_flood_50pps_rep3.pcap` | Tcp Syn Flood 50Pps | `first_detection_delay_sec (2.3804s -> 2.6304s, diff=0.25s)<br>alert_seconds_set (120s -> 121s)` | 2.6304 s | 2.6304 s | +0.2500 s |
| `session3_tcp_syn_flood_200pps_rep1.pcap` | Tcp Syn Flood 200Pps | `first_detection_delay_sec (2.0953s -> 2.3453s, diff=0.25s)<br>alert_seconds_set (120s -> 121s)` | 2.3453 s | 2.3453 s | +0.2500 s |
| `session3_tcp_syn_flood_200pps_rep2.pcap` | Tcp Syn Flood 200Pps | `first_detection_delay_sec (2.0946s -> 2.3446s, diff=0.25s)<br>alert_seconds_set (120s -> 121s)` | 2.3446 s | 2.3446 s | +0.2500 s |
| `session3_tcp_syn_flood_200pps_rep3.pcap` | Tcp Syn Flood 200Pps | `first_detection_delay_sec (2.0947s -> 2.3447s, diff=0.25s)<br>alert_seconds_set (120s -> 121s)` | 2.3447 s | 2.3447 s | +0.2500 s |
| `session3_tcp_syn_flood_500pps_rep1.pcap` | Tcp Syn Flood 500Pps | `first_detection_delay_sec (2.0376s -> 2.2876s, diff=0.25s)<br>alert_seconds_set (120s -> 121s)` | 2.2876 s | 2.2876 s | +0.2500 s |
| `session3_tcp_syn_flood_500pps_rep2.pcap` | Tcp Syn Flood 500Pps | `first_detection_delay_sec (2.0377s -> 2.2877s, diff=0.25s)<br>alert_seconds_set (120s -> 121s)` | 2.2877 s | 2.2877 s | +0.2500 s |
| `session3_tcp_syn_flood_500pps_rep3.pcap` | Tcp Syn Flood 500Pps | `first_detection_delay_sec (2.0387s -> 2.2887s, diff=0.25s)<br>alert_seconds_set (120s -> 121s)` | 2.2887 s | 2.2887 s | +0.2500 s |
| `session3_tcp_syn_flood_1000pps_rep1.pcap` | Tcp Syn Flood 1000Pps | `first_detection_delay_sec (2.0198s -> 2.2698s, diff=0.25s)<br>alert_seconds_set (120s -> 121s)` | 2.2698 s | 2.2698 s | +0.2500 s |
| `session3_tcp_syn_flood_1000pps_rep2.pcap` | Tcp Syn Flood 1000Pps | `first_detection_delay_sec (2.0194s -> 2.2694s, diff=0.25s)<br>alert_seconds_set (120s -> 121s)` | 2.2694 s | 2.2694 s | +0.2500 s |
| `session3_tcp_syn_flood_1000pps_rep3.pcap` | Tcp Syn Flood 1000Pps | `first_detection_delay_sec (2.019s -> 2.269s, diff=0.25s)` | 2.2690 s | 2.2690 s | +0.2500 s |
| `session3_reconnaissance_port_scan_30pps_rep1.pcap` | Reconnaissance Port Scan 30Pps | `first_detection_delay_sec (2.4674s -> 2.7174s, diff=0.25s)` | 2.7174 s | 2.7174 s | +0.2500 s |
| `session3_reconnaissance_port_scan_30pps_rep2.pcap` | Reconnaissance Port Scan 30Pps | `first_detection_delay_sec (2.4663s -> 2.7163s, diff=0.25s)<br>alert_seconds_set (120s -> 121s)` | 2.7163 s | 2.7163 s | +0.2500 s |
| `session3_reconnaissance_port_scan_30pps_rep3.pcap` | Reconnaissance Port Scan 30Pps | `first_detection_delay_sec (2.4663s -> 2.7163s, diff=0.25s)` | 2.7163 s | 2.7163 s | +0.2500 s |

##### Mutation (ii-a): Condition B Threshold 20 -> 25:
- **Failed Captures (12 runs)**:
| PCAP File | Scenario | Differing Field(s) | Streaming Baseline Value | Mutated Value | Signed Delay Diff |
| :--- | :--- | :--- | :---: | :---: | :---: |
| `session3_tcp_syn_flood_50pps_rep1.pcap` | Tcp Syn Flood 50Pps | `first_detection_delay_sec (2.3802s -> 2.4797s, diff=0.0995s)<br>first_alert_volume (20 -> 25)` | 2.4797 s | 2.4797 s | +0.0995 s |
| `session3_tcp_syn_flood_50pps_rep2.pcap` | Tcp Syn Flood 50Pps | `first_detection_delay_sec (2.3803s -> 2.4817s, diff=0.1014s)<br>first_alert_volume (20 -> 25)` | 2.4817 s | 2.4817 s | +0.1014 s |
| `session3_tcp_syn_flood_50pps_rep3.pcap` | Tcp Syn Flood 50Pps | `first_detection_delay_sec (2.3804s -> 2.4811s, diff=0.1007s)<br>first_alert_volume (20 -> 25)` | 2.4811 s | 2.4811 s | +0.1007 s |
| `session3_tcp_syn_flood_200pps_rep1.pcap` | Tcp Syn Flood 200Pps | `first_detection_delay_sec (2.0953s -> 2.1194s, diff=0.0241s)<br>first_alert_volume (20 -> 25)` | 2.1194 s | 2.1194 s | +0.0241 s |
| `session3_tcp_syn_flood_200pps_rep2.pcap` | Tcp Syn Flood 200Pps | `first_detection_delay_sec (2.0946s -> 2.1208s, diff=0.0262s)<br>first_alert_volume (20 -> 25)` | 2.1208 s | 2.1208 s | +0.0262 s |
| `session3_tcp_syn_flood_200pps_rep3.pcap` | Tcp Syn Flood 200Pps | `first_detection_delay_sec (2.0947s -> 2.1204s, diff=0.0257s)<br>first_alert_volume (20 -> 25)` | 2.1204 s | 2.1204 s | +0.0257 s |
| `session3_tcp_syn_flood_500pps_rep1.pcap` | Tcp Syn Flood 500Pps | `first_alert_volume (20 -> 25)` | 25 | 25 | +0.0105 s |
| `session3_tcp_syn_flood_500pps_rep2.pcap` | Tcp Syn Flood 500Pps | `first_alert_volume (20 -> 25)` | 25 | 25 | +0.0108 s |
| `session3_tcp_syn_flood_500pps_rep3.pcap` | Tcp Syn Flood 500Pps | `first_alert_volume (20 -> 25)` | 25 | 25 | +0.0101 s |
| `session3_tcp_syn_flood_1000pps_rep1.pcap` | Tcp Syn Flood 1000Pps | `first_alert_volume (20 -> 25)` | 25 | 25 | +0.0051 s |
| `session3_tcp_syn_flood_1000pps_rep2.pcap` | Tcp Syn Flood 1000Pps | `first_alert_volume (20 -> 25)` | 25 | 25 | +0.0046 s |
| `session3_tcp_syn_flood_1000pps_rep3.pcap` | Tcp Syn Flood 1000Pps | `first_alert_volume (20 -> 25)` | 25 | 25 | +0.0047 s |

##### Mutation (ii-b): Condition B Threshold 20 -> 30:
- **Failed Captures (12 runs)**:
| PCAP File | Scenario | Differing Field(s) | Streaming Baseline Value | Mutated Value | Signed Delay Diff |
| :--- | :--- | :--- | :---: | :---: | :---: |
| `session3_tcp_syn_flood_50pps_rep1.pcap` | Tcp Syn Flood 50Pps | `first_detection_delay_sec (2.3802s -> 2.5802s, diff=0.2s)<br>first_alert_volume (20 -> 30)` | 2.5802 s | 2.5802 s | +0.2000 s |
| `session3_tcp_syn_flood_50pps_rep2.pcap` | Tcp Syn Flood 50Pps | `first_detection_delay_sec (2.3803s -> 2.5815s, diff=0.2012s)<br>first_alert_volume (20 -> 30)` | 2.5815 s | 2.5815 s | +0.2012 s |
| `session3_tcp_syn_flood_50pps_rep3.pcap` | Tcp Syn Flood 50Pps | `first_detection_delay_sec (2.3804s -> 2.5807s, diff=0.2003s)<br>first_alert_volume (20 -> 30)` | 2.5807 s | 2.5807 s | +0.2003 s |
| `session3_tcp_syn_flood_200pps_rep1.pcap` | Tcp Syn Flood 200Pps | `first_detection_delay_sec (2.0953s -> 2.1443s, diff=0.049s)<br>first_alert_volume (20 -> 30)` | 2.1443 s | 2.1443 s | +0.0490 s |
| `session3_tcp_syn_flood_200pps_rep2.pcap` | Tcp Syn Flood 200Pps | `first_detection_delay_sec (2.0946s -> 2.1444s, diff=0.0498s)<br>first_alert_volume (20 -> 30)` | 2.1444 s | 2.1444 s | +0.0498 s |
| `session3_tcp_syn_flood_200pps_rep3.pcap` | Tcp Syn Flood 200Pps | `first_detection_delay_sec (2.0947s -> 2.1456s, diff=0.0509s)<br>first_alert_volume (20 -> 30)` | 2.1456 s | 2.1456 s | +0.0509 s |
| `session3_tcp_syn_flood_500pps_rep1.pcap` | Tcp Syn Flood 500Pps | `first_alert_volume (20 -> 30)` | 30 | 30 | +0.0189 s |
| `session3_tcp_syn_flood_500pps_rep2.pcap` | Tcp Syn Flood 500Pps | `first_detection_delay_sec (2.0377s -> 2.0588s, diff=0.0211s)<br>first_alert_volume (20 -> 30)` | 2.0588 s | 2.0588 s | +0.0211 s |
| `session3_tcp_syn_flood_500pps_rep3.pcap` | Tcp Syn Flood 500Pps | `first_alert_volume (20 -> 30)` | 30 | 30 | +0.0198 s |
| `session3_tcp_syn_flood_1000pps_rep1.pcap` | Tcp Syn Flood 1000Pps | `first_alert_volume (20 -> 30)` | 30 | 30 | +0.0095 s |
| `session3_tcp_syn_flood_1000pps_rep2.pcap` | Tcp Syn Flood 1000Pps | `first_alert_volume (20 -> 30)` | 30 | 30 | +0.0109 s |
| `session3_tcp_syn_flood_1000pps_rep3.pcap` | Tcp Syn Flood 1000Pps | `first_alert_volume (20 -> 30)` | 30 | 30 | +0.0102 s |

##### Mutation (iii): UDP Volumetric Threshold 40 -> 60 pkts/s:
- **Failed Captures (12 runs)**:
| PCAP File | Scenario | Differing Field(s) | Streaming Baseline Value | Mutated Value | Signed Delay Diff |
| :--- | :--- | :--- | :---: | :---: | :---: |
| `session3_udp_flood_volumetric_port80_50pps_rep1.pcap` | Udp Flood Volumetric Port80 50Pps | `first_detection_delay_sec (0.5398s -> 0.8188s, diff=0.279s)<br>first_alert_volume (40 -> 60)` | 0.8188 s | 0.8188 s | +0.2790 s |
| `session3_udp_flood_volumetric_port80_50pps_rep2.pcap` | Udp Flood Volumetric Port80 50Pps | `first_detection_delay_sec (0.5404s -> 0.844s, diff=0.3036s)<br>first_alert_volume (40 -> 60)` | 0.8440 s | 0.8440 s | +0.3036 s |
| `session3_udp_flood_volumetric_port80_50pps_rep3.pcap` | Udp Flood Volumetric Port80 50Pps | `first_detection_delay_sec (0.5398s -> 0.8262s, diff=0.2864s)<br>first_alert_volume (40 -> 60)` | 0.8262 s | 0.8262 s | +0.2864 s |
| `session3_udp_flood_volumetric_port80_200pps_rep1.pcap` | Udp Flood Volumetric Port80 200Pps | `first_detection_delay_sec (0.1681s -> 0.2598s, diff=0.0917s)<br>first_alert_volume (40 -> 60)` | 0.2598 s | 0.2598 s | +0.0917 s |
| `session3_udp_flood_volumetric_port80_200pps_rep2.pcap` | Udp Flood Volumetric Port80 200Pps | `first_detection_delay_sec (0.1641s -> 0.2598s, diff=0.0957s)<br>first_alert_volume (40 -> 60)` | 0.2598 s | 0.2598 s | +0.0957 s |
| `session3_udp_flood_volumetric_port80_200pps_rep3.pcap` | Udp Flood Volumetric Port80 200Pps | `first_detection_delay_sec (0.1697s -> 0.2658s, diff=0.0961s)<br>first_alert_volume (40 -> 60)` | 0.2658 s | 0.2658 s | +0.0961 s |
| `session3_udp_flood_volumetric_port80_500pps_rep1.pcap` | Udp Flood Volumetric Port80 500Pps | `first_detection_delay_sec (0.0699s -> 0.1078s, diff=0.0379s)<br>first_alert_volume (40 -> 60)` | 0.1078 s | 0.1078 s | +0.0379 s |
| `session3_udp_flood_volumetric_port80_500pps_rep2.pcap` | Udp Flood Volumetric Port80 500Pps | `first_detection_delay_sec (0.0688s -> 0.1074s, diff=0.0386s)<br>first_alert_volume (40 -> 60)` | 0.1074 s | 0.1074 s | +0.0386 s |
| `session3_udp_flood_volumetric_port80_500pps_rep3.pcap` | Udp Flood Volumetric Port80 500Pps | `first_detection_delay_sec (0.0699s -> 0.107s, diff=0.0371s)<br>first_alert_volume (40 -> 60)` | 0.1070 s | 0.1070 s | +0.0371 s |
| `session3_udp_flood_volumetric_port80_1000pps_rep1.pcap` | Udp Flood Volumetric Port80 1000Pps | `first_alert_volume (40 -> 60)` | 60 | 60 | +0.0191 s |
| `session3_udp_flood_volumetric_port80_1000pps_rep2.pcap` | Udp Flood Volumetric Port80 1000Pps | `first_detection_delay_sec (0.0337s -> 0.0544s, diff=0.0207s)<br>first_alert_volume (40 -> 60)` | 0.0544 s | 0.0544 s | +0.0207 s |
| `session3_udp_flood_volumetric_port80_1000pps_rep3.pcap` | Udp Flood Volumetric Port80 1000Pps | `first_detection_delay_sec (0.0349s -> 0.0553s, diff=0.0204s)<br>first_alert_volume (40 -> 60)` | 0.0553 s | 0.0553 s | +0.0204 s |

#### Methodology & Reference Alignment:
> [!NOTE]
> **Streaming Delay Reference & Sub-Second Sensitivity (Tolerance 0.02 s)**:
> To evaluate mutation sensitivity rigorously without calendar-bin discretization artifacts, streaming first-alert times from `phase7_parity_eval.json` serve as the delay reference (pre-registered offline values in `session3_evaluation.json` remain untouched).
> At 0.02 s delay tolerance combined with exact offset-free field matching (`first_alert_volume`, `distinct_sources`, `class`, and `alert_seconds_set`):
> 1. **Unmutated-class runs pass 100%**: Zero divergence (0.0000 s delay diff, identical field values).
> 2. **Mutations are detected unambiguously**: Each parameter perturbation triggers immediate parity failure on all targeted runs, isolating the exact field that differed.

*Mutation Acceptance Criteria: Parameter perturbations MUST trigger parity failure (FAIL) in the parity evaluation harness on affected runs, while unmutated-class runs pass 100%.*

