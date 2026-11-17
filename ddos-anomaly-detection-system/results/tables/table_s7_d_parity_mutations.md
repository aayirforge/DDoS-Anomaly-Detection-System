### Table S7-D: Phase 7 Rule & Threshold Parity Mutation Sensitivity Tests (`phase7_parity_mutations.json`)
| Mutation Test | Parameter Perturbation | Affected Scenarios | Failed Runs Count | Parity Harness Status | Sensitivity Verified |
| :--- | :--- | :--- | :---: | :---: | :---: |
| **Mutation (i): Handshake Timeout 2.0s -> 3.0s** | Increases incomplete handshake timeout from 2.0s to 3.0s | TCP SYN Floods and Scans (first-alert delay increases by ~1.0s) | **18 / 40** | **FAIL** | **PASS (Detected)** |
| **Mutation (ii): Condition B Threshold 20 -> 25** | Increases concentrated incomplete SYN threshold from 20 to 25 | TCP SYN Floods operating near or at Condition B threshold | **9 / 40** | **FAIL** | **PASS (Detected)** |
| **Mutation (iii): UDP Volumetric Threshold 40 -> 60 pkts/s** | Increases UDP volumetric threshold from 40 to 60 pkts/s | UDP Volumetric Floods at 50 pps (fail to cross 60 pps threshold) | **17 / 40** | **FAIL** | **PASS (Detected)** |

#### Detailed Breakdown of Failed Runs per Mutation:
##### Mutation (i): Handshake Timeout 2.0s -> 3.0s:
- **Failed Captures (18 runs)**:
  - `session3_tcp_syn_flood_50pps_rep1.pcap`
  - `session3_tcp_syn_flood_50pps_rep2.pcap`
  - `session3_tcp_syn_flood_50pps_rep3.pcap`
  - `session3_tcp_syn_flood_200pps_rep1.pcap`
  - `session3_tcp_syn_flood_200pps_rep2.pcap`
  - `session3_tcp_syn_flood_200pps_rep3.pcap`
  - `session3_tcp_syn_flood_500pps_rep1.pcap`
  - `session3_tcp_syn_flood_500pps_rep2.pcap`
  - `session3_tcp_syn_flood_500pps_rep3.pcap`
  - `session3_tcp_syn_flood_1000pps_rep1.pcap`
  - `session3_tcp_syn_flood_1000pps_rep2.pcap`
  - `session3_tcp_syn_flood_1000pps_rep3.pcap`
  - `session3_udp_flood_random_ports_50pps_rep1.pcap`
  - `session3_udp_flood_random_ports_50pps_rep2.pcap`
  - `session3_udp_flood_random_ports_50pps_rep3.pcap`
  - `session3_reconnaissance_port_scan_30pps_rep1.pcap`
  - `session3_reconnaissance_port_scan_30pps_rep2.pcap`
  - `session3_reconnaissance_port_scan_30pps_rep3.pcap`

##### Mutation (ii): Condition B Threshold 20 -> 25:
- **Failed Captures (9 runs)**:
  - `session3_tcp_syn_flood_50pps_rep1.pcap`
  - `session3_tcp_syn_flood_500pps_rep1.pcap`
  - `session3_tcp_syn_flood_500pps_rep3.pcap`
  - `session3_tcp_syn_flood_1000pps_rep1.pcap`
  - `session3_tcp_syn_flood_1000pps_rep2.pcap`
  - `session3_tcp_syn_flood_1000pps_rep3.pcap`
  - `session3_udp_flood_random_ports_50pps_rep1.pcap`
  - `session3_udp_flood_random_ports_50pps_rep2.pcap`
  - `session3_udp_flood_random_ports_50pps_rep3.pcap`

##### Mutation (iii): UDP Volumetric Threshold 40 -> 60 pkts/s:
- **Failed Captures (17 runs)**:
  - `session3_tcp_syn_flood_50pps_rep2.pcap`
  - `session3_tcp_syn_flood_50pps_rep3.pcap`
  - `session3_tcp_syn_flood_200pps_rep2.pcap`
  - `session3_tcp_syn_flood_500pps_rep1.pcap`
  - `session3_tcp_syn_flood_500pps_rep3.pcap`
  - `session3_tcp_syn_flood_1000pps_rep1.pcap`
  - `session3_tcp_syn_flood_1000pps_rep2.pcap`
  - `session3_tcp_syn_flood_1000pps_rep3.pcap`
  - `session3_udp_flood_random_ports_50pps_rep1.pcap`
  - `session3_udp_flood_random_ports_50pps_rep2.pcap`
  - `session3_udp_flood_random_ports_50pps_rep3.pcap`
  - `session3_udp_flood_volumetric_port80_50pps_rep1.pcap`
  - `session3_udp_flood_volumetric_port80_50pps_rep2.pcap`
  - `session3_udp_flood_volumetric_port80_50pps_rep3.pcap`
  - `session3_udp_flood_volumetric_port80_200pps_rep1.pcap`
  - `session3_udp_flood_volumetric_port80_200pps_rep2.pcap`
  - `session3_udp_flood_volumetric_port80_200pps_rep3.pcap`

*Mutation Acceptance Criteria: Any parameter perturbation MUST trigger parity failure (FAIL) in the parity evaluation harness on affected runs.*

