### Table S3-D2: Attack Packets-Per-Flow Histograms & 5-Tuple Source-Port Reuse Verification (`session3_packets_per_flow_histograms.json`)
| Attack Scenario | Total Attack Packets | Unique 5-Tuples | Single-Pkt Tuples (Dropped by Java Meter) | Reused 5-Tuples ($\ge 2$ Pkts, All Attacker Packets; Dumped by Java Meter) | Reused Tuples % | Reused Packets (% of Volume) | 2 Pkts | 3 Pkts | 4 Pkts | 5 Pkts | 6-10 Pkts | >10 Pkts |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Reconnaissance Port Scan 30Pps** | 10,800 | 10,800 | 10,800 | **0** | 0.00% | 0.00% | 0 | 0 | 0 | 0 | 0 | 0 |
| **Tcp Syn Flood 1000Pps** | 361,423 | 163,338 | 55,800 | **107,538** | 65.84% | 84.56% | 51,823 | 32,339 | 15,176 | 5,751 | 2,448 | 1 |
| **Tcp Syn Flood 200Pps** | 72,298 | 60,217 | 49,589 | **10,628** | 17.65% | 31.41% | 9,309 | 1,196 | 112 | 11 | 0 | 0 |
| **Tcp Syn Flood 500Pps** | 180,713 | 117,366 | 70,951 | **46,415** | 39.55% | 60.74% | 33,146 | 10,266 | 2,435 | 484 | 84 | 0 |
| **Tcp Syn Flood 50Pps** | 18,070 | 17,134 | 16,231 | **903** | 5.27% | 10.18% | 871 | 31 | 1 | 0 | 0 | 0 |
| **Udp Flood Random Ports 1000Pps** | 360,364 | 163,858 | 56,600 | **107,258** | 65.46% | 84.29% | 51,908 | 32,403 | 15,063 | 5,568 | 2,315 | 1 |
| **Udp Flood Random Ports 200Pps** | 72,375 | 60,492 | 49,912 | **10,580** | 17.49% | 31.04% | 9,370 | 1,118 | 91 | 1 | 0 | 0 |
| **Udp Flood Random Ports 500Pps** | 180,371 | 117,464 | 71,311 | **46,153** | 39.29% | 60.46% | 32,982 | 10,199 | 2,443 | 457 | 72 | 0 |
| **Udp Flood Random Ports 50Pps** | 18,372 | 17,582 | 16,808 | **774** | 4.40% | 8.51% | 758 | 16 | 0 | 0 | 0 | 0 |
| **Udp Flood Volumetric Port80 1000Pps** | 360,377 | 6 | 0 | **6** | 100.00% | 100.00% | 0 | 0 | 0 | 0 | 0 | 6 |
| **Udp Flood Volumetric Port80 200Pps** | 72,375 | 6 | 0 | **6** | 100.00% | 100.00% | 0 | 0 | 0 | 0 | 0 | 6 |
| **Udp Flood Volumetric Port80 500Pps** | 180,375 | 6 | 0 | **6** | 100.00% | 100.00% | 0 | 0 | 0 | 0 | 0 | 6 |
| **Udp Flood Volumetric Port80 50Pps** | 18,375 | 6 | 0 | **6** | 100.00% | 100.00% | 0 | 0 | 0 | 0 | 0 | 6 |
*\*Mechanism Summary: Confirms that in random SYN and UDP floods, attack flows dumped by Java CICFlowMeter ($packetCount() > 1$) arise strictly from Birthday collisions in the 64,512 ephemeral source-port space within the 120s window. Single-packet attempts ($packetCount() == 1$) are discarded by the Java meter. In port scans, 0 source ports are reused, but all 10,800 probes elicit bidirectional RST-ACK responses from the victim host.*
*\*Flow Definition Note: The histogram generator script filters with -Y 'ip.src == 172.20.0.3' (All Attacker Packets), matching Java CICFlowMeter flow accumulation. Under this All Attacker TCP packet definition, SYN 1,000 pps Rep 1, 2, and 3 produce exactly 35,826, 35,826, and 35,886 reused 5-tuples. Under strict SYN-only filtering (`ip.src == 172.20.0.3 && tcp.flags.syn == 1 && tcp.flags.ack == 0`), they produce 35,748, 35,752, and 35,826 reused 5-tuples.*
