### Table S7-B: Phase 7 Detector Performance, Throughput, and Arrival-to-Alert Latency (`phase7_live_detector_benchmark.json`)
| Metric / Dimension | 1,000 pps Realistic Flood Replay | 20,000 pps Spoofed SYN Stress Test (2.4M Pkts) |
| :--- | :---: | :---: |
| **Throughput Classification** | **Offline Throughput** (pcap replay) | **Offline Throughput** (synthetic stream; sandbox unprivileged) |
| **Live Capture Drops Note** | *Live-capture drop limits not measured (sandbox lacks CAP_NET_RAW)* | *Live-capture drop limits not measured (sandbox lacks CAP_NET_RAW)* |
| **Evaluation Duration** | 120 s | 120 s |
| **Packets Seen by dumpcap / Source** | 132,530 | 2,400,000 |
| **Packets Processed by Detector** | 132,530 | 2,400,000 |
| **tshark / dumpcap Dropped Packets** | **0 drops** | **0 drops** |
| **Processing Throughput** | **84,776.2 pps** | **304,374.2 pps** |
| **Maximum Sustained Rate Without Drops** | **76,743 pps** (Full stdout pipe) | **76,743 pps** (Full stdout pipe) |
| **Detector Process CPU Utilization** | 63.05% (Isolated Process) | 99.48% (Isolated Process) |
| **Detector Process Peak RSS Memory** | 205.75 MB | 205.75 MB |
| **Handshake Table Capacity Cap** | 100,000 entries | 100,000 entries |
| **Capacity Evictions Triggered** | 0 | 0 (0 under cap) |
| **Evicted Entries Count as Incomplete** | **No** (Strictly 0) | **No** (Strictly 0) |
| **Flood Still Emits Alerts** | **Yes** (120 alerts) | **Yes** (122 alerts) |
| **Benign Host False Alarms** | **0 false alarms** | **0 false alarms** |
| **First-Alert Arrival-to-Alert Latency** | **0.018 ms** (17.5 µs) | **0.005 ms** (5.1 µs) |
| **Arrival-to-Alert Latency (p50 / Median)** | 0.009 ms (8.6 µs) | 0.009 ms (9.4 µs) |
| **Arrival-to-Alert Latency (p95)** | 0.017 ms (17.2 µs) | 0.012 ms (12.2 µs) |
| **Arrival-to-Alert Latency (p99)** | 0.047 ms (47.4 µs) | 0.014 ms (14.1 µs) |
| **Detector Blind Counter Active on Drops** | False (Active when drops > 0) | False |

