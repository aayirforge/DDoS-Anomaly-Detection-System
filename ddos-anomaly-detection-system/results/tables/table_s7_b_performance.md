### Table S7-B: Phase 7 Detector Performance, Throughput, and Arrival-to-Alert Latency (`phase7_live_detector_benchmark.json`)
| Metric / Dimension | 1,000 pps Realistic Flood Replay | 20,000 pps Spoofed SYN Stress Test (2.4M Pkts) |
| :--- | :---: | :---: |
| **Throughput Classification** | **Live Stream Throughput** | **Offline Replay Throughput** (Sandbox unprivileged) |
| **Evaluation Duration** | 120 s | 120 s |
| **Packets Seen by dumpcap / Source** | 132,530 | 2,400,000 |
| **Packets Processed by Detector** | 132,530 | 2,400,000 |
| **tshark / dumpcap Dropped Packets** | **0 drops** | **0 drops** |
| **Processing Throughput** | **73,890.1 pps** | **353,057.6 pps** |
| **Maximum Sustained Rate Without Drops** | **76,743 pps** (Full stdout pipe) | **76,743 pps** (Full stdout pipe) |
| **Detector Process CPU Utilization** | 65.87% (Isolated Process) | 99.75% (Isolated Process) |
| **Detector Process Peak RSS Memory** | 206.27 MB | 206.27 MB |
| **Handshake Table Capacity Cap** | 100,000 entries | 100,000 entries |
| **Capacity Evictions Triggered** | 0 | 0 (0 under cap) |
| **Evicted Entries Count as Incomplete** | **No** (Strictly 0) | **No** (Strictly 0) |
| **Flood Still Emits Alerts** | **Yes** (120 alerts) | **Yes** (120 alerts) |
| **Benign Host False Alarms** | **0 false alarms** | **0 false alarms** |
| **First-Alert Arrival-to-Alert Latency** | **0.015 ms** (15.2 µs) | **0.013 ms** (13.5 µs) |
| **Arrival-to-Alert Latency (p50 / Median)** | 0.014 ms (13.8 µs) | 0.012 ms (11.8 µs) |
| **Arrival-to-Alert Latency (p95)** | 0.028 ms (27.5 µs) | 0.022 ms (22.2 µs) |
| **Arrival-to-Alert Latency (p99)** | 0.113 ms (113.0 µs) | 0.028 ms (28.1 µs) |
| **Detector Blind Counter Active on Drops** | False (Active when drops > 0) | False |

