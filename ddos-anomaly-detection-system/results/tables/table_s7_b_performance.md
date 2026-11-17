### Table S7-B: Phase 7 Detector Performance, Throughput, and Arrival-to-Alert Latency (`phase7_live_detector_benchmark.json`)
| Metric / Dimension | 1,000 pps Realistic Flood Replay | 20,000 pps Spoofed SYN Stress Test (2.4M Pkts) |
| :--- | :---: | :---: |
| **Evaluation Duration** | 120 s | 120 s |
| **Packets Processed** | 132,530 | 2,400,000 |
| **Wall Time Elapsed** | 1.6239 s | 5.8116 s |
| **Processing Throughput** | **81,613.0 pps** | **412,966.7 pps** |
| **CPU Utilization** | 70.98% | 100.00% |
| **Peak Resident Set Size (RSS)** | 213.83 MB | 213.83 MB |
| **tshark Dropped-Packet Count** | 0 drops (recorded in alerts) | 0 drops (in-memory stream) |
| **Detector Marked Blind on Drops** | False (Active when drops > 0) | False |
| **Handshake Table Capacity Cap** | 100,000 entries | 20,000 entries |
| **Capacity Evictions Triggered** | 0 | **2,380,000** (FIFO bounded) |
| **Flood Still Emits Alerts** | **Yes** (120 alerts) | **Yes** (Reliably detected) |
| **Benign Host False Alarms** | **0 false alarms** | **0 false alarms** (Eviction safe) |
| **Arrival-to-Alert Latency (p50 / Median)** | 0.013 ms (13.2 µs) | 0.009 ms (8.7 µs) |
| **Arrival-to-Alert Latency (p95)** | 0.021 ms (21.5 µs) | 0.015 ms (15.2 µs) |
| **Arrival-to-Alert Latency (p99)** | 0.096 ms (96.3 µs) | 0.018 ms (18.3 µs) |
| **Total High-Signal Alerts Emitted** | 120 | 120 |

