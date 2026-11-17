### Table S7-B: Phase 7 Detector Performance, Throughput, and Arrival-to-Alert Latency (`phase7_live_detector_benchmark.json`)
| Metric / Dimension | 1,000 pps Realistic Flood Replay | 20,000 pps Spoofed SYN Stress Test (100k Pkts) |
| :--- | :---: | :---: |
| **Packets Processed** | 132,530 | 100,000 |
| **Wall Time Elapsed** | 1.6140 s | 0.1640 s |
| **Processing Throughput** | **82,112.4 pps** | **609,617.0 pps** |
| **CPU Utilization** | 41.15% | 99.99% |
| **Peak Resident Set Size (RSS)** | 213.52 MB | 213.52 MB |
| **Handshake Table Capacity Cap** | 100,000 entries | 20,000 entries |
| **Capacity Evictions Triggered** | 0 | **80,000** (FIFO bounded) |
| **Arrival-to-Alert Latency (Mean)** | 0.012 ms (11.8 µs) | 0.000 ms (0.0 µs) |
| **Arrival-to-Alert Latency (p50 / Median)** | 0.010 ms (10.0 µs) | 0.000 ms (0.0 µs) |
| **Arrival-to-Alert Latency (p95)** | 0.014 ms (14.4 µs) | 0.000 ms (0.0 µs) |
| **Arrival-to-Alert Latency (p99)** | 0.081 ms (81.3 µs) | 0.000 ms (0.0 µs) |
| **Arrival-to-Alert Latency (Max)** | 0.120 ms | 0.000 ms |
| **Total High-Signal Alerts Emitted** | 120 | 1 |

