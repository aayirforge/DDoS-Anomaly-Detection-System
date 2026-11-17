### Table S7-C: Phase 7 Streaming Process Supervisor Crash, Restart & Flash Crowd Evaluation (`phase7_live_detector_benchmark.json`)
| Evaluation Metric | Observed Result | Operational Verification |
| :--- | :---: | :--- |
| **Test Specification** | Mid-Run tshark Termination & Supervisor Auto-Restart | Validates process supervisor under worker crashes |
| **Worker Termination Signal** | SIGTERM delivered to tshark worker | Worker crash simulation |
| **Raw Kill Timestamp** | `1794943718.59002` | Precise timestamp of termination signal |
| **Raw Respawn Timestamp** | `1794943718.59022` | Supervisor fork/exec of new worker |
| **Raw First Processed Packet Timestamp** | `1794943718.59052` | First line received from pipe post-restart |
| **Kill-to-First-Processed-Packet Downtime** | **0.50 ms** | Rapid respawn and first packet processed in < 1 ms |
| **Whole Gap Logged as DETECTOR_BLIND** | **True** (Full gap [1000.14s, 1001.00s]) | Gap recorded as blind state (not 'no attack') |
| **Pre-Gap Pending Handshakes Dropped on Restart** | **15 dropped** | Prevents false incomplete alerts from missed ACKs |
| **False Incomplete Alerts Post-Restart** | **0 false alerts** | Verified 0 false alarms when time advances past 2.0s |
| **Do Evicted Entries Count as Incomplete?** | **No** | Evictions do NOT count as incomplete handshakes |
| **Benign Flash Crowd Connections Tested** | **5,000 connections** | High-load benign burst above table capacity |
| **Flash Crowd Table Capacity Cap** | **1,000 entries** | Table strictly bounded |
| **Flash Crowd Capacity Evictions** | **4,000 evictions** | Oldest uncompleted handshakes evicted via FIFO |
| **Flash Crowd False Alarms** | **0 false alarms** | Zero false alarms despite massive capacity evictions |
| **Supervisor Overall Status** | **PASS** | Streaming pipeline resilient and safe against restarts and flash crowds |

