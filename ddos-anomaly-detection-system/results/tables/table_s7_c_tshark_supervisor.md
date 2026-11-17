### Table S7-C: Phase 7 Streaming Process Supervisor Crash & Auto-Restart Evaluation (`phase7_live_detector_benchmark.json`)
| Evaluation Metric | Observed Result | Operational Verification |
| :--- | :---: | :--- |
| **Test Specification** | tshark Process Termination & Supervisor Auto-Restart | Validates process supervisor under worker crashes |
| **Simulated Crash Events** | 3 termination cycles | SIGTERM / exit code 1 delivered to worker process |
| **Automatic Restarts Handled** | 3 restarts | Process supervisor detected exit and respawned process |
| **Rule Engine State Preserved** | **True** | Handshake tables, incomplete queues, and counts preserved across worker restarts |
| **Supervisor Status** | **PASS** | Zero data corruption; streaming recovers automatically |

