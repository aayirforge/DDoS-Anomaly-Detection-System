### Table S7-C: Phase 7 Streaming Process Supervisor Crash & Auto-Restart Evaluation (`phase7_live_detector_benchmark.json`)
| Evaluation Metric | Observed Result | Operational Verification |
| :--- | :---: | :--- |
| **Test Specification** | Mid-Run tshark Termination & Supervisor Auto-Restart | Validates process supervisor under worker crashes |
| **Mid-Run Termination Event** | SIGTERM signal delivered to worker | Simulated crash / termination |
| **Downtime Until Restart** | **0.50 ms** | Rapid respawn within milliseconds |
| **Gap Logged as DETECTOR_BLIND** | **True** | Gap recorded as blind state (not 'no attack') |
| **Rule Engine State Preserved** | **True** | Handshake tables and sliding counts preserved |
| **Supervisor Status** | **PASS** | Zero data corruption; streaming recovers automatically |

