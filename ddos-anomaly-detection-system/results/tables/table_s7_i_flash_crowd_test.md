### Table S7-I: Phase 7 Saturated Table Flash Crowd Evaluation (`results/phase7_round3_evaluation.json`)
*Stress Scenario: 1,000-entry table saturated with 5,000 conn/s for 10.0s (50,000 handshakes total) from 10 clients, RTT=200ms*
| Evaluation Condition | Client Count | Offered Rate | Handshake Completion Status | Capacity Evictions | Completed Handshakes | Stateful Alerts | Arrival Alerts | First Alert Delay (s) | Evaluation Note |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **Benign Flash Crowd (Saturated)** | 10 | 5,000 conn/s | Completed after 200 ms | **9,802** | **40,198** | **0 alerts** | 2 alerts | 0.029800 s | Zero stateful false alerts; arrival rule flags in-flight pipeline delay during ramp. |
| **Pure SYN Flood (No ACKs)** | 10 | 5,000 pkts/s | Pure SYNs (Zero ACKs) | **49,000** | 0 | 0 alerts | 10 alerts | 0.030000 s | Prompt detection on arrival rate. |
