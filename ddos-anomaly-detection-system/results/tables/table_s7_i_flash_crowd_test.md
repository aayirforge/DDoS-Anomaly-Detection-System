### Table S7-I: Phase 7 Multi-Rate Flash Crowd Evaluation (`results/phase7_round3_evaluation.json`)
*Stress Scenario: 1,000-entry table, 10 clients, 200 ms RTT, completing handshakes, 10.0 s evaluation window*
| Offered Rate | In-Flight SYNs (200ms RTT) | Capacity Evictions | Completed Handshakes | Stateful False Alarms | Standard Arrival Alerts | First Alert Delay (s) | Sustained-Variant False Alarms (3 windows) |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| 500 conn/s | 100 pkts | 0 | 5,000 | **0** | 0 | None (0 alerts) | **0 alerts (0.00%)** |
| 1,000 conn/s | 200 pkts | 0 | 10,000 | **0** | 1 | 0.149000 s | **0 alerts (0.00%)** |
| 2,000 conn/s | 400 pkts | 0 | 20,000 | **0** | 2 | 0.074500 s | **0 alerts (0.00%)** |
| 5,000 conn/s | 1000 pkts | 9,802 | 40,198 | **0** | 2 | 0.029800 s | **0 alerts (0.00%)** |
