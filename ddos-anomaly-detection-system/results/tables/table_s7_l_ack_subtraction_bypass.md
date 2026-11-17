### Table S7-L: Phase 7 ACK-Subtraction Bypass Evaluation (`results/phase7_round3_evaluation.json`)
*Analysis: Attacker interleaving bare ACKs with SYNs to bypass stateless arrival rate subtraction*
| Attack Scenario | Description | Alerts Emitted | Alert Class | Rule Evaluation Outcome | Security Assessment |
| :--- | :--- | :---: | :---: | :--- | :--- |
| **Arbitrary Source Bare ACKs** | Attacker sends 20k SYNs/s + 20k bare ACKs from non-SYN sources | 3 | `ALERT_SYN_RATE` | **DETECTED** | **Fixed**: ACKs lacking active SYN in window are discarded. |
| **Paired Spoofed Bare ACKs** | Attacker sends 20k SYNs/s + 20k bare ACKs paired to same spoofed IPs | 0 | None | **NOT DETECTED** | **Documented Bypass**: Paired ACKs cancel arrival counter; requires 2x packet bandwidth. |
| **Single-Source Paired Bare ACKs** | Attacker sends 20k SYNs/s + 20k bare ACKs from single source 172.20.0.3 | 0 | None | **NOT DETECTED** | **Documented Bypass**: Paired ACKs cancel arrival counter; requires 2x packet bandwidth. |
