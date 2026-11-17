### Table S7-J: Phase 7 ALERT_SYN_RATE Rule Mutation Sensitivity Analysis (`results/phase7_round2_evaluation.json`)
*Rule Status: Post-hoc, unregistered (Preserves frozen pre-registered evaluation; fires on 0 of 40 Session 3 PCAPs)*
| Configuration / Mutation | S2b Spoofed Alerted | S2b First Delay (s) | S2b Alert Class | S2b Unacked Count | S2b Distinct Sources | 3-Client Synthetic Alerts | Session 3 PCAPs Fired (of 40) | Mutation Test Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| Baseline (thresh=150, srcs=3) | **Yes** | 0.774215 s | `ALERT_SYN_RATE` | 150 | 88 | 8 alerts | **0/40 fired** | **PASS (Target Detected)** |
| Mutation 1 (150 -> 200) | **No (0 alerts)** | None | None | None | None | 8 alerts | **0/40 fired** | **FAIL (Misses S2b Flood)** |
| Mutation 2 (sources 3 -> 5) | **Yes** | 0.774215 s | `ALERT_SYN_RATE` | 150 | 88 | 3 alerts | **0/40 fired** | PASS |
| Mutation 3 (150 -> 100) | **Yes** | 0.515674 s | `ALERT_SYN_RATE` | 100 | 68 | 8 alerts | **0/40 fired** | **FAIL (Premature Trigger)** |
