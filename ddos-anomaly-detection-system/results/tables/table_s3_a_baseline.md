### Table S3-A: 15-Minute Continuous Benign Baseline Evaluation (`session3_evaluation.json`)
| Traffic Scenario | Capture File | Evaluated Duration | Interface Drops | SYN Flood False Alarms | Port Scan False Alarms | Dual-UDP False Alarms | Combined Active Defense Alarms | False Positive Rate (FPR) | One-Sided 95% Upper Bound (0/900) | Target Max FPR | Final Status |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| Diverse Benign Client Traffic | `session3_benign_baseline_900s.pcap` | 900 s (15 min) | 0 | 0 s | 0 s (0 in 900 s; PASS) | 0 s | 0 s | **0.00%** | **$\le 0.33\%$** (applies to this traffic mix only) | $\le 1.0\%$ | **PASS** |
