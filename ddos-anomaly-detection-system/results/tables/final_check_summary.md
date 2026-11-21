# Final Verification Audit Summary: Models, System, UI & Explicit Limits

Generated at: 2026-11-22T00:48:00+05:30

## Comprehensive Verification Matrix (Checks 1.1 through 3.7 & Part 4)

| Check ID | Verification Area | Target File / Artifact | Audit Methodology & Criteria | Key Metric / Result | Status |
| :---: | :--- | :--- | :--- | :---: | :---: |
| **1.1** | Artifact Integrity | `models/` & `checksums.sha256` | Byte-for-byte SHA-256 match against freeze tag `v1.0-phase5-freeze` and `v3.4` | Exact SHA-256 match across all 11 model files | **PASS** |
| **1.2** | Architecture & Features | `models/features.json`, `scaler.joblib` | 25 features in expected order, 0 identifier columns, zero NaN/inf in scaler | 25 features verified; 0 identifiers; 0 NaN/inf | **PASS** |
| **1.3** | Preprocessing Leakage | `data/processed/*.parquet` | Chronological split boundaries strictly monotonic; zero cross-split row hash collisions | Strict ordering (`train < val < test`); 0 collisions | **PASS** |
| **2.1** | Metric Reproduction | `results/metrics.json` | Exact parity on Same-Day, Cross-Day Zero-Shot & Target-Calibrated across RF, KNN, LSTM | Max difference = 0.000000 across all 81 metric cells | **PASS** |
| **2.2** | Sanity Baselines | `data/processed/test_same_day.parquet` | Majority dummy, Logistic Regression linear baseline, label-shuffle control ($\text{AUC} \approx 0.5$) | Dummy F1: 0.9632; LR AUC: 0.9839; Shuffled AUC: 0.4603 | **PASS** |
| **2.3** | Overfitting & Stability | `results/metrics.json`, `models/lstm_seed_*.pt` | Train vs Val vs Test generalization; multi-seed LSTM test F1/AUC spread across seeds 42, 43, 44 | Same F1: $0.9997 \pm 0.0000$; Cross Zero-Shot F1: $0.9987 \pm 0.0002$; Cal F1: $0.9986 \pm 0.0004$ | **PASS** |
| **2.4** | Retrain Reproducibility | Scratch directory training | Retrain RF, KNN, and LSTM in scratch; execute `--smoke-test` across all 3 trainer CLIs | RF max diff: 0.000000; KNN diff: 0.000000; LSTM val AUC: 1.0000; 3/3 smoke tests pass | **PASS** |
| **2.5** | Threshold Provenance | `results/thresholds.json` | Recompute thresholds on validation set at target $\text{FPR} \le 1.0\%$ | RF: 0.1288; KNN: 0.1268; LSTM: 0.9919 (logit +4.8078) | **PASS** |
| **2.6** | Empirical Limits Citations | `results/report.html` | Grounding citations for Cross-Day Drift, Temporal Invariance, Model Collapse, Robust-14 | All 4 empirical limits documented verbatim in report | **PASS** |
| **3.1** | Fresh Environment Test | `pytest tests/ -v` | Pytest suite execution across all test modules | **71 / 71 passed** (Exit Code 0) | **PASS** |
| **3.2** | Replay Parity & Mutations | `results/phase7_parity_eval.json` | 40/40 attack captures pass ($\Delta \le 0.25\text{s}$ tolerance); 0 baseline alarms; 5 mutations fail | Max delay diff: **0.1538 s**; 0 baseline alarms; 5/5 caught | **PASS** |
| **3.3** | Stress & Robustness | `results/phase7_round3_evaluation.json` | Single-source & spoofed 20k/40k/80k pps floods alert in $\le 3.0\text{s}$; flash crowd & ACK masking | Single-source: 0.075/0.0375/0.01875s; Spoofed: 0.0075/0.00375/0.001875s; 0 stateful FC alarms | **PASS** |
| **3.4** | Tamper Tests | `ddos_ads.table_validator` | Corrupt scratch copy of JSON / markdown table; assert validator catches corruption | Caught JSON corruption; Caught table cell corruption | **PASS** |
| **3.5** | Safety Audit | `src/`, `scripts/` | Audit `enable_blocking`, `nft`, `iptables`, `os.system`, `shell=True`, dangerous functions | Passive alert-only default; zero shell injections; 0 exec/eval | **PASS** |
| **3.6** | Analysis UI | `src/ddos_ads/ui_analyzer.py` | UI analysis on original & rewritten pcaps; reject PE/EXE, gzip, path traversal; 127.0.0.1 bind | Subnets match delays; invalid uploads rejected; 127.0.0.1 bound | **PASS** |
| **3.7** | Forbidden Phrases | HTML, PDF, DOCX, Slides, Markdown | Grep for `safety polic`, `public reflection`, `hallucinat`, `draft`, `prompt [0-9]`, `turn [0-9]`, `proves`, `guarantees` | 0 matches found across all published artifacts | **PASS** |
| **4.1** | Real live capture with dumpcap | Real network capture with dumpcap | NOT RUN in automated verification; requires elevated network interface privileges | Status: **NOT RUN** | **NOT RUN** |
| **4.2** | Real tshark start-up and kernel drop limits | Physical socket / tshark start-up latency & drop bounds | NOT RUN; physical driver and interface specific | Status: **NOT RUN** | **NOT RUN** |
| **4.3** | Behaviour on other networks | Arbitrary enterprise / WAN topology evaluation | NOT RUN; evaluated on pre-registered lab topology and captures | Status: **NOT RUN** | **NOT RUN** |
| **4.4** | Reflection amplification | Amplification flood simulation | Stated plainly: planning error, reflector container never provisioned | Status: **NOT RUN** | **NOT RUN** |
| **4.5** | SSH/SFTP, bulk transfers, ICMP baseline | Benign protocol variety baseline | Pre-registered baseline captures did not include sustained SSH/SFTP transfers | Status: **NOT RUN** | **NOT RUN** |

## Numerical Verification Records

1. **Parity Maximum First-Alert Time Difference**:
   - Across all 40 Session 3 attack captures: **`0.1538 s`** (Threshold requirement: $\le 0.2000\text{ s}$).
   - Maximum difference in alerted seconds across all 40 runs: **`0`**.
   - Spurious alerts on 900 s benign baseline & Session 4 baseline: **`0`**.

2. **Parity Mutation Sensitivity (Failed Runs per Mutation)**:
   - **Mutation (i-a)** (*Handshake Timeout 2.0s $\rightarrow$ 3.0s*): **`15 / 40`** failed (`100% PASS` on unmutated class).
   - **Mutation (i-b)** (*Handshake Timeout 2.0s $\rightarrow$ 2.25s*): **`15 / 40`** failed (`100% PASS` on unmutated class).
   - **Mutation (ii-a)** (*Condition B Incomplete Threshold 20 $\rightarrow$ 25*): **`12 / 40`** failed (`100% PASS` on unmutated class).
   - **Mutation (ii-b)** (*Condition B Incomplete Threshold 20 $\rightarrow$ 30*): **`12 / 40`** failed (`100% PASS` on unmutated class).
   - **Mutation (iii)** (*UDP Volumetric Threshold 40 $\rightarrow$ 60 pps*): **`12 / 40`** failed (`100% PASS` on unmutated class).

3. **UI First-Alert Time on Original vs Rewritten Pcaps**:
   - **TCP SYN Flood 200 pps**:
     - Original (`172.20.0.0/16`): **`2.0953 s`** (120 alerts)
     - Rewritten (`10.50.0.0/16`): **`2.0953 s`** (120 alerts) | Difference: **`0.0000 s`**
   - **UDP Flood 50 pps**:
     - Original (`172.20.0.0/16`): **`0.3999 s`** (120 alerts)
     - Rewritten (`10.50.0.0/16`): **`0.3999 s`** (120 alerts) | Difference: **`0.0000 s`**
   - **Port Scan 30 pps**:
     - Original (`172.20.0.0/16`): **`2.4674 s`** (118 alerts)
     - Rewritten (`10.50.0.0/16`): **`2.4674 s`** (118 alerts) | Difference: **`0.0000 s`**

4. **Pytest Suite Passing Count**:
   - Command: `PYTHONPATH=src .venv/bin/pytest tests/ -v`
   - Total Passed: **`71 / 71 passed`** (100% passing rate, exit code 0).

5. **Section 3.7 Forbidden Phrases Verification**:
   - Location: Search performed across `results/report.html`, `results/report.pdf`, `results/report.docx`, `results/presentation_slides.pdf`, `results/presentation_slides.md`, `results/tables/table_claims.md`, `README.md`, and `demo/demo_script.md`.
   - Result: **0 matches found** across all target files. Status: **PASS (100% Compliant)**.

## Checksum Manifests of Audit Tables

- `results/tables/final_check_part1_models.md`: `90daa497495122cca955e10587f70190c98a89f6e561635edfb000ac481214a3`
- `results/tables/final_check_part2_reproducibility.md`: `75bb4702f369f614b459ae8c82ef7fda2e03a13bf116fae30bb1c60dd9cbb055`
- `results/tables/final_check_part3_system.md`: `d5d75d17d1eb32169bf78c65b64a100aa3e573e40daab264787ff2bba6a78e07`
