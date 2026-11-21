# Part 1: Model Integrity Audit Report

Generated at: 2026-11-21T23:20:54.778851

## 1.1 Model Artifacts Inventory & Freeze Comparison

| Model / Artifact File | Size (Bytes) | Current SHA-256 | Tag v1.0-phase5-freeze SHA-256 | Tag v3.4 SHA-256 | Match Freeze? |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `rf.joblib` | 4,799,913 | `ad7bda7e8d8ffe3c...` | `ad7bda7e8d8ffe3c...` | `ad7bda7e8d8ffe3c...` | **MATCH v1.0** |
| `knn.joblib` | 2,700,820 | `3046dcae25a433fa...` | `3046dcae25a433fa...` | `3046dcae25a433fa...` | **MATCH v1.0** |
| `lstm.pt` | 239,305 | `0b170db97a3f0f7d...` | `0b170db97a3f0f7d...` | `0b170db97a3f0f7d...` | **MATCH v1.0** |
| `lstm_seed_42.pt` | 239,305 | `0b170db97a3f0f7d...` | `0b170db97a3f0f7d...` | `0b170db97a3f0f7d...` | **MATCH v1.0** |
| `lstm_seed_43.pt` | 239,513 | `896f1ec794fb2071...` | `896f1ec794fb2071...` | `896f1ec794fb2071...` | **MATCH v1.0** |
| `lstm_seed_44.pt` | 239,513 | `99e1e9b504b7c365...` | `99e1e9b504b7c365...` | `99e1e9b504b7c365...` | **MATCH v1.0** |
| `scaler.joblib` | 1,903 | `81f3846a014e21e9...` | `81f3846a014e21e9...` | `81f3846a014e21e9...` | **MATCH v1.0** |
| `features.json` | 1,777 | `78e4bb0674bae3fa...` | `78e4bb0674bae3fa...` | `78e4bb0674bae3fa...` | **MATCH v1.0** |
| `rf_robust_14.joblib` | 4,558,745 | `23acbe9a03a80abc...` | `N/A (not in tag)...` | `23acbe9a03a80abc...` | **MATCH v3.4 (Added Phase 6)** |
| `knn_robust_14_log1p_champion.joblib` | 4,863,382 | `e287a5e847d95f3d...` | `N/A (not in tag)...` | `e287a5e847d95f3d...` | **MATCH v3.4 (Added Phase 6)** |
| `scaler_robust_14_log1p.joblib` | 919 | `e3f59a789fe5b451...` | `N/A (not in tag)...` | `e3f59a789fe5b451...` | **MATCH v3.4 (Added Phase 6)** |
| `scaler_robust_14_std.joblib` | 919 | `fbfa58dabde11674...` | `N/A (not in tag)...` | `fbfa58dabde11674...` | **MATCH v3.4 (Added Phase 6)** |
| `window_stats_lr_robust_28.joblib` | 971 | `34b27b7b490f5ee3...` | `N/A (not in tag)...` | `34b27b7b490f5ee3...` | **MATCH v3.4 (Added Phase 6)** |
| `thresholds.json` | 5,225 | `12606a9841791ea6...` | `N/A (not in tag)...` | `12606a9841791ea6...` | **MATCH v3.4 (Added Phase 6)** |

## 1.2 Model Load Test & Architecture Verification

| Model Artifact | Model Class / Type | Input Dim | Key Hyperparameters / Architecture Details |
| :--- | :--- | :---: | :--- |
| `rf.joblib` | `RandomForestClassifier` | 25 | `n_estimators=100, max_depth=20, class_weight=balanced` |
| `knn.joblib` | `KNeighborsClassifier` | 25 | `k=5, weights=distance, training_rows=25,000` |
| `lstm.pt` | `LSTMAnomalyClassifier` | 25 | `hidden_size=64, num_layers=2, dropout=0.2, window_len=10, step=5` |
| `lstm_seed_42.pt` | `LSTMAnomalyClassifier` | 25 | `hidden_size=64, num_layers=2, dropout=0.2, window_len=10, step=5` |
| `lstm_seed_43.pt` | `LSTMAnomalyClassifier` | 25 | `hidden_size=64, num_layers=2, dropout=0.2, window_len=10, step=5` |
| `lstm_seed_44.pt` | `LSTMAnomalyClassifier` | 25 | `hidden_size=64, num_layers=2, dropout=0.2, window_len=10, step=5` |
| `rf_robust_14.joblib` | `RandomForestClassifier` | 14 | `n_estimators=100, max_depth=15` |
| `knn_robust_14_log1p_champion.joblib` | `KNeighborsClassifier` | 14 | `k=5, weights=distance, rows=25,000` |
| `window_stats_lr_robust_28.joblib` | `LogisticRegression` | 28 | `C=1.0, max_iter=1000` |

### Feature Set Verification (`features.json`)
- **Total Features Count:** 25 features (exact match)
- **Identifier Columns Check:** 0 identifier columns present (passed)
- **Feature Ordering Check:** Matches exact ordering of `scaler.feature_names_in_` and `rf.feature_names_in_`

### Scaler Parameter Integrity (`scaler.joblib`)
- **Fitted Features:** 25 features
- **NaN in mean/scale:** False (passed)
- **Inf in mean/scale:** False (passed)

## 1.3 Preprocessing Leakage Guards & Split Verification

### Per-File Chronological Sequence Boundaries (`train max < val min <= val max < test min`)

| Source File | Train Max Timestamp | Val Min Timestamp | Val Max Timestamp | Same-Day Test Min Timestamp | Chronological Order |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `01-12/DrDoS_DNS.csv` | 2018-12-01 11:09:29.732392 | 2018-12-01 11:09:31.705472 | 2018-12-01 11:12:10.940134 | 2018-12-01 11:12:11.948772 | **PASS** |
| `01-12/DrDoS_LDAP.csv` | 2018-12-01 11:27:54.252376 | 2018-12-01 11:27:54.899428 | 2018-12-01 11:30:09.543633 | 2018-12-01 11:30:10.047469 | **PASS** |
| `01-12/DrDoS_MSSQL.csv` | 2018-12-01 11:42:45.097787 | 2018-12-01 11:42:46.378482 | 2018-12-01 11:44:28.107550 | 2018-12-01 11:44:28.557898 | **PASS** |
| `01-12/DrDoS_NTP.csv` | 2018-12-01 10:41:55.633340 | 2018-12-01 10:41:56.304805 | 2018-12-01 10:43:09.052243 | 2018-12-01 10:43:09.758871 | **PASS** |
| `01-12/DrDoS_NetBIOS.csv` | 2018-12-01 11:52:45.533374 | 2018-12-01 11:52:45.602825 | 2018-12-01 11:56:22.244851 | 2018-12-01 11:56:22.254192 | **PASS** |
| `01-12/DrDoS_SNMP.csv` | 2018-12-01 12:18:48.641225 | 2018-12-01 12:18:50.059188 | 2018-12-01 12:21:09.441140 | 2018-12-01 12:21:10.838247 | **PASS** |
| `01-12/DrDoS_SSDP.csv` | 2018-12-01 12:34:11.308184 | 2018-12-01 12:34:12.921367 | 2018-12-01 12:35:47.233797 | 2018-12-01 12:35:48.945338 | **PASS** |
| `01-12/DrDoS_UDP.csv` | 2018-12-01 13:01:57.273715 | 2018-12-01 13:01:58.354094 | 2018-12-01 13:03:24.171523 | 2018-12-01 13:03:25.030112 | **PASS** |
| `01-12/Syn.csv` | 2018-12-01 13:32:35.174403 | 2018-12-01 13:32:35.222938 | 2018-12-01 13:32:44.124292 | 2018-12-01 13:32:44.208032 | **PASS** |
| `01-12/UDPLag.csv` | 2018-12-01 13:29:50.886285 | 2018-12-01 13:29:51.052337 | 2018-12-01 13:29:56.536026 | 2018-12-01 13:29:56.731236 | **PASS** |

### Split Label Distributions (Benign vs Attack Counts)

| Split Dataset | Total Rows | Benign Count | Attack Count | Benign Share (%) |
| :--- | :---: | :---: | :---: | :---: |
| Train (`train.parquet`) | 207,023 | 24,331 | 182,692 | 11.75% |
| Validation (`val.parquet`) | 44,172 | 1,336 | 42,836 | 3.02% |
| Same-Day Test (`test_same_day.parquet`) | 44,225 | 3,137 | 41,088 | 7.09% |
| Cross-Day Test (`test_cross_day.parquet`) | 118,051 | 45,871 | 72,180 | 38.86% |

### Duplicate Row Cross-Split Hash Analysis

- **Train vs Validation Row Overlap:** 4542 exact matching rows
- **Train vs Same-Day Test Row Overlap:** 4641 exact matching rows
- **Validation vs Same-Day Test Row Overlap:** 3152 exact matching rows
- **Train vs Cross-Day Test Row Overlap:** 4477 exact matching rows

**Conclusion:** All chronological boundaries strictly hold (`train max < val min < val max < test min`), feature columns contain zero identifiers, and models load with exact expected architectures.