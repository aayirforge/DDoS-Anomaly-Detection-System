# DDoS Anomaly Detection System: Comprehensive Benchmark Report

> **Source of Truth:** All metrics, thresholds, and distributions are loaded directly from `metrics.json`.
> **Version History & Superseded Status:** The commit message and interim markdown tables of tag `v1.7` (*'Freeze v1.7: Scan evaluation PASS, 5-tuple repeat analysis and packets-per-flow histogram, UDP background delay notes, and pooled run-level bounds clarification'*) are superseded. All authoritative Session 3 benchmark tables are extracted directly from JSON ground truth into standalone markdown files in `results/tables/*.md` and verified during `make report`.

## 1. Flow-Level Model Performance (Primary Operating Points)

| Model | Split / Mode | Threshold | Benign Count | Attack Count | Precision | Recall | F1 Score | FPR [95% Wilson CI] | ROC-AUC | PR-AUC | Latency (ms/1k) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| Random Forest | Same-Day (Zero-Shot) | 0.1288 | 3,137 | 41,088 | 0.9992 | 0.9998 | 0.9995 | 0.0105 [0.00750, 0.01474] | 0.9987 | 0.9999 | 66.69 |
| Random Forest | Cross-Day (Zero-Shot) | 0.1288 | 45,871 | 72,180 | 0.9506 | 0.9998 | 0.9746 | 0.0818 [0.07932, 0.08434] | 0.9984 | 0.9989 | 74.58 |
| Random Forest | Cross-Day (Target-Calibrated) | 0.6690 | 22,936 | 72,180 | 0.9987 | 0.9142 | 0.9546 | 0.0038 [0.00308, 0.00468] | 0.9984 | 0.9989 | 74.58 |
| KNN | Same-Day (Zero-Shot) | 0.1268 | 3,137 | 41,088 | 0.9989 | 0.9966 | 0.9977 | 0.0150 [0.01129, 0.01987] | 0.9973 | 0.9998 | 67.76 |
| KNN | Cross-Day (Zero-Shot) | 0.1268 | 45,871 | 72,180 | 0.9797 | 0.9965 | 0.9880 | 0.0324 [0.03084, 0.03408] | 0.9954 | 0.9975 | 91.51 |
| KNN | Cross-Day (Target-Calibrated) | 0.8200 | 22,936 | 72,180 | 0.9989 | 0.9899 | 0.9943 | 0.0036 [0.00288, 0.00444] | 0.9954 | 0.9975 | 91.51 |
| LSTM | Same-Day (Zero-Shot) | 0.9919 | 614 | 7,465 | 0.9999 | 0.9996 | 0.9997 | 0.0016 [0.00029, 0.00917] | 1.0000 | 1.0000 | 21.55 |
| LSTM | Cross-Day (Zero-Shot) | 0.9919 | 9,166 | 13,318 | 0.9995 | 0.9977 | 0.9986 | 0.0008 [0.00037, 0.00158] | 1.0000 | 1.0000 | 12.59 |
| LSTM | Cross-Day (Target-Calibrated) | 0.0043 | 4,583 | 13,318 | 0.9980 | 0.9997 | 0.9988 | 0.0059 [0.00405, 0.00856] | 1.0000 | 1.0000 | 12.59 |

## 2. Window-Level Evaluation across Models (Length 10, Step 5)

Windows evaluated under validation threshold protocol (max recall with $\text{FPR} \le 1.0\%$ on all-benign validation windows).

| Model / Aggregation | Split / Mode | Threshold | TP | FP | TN | FN | FPR [95% CI] | ROC-AUC | PR-AUC |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| RF (Max Agg) | Same-Day (Zero-Shot) | 0.9094 | 7,465 | 11 | 603 | 0 | 0.0179 [0.01003, 0.03179] | 0.9929 | 0.9994 |
| RF (Max Agg) | Cross-Day (Zero-Shot) | 0.9094 | 10,484 | 60 | 9,106 | 2,834 | 0.0066 [0.00509, 0.00842] | 0.9940 | 0.9954 |
| RF (Max Agg) | Cross-Day (Target-Calibrated) | 0.9535 | 10,476 | 0 | 4,583 | 2,842 | 0.0000 [0.00000, 0.00084] | 0.9981 | 0.9993 |
| RF (Mean Agg) | Same-Day (Zero-Shot) | 0.7563 | 7,464 | 0 | 614 | 1 | 0.0000 [0.00000, 0.00622] | 1.0000 | 1.0000 |
| RF (Mean Agg) | Cross-Day (Zero-Shot) | 0.7563 | 11,105 | 0 | 9,166 | 2,213 | 0.0000 [0.00000, 0.00042] | 1.0000 | 1.0000 |
| RF (Mean Agg) | Cross-Day (Target-Calibrated) | 0.3973 | 13,318 | 14 | 4,569 | 0 | 0.0031 [0.00182, 0.00512] | 1.0000 | 1.0000 |
| KNN (Max Agg) | Same-Day (Zero-Shot) | 1.0000 | 7,465 | 9 | 605 | 0 | 0.0147 [0.00773, 0.02762] | 0.9927 | 0.9994 |
| KNN (Max Agg) | Cross-Day (Zero-Shot) | 1.0000 | 13,317 | 358 | 8,808 | 1 | 0.0391 [0.03528, 0.04322] | 0.9805 | 0.9869 |
| KNN (Max Agg) | Cross-Day (Target-Calibrated) | 1.0000 | 13,317 | 101 | 4,482 | 1 | 0.0220 [0.01817, 0.02671] | 0.9890 | 0.9962 |
| KNN (Mean Agg) | Same-Day (Zero-Shot) | 0.6482 | 7,459 | 0 | 614 | 6 | 0.0000 [0.00000, 0.00622] | 1.0000 | 1.0000 |
| KNN (Mean Agg) | Cross-Day (Zero-Shot) | 0.6482 | 13,285 | 5 | 9,161 | 33 | 0.0006 [0.00023, 0.00128] | 1.0000 | 1.0000 |
| KNN (Mean Agg) | Cross-Day (Target-Calibrated) | 0.3115 | 13,314 | 19 | 4,564 | 4 | 0.0042 [0.00266, 0.00647] | 1.0000 | 1.0000 |
| LSTM | Same-Day (Zero-Shot) | 0.9919 | 7,462 | 1 | 613 | 3 | 0.0016 [0.00029, 0.00917] | 1.0000 | 1.0000 |
| LSTM | Cross-Day (Zero-Shot) | 0.9919 | 13,288 | 7 | 9,159 | 30 | 0.0008 [0.00037, 0.00158] | 1.0000 | 1.0000 |
| LSTM | Cross-Day (Target-Calibrated) | 0.0043 | 13,314 | 27 | 4,556 | 4 | 0.0059 [0.00405, 0.00856] | 1.0000 | 1.0000 |

## 3. Smooth-Model Baselines (Logistic Regression & 1-Layer MLP) on 50 Window Statistics

Trained on the 50 window summary statistics (mean and standard deviation of 25 features across 10 flows) under identical validation thresholding:

| Model / Architecture | Split / Mode | Threshold | TP | FP | TN | FN | Recall | FPR [95% CI] | ROC-AUC | PR-AUC |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| Logistic Regression | Same-Day (Zero-Shot) | 0.6206 | 7,460 | 3 | 611 | 5 | 0.9993 | 0.0049 [0.00166, 0.01427] | 0.9985 | 0.9997 |
| Logistic Regression | Cross-Day (Zero-Shot) | 0.6206 | 13,313 | 82 | 9,084 | 5 | 0.9996 | 0.0089 [0.00721, 0.01109] | 0.9997 | 0.9997 |
| Logistic Regression | Cross-Day (Target-Calibrated) | 0.6071 | 13,313 | 41 | 4,542 | 5 | 0.9996 | 0.0089 [0.00660, 0.01211] | 0.9999 | 1.0000 |
| MLP (1 hidden layer, 32 units) | Same-Day (Zero-Shot) | 0.5529 | 7,464 | 4 | 610 | 1 | 0.9999 | 0.0065 [0.00254, 0.01663] | 0.9968 | 0.9985 |
| MLP (1 hidden layer, 32 units) | Cross-Day (Zero-Shot) | 0.5529 | 13,285 | 26 | 9,140 | 33 | 0.9975 | 0.0028 [0.00194, 0.00415] | 1.0000 | 1.0000 |
| MLP (1 hidden layer, 32 units) | Cross-Day (Target-Calibrated) | 0.1585 | 13,307 | 27 | 4,556 | 11 | 0.9992 | 0.0059 [0.00405, 0.00856] | 1.0000 | 1.0000 |

### Side-by-Side Comparison of ROC-AUC and FPR across Operating Points

| Model | Same-Day Zero-Shot (FPR / AUC) | Cross-Day Zero-Shot (FPR / AUC) | Cross-Day Calibrated (FPR / AUC) |
| :--- | :---: | :---: | :---: |
| Logistic Regression (50 stats) | 0.0049 / 0.9985 | 0.0089 / 0.9997 | 0.0089 / 0.9999 |
| MLP (1 layer, 32 units) | 0.0065 / 0.9968 | 0.0028 / 1.0000 | 0.0059 / 1.0000 |
| LSTM (Seed 42, Primary) | 0.0016 / 1.0000 | 0.0008 / 1.0000 | 0.0059 / 1.0000 |
| RF Window-Stats (50 stats) | 0.0016 / 1.0000 | 0.0002 / 0.9995 | 0.0070 / 0.9996 |

#### Smooth-Model Takeaways
- **Comparable Performance:** Smooth non-recurrent baselines achieve detection performance comparable to the LSTM. On cross-day zero-shot evaluation, Logistic Regression achieves 99.96% recall with 0.89% FPR (ROC-AUC 0.9997), and the 1-layer MLP achieves 99.75% recall with 0.28% FPR (ROC-AUC 1.0000), compared to the LSTM's 99.77% recall and 0.08% FPR (ROC-AUC 1.0000).
- **Tree-Boundary Hypothesis:** *Hypothesis:* The tree-based Random Forest's zero-shot drop on window statistics (recall dropped to 84.53%) may be attributable to axis-aligned orthogonal split boundaries under covariate feature shift, whereas smooth decision boundaries (linear and sigmoidal/ReLU) maintain continuous classification manifolds.

## 4. Onset Order Sensitivity Test (Attack First vs. Last vs. Random Order)

Operating thresholds: LSTM $\tau = 0.9919$, RF-mean $\tau = 0.7563$, KNN-mean $\tau = 0.6482$.
All-benign window ($k=0$) FPR: LSTM = 0.00076, RF-mean = 0.00000, KNN-mean = 0.00055.

| Burst ($k$) | Composition (Benign / Attack) | LSTM Recall (First) | LSTM Recall (Last) | LSTM Recall (Random) | RF-mean Recall (Order-Invariant) | KNN-mean Recall (Order-Invariant) |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| k = 1 | 9 Benign + 1 Attack | 0.002 | 0.001 | 0.001 | 0.000 | 0.002 |
| k = 2 | 8 Benign + 2 Attack | 0.005 | 0.004 | 0.007 | 0.000 | 0.003 |
| k = 3 | 7 Benign + 3 Attack | 0.009 | 0.011 | 0.017 | 0.000 | 0.001 |
| k = 4 | 6 Benign + 4 Attack | 0.020 | 0.025 | 0.027 | 0.000 | 0.005 |
| k = 5 | 5 Benign + 5 Attack | 0.064 | 0.090 | 0.096 | 0.002 | 0.014 |
| k = 6 | 4 Benign + 6 Attack | 0.183 | 0.211 | 0.213 | 0.012 | 0.064 |
| k = 7 | 3 Benign + 7 Attack | 0.467 | 0.396 | 0.443 | 0.053 | 0.976 |
| k = 8 | 2 Benign + 8 Attack | 0.934 | 0.758 | 0.789 | 0.767 | 0.996 |
| k = 9 | 1 Benign + 9 Attack | 0.998 | 0.993 | 0.989 | 0.854 | 0.996 |

#### Onset Order Sensitivity Summary
- **Homogeneous Windows:** Order sensitivity is **absent** on real homogeneous windows: randomly permuting the 10 flows inside each cross-day test window resulted in a recall change of -0.00008 (0.99775 -> 0.99767) and an FPR change of -0.00033 (0.00076 -> 0.00044).
- **Mixed Transition Windows:** Order sensitivity is **present** on synthetic mixed windows, especially near the detection threshold at $k = 7$ and $k = 8$. At $k = 7$, recall is 0.467 (First) vs. 0.396 (Last) vs. 0.443 (Random). At $k = 8$, placing attack flows at the beginning (`First`) yields a recall of 0.934, compared to 0.758 when placed at the end (`Last`)—a difference of 17.6 percentage points (0.789 for Random). By $k = 9$, recall converges to 0.998 (First), 0.993 (Last), and 0.989 (Random).

## 5. Day 2 Benign File-Ordered Blocks Provenance & Per-File Time Ranges

Day 2 cross-day test benign windows (9,166 total) are partitioned into 5 contiguous file-ordered blocks (1,833 windows each, block 5 with 1,834).

| Block | Slice Index | Total Windows | Source File | File Windows | Time Range (UTC) |
| :---: | :---: | :---: | :--- | :---: | :---: |
| block_1 | [0:1833] | 1,833 | `03-11/LDAP.csv` | 947 | 10:09:00 - 10:29:51 |
|  |  |  | `03-11/MSSQL.csv` | 494 | 10:29:52 - 10:42:52 |
|  |  |  | `03-11/NetBIOS.csv` | 237 | 10:01:49 - 10:08:59 |
|  |  |  | `03-11/Portmap.csv` | 155 | 09:18:16 - 09:28:12 |
| block_2 | [1833:3666] | 1,833 | `03-11/Portmap.csv` | 703 | 09:28:11 - 10:01:42 |
|  |  |  | `03-11/Syn.csv` | 1,130 | 11:30:26 - 12:47:48 |
| block_3 | [3666:5499] | 1,833 | `03-11/Syn.csv` | 1,833 | 12:47:48 - 14:37:50 |
| block_4 | [5499:7332] | 1,833 | `03-11/Syn.csv` | 1,833 | 14:37:50 - 16:28:31 |
| block_5 | [7332:9166] | 1,834 | `03-11/Syn.csv` | 619 | 16:28:31 - 17:36:33 |
|  |  |  | `03-11/UDP.csv` | 527 | 10:42:57 - 11:01:34 |
|  |  |  | `03-11/UDPLag.csv` | 688 | 11:01:44 - 11:30:17 |

### 5-Fold Calibration Sensitivity across File-Ordered Blocks

| Model / Aggregation | Min FPR | Max FPR | Mean FPR | Median FPR | Fold FPRs (Blocks 1..5) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| RF (Max Agg) | 0.00000 | 0.07255 | 0.02515 | 0.02032 | [0.00000, 0.02032, 0.00873, 0.07255, 0.02414] |
| RF (Mean Agg) | 0.00164 | 0.08673 | 0.02498 | 0.01105 | [0.01582, 0.00968, 0.00164, 0.08673, 0.01105] |
| KNN (Max Agg) | 0.03464 | 0.07091 | 0.04370 | 0.03696 | [0.03464, 0.03696, 0.03505, 0.07091, 0.04092] |
| KNN (Mean Agg) | 0.00368 | 0.10310 | 0.02654 | 0.00846 | [0.00927, 0.00818, 0.00368, 0.10310, 0.00846] |
| LSTM | 0.00491 | 0.04050 | 0.01467 | 0.00818 | [0.01227, 0.00818, 0.00491, 0.04050, 0.00750] |

*(Note: Block 4 exhibits the highest FPR across every single model due to the distinct daytime traffic distribution in `03-11/Syn.csv` during 14:37–16:28.)*

## 6. Multi-Seed LSTM Evaluation & Reproducibility

| LSTM Seed Checkpoint | Same-Day Zero-Shot (F1 / FPR) | Cross-Day Zero-Shot (Recall / FPR) | Cross-Day Calibrated (Recall / FPR) | Checkpoint Status |
| :---: | :---: | :---: | :---: | :---: |
| Seed 42 | F1: 0.9997 / FPR: 0.0016 | Rec: 0.9977 / FPR: 0.0008 | Rec: 0.9997 / FPR: 0.0059 | **Primary** |
| Seed 43 | F1: 0.9997 / FPR: 0.0065 | Rec: 0.9990 / FPR: 0.0020 | Rec: 0.9997 / FPR: 0.0074 | Seed Run |
| Seed 44 | F1: 0.9997 / FPR: 0.0016 | Rec: 0.9989 / FPR: 0.0022 | Rec: 0.9996 / FPR: 0.0081 | Seed Run |

## 7. Effective Sample Size & Block Bootstrap Uncertainty Bands

Resampling: $R = 1000$ replicates over contiguous blocks of 20 windows.

| Metric | Point Estimate | Wilson 95% Score CI | Empirical Block Bootstrap 95% CI |
| :--- | :---: | :---: | :---: |
| **False Positive Rate (FPR)** | 0.00076 | [0.00037, 0.00158] | [0.00023, 0.00138] |
| **Detection Recall** | 0.99775 | [0.99679, 0.99842] | [0.99537, 0.99969] |

## 8. Isolated Lab Benchmark: Session 2 Java CICFlowMeter Evaluation

> **Ground Truth:** Metrics generated from `results/lab_session2_java_eval.json` using official Java CICFlowMeter with Direction Inversion Rule.

### 8.1 Reconciliation of SYN Capture Flows (5,672 vs 5,622)

In `lab_syn_flood.pcap`, 5,672 total flows were extracted by the Python port:
- **Attack SYN Flows (`172.20.0.3`):** 5,622 flows
- **Benign Background HTTP Flows (`172.20.0.4`):** 49 flows
- **Docker Host Multicast SSDP (`172.20.0.1`):** 1 flows
- **Sum Verified:** 5,672 flows

### 8.2 SYN Flood Feature Extraction: Payload vs Packet Length

| Extractor Backend | Flows ($N$) | Total Length of Fwd Packets [Min, Med, Max] | Fwd Packet Length Max [Min, Med, Max] | Extraction Basis |
| :--- | :---: | :---: | :---: | :--- |
| **Python cicflowmeter** | 5,622 | [108.0, 108.0, 270.0] | [54.0, 54.0, 54.0] | Total IP/TCP Packet Length (40B/54B headers included) |
| **Java CICFlowMeter** | 277 | [0.0, 0.0, 0.0] | [0.0, 0.0, 0.0] | TCP Payload Length (0B for pure SYNs, matching CIC-DDoS2019) |

### 8.3 25-Feature Distribution Comparison (Train Benign vs Java Session 2 Benign)

| Feature | Type | Train Benign [Min, P5, Med, P95, Max] or P(1) | Lab Benign [Min, P5, Med, P95, Max] or P(1) | KS Distance | P5-P95 Overlap |
| :--- | :---: | :---: | :---: | :---: | :---: |
| Bwd Packets/s | Continuous | [0.0, 0.0, 62.2, 12269.9, 2000000.0] | [0.1, 97.5, 199.2, 4226.4, 181818.2] | 0.8070 | True |
| URG Flag Count | Binary | 9,478 / 24,331 (0.3895) | 0 / 6,014 (0.0000) | 0.3895 | N/A (Binary) |
| Down/Up Ratio | Continuous | [0.0, 0.0, 1.0, 3.0, 23.0] | [0.0, 0.0, 1.0, 1.0, 3.0] | 0.1973 | True |
| Bwd Packet Length Mean | Continuous | [-0.0, -0.0, 48.0, 496.6, 5011.1] | [0.0, 0.0, 43.5, 1427.4, 1448.0] | 0.4146 | True |
| Bwd Packet Length Max | Continuous | [0.0, 0.0, 51.0, 2860.0, 37960.0] | [0.0, 0.0, 118.0, 1448.0, 1448.0] | 0.3357 | True |
| Init_Win_bytes_forward | Continuous | [-1.0, -1.0, 252.0, 64240.0, 65535.0] | [0.0, 63.0, 108.0, 64240.0, 64240.0] | 0.4235 | True |
| Init_Win_bytes_backward | Continuous | [-1.0, -1.0, -1.0, 29200.0, 65535.0] | [64.0, 64.0, 64.0, 64.0, 64.0] | 0.5584 | True |
| Total Length of Bwd Packets | Continuous | [0.0, 0.0, 106.0, 9227.0, 8829488.0] | [0.0, 0.0, 125.0, 84056.4, 536186.0] | 0.1020 | True |
| Bwd IAT Total | Continuous | [0.0, 0.0, 3.0, 110339772.0, 119841024.0] | [0.0, 0.0, 1391.5, 64507.4, 44717015.0] | 0.5077 | True |
| Bwd IAT Min | Continuous | [0.0, 0.0, 2.0, 3.0, 168.0] | [0.0, 0.0, 100.0, 2060.9, 12767.0] | 0.5949 | True |
| Bwd Header Length | Continuous | [-2125438080.0, 0.0, 40.0, 648.0, 37264.0] | [32.0, 32.0, 72.0, 1945.2, 12072.0] | 0.4145 | True |
| Flow Packets/s | Continuous | [0.1, 0.6, 191.8, 63829.8, 3000000.0] | [0.2, 185.0, 511.2, 7610.5, 181818.2] | 0.7116 | True |
| Bwd IAT Max | Continuous | [-0.1, -0.1, 3.0, 10192101.0, 109011160.0] | [0.0, 0.0, 1367.5, 26690.5, 44699172.0] | 0.4991 | True |
| Total Backward Packets | Continuous | [0.0, 0.0, 2.0, 28.0, 1862.0] | [1.0, 1.0, 2.0, 60.7, 377.0] | 0.2397 | True |
| Bwd IAT Mean | Continuous | [0.0, 0.0, 3.0, 3343622.2, 54505588.0] | [0.0, 0.0, 693.2, 11695.3, 18251312.0] | 0.4955 | True |
| Bwd Packet Length Min | Continuous | [0.0, 0.0, 0.0, 159.0, 1460.0] | [0.0, 0.0, 0.0, 130.0, 1448.0] | 0.2932 | True |
| Flow Bytes/s | Continuous | [0.0, 0.0, 4032.0, 191232.0, 1715000064.0] | [0.0, 0.0, 17791.2, 5301185.2, 24900928.3] | 0.3678 | True |
| Protocol | Continuous | [0.0, 6.0, 6.0, 17.0, 17.0] | [6.0, 6.0, 6.0, 6.0, 6.0] | 0.4074 | True |
| Total Length of Fwd Packets | Continuous | [-0.0, -0.0, 70.0, 3371.0, 130324.0] | [0.0, 0.0, 0.0, 209.0, 209.0] | 0.3039 | True |
| CWE Flag Count | Binary | 5,172 / 24,331 (0.2126) | 0 / 6,014 (0.0000) | 0.7874 | N/A (Binary) |
| Fwd PSH Flags | Binary | 2,418 / 24,331 (0.0994) | 0 / 6,014 (0.0000) | 0.0994 | N/A (Binary) |
| Total Fwd Packets | Continuous | [1.0, 1.0, 2.0, 32.0, 916.0] | [0.0, 2.0, 3.0, 99.3, 323.0] | 0.4772 | True |
| Fwd Packet Length Max | Continuous | [0.0, 0.0, 35.0, 709.0, 3569.0] | [0.0, 0.0, 0.0, 173.0, 173.0] | 0.3023 | True |
| Idle Std | Continuous | [0.0, 0.0, 0.0, 220208.2, 50725768.0] | [0.0, 0.0, 0.0, 0.0, 0.0] | 0.0931 | True |
| ACK Flag Count | Binary | 4,592 / 24,331 (0.1887) | 6,014 / 6,014 (1.0000) | 1.0000 | N/A (Binary) |

### 8.4 Model Rescoring at Fixed Day 1 Validation Thresholds (Step-Size 5 Windows)

| Model | Level | Threshold | Benign Count | Attack Count | TP | FP | TN | FN | FPR | SYN Recall | ROC-AUC |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| Random Forest (Flow) | Flow | 0.1288 | 6,014 | 277 | 32 | 5,486 | 528 | 245 | 0.9122 | 0.1155 | 0.0632 |
| KNN (Flow) | Flow | 0.1268 | 6,014 | 277 | 1 | 1,395 | 4,619 | 276 | 0.2320 | 0.0036 | 0.3704 |
| RF Window-Max | Window (Step 5) | 0.9094 | 1,200 | 54 | 0 | 0 | 1,200 | 54 | 0.0000 | 0.0000 | 0.0000 |
| RF Window-Mean | Window (Step 5) | 0.7563 | 1,200 | 54 | 0 | 0 | 1,200 | 54 | 0.0000 | 0.0000 | 0.0005 |
| KNN Window-Max | Window (Step 5) | 1.0000 | 1,200 | 54 | 2 | 743 | 457 | 52 | 0.6192 | 0.0370 | 0.0970 |
| KNN Window-Mean | Window (Step 5) | 0.6482 | 1,200 | 54 | 0 | 165 | 1,035 | 54 | 0.1375 | 0.0000 | 0.0869 |
| LSTM (Window) | Window (Step 5) | 0.9919 | 1,200 | 54 | 0 | 882 | 318 | 54 | 0.7350 | 0.0000 | 0.0088 |
| Window-Stats LR | Window (Step 5) | 0.6206 | 1,200 | 54 | 48 | 140 | 1,060 | 6 | 0.1167 | 0.8889 | 0.8622 |

## 9. Scope and Boundary Limitations of the Stateless Arrival Detector (Phase 7 Design Fix)

The post-hoc stateless arrival rate detector (`tcp_syn_arrival_rate`) was introduced to protect against handshake table exhaustion during volumetric and multi-source SYN floods without altering frozen pre-registered rule thresholds. Its operational boundaries and design scope are explicitly defined as follows:

1. **Inefficacy at 50–1,000 pps Single-Source Floods**:
   The single-source arrival threshold is deliberately calibrated to 1,500 unacked SYNs/s to protect pre-registered parity across all 40 Session 3 PCAPs (where single-source attack rates reach up to 1,000 pps / 1,017 pkts/s). Consequently, the stateless arrival detector adds zero detection capability for single-source floods at $\le 1,000$ pps; these lower-rate single-source floods remain 100% dependent on the pre-registered stateful incomplete-handshake engine (`tcp_incomplete_handshake`, Condition B $\ge 20$).

2. **Paired SYN+ACK Subtraction Bypass**:
   Because the arrival detector performs stateless ingress subtraction ($\text{unacked} = \max(0, \text{len}(\text{syn\_window}) - \text{len}(\text{ack\_window}))$) and filters ACKs by verifying that the ACK source IP previously transmitted a SYN in the sliding window (`src_ip in syn_arrival_src_counts`), an attacker who crafts paired `(SYN, bare ACK)` packets from the same source IP completely cancels out the arrival counter. This bypasses the arrival rate rule entirely, although it imposes a $2\times$ packet bandwidth cost on the attacker without establishing server connection state.

3. **Sub-Threshold Floods**:
   Floods operating below 150 unacked SYNs/s (multi-source) or below 1,500 unacked SYNs/s (single-source) do not trigger `ALERT_SYN_RATE`. They must be detected by stateful handshake tracking or downstream volumetric baselining.

4. **10,000-Entry Sliding Window Cap**:
   To strictly guarantee bounded $O(1)$ memory consumption ($\le 1$ MB RSS) regardless of attack intensity, `syn_arrival_window` and `ack_arrival_window` are hard-capped at 10,000 entries via FIFO eviction. At extreme packet rates ($> 10,000$ pps in a 1 s window), the window holds only the most recent 10,000 packets. While sufficient to trigger the 150 and 1,500 thresholds within milliseconds, it saturates internal queue depth at ultra-high packet rates.


