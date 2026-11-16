# Phase 6 Isolated Lab Evaluation Report

> **Execution Environment:** Docker `isolated_lab_net` (`internal: true`, zero outbound Internet routing).
> **Operational Mode:** Alert-only throughout (no disruptive packet drops or host blocking).
> **Provenance:** All numbers generated programmatically from `results/lab_metrics.json`.

## 1. Internal-Only Network Isolation Verification

Strict isolation verification passed all checks via `lab/scripts/check_isolated_network.sh`:
- Docker network inspect confirmed `Internal: true`.
- Containers (`victim-web`, `benign-client`, `traffic-generator`): zero default gateways.
- Outbound egress probes (`ping 8.8.8.8`, `curl http://1.1.1.1`): 100% blocked / unreachable.
- Internal inter-container reachability (`benign-client -> http://victim-web`): verified.

## 2. Feature Distribution Comparison & Directionality

### 2.1 25-Feature Distribution Comparison

| Feature | Train Med | Train Max | Day 2 Med | Lab Med | Lab P95 | Lab Max | Status | Notes |
|:---|---:|---:|---:|---:|---:|---:|:---:|:---|
| `Bwd Packets/s` | 62.25 | 2000000.0 | 37.95 | 6018.05 | 13290.88 | 38034.9 | **OK** | OK |
| `URG Flag Count` | 0.00 | 1.0 | 0.00 | 0.00 | 0.00 | 0.0 | **FLAGGED** | ALL_ZERO_IN_LAB |
| `Down/Up Ratio` | 1.00 | 23.0 | 1.00 | 0.86 | 1.00 | 1.4 | **OK** | OK |
| `Bwd Packet Length Mean` | 48.00 | 5011.1 | 41.44 | 156.17 | 21918.21 | 26288.7 | **OK** | OK |
| `Bwd Packet Length Max` | 51.00 | 37960.0 | 46.00 | 475.00 | 65226.00 | 65226.0 | **OK** | OK |
| `Init_Win_bytes_forward` | 252.00 | 65535.0 | 255.00 | 64240.00 | 64240.00 | 64240.0 | **FLAGGED** | median_ratio(254.9x) |
| `Init_Win_bytes_backward` | -1.00 | 65535.0 | 0.00 | 65160.00 | 65160.00 | 65160.0 | **OK** | OK |
| `Total Length of Bwd Packets` | 106.00 | 8829488.0 | 94.00 | 938.00 | 526103.00 | 1118302.0 | **OK** | OK |
| `Bwd IAT Total` | 3.00 | 119841024.0 | 3.00 | 0.00 | 41.13 | 79.7 | **FLAGGED** | max_ratio(1/1503828.0x); median_ratio(1/2526.3x) |
| `Bwd IAT Min` | 2.00 | 168.0 | 1.00 | 0.00 | 0.00 | 0.0 | **FLAGGED** | max_ratio(1/835820.9x); median_ratio(1/37037.0x) |
| `Bwd Header Length` | 40.00 | 37264.0 | 40.00 | 120.00 | 500.00 | 1120.0 | **OK** | OK |
| `Flow Packets/s` | 191.75 | 3000000.0 | 180.06 | 12993.51 | 27675.93 | 77654.5 | **OK** | OK |
| `Bwd IAT Max` | 3.00 | 109011160.0 | 3.00 | 0.00 | 40.99 | 79.0 | **FLAGGED** | max_ratio(1/1380163.9x); median_ratio(1/5848.0x) |
| `Total Backward Packets` | 2.00 | 1862.0 | 2.00 | 6.00 | 25.00 | 56.0 | **OK** | OK |
| `Bwd IAT Mean` | 3.00 | 54505588.0 | 3.00 | 0.00 | 3.40 | 6.9 | **FLAGGED** | max_ratio(1/7848617.1x); median_ratio(1/15691.7x) |
| `Bwd Packet Length Min` | 0.00 | 1460.0 | 6.00 | 66.00 | 66.00 | 66.0 | **OK** | OK |
| `Flow Bytes/s` | 4032.00 | 1715000064.0 | 6656.00 | 1419300.33 | 238497794.19 | 836502377.2 | **FLAGGED** | median_ratio(352.0x) |
| `Protocol` | 6.00 | 17.0 | 6.00 | 6.00 | 6.00 | 17.0 | **OK** | OK |
| `Total Length of Fwd Packets` | 70.00 | 130324.0 | 72.00 | 608.00 | 1862.00 | 4394.0 | **OK** | OK |
| `CWE Flag Count` | -0.00 | 1.0 | -0.00 | 0.00 | 0.00 | 0.0 | **FLAGGED** | ALL_ZERO_IN_LAB |
| `Fwd PSH Flags` | 0.00 | 1.0 | 0.00 | 1.00 | 3.00 | 6.0 | **OK** | OK |
| `Total Fwd Packets` | 2.00 | 916.0 | 2.00 | 7.00 | 26.00 | 59.0 | **OK** | OK |
| `Fwd Packet Length Max` | 35.00 | 3569.0 | 35.00 | 195.00 | 239.00 | 239.0 | **OK** | OK |
| `Idle Std` | 0.00 | 50725768.0 | 0.00 | 0.00 | 0.00 | 0.0 | **FLAGGED** | ALL_ZERO_IN_LAB |
| `ACK Flag Count` | 0.00 | 1.0 | 0.00 | 11.00 | 48.00 | 111.0 | **FLAGGED** | max_ratio(111.0x) |

### 2.2 Directionality & Backward-Heavy Features Assessment

- **Client-to-Server Mapping:** Forward direction (`src_ip=172.20.0.3 -> dst_ip=172.20.0.2:80`).
- **Server-to-Client Mapping:** Backward direction (`src_ip=172.20.0.2:80 -> dst_ip=172.20.0.3`).
- **Total Forward Packets:** 76,834 (HTTP requests).
- **Total Backward Packets:** 70,188 (HTTP responses/payloads).
- **Overall Down/Up Packet Ratio:** 0.914.
- **Total Forward Volume:** 6.08 MB.
- **Total Backward Volume:** 457.99 MB (web downloads).
- **Backward-Heavy Features Populated:** 13 of 13 features populated with non-zero values.

## 3. Model Scoring on Lab Benign Traffic (FPR Evaluation)

### 3.1 Raw cicflowmeter Units

| Model | Val Thresh | Zero-Shot Idle FPR | Zero-Shot Busy FPR | Cal Thresh | Cal Idle FPR (2nd Half) | Cal Busy FPR |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Random Forest (Flow)** | 0.1288 | 97.92% (141/144) | 86.41% (6161/7130) | 0.4036 | 1.39% (1/72) | 0.01% (1/7130) |
| **KNN (Flow)** | 0.1268 | 1.39% (2/144) | 0.01% (1/7130) | 0.2900 | 1.39% (1/72) | 0.01% (1/7130) |
| **LSTM (Window)** | 0.9919 | 0.00% (0/135) | 5.48% (390/7121) | 0.1477 | 4.76% (3/63) | 26.05% (1855/7121) |
| **RF Window-Max** | 0.1288 | 100.00% (135/135) | 98.96% (7047/7121) | 0.7841 | 15.87% (10/63) | 0.14% (10/7121) |
| **RF Window-Mean** | 0.1288 | 100.00% (135/135) | 94.78% (6749/7121) | 0.2594 | 0.00% (0/63) | 1.38% (98/7121) |
| **KNN Window-Mean** | 0.1268 | 0.00% (0/135) | 0.00% (0/7121) | 0.1000 | 15.87% (10/63) | 0.14% (10/7121) |

## 4. Low-Rate Flood Attack Evaluation

Low-rate SYN and UDP floods (50, 200, 500 pps) executed against `victim-web` with concurrent background benign traffic.

### 4.1 Zero-Shot Operating Point (Validation Threshold)

| Attack | Rate | Attack Flows | Benign Flows | RF Flow Recall | RF False Alarms | RF Delay | CW Recall | CW Delay | Dest Agg Recall | Dest Agg Delay |
|:---|:---:|---:|---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| SYN | 50 pps | 496 | 12 | 100.0% | 11 | 0.00s | 0.0% | 0.00s | 100.0% | 0.00s |
| SYN | 200 pps | 1897 | 13 | 100.0% | 12 | 0.00s | 0.0% | 0.00s | 100.0% | 0.00s |
| SYN | 500 pps | 4414 | 11 | 100.0% | 11 | 0.00s | 0.0% | 0.00s | 100.0% | 0.00s |
| UDP | 50 pps | 1 | 12 | 100.0% | 12 | 0.00s | 0.0% | 0.00s | 0.0% | 0.00s |
| UDP | 200 pps | 1 | 13 | 100.0% | 13 | 0.00s | 0.0% | 0.00s | 0.0% | 0.00s |
| UDP | 500 pps | 1 | 12 | 100.0% | 12 | 0.00s | 0.0% | 0.00s | 0.0% | 0.00s |

### 4.1 Target-Calibrated Operating Point (Lab Idle Threshold)

| Attack | Rate | Attack Flows | Benign Flows | RF Flow Recall | RF False Alarms | RF Delay | CW Recall | CW Delay | Dest Agg Recall | Dest Agg Delay |
|:---|:---:|---:|---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| SYN | 50 pps | 496 | 12 | 0.0% | 0 | 0.00s | 0.0% | 0.00s | 0.0% | 0.00s |
| SYN | 200 pps | 1897 | 13 | 0.0% | 1 | 0.00s | 0.0% | 0.00s | 0.0% | 0.00s |
| SYN | 500 pps | 4414 | 11 | 0.0% | 0 | 0.00s | 0.0% | 0.00s | 0.0% | 0.00s |
| UDP | 50 pps | 1 | 12 | 100.0% | 0 | 0.00s | 100.0% | 9.00s | 0.0% | 0.00s |
| UDP | 200 pps | 1 | 13 | 100.0% | 0 | 0.00s | 100.0% | 9.00s | 0.0% | 0.00s |
| UDP | 500 pps | 1 | 12 | 100.0% | 0 | 0.00s | 100.0% | 8.00s | 0.0% | 0.00s |
