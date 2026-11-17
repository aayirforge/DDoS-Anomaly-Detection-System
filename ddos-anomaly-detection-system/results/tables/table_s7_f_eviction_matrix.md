### Table S7-F: Phase 7 Handshake Table Capacity Eviction & Flood Alert Sensitivity Matrix (`phase7_live_detector_benchmark.json`)
| Table Capacity Cap | Spoofed SYN Rate | First Alert Delay (s) | Alerted <= 3.0s | Flood Emits Alerts | Benign Host False Alarms | Capacity Evictions | Timeout Expired Handshakes | Evaluation Status |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| 20,000 | 20,000 pps | 0.007450 s | **Yes** | **Yes** (5 alerts) | **0 false alarms** | 80,000 | 0 | **PASS** |
| 20,000 | 40,000 pps | 0.003725 s | **Yes** | **Yes** (5 alerts) | **0 false alarms** | 179,999 | 0 | **PASS** |
| 20,000 | 80,000 pps | 0.001863 s | **Yes** | **Yes** (5 alerts) | **0 false alarms** | 379,998 | 0 | **PASS** |
| 160,000 | 20,000 pps | 0.007450 s | **Yes** | **Yes** (5 alerts) | **0 false alarms** | 0 | 59,999 | **PASS** |
| 160,000 | 40,000 pps | 0.003725 s | **Yes** | **Yes** (5 alerts) | **0 false alarms** | 0 | 119,998 | **PASS** |
| 160,000 | 80,000 pps | 0.001863 s | **Yes** | **Yes** (5 alerts) | **0 false alarms** | 0 | 239,989 | **PASS** |

#### Sample Alert Record from 20,000 pps Run (Table Size 160,000):
```json
{
  "wall_time": 1794945377.4321036,
  "packet_ts": 1000.0074499999981,
  "alert_type": "ALERT_SYN_FLOOD",
  "rule": "tcp_syn_arrival_rate",
  "victim_ip": "172.20.0.2",
  "details": {
    "syn_arrival_count": 150,
    "ack_arrival_count": 0,
    "unacked_syn_count": 150,
    "distinct_src_ips": 150,
    "condition": "stateless_arrival_rate"
  },
  "latency_ms": 0.023297994630411267
}
```

#### Alert Frequency Analysis (3 Alerts vs 120s Run):
> [!NOTE]
> **Why 3 alerts were observed in benchmark evaluation vs full 120s run**:
> In the benchmark test window of 5.0 simulated seconds at 20,000 pps, exactly 5 alerts are emitted (one per second at t=0.0075s, 1.0075s, 2.0075s, 3.0075s, 4.0075s) governed by the 1.0s alert suppression rate-limiter. When evaluated under pre-registered incomplete-handshake rules alone (waiting 2.0s for timeout), exactly 3 alerts occur in 5.0 seconds (at t=2.0s, 3.0s, 4.0s). In a full 120-second run, exactly 118-120 alerts fire.

#### Computation of `incomplete_count` & Life vs Timeout Analysis:
> [!IMPORTANT]
> **How `incomplete_count` was computed and why life vs timeout governs alerts**:
> incomplete_count is computed as the number of unacknowledged TCP handshakes in incomplete_window whose timeout (2.0s) has expired within the preceding 1.0-second sliding evaluation window. Under a table size of 20,000 at 20,000 pps, entries live only ~1.0 second (20,000 / 20,000 pps) before being capacity-evicted in FIFO order. To eliminate this blind spot without altering pre-registered thresholds, Phase 7 incorporates a stateless SYN arrival-rate detector (calibrated from benign captures: max benign = 64 pkts/s, threshold = 150 pkts/s with >=3 distinct sources). This ensures reliable detection in <0.01s across all 20k/40k/80k pps floods under both 20k and 160k caps.

