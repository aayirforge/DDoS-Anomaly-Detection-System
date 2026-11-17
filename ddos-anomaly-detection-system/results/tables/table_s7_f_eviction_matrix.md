### Table S7-F: Phase 7 Handshake Table Capacity Eviction & Flood Alert Sensitivity Matrix (`phase7_live_detector_benchmark.json`)
| Table Capacity Cap | Spoofed SYN Rate | Flood Emits Alerts | Benign Host False Alarms | Capacity Evictions | Timeout Expired Handshakes | Evaluation Status |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| 20,000 | 20,000 pps | **No (0 alerts)** | **0 false alarms** | 80,000 | 0 | **PASS** |
| 20,000 | 40,000 pps | **No (0 alerts)** | **0 false alarms** | 179,999 | 0 | **PASS** |
| 20,000 | 80,000 pps | **No (0 alerts)** | **0 false alarms** | 379,998 | 0 | **PASS** |
| 160,000 | 20,000 pps | **Yes** (3 alerts) | **0 false alarms** | 0 | 59,999 | **PASS** |
| 160,000 | 40,000 pps | **Yes** (3 alerts) | **0 false alarms** | 0 | 119,998 | **PASS** |
| 160,000 | 80,000 pps | **Yes** (3 alerts) | **0 false alarms** | 0 | 239,989 | **PASS** |

#### Sample Alert Record from 20,000 pps Run (Table Size 160,000):
```json
{
  "wall_time": 1794943719.6901345,
  "packet_ts": 1002.0007499999998,
  "alert_type": "ALERT_SYN_FLOOD",
  "rule": "tcp_incomplete_handshake",
  "victim_ip": "172.20.0.2",
  "details": {
    "incomplete_count": 15,
    "distinct_dst_ports": 1,
    "distinct_dst_ips": 1,
    "distinct_src_ips": 15
  },
  "latency_ms": 0.010890013072639704
}
```

#### Computation of `incomplete_count` & Life vs Timeout Analysis:
> [!IMPORTANT]
> **How `incomplete_count` was computed and why life vs timeout governs alerts**:
> incomplete_count is computed as the number of unacknowledged TCP handshakes in incomplete_window whose timeout (2.0s) has expired within the preceding 1.0-second sliding evaluation window. Under a table size of 20,000 at 20,000 pps, entries live only ~1.0 second (20,000 / 20,000 pps) before being capacity-evicted in FIFO order. Because capacity-evicted entries do NOT count as incomplete handshakes (to protect benign flash crowds from false alarms), zero entries reach the 2.0s completion timeout, resulting in 0 expired handshakes and 0 alerts under the 20k cap. With a 160,000 table size, entries live up to 8.0 seconds at 20k pps (and 2.0 seconds at 80k pps), allowing entries to reach the 2.0s timeout and fire Condition A (incomplete_count >= 15 with distinct sources >= 3).

