# Table S7-M: ACK Masking Resilience Evaluation

**Test Description**: Merges Session 2 busy benign traffic (`lab_busy.pcap`, victim `172.20.0.2`, 231,620 packets, ~1,500--2,500 ACKs/sec from client `172.20.0.4`) with Session 2b spoofed SYN flood (`lab_spoofed_syn_flood.pcap`, ~194 SYNs/sec from spoofed `172.20.x.y` sources) onto a synchronized common timeline (attack begins at $t_{\text{offset}} = 5.0$s). Replayed through the detection engine under two architectures:
1. **Naive Global ACK Subtraction**: ACKs from any source with a SYN in the window subtract globally from total window SYNs (naive $\text{unacked} = \max(0, \text{syn\_cnt} - \text{ack\_cnt})$).
2. **Per-Source ACK Credit**: ACK credits are tracked strictly per-source and capped at each source's SYN arrival count in the sliding window (bounded memory, dynamic $O(1)$ tracking: $\text{unacked} = \sum_{s} \max(0, \text{syn}[s] - \text{ack}[s])$).

### Summary Comparison

| Architecture | Victim | Background Traffic | Attack Traffic | ALERT_SYN_RATE Alerts | ALERT_SYN_RATE First Alert Delay | Stateful Incomplete Alerts | Masking Status |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---|
| Naive Global ACK Subtraction | `172.20.0.2` | `lab_busy.pcap` (~2k ACK/s) | `lab_spoofed_syn_flood` (194 SYN/s) | **0** | **None (Silent)** | 12 | **MASKED (VULNERABLE)** |
| Per-Source ACK Credit (Production) | `172.20.0.2` | `lab_busy.pcap` (~2k ACK/s) | `lab_spoofed_syn_flood` (194 SYN/s) | **12** | **0.7742s** | 12 | **DETECTED (RESILIENT)** |

### Per-Second Timeline During Attack Window ($t_{\text{rel}} = 5\text{s} \dots 17\text{s}$)

| Timeline Second ($t_{\text{rel}}$) | Attack Second ($t_{\text{attack}}$) | SYN Packets to Victim | ACK Packets to Victim | Naive Unacked SYNs | Naive SYN_RATE Alerts | Prod Unacked SYNs | Prod Distinct Sources | Prod SYN_RATE Alerts | Stateful Alerts |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| 5.0s | +0.0s | 240 | 1750 | 0 | 0 | 150 | 89 | **1** | 0 |
| 6.0s | +1.0s | 236 | 1176 | 0 | 0 | 193 | 110 | **1** | 0 |
| 7.0s | +2.0s | 236 | 2264 | 0 | 0 | 193 | 110 | **1** | 1 |
| 8.0s | +3.0s | 243 | 896 | 0 | 0 | 193 | 109 | **1** | 1 |
| 9.0s | +4.0s | 239 | 1798 | 0 | 0 | 194 | 108 | **1** | 1 |
| 10.0s | +5.0s | 239 | 2126 | 0 | 0 | 195 | 108 | **1** | 1 |
| 11.0s | +6.0s | 239 | 816 | 0 | 0 | 193 | 110 | **1** | 1 |
| 12.0s | +7.0s | 238 | 1386 | 0 | 0 | 194 | 110 | **1** | 1 |
| 13.0s | +8.0s | 241 | 1264 | 0 | 0 | 195 | 112 | **1** | 1 |
| 14.0s | +9.0s | 236 | 1705 | 0 | 0 | 193 | 107 | **1** | 1 |
| 15.0s | +10.0s | 233 | 2512 | 0 | 0 | 193 | 114 | **1** | 1 |
| 16.0s | +11.0s | 218 | 1570 | 0 | 0 | 192 | 109 | **1** | 1 |
| 17.0s | +12.0s | 44 | 1621 | 0 | 0 | 0 | - | **0** | 1 |

> [!IMPORTANT]
> **Mechanism of ACK Masking and Resolution**:
> - In `lab_busy.pcap`, legitimate client `172.20.0.4` initiates ~45 HTTP connections/sec and emits 1,000--2,500 data ACKs/sec. Because `172.20.0.4` has active SYNs in the sliding window, naive source-checking (`if src_ip in syn_sources`) admitted all ~2,000 ACKs into a global cancellation pool, completely wiping out the 194 attack SYNs from spoofed sources `172.20.x.y` (producing 0 `ALERT_SYN_RATE` alerts).
> - With **per-source ACK credit**, client `172.20.0.4` receives credit capped at its own 45 SYNs/sec ($45 - 45 = 0$), preventing its 1,955 excess ACKs from canceling attack SYNs. The spoofed sources receive 0 credit ($1 - 0 = 1$), preserving the full 194 unacknowledged attack SYNs and triggering `ALERT_SYN_RATE` in **0.774s** ($t_{\text{offset}} = 0.7742$s, accumulating 150 attack SYNs at ~194 SYN/s).
> - Memory remains strictly bounded to `max_arrival_window_entries = 10,000` entries, and dynamic maintenance runs in **$O(1)$** time per packet.
