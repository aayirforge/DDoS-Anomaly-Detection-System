"""
Phase 7 Unified Packet-Level Rule Engine Library.
=================================================
Provides packet-timestamp-driven rule evaluation for:
1. TCP Incomplete Handshake Rule (Scan vs. Flood discrimination, N=2.0s timeout, W=1.0s window).
   Features a bounded handshake table with documented FIFO/LRU capacity eviction.
2. Dual-Condition UDP Flood Rule (volumetric >= 40 pkts/s, random port >= 30 pkts/s with >= 10 ports).

Used identically by both offline batch evaluators and the live streaming detection loop.
"""

from __future__ import annotations

from collections import OrderedDict, defaultdict, deque
from dataclasses import asdict, dataclass, field
import json
from pathlib import Path
import subprocess
import time
from typing import Any, Dict, List, Optional, Set, Tuple
import numpy as np


@dataclass
class Alert:
    """Detection alert emitted by the packet rule engine."""
    wall_time: float
    packet_ts: float
    alert_type: str  # ALERT_SYN_FLOOD, ALERT_SCAN, ALERT_UDP_FLOOD
    rule: str        # tcp_incomplete_handshake, dual_condition_udp
    victim_ip: str
    details: Dict[str, Any] = field(default_factory=dict)
    latency_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class RuleEngine:
    """
    Unified packet-level detection engine driven by packet timestamps.
    
    Documented Handshake Table Eviction Policy:
      1. Completion Eviction: A 3-way handshake completed by an ACK within the 2.0s
         timeout is immediately removed from the active tracking table.
      2. Expiration Eviction: Active handshakes with (current_ts - syn_ts >= 2.0s)
         transition to confirmed incomplete SYN events and are evicted from the active table.
      3. Window Eviction: Confirmed incomplete SYN events older than 1.0s relative to the
         current evaluation time are pruned from the sliding evaluation window.
      4. Bounded Capacity Eviction: Under severe traffic volume (e.g. 20,000+ pps spoofed
         floods), the active handshake table is strictly capped at `max_handshakes` entries
         (default: 100,000). If capacity is reached, the oldest uncompleted handshakes
         are evicted in FIFO order, incrementing `capacity_evictions`. Capacity-evicted
         entries do NOT count as confirmed incomplete handshakes, ensuring that a benign
         flash crowd exceeding the table capacity never generates false incomplete-handshake alerts.
    """

    def __init__(
        self,
        victim_ip: str = "172.20.0.2",
        handshake_timeout: float = 2.0,
        sliding_window_sec: float = 1.0,
        max_handshakes: int = 100_000,
        syn_flood_thresh_cond_a: int = 15,  # >= 15 incomplete & >= 3 distinct src IPs
        syn_flood_thresh_cond_b: int = 20,  # >= 20 incomplete
        scan_thresh: int = 15,              # >= 15 incomplete & (>=3 dst ports or >=3 dst IPs)
        udp_volumetric_thresh: int = 40,    # >= 40 UDP pkts/s to dst
        udp_random_port_thresh: int = 30,   # >= 30 UDP pkts/s to dst
        udp_distinct_ports_thresh: int = 10,# with >= 10 distinct dst ports
        enable_syn_arrival_rule: bool = True,
        syn_arrival_thresh: int = 150,      # >= 150 unacked SYNs/s to dst (calibrated from benign max 64 pkts/s)
        syn_arrival_sources_thresh: int = 3,# with >= 3 distinct src IPs (calibrated from benign max 1 source)
    ) -> None:
        self.victim_ip = victim_ip
        self.handshake_timeout = handshake_timeout
        self.sliding_window_sec = sliding_window_sec
        self.max_handshakes = max_handshakes
        self.syn_flood_thresh_cond_a = syn_flood_thresh_cond_a
        self.syn_flood_thresh_cond_b = syn_flood_thresh_cond_b
        self.scan_thresh = scan_thresh
        self.udp_volumetric_thresh = udp_volumetric_thresh
        self.udp_random_port_thresh = udp_random_port_thresh
        self.udp_distinct_ports_thresh = udp_distinct_ports_thresh
        self.enable_syn_arrival_rule = enable_syn_arrival_rule
        self.syn_arrival_thresh = syn_arrival_thresh
        self.syn_arrival_sources_thresh = syn_arrival_sources_thresh

        # State: Active TCP handshakes: fwd_key -> (syn_ts, src_ip, dst_ip, sport, dport)
        self.active_handshakes: OrderedDict[Tuple[str, str, int, int], Tuple[float, str, str, int, int]] = OrderedDict()
        self.capacity_evictions: int = 0
        self.completed_handshakes: int = 0
        self.expired_handshakes: int = 0

        # State: Stateless SYN arrival window (independent of per-connection state)
        self.syn_arrival_window: deque[Tuple[float, str]] = deque()
        self.syn_arrival_src_counts: Dict[str, int] = defaultdict(int)
        self.ack_arrival_window: deque[float] = deque()

        # State: Incomplete SYN sliding window: deque of (eval_time, src_ip, dst_ip, sport, dport)
        self.incomplete_window: deque[Tuple[float, str, str, int, int]] = deque()
        self.dst_port_counts: Dict[int, int] = defaultdict(int)
        self.src_ip_counts: Dict[str, int] = defaultdict(int)
        self.dst_ip_counts: Dict[str, int] = defaultdict(int)

        # State: UDP sliding window: deque of (ts, dst_ip, dst_port)
        self.udp_window: deque[Tuple[float, str, int]] = deque()
        self.udp_dst_port_counts: Dict[int, int] = defaultdict(int)

        # Metrics & Alert tracking
        self.alerts_emitted: List[Alert] = []
        self.last_processed_ts: Optional[float] = None
        self.first_alert_ts: Optional[float] = None
        self.first_alert_type: Optional[str] = None
        self.alert_seconds: Set[int] = set()
        self.last_alert_ts_by_type: Dict[str, float] = {}

    def reset(self) -> None:
        """Reset all state structures."""
        self.active_handshakes.clear()
        self.capacity_evictions = 0
        self.completed_handshakes = 0
        self.expired_handshakes = 0
        self.syn_arrival_window.clear()
        self.syn_arrival_src_counts.clear()
        self.ack_arrival_window.clear()
        self.incomplete_window.clear()
        self.dst_port_counts.clear()
        self.src_ip_counts.clear()
        self.dst_ip_counts.clear()
        self.udp_window.clear()
        self.udp_dst_port_counts.clear()
        self.alerts_emitted.clear()
        self.last_processed_ts = None
        self.first_alert_ts = None
        self.first_alert_type = None
        self.alert_seconds.clear()
        self.last_alert_ts_by_type.clear()

    def _process_incomplete_handshake(
        self,
        syn_ts: float,
        s_ip: str,
        d_ip: str,
        sp: int,
        dp: int,
        eval_time: float,
        t_start: Optional[float] = None,
    ) -> List[Alert]:
        """Process an evicted/incomplete handshake through the sliding window and evaluate alert rules."""
        new_alerts: List[Alert] = []

        # Append to sliding incomplete window
        self.incomplete_window.append((eval_time, s_ip, d_ip, sp, dp))
        self.dst_port_counts[dp] += 1
        self.src_ip_counts[s_ip] += 1
        self.dst_ip_counts[d_ip] += 1

        # Prune events older than sliding_window_sec from eval_time
        window_cutoff = eval_time - self.sliding_window_sec
        while self.incomplete_window and self.incomplete_window[0][0] <= window_cutoff:
            _, old_sip, old_dip, _, old_dp = self.incomplete_window.popleft()
            self.dst_port_counts[old_dp] -= 1
            if self.dst_port_counts[old_dp] == 0:
                del self.dst_port_counts[old_dp]
            self.src_ip_counts[old_sip] -= 1
            if self.src_ip_counts[old_sip] == 0:
                del self.src_ip_counts[old_sip]
            self.dst_ip_counts[old_dip] -= 1
            if self.dst_ip_counts[old_dip] == 0:
                del self.dst_ip_counts[old_dip]

        # Evaluate sliding condition
        cnt = len(self.incomplete_window)
        distinct_dst_ports = len(self.dst_port_counts)
        distinct_dst_ips = len(self.dst_ip_counts)
        distinct_src_ips = len(self.src_ip_counts)

        # Check Reconnaissance Scan
        if cnt >= self.scan_thresh and (distinct_dst_ports >= 3 or distinct_dst_ips >= 3):
            if self.first_alert_ts is None:
                self.first_alert_ts = eval_time
                self.first_alert_type = "ALERT_SCAN"
            if t_start is not None:
                self.alert_seconds.add(int(eval_time - t_start))

            last_alert = self.last_alert_ts_by_type.get("ALERT_SCAN", -999.0)
            if eval_time - last_alert >= 1.0:
                self.last_alert_ts_by_type["ALERT_SCAN"] = eval_time
                alert = Alert(
                    wall_time=time.time(),
                    packet_ts=eval_time,
                    alert_type="ALERT_SCAN",
                    rule="tcp_incomplete_handshake",
                    victim_ip=self.victim_ip,
                    details={
                        "incomplete_count": cnt,
                        "distinct_dst_ports": distinct_dst_ports,
                        "distinct_dst_ips": distinct_dst_ips,
                        "distinct_src_ips": distinct_src_ips,
                    }
                )
                new_alerts.append(alert)
                self.alerts_emitted.append(alert)

        # Check SYN Flood
        elif distinct_dst_ports <= 2 and distinct_dst_ips <= 2:
            if (cnt >= self.syn_flood_thresh_cond_a and distinct_src_ips >= 3) or (cnt >= self.syn_flood_thresh_cond_b):
                if self.first_alert_ts is None:
                    self.first_alert_ts = eval_time
                    self.first_alert_type = "ALERT_SYN_FLOOD"
                if t_start is not None:
                    self.alert_seconds.add(int(eval_time - t_start))

                last_alert = self.last_alert_ts_by_type.get("ALERT_SYN_FLOOD", -999.0)
                if eval_time - last_alert >= 1.0:
                    self.last_alert_ts_by_type["ALERT_SYN_FLOOD"] = eval_time
                    alert = Alert(
                        wall_time=time.time(),
                        packet_ts=eval_time,
                        alert_type="ALERT_SYN_FLOOD",
                        rule="tcp_incomplete_handshake",
                        victim_ip=self.victim_ip,
                        details={
                            "incomplete_count": cnt,
                            "distinct_dst_ports": distinct_dst_ports,
                            "distinct_dst_ips": distinct_dst_ips,
                            "distinct_src_ips": distinct_src_ips,
                        }
                    )
                    new_alerts.append(alert)
                    self.alerts_emitted.append(alert)

        return new_alerts

    def _evict_active_handshakes(self, current_ts: float, t_start: Optional[float] = None) -> List[Alert]:
        """
        Evict handshakes that exceeded completion timeout and evaluate sliding window.
        """
        new_alerts: List[Alert] = []
        timeout_cutoff = current_ts - self.handshake_timeout

        while self.active_handshakes:
            oldest_key, (syn_ts, s_ip, d_ip, sp, dp) = next(iter(self.active_handshakes.items()))
            if syn_ts <= timeout_cutoff:
                self.active_handshakes.popitem(last=False)
                self.expired_handshakes += 1
                eval_time = syn_ts + self.handshake_timeout
                new_alerts.extend(self._process_incomplete_handshake(syn_ts, s_ip, d_ip, sp, dp, eval_time, t_start=t_start))
            else:
                break

        return new_alerts

    def process_packet(
        self,
        ts: float,
        src_ip: str,
        dst_ip: str,
        sport: int,
        dport: int,
        proto: str,
        syn: int = 0,
        ack: int = 0,
        rst: int = 0,
        t_start: Optional[float] = None,
    ) -> List[Alert]:
        """
        Process a single network packet driven by its packet timestamp.
        """
        t_recv = time.perf_counter()
        alerts: List[Alert] = []
        self.last_processed_ts = ts

        # 1. Advance TCP handshake state and evict expired handshakes
        alerts.extend(self._evict_active_handshakes(ts, t_start=t_start))

        # 2. Process TCP Packet
        if proto in ("tcp", "6", 6):
            fwd_key = (src_ip, dst_ip, sport, dport)

            if syn == 1 and ack == 0 and dst_ip == self.victim_ip:
                # Capacity eviction if active table exceeds bound: evict oldest in FIFO order
                # Evicted entries do NOT count as incomplete handshakes to protect flash crowds
                if len(self.active_handshakes) >= self.max_handshakes:
                    self.active_handshakes.popitem(last=False)
                    self.capacity_evictions += 1

                # If entry already present, pop to refresh position at end
                if fwd_key in self.active_handshakes:
                    del self.active_handshakes[fwd_key]
                self.active_handshakes[fwd_key] = (ts, src_ip, dst_ip, sport, dport)

                if self.enable_syn_arrival_rule:
                    self.syn_arrival_window.append((ts, src_ip))
                    self.syn_arrival_src_counts[src_ip] += 1

            elif ack == 1 and syn == 0 and dst_ip == self.victim_ip:
                if fwd_key in self.active_handshakes:
                    syn_ts = self.active_handshakes[fwd_key][0]
                    if ts - syn_ts <= self.handshake_timeout:
                        del self.active_handshakes[fwd_key]
                        self.completed_handshakes += 1

                if self.enable_syn_arrival_rule:
                    self.ack_arrival_window.append(ts)

            # Evaluate Stateless SYN Arrival Rate Detector (independent of per-connection state)
            if self.enable_syn_arrival_rule and dst_ip == self.victim_ip:
                cutoff = ts - self.sliding_window_sec
                while self.syn_arrival_window and self.syn_arrival_window[0][0] <= cutoff:
                    _, old_sip = self.syn_arrival_window.popleft()
                    self.syn_arrival_src_counts[old_sip] -= 1
                    if self.syn_arrival_src_counts[old_sip] == 0:
                        del self.syn_arrival_src_counts[old_sip]
                while self.ack_arrival_window and self.ack_arrival_window[0] <= cutoff:
                    self.ack_arrival_window.popleft()

                syn_cnt = len(self.syn_arrival_window)
                ack_cnt = len(self.ack_arrival_window)
                unacked_cnt = max(0, syn_cnt - ack_cnt)
                distinct_srcs = len(self.syn_arrival_src_counts)

                if unacked_cnt >= self.syn_arrival_thresh and distinct_srcs >= self.syn_arrival_sources_thresh:
                    if self.first_alert_ts is None:
                        self.first_alert_ts = ts
                        self.first_alert_type = "ALERT_SYN_FLOOD"
                    if t_start is not None:
                        self.alert_seconds.add(int(ts - t_start))

                    last_alert = self.last_alert_ts_by_type.get("ALERT_SYN_FLOOD", -999.0)
                    if ts - last_alert >= 1.0:
                        self.last_alert_ts_by_type["ALERT_SYN_FLOOD"] = ts
                        alert = Alert(
                            wall_time=time.time(),
                            packet_ts=ts,
                            alert_type="ALERT_SYN_FLOOD",
                            rule="tcp_syn_arrival_rate",
                            victim_ip=self.victim_ip,
                            details={
                                "syn_arrival_count": syn_cnt,
                                "ack_arrival_count": ack_cnt,
                                "unacked_syn_count": unacked_cnt,
                                "distinct_src_ips": distinct_srcs,
                                "condition": "stateless_arrival_rate",
                            }
                        )
                        alerts.append(alert)
                        self.alerts_emitted.append(alert)

        # 3. Process UDP Packet (excluding ICMP)
        elif proto in ("udp", "17", 17):
            if dst_ip == self.victim_ip:
                self.udp_window.append((ts, dst_ip, dport))
                self.udp_dst_port_counts[dport] += 1

                # Prune UDP packets older than sliding 1.0s window
                udp_cutoff = ts - self.sliding_window_sec
                while self.udp_window and self.udp_window[0][0] <= udp_cutoff:
                    _, _, old_dp = self.udp_window.popleft()
                    self.udp_dst_port_counts[old_dp] -= 1
                    if self.udp_dst_port_counts[old_dp] == 0:
                        del self.udp_dst_port_counts[old_dp]

                # Evaluate Dual-Condition UDP Rule
                cnt = len(self.udp_window)
                distinct_p = len(self.udp_dst_port_counts)

                if cnt >= self.udp_volumetric_thresh or (
                    cnt >= self.udp_random_port_thresh and distinct_p >= self.udp_distinct_ports_thresh
                ):
                    if self.first_alert_ts is None:
                        self.first_alert_ts = ts
                        self.first_alert_type = "ALERT_UDP_FLOOD"
                    if t_start is not None:
                        self.alert_seconds.add(int(ts - t_start))

                    last_alert = self.last_alert_ts_by_type.get("ALERT_UDP_FLOOD", -999.0)
                    if ts - last_alert >= 1.0:
                        self.last_alert_ts_by_type["ALERT_UDP_FLOOD"] = ts
                        alert = Alert(
                            wall_time=time.time(),
                            packet_ts=ts,
                            alert_type="ALERT_UDP_FLOOD",
                            rule="dual_condition_udp",
                            victim_ip=self.victim_ip,
                            details={
                                "udp_count_1s": cnt,
                                "distinct_dst_ports": distinct_p,
                                "condition": "volumetric" if cnt >= self.udp_volumetric_thresh else "random_port",
                            }
                        )
                        alerts.append(alert)
                        self.alerts_emitted.append(alert)

        # Record arrival-to-alert latency
        t_done = time.perf_counter()
        lat_ms = (t_done - t_recv) * 1000.0
        for a in alerts:
            a.latency_ms = lat_ms

        return alerts

    def flush(self, t_start: Optional[float] = None) -> List[Alert]:
        """Flush remaining pending handshakes up to end-of-stream."""
        if self.last_processed_ts is not None:
            return self._evict_active_handshakes(self.last_processed_ts + self.handshake_timeout + 1.0, t_start=t_start)
        return []

    def drop_pending_handshakes_before(self, cutoff_ts: Optional[float] = None) -> int:
        """
        Drop active handshakes that began before a restart/blind gap.
        Prevents false incomplete handshake alerts for handshakes whose completing ACKs
        were dropped during supervisor downtime.
        """
        if cutoff_ts is None:
            dropped = len(self.active_handshakes)
            self.active_handshakes.clear()
            return dropped

        keys_to_drop = [
            k for k, v in self.active_handshakes.items()
            if v[0] <= cutoff_ts
        ]
        for k in keys_to_drop:
            del self.active_handshakes[k]
        return len(keys_to_drop)

    # -------------------------------------------------------------------------
    # Batch / Offline Evaluator API (exact parity with run_session3_suite.py)
    # -------------------------------------------------------------------------
    @staticmethod
    def evaluate_handshake_rule_offline(
        packets: List[Dict[str, Any]],
        duration_sec: int,
        t_start: float,
        victim_ip: str = "172.20.0.2",
    ) -> Dict[str, Any]:
        """Exact batch evaluation function matching session3_evaluation.json."""
        syn_sessions: Dict[Tuple[str, str, int, int], Dict[str, Any]] = {}
        for p in packets:
            ts = p["ts"]
            s_ip, d_ip = p["src"], p["dst"]
            s_p, d_p = p["sport"], p["dport"]
            syn, ack = p["syn"], p["ack"]

            fwd_key = (s_ip, d_ip, s_p, d_p)

            if syn == 1 and ack == 0 and d_ip == victim_ip:
                syn_sessions[fwd_key] = {"syn_ts": ts, "completed": False, "dst_ip": d_ip, "dst_port": d_p, "src_ip": s_ip}
            elif ack == 1 and syn == 0 and d_ip == victim_ip:
                if fwd_key in syn_sessions:
                    if ts - syn_sessions[fwd_key]["syn_ts"] <= 2.0:
                        syn_sessions[fwd_key]["completed"] = True

        incomplete_events = [v for v in syn_sessions.values() if not v["completed"]]
        incomplete_events.sort(key=lambda x: x["syn_ts"])
        inc_ts = np.array([e["syn_ts"] for e in incomplete_events])

        first_alert_ts = None
        first_alert_type = None
        alert_syn_flood_seconds: Set[int] = set()
        alert_scan_seconds: Set[int] = set()

        for e in incomplete_events:
            eval_time = e["syn_ts"] + 2.0
            mask = (inc_ts + 2.0 > eval_time - 1.0) & (inc_ts + 2.0 <= eval_time)
            cnt = int(np.sum(mask))
            window_events = [incomplete_events[j] for j in np.where(mask)[0]]
            distinct_dst_ports = len(set(ev["dst_port"] for ev in window_events))
            distinct_dst_ips = len(set(ev["dst_ip"] for ev in window_events))
            distinct_src_ips = len(set(ev["src_ip"] for ev in window_events))

            sec_bin = int(np.floor(eval_time - t_start))
            if 0 <= sec_bin < duration_sec:
                if cnt >= 15 and (distinct_dst_ports >= 3 or distinct_dst_ips >= 3):
                    alert_scan_seconds.add(sec_bin)
                    if first_alert_ts is None:
                        first_alert_ts = eval_time
                        first_alert_type = "ALERT_SCAN"
                elif distinct_dst_ports <= 2 and distinct_dst_ips <= 2:
                    if (cnt >= 15 and distinct_src_ips >= 3) or (cnt >= 20):
                        alert_syn_flood_seconds.add(sec_bin)
                        if first_alert_ts is None:
                            first_alert_ts = eval_time
                            first_alert_type = "ALERT_SYN_FLOOD"

        return {
            "first_alert_ts": first_alert_ts,
            "first_alert_type": first_alert_type,
            "alert_syn_flood_seconds": alert_syn_flood_seconds,
            "alert_scan_seconds": alert_scan_seconds,
            "total_incomplete_syns": len(incomplete_events)
        }

    @staticmethod
    def evaluate_udp_rule_offline(
        packets: List[Dict[str, Any]],
        duration_sec: int,
        t_start: float,
        victim_ip: str = "172.20.0.2",
    ) -> Dict[str, Any]:
        """Exact batch evaluation function matching session3_evaluation.json."""
        victim_pkts = [p for p in packets if p["dst"] == victim_ip]
        alert_udp_seconds: Set[int] = set()
        first_alert_ts = None

        ts_arr = np.array([p["ts"] for p in victim_pkts])
        ports_arr = np.array([p["dport"] for p in victim_pkts])

        for b in range(duration_sec):
            bin_start = t_start + b
            bin_end = bin_start + 1.0
            mask = (ts_arr >= bin_start) & (ts_arr < bin_end)
            cnt = int(np.sum(mask))
            distinct_p = len(np.unique(ports_arr[mask])) if cnt > 0 else 0

            if cnt >= 40 or (cnt >= 30 and distinct_p >= 10):
                alert_udp_seconds.add(b)
                if first_alert_ts is None:
                    idx_in_bin = np.where(mask)[0]
                    if cnt >= 40 and len(idx_in_bin) >= 40:
                        crossing_pkt_idx = idx_in_bin[39]
                        first_alert_ts = float(ts_arr[crossing_pkt_idx])
                    else:
                        first_alert_ts = float(ts_arr[idx_in_bin[0]])

        return {
            "first_alert_ts": first_alert_ts,
            "alert_udp_seconds": alert_udp_seconds,
            "total_victim_udp_packets": len(victim_pkts)
        }

    def evaluate_pcap_streaming(
        self,
        pcap_path: Path,
        duration_sec: int = 120,
        t_start: Optional[float] = None,
        is_baseline: bool = False,
        preregistered_only: bool = True,
    ) -> Dict[str, Any]:
        """
        Evaluates a PCAP file packet-by-packet in streaming mode.
        """
        self.reset()
        prev_arrival_rule = self.enable_syn_arrival_rule
        if preregistered_only:
            self.enable_syn_arrival_rule = False
        cmd = [
            "tshark", "-r", str(pcap_path), "-Y", "(tcp || udp) && !icmp",
            "-T", "fields",
            "-e", "frame.time_epoch",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "ip.proto",
            "-e", "tcp.srcport",
            "-e", "tcp.dstport",
            "-e", "tcp.flags.syn",
            "-e", "tcp.flags.ack",
            "-e", "tcp.flags.reset",
            "-e", "udp.srcport",
            "-e", "udp.dstport"
        ]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if proc.stdout is None:
            raise RuntimeError(f"Failed to open tshark pipe for {pcap_path}")

        first_pkt_ts: Optional[float] = None
        attack_gen_ip = "172.20.0.3"
        first_attack_ts: Optional[float] = None

        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) < 4:
                continue
            ts = float(parts[0])
            if first_pkt_ts is None:
                first_pkt_ts = ts
            s_ip = parts[1]
            d_ip = parts[2]
            proto = parts[3]

            if s_ip == attack_gen_ip and first_attack_ts is None:
                first_attack_ts = ts

            if proto in ("6", "tcp"):
                sp = int(parts[4]) if len(parts) > 4 and parts[4] else 0
                dp = int(parts[5]) if len(parts) > 5 and parts[5] else 0
                syn = 1 if len(parts) > 6 and parts[6] in ("1", "True") else 0
                ack = 1 if len(parts) > 7 and parts[7] in ("1", "True") else 0
                rst = 1 if len(parts) > 8 and parts[8] in ("1", "True") else 0
            else:
                sp = int(parts[9]) if len(parts) > 9 and parts[9] else 0
                dp = int(parts[10]) if len(parts) > 10 and parts[10] else 0
                syn = ack = rst = 0

            target_t_start = t_start if t_start is not None else (first_pkt_ts if is_baseline else first_attack_ts)
            self.process_packet(ts, s_ip, d_ip, sp, dp, proto, syn=syn, ack=ack, rst=rst, t_start=target_t_start)

        proc.wait()
        target_t_start = t_start if t_start is not None else (first_pkt_ts if is_baseline else first_attack_ts)
        self.flush(t_start=target_t_start)

        delay = None
        if self.first_alert_ts is not None and target_t_start is not None:
            delay = round(self.first_alert_ts - target_t_start, 4)

        first_bin = int(np.floor(delay)) if delay is not None else 0
        evaluated_seconds_post_first = max(1, duration_sec - first_bin)
        alerted_post_first = len([s for s in self.alert_seconds if s >= first_bin and s < duration_sec])

        first_alert = self.alerts_emitted[0] if self.alerts_emitted else None
        first_details = first_alert.details if first_alert else {}
        first_volume = (
            first_details.get("incomplete_count")
            or first_details.get("udp_count_1s")
            or first_details.get("packet_count")
        )
        first_srcs = first_details.get("distinct_src_ips", 1)

        self.enable_syn_arrival_rule = prev_arrival_rule

        return {
            "first_detection_delay_sec": delay,
            "first_alert_ts": self.first_alert_ts,
            "first_alert_type": self.first_alert_type,
            "first_alert_class": self.first_alert_type,
            "first_alert_volume": first_volume,
            "first_alert_distinct_sources": first_srcs,
            "first_alert_details": first_details,
            "alert_seconds_set": sorted(list(self.alert_seconds)),
            "alerted_seconds_post_first_alert": alerted_post_first,
            "evaluated_attack_seconds_post_first_alert": evaluated_seconds_post_first,
            "alerted_seconds_total": len([s for s in self.alert_seconds if 0 <= s < duration_sec]),
            "capacity_evictions": self.capacity_evictions,
            "completed_handshakes": self.completed_handshakes,
            "expired_handshakes": self.expired_handshakes,
        }
