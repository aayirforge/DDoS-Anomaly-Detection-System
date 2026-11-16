#!/usr/bin/env python3
"""Evaluate Incomplete Handshake Rule on Session 2 and Session 2b.

Definition of Incomplete Handshake:
A TCP connection attempt where a client SYN is sent to destination D,
but no completing final ACK is received from the client within N = 2.0 seconds
(including cases where the server replies with RST/ACK, e.g. closed port, or drops/times out).

Evaluates:
- Session 2: Idle Benign, Busy Benign, SYN Flood (Single Source)
- Session 2b: Closed Port (port 81), Stopped Server (unbound IP), 20+ Short-Lived Clients,
  Scanner Burst (ports 20-70), and Multi-Source Spoofed SYN Flood (172.20.0.100-200).

Reports:
- Incomplete handshakes/sec (min, median, max)
- Distinct incomplete source IPs/sec (min, median, max)
- Detection delay from attack onset
- False alarm rate across benign scenarios
- Frozen rule threshold definition based on Session 2/2b
"""

from collections import defaultdict
import json
from pathlib import Path
import subprocess
import numpy as np


def analyze_pcap_handshakes(pcap_path: Path, target_dst_ip: str = "172.20.0.2", timeout_sec: float = 2.0):
    cmd = [
        "tshark", "-r", str(pcap_path), "-Y", "tcp",
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "tcp.flags.syn",
        "-e", "tcp.flags.ack",
        "-e", "tcp.flags.reset"
    ]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    bins = defaultdict(lambda: {
        "total_syns": 0,
        "completed_syns": 0,
        "incomplete_syns": 0,
        "incomplete_srcs": set(),
        "total_packets": 0,
        "syn_timestamps": []
    })

    conn_history = defaultdict(list)
    syn_events = []

    start_time = None
    for line in p.stdout:
        parts = line.strip().split("\t")
        if len(parts) < 8:
            continue
        t = float(parts[0])
        if start_time is None:
            start_time = t
        sec = int(t - start_time)
        src, dst = parts[1], parts[2]
        sport, dport = int(parts[3]), int(parts[4])
        syn = parts[5] in ("True", "1")
        ack = parts[6] in ("True", "1")
        rst = parts[7] in ("True", "1")

        bins[sec]["total_packets"] += 1

        if syn and not ack:
            if dst == target_dst_ip or target_dst_ip is None:
                key = (src, dst, sport, dport)
                conn_history[key].append({"type": "SYN", "time": t, "sec": sec, "src": src})
                bins[sec]["total_syns"] += 1
                bins[sec]["syn_timestamps"].append(t)
        elif syn and ack:
            key = (dst, src, dport, sport)
            conn_history[key].append({"type": "SYN_ACK", "time": t})
        elif ack and not syn:
            key = (src, dst, sport, dport)
            conn_history[key].append({"type": "ACK", "time": t})
        elif rst:
            # RST could be from server or client
            key1 = (dst, src, dport, sport)
            conn_history[key1].append({"type": "RST", "time": t})
            key2 = (src, dst, sport, dport)
            conn_history[key2].append({"type": "RST", "time": t})

    p.stdout.close()
    p.wait()

    # Determine handshake completion
    for key, events in conn_history.items():
        # Match each SYN with subsequent events
        syn_idx = [i for i, e in enumerate(events) if e["type"] == "SYN"]
        for s_i in syn_idx:
            syn_event = events[s_i]
            t_syn = syn_event["time"]
            s_bin = syn_event["sec"]
            s_src = syn_event["src"]

            # Look for completing ACK within timeout_sec
            completed = False
            for e in events[s_i + 1 :]:
                if e["time"] - t_syn > timeout_sec:
                    break
                if e["type"] == "ACK":
                    completed = True
                    break
                if e["type"] == "RST":
                    # Explicit reset -> incomplete
                    break

            if completed:
                bins[s_bin]["completed_syns"] += 1
            else:
                bins[s_bin]["incomplete_syns"] += 1
                bins[s_bin]["incomplete_srcs"].add(s_src)

    total_secs = max(bins.keys()) + 1 if bins else 0
    time_series = []
    for s in range(total_secs):
        b = bins[s]
        time_series.append({
            "second": s,
            "total_syns": b["total_syns"],
            "completed_syns": b["completed_syns"],
            "incomplete_syns": b["incomplete_syns"],
            "distinct_incomplete_sources": len(b["incomplete_srcs"]),
            "incomplete_source_ips": sorted(list(b["incomplete_srcs"]))[:10]
        })

    inc_counts = [b["incomplete_syns"] for b in time_series]
    src_counts = [b["distinct_incomplete_sources"] for b in time_series]

    first_syn_t = None
    for s in sorted(bins.keys()):
        if bins[s]["syn_timestamps"]:
            first_syn_t = bins[s]["syn_timestamps"][0]
            break

    return {
        "pcap_file": pcap_path.name,
        "duration_seconds": total_secs,
        "first_syn_timestamp": first_syn_t,
        "incomplete_syns_per_sec": {
            "min": int(min(inc_counts)) if inc_counts else 0,
            "median": float(np.median(inc_counts)) if inc_counts else 0.0,
            "mean": float(round(np.mean(inc_counts), 2)) if inc_counts else 0.0,
            "max": int(max(inc_counts)) if inc_counts else 0,
        },
        "distinct_sources_per_sec": {
            "min": int(min(src_counts)) if src_counts else 0,
            "median": float(np.median(src_counts)) if src_counts else 0.0,
            "mean": float(round(np.mean(src_counts), 2)) if src_counts else 0.0,
            "max": int(max(src_counts)) if src_counts else 0,
        },
        "time_series": time_series
    }


def main():
    root = Path(__file__).resolve().parent.parent
    s2_dir = root / "lab/captures/session2"
    s2b_dir = root / "lab/captures/session2b"

    print("Analyzing Session 2 PCAPs...")
    s2_idle = analyze_pcap_handshakes(s2_dir / "lab_idle.pcap", target_dst_ip="172.20.0.2")
    s2_busy = analyze_pcap_handshakes(s2_dir / "lab_busy.pcap", target_dst_ip="172.20.0.2")
    s2_flood = analyze_pcap_handshakes(s2_dir / "lab_syn_flood.pcap", target_dst_ip="172.20.0.2")

    print("Analyzing Session 2b PCAPs...")
    s2b_benign = analyze_pcap_handshakes(s2b_dir / "lab_benign_2b.pcap", target_dst_ip=None)
    s2b_spoofed = analyze_pcap_handshakes(s2b_dir / "lab_spoofed_syn_flood.pcap", target_dst_ip="172.20.0.2")

    # Define Frozen Handshake Detection Rule
    # Rule incorporates dual condition:
    # 1. Multi-source flood: incomplete_syns >= 15 AND distinct_sources >= 3
    # 2. High-rate flood: incomplete_syns >= 50 (any number of sources)
    # Rejects: closed port (1/s), stopped server (1/s), 20+ short clients (0/s), and scanner burst (30/s from 1 source).
    frozen_rule = {
        "rule_name": "Incomplete_TCP_Handshake_Detector",
        "definition_of_incomplete": "TCP SYN packet where no completing final ACK is received within N = 2.0 seconds.",
        "timeout_seconds_N": 2.0,
        "multi_source_threshold_incomplete_syns_per_sec": 15,
        "multi_source_threshold_distinct_sources": 3,
        "volumetric_single_source_threshold_incomplete_syns_per_sec": 50,
        "time_bin_seconds": 1.0,
        "action": "Alert-Only (Passive Logging)",
        "freeze_basis": "Calibrated and frozen on Session 2 and Session 2b captures."
    }

    th_multi_syn = frozen_rule["multi_source_threshold_incomplete_syns_per_sec"]
    th_multi_src = frozen_rule["multi_source_threshold_distinct_sources"]
    th_vol_syn = frozen_rule["volumetric_single_source_threshold_incomplete_syns_per_sec"]

    def eval_capture(res):
        alerts = []
        for b in res["time_series"]:
            inc = b["incomplete_syns"]
            srcs = b["distinct_incomplete_sources"]
            triggered = (inc >= th_multi_syn and srcs >= th_multi_src) or (inc >= th_vol_syn)
            if triggered:
                alerts.append(b["second"])
        return alerts

    alerts_s2_idle = eval_capture(s2_idle)
    alerts_s2_busy = eval_capture(s2_busy)
    alerts_s2_flood = eval_capture(s2_flood)
    alerts_s2b_benign = eval_capture(s2b_benign)
    alerts_s2b_spoofed = eval_capture(s2b_spoofed)

    # Detection Delay
    # Session 2 Flood (Single source 172.20.0.3 at 100 pps)
    delay_s2_flood_sec = alerts_s2_flood[0] if alerts_s2_flood else None
    # Session 2b Spoofed Flood (Multi source at 200 pps)
    delay_s2b_spoofed_sec = alerts_s2b_spoofed[0] if alerts_s2b_spoofed else None

    # Estimate detection delay in ms within the first triggered second:
    # At 100 pps, 50 packets arrive in 0.50 seconds (500 ms).
    # At 200 pps, 15 packets arrive in 15 / 200 = 0.075 seconds (75 ms).
    detection_delay_metrics = {
        "session2_single_source_flood": {
            "first_alert_second": delay_s2_flood_sec,
            "estimated_packet_arrival_delay_ms": 500.0,
            "explanation": "At 100 pps, threshold of 50 incomplete SYNs is crossed at packet #50 (t = 500 ms)."
        },
        "session2b_multi_source_spoofed_flood": {
            "first_alert_second": delay_s2b_spoofed_sec,
            "estimated_packet_arrival_delay_ms": 75.0,
            "explanation": "At 200 pps with 100+ sources, threshold of 15 incomplete SYNs and 3 sources is crossed at packet #15 (t = 75 ms)."
        }
    }

    # Summary table
    scenarios = [
        ("Session 2 Idle Benign", s2_idle, len(alerts_s2_idle), "Benign"),
        ("Session 2 Busy Benign", s2_busy, len(alerts_s2_busy), "Benign"),
        ("Session 2b Combined Benign (Closed port, Stopped server, 25 clients, Scanner)", s2b_benign, len(alerts_s2b_benign), "Benign"),
        ("Session 2 Single-Source SYN Flood (100 pps)", s2_flood, len(alerts_s2_flood), "Attack"),
        ("Session 2b Multi-Source Spoofed SYN Flood (200 pps)", s2b_spoofed, len(alerts_s2b_spoofed), "Attack"),
    ]

    print("\n" + "=" * 110)
    print(f"{'Capture Scenario':<45} | {'Duration (s)':<12} | {'Max Inc/s':<10} | {'Max Srcs/s':<10} | {'Alert Seconds':<13} | {'Outcome'}")
    print("=" * 110)
    for name, res, n_alerts, kind in scenarios:
        m_inc = res["incomplete_syns_per_sec"]["max"]
        m_src = res["distinct_sources_per_sec"]["max"]
        dur = res["duration_seconds"]
        if kind == "Benign":
            outcome = "PASS (0 FP)" if n_alerts == 0 else f"FAIL ({n_alerts} FP)"
        else:
            rec = n_alerts / max(1, dur)
            outcome = f"DETECTED ({n_alerts}/{dur}s, {rec*100:.1f}%)"
        print(f"{name:<45} | {dur:<12} | {m_inc:<10} | {m_src:<10} | {n_alerts:<13} | {outcome}")
    print("=" * 110)

    total_benign_secs = s2_idle["duration_seconds"] + s2_busy["duration_seconds"] + s2b_benign["duration_seconds"]
    total_benign_fps = len(alerts_s2_idle) + len(alerts_s2_busy) + len(alerts_s2b_benign)
    benign_fpr = total_benign_fps / max(1, total_benign_secs)

    out_data = {
        "frozen_rule_configuration": frozen_rule,
        "detection_delay_metrics": detection_delay_metrics,
        "overall_evaluation": {
            "total_benign_seconds_monitored": total_benign_secs,
            "total_benign_false_alarm_seconds": total_benign_fps,
            "benign_second_level_fpr": float(round(benign_fpr, 5)),
            "session2_flood_duration_sec": s2_flood["duration_seconds"],
            "session2_flood_detected_seconds": len(alerts_s2_flood),
            "session2_flood_recall": float(round(len(alerts_s2_flood) / max(1, s2_flood["duration_seconds"]), 4)),
            "session2b_spoofed_flood_duration_sec": s2b_spoofed["duration_seconds"],
            "session2b_spoofed_flood_detected_seconds": len(alerts_s2b_spoofed),
            "session2b_spoofed_flood_recall": float(round(len(alerts_s2b_spoofed) / max(1, s2b_spoofed["duration_seconds"]), 4))
        },
        "scenario_details": {
            "session2_idle": s2_idle,
            "session2_busy": s2_busy,
            "session2_single_source_syn_flood": s2_flood,
            "session2b_benign_mixed": s2b_benign,
            "session2b_multi_source_spoofed_flood": s2b_spoofed
        }
    }

    out_path = root / "results/session2b_handshake_rule_eval.json"
    with open(out_path, "w") as f:
        json.dump(out_data, f, indent=2)
    print(f"\nWrote Session 2b Handshake Rule evaluation to {out_path}")


if __name__ == "__main__":
    main()
