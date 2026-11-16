#!/usr/bin/env python3
"""Item 6: Packet Rule - SYN without completed handshake per destination per second + distinct sources.

Evaluates handshakes on Session 2 pcaps (idle, busy, syn_flood).
Chooses and freezes the detection threshold on Session 2 only.
"""

from collections import defaultdict
import json
from pathlib import Path
import subprocess
import numpy as np


def analyze_pcap_handshakes(pcap_path: Path, target_dst_ip: str = "172.20.0.2"):
    cmd = [
        "tshark", "-r", str(pcap_path), "-Y", "tcp",
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "tcp.flags.syn",
        "-e", "tcp.flags.ack"
    ]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    bins = defaultdict(lambda: {
        "total_syns": 0,
        "completed_syns": 0,
        "incomplete_syns": 0,
        "incomplete_srcs": set(),
        "total_packets": 0
    })

    conn_state = {}
    syn_bin = {}
    syn_src = {}

    start_time = None
    for line in p.stdout:
        parts = line.strip().split("\t")
        if len(parts) < 7:
            continue
        t = float(parts[0])
        if start_time is None:
            start_time = t
        sec = int(t - start_time)
        src, dst = parts[1], parts[2]
        sport, dport = int(parts[3]), int(parts[4])
        syn = parts[5] in ("True", "1")
        ack = parts[6] in ("True", "1")

        bins[sec]["total_packets"] += 1

        if syn and not ack:
            if dst == target_dst_ip:
                key = (src, dst, sport, dport)
                conn_state[key] = 1  # SYN seen
                syn_bin[key] = sec
                syn_src[key] = src
                bins[sec]["total_syns"] += 1
        elif syn and ack:
            if src == target_dst_ip:
                key = (dst, src, dport, sport)
                if key in conn_state and conn_state[key] == 1:
                    conn_state[key] = 2  # SYN-ACK seen
        elif ack and not syn:
            if dst == target_dst_ip:
                key = (src, dst, sport, dport)
                if key in conn_state and conn_state[key] == 2:
                    conn_state[key] = 3  # Handshake complete!

    p.stdout.close()
    p.wait()

    for key, state in conn_state.items():
        sb = syn_bin[key]
        if state < 3:
            bins[sb]["incomplete_syns"] += 1
            bins[sb]["incomplete_srcs"].add(syn_src[key])
        else:
            bins[sb]["completed_syns"] += 1

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
            "incomplete_source_ips": sorted(list(b["incomplete_srcs"]))
        })

    inc_counts = [b["incomplete_syns"] for b in time_series]
    src_counts = [b["distinct_incomplete_sources"] for b in time_series]

    return {
        "pcap_file": pcap_path.name,
        "duration_seconds": total_secs,
        "target_destination_ip": target_dst_ip,
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
    session2_dir = root / "lab/captures/session2"

    idle_res = analyze_pcap_handshakes(session2_dir / "lab_idle.pcap")
    busy_res = analyze_pcap_handshakes(session2_dir / "lab_busy.pcap")
    flood_res = analyze_pcap_handshakes(session2_dir / "lab_syn_flood.pcap")

    # Frozen threshold definition based strictly on Session 2:
    # Benign max incomplete SYNs/sec = 0
    # Benign max distinct incomplete sources/sec = 0
    # SYN flood min incomplete SYNs/sec = 84 (mean 93.7, max 98)
    # Frozen Threshold: Incomplete SYNs/s >= 10 AND Distinct Incomplete Sources >= 1
    frozen_rule = {
        "rule_name": "SYN_Without_Completed_Handshake_Per_Destination",
        "threshold_incomplete_syns_per_sec": 10,
        "threshold_distinct_sources": 1,
        "time_bin_seconds": 1.0,
        "action": "Alert-Only (No packet drop)",
        "freeze_basis": "Calibrated and frozen strictly on Session 2 captures."
    }

    th_syn = frozen_rule["threshold_incomplete_syns_per_sec"]
    th_src = frozen_rule["threshold_distinct_sources"]

    # Evaluate frozen rule on Session 2
    def evaluate_rule(ts):
        triggered_bins = [
            b for b in ts
            if b["incomplete_syns"] >= th_syn and b["distinct_incomplete_sources"] >= th_src
        ]
        return len(triggered_bins), len(ts)

    idle_trig, idle_tot = evaluate_rule(idle_res["time_series"])
    busy_trig, busy_tot = evaluate_rule(busy_res["time_series"])
    flood_trig, flood_tot = evaluate_rule(flood_res["time_series"])

    benign_tot_bins = idle_tot + busy_tot
    benign_fp_bins = idle_trig + busy_trig
    fpr = benign_fp_bins / max(1, benign_tot_bins)
    recall = flood_trig / max(1, flood_tot)

    performance_summary = {
        "benign_idle_bins": idle_tot,
        "benign_idle_triggered_false_alarms": idle_trig,
        "benign_busy_bins": busy_tot,
        "benign_busy_triggered_false_alarms": busy_trig,
        "total_benign_seconds": benign_tot_bins,
        "benign_false_alarm_rate_per_sec": float(round(fpr, 4)),
        "syn_flood_duration_seconds": flood_tot,
        "syn_flood_detected_seconds": flood_trig,
        "syn_flood_detection_recall": float(round(recall, 4)),
        "first_detection_second": flood_res["time_series"][0]["second"] if flood_trig > 0 else None
    }

    out_data = {
        "frozen_rule_configuration": frozen_rule,
        "session2_evaluation_summary": performance_summary,
        "captures": {
            "lab_idle": {
                "duration_seconds": idle_res["duration_seconds"],
                "incomplete_syns_per_sec": idle_res["incomplete_syns_per_sec"],
                "distinct_sources_per_sec": idle_res["distinct_sources_per_sec"],
            },
            "lab_busy": {
                "duration_seconds": busy_res["duration_seconds"],
                "incomplete_syns_per_sec": busy_res["incomplete_syns_per_sec"],
                "distinct_sources_per_sec": busy_res["distinct_sources_per_sec"],
            },
            "lab_syn_flood": {
                "duration_seconds": flood_res["duration_seconds"],
                "incomplete_syns_per_sec": flood_res["incomplete_syns_per_sec"],
                "distinct_sources_per_sec": flood_res["distinct_sources_per_sec"],
            }
        }
    }

    out_file = root / "results/handshake_packet_rule_eval.json"
    with open(out_file, "w") as f:
        json.dump(out_data, f, indent=2)
    print(f"Wrote handshake packet rule evaluation to {out_file}")


if __name__ == "__main__":
    main()
