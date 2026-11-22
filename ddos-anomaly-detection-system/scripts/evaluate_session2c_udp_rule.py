#!/usr/bin/env python3
"""
Evaluates Packet-Level UDP Rule on Session 2c Captures:
  - lab_session2c_benign.pcap (DNS, NTP, Echo, Streaming UDP, Bursty HTTP)
  - lab_session2c_udp_flood_30.pcap (30 pps flood)
  - lab_session2c_udp_flood_80.pcap (80 pps flood)
  - lab_session2c_udp_flood_300.pcap (300 pps flood)
Computes per-second UDP metrics, evaluates detection performance across thresholds,
and freezes the UDP defense threshold on Session 2c.
Saves to results/session2c_udp_evaluation.json.
"""
import json
from pathlib import Path
import subprocess
import numpy as np

REPO_ROOT = Path(__file__).resolve().parent.parent
CAPTURES_DIR = REPO_ROOT / "lab/captures/session2c"
RESULTS_DIR = REPO_ROOT / "results"

def parse_udp_pcap(pcap_path):
    cmd = [
        "tshark", "-r", str(pcap_path),
        "-Y", "udp",
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "udp.srcport",
        "-e", "udp.dstport"
    ]
    out = subprocess.check_output(cmd, text=True)
    packets = []
    for line in out.strip().splitlines():
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) >= 5:
            packets.append({
                "epoch": float(parts[0]),
                "src_ip": parts[1],
                "dst_ip": parts[2],
                "src_port": int(parts[3]),
                "dst_port": int(parts[4])
            })
    return packets

def bin_udp_packets(packets):
    if not packets:
        return {}
    t0 = packets[0]["epoch"]
    bins = {}
    for p in packets:
        sec = int(p["epoch"] - t0)
        if sec not in bins:
            bins[sec] = []
        bins[sec].append(p)
    return bins

def main():
    print("Evaluating Session 2c UDP Captures...")

    pcaps = {
        "benign": CAPTURES_DIR / "lab_session2c_benign.pcap",
        "flood_30": CAPTURES_DIR / "lab_session2c_udp_flood_30.pcap",
        "flood_80": CAPTURES_DIR / "lab_session2c_udp_flood_80.pcap",
        "flood_300": CAPTURES_DIR / "lab_session2c_udp_flood_300.pcap"
    }

    pcap_data = {}
    for k, pcap in pcaps.items():
        if pcap.exists():
            print(f"Reading {pcap.name}...")
            pkts = parse_udp_pcap(pcap)
            binned = bin_udp_packets(pkts)
            # Exclude very first and last fractional seconds for clean steady-state rates
            sec_keys = sorted(binned.keys())
            steady_keys = sec_keys[1:-1] if len(sec_keys) > 2 else sec_keys
            rates = [len(binned[s]) for s in steady_keys]
            pcap_data[k] = {
                "total_udp_packets": len(pkts),
                "duration_seconds": len(sec_keys),
                "steady_state_seconds": len(steady_keys),
                "rates": rates,
                "binned": binned,
                "stats": {
                    "min": int(np.min(rates)) if rates else 0,
                    "median": float(np.median(rates)) if rates else 0,
                    "p95": float(np.percentile(rates, 95)) if rates else 0,
                    "max": int(np.max(rates)) if rates else 0
                }
            }

    benign_rates = pcap_data["benign"]["rates"]
    print(f"Benign UDP Rates: Min={min(benign_rates)}, Med={np.median(benign_rates)}, Max={max(benign_rates)}")

    # Evaluate candidate thresholds:
    # Rule Form: Alert if (udp_pkts_per_sec >= T_high) OR (udp_pkts_per_sec >= T_multi AND distinct_dst_ports >= 5)
    candidate_thresholds = [25, 30, 35, 40, 50]
    thresh_eval = []

    for th in candidate_thresholds:
        # Benign False Positives: seconds where benign rate >= th
        # Note: In benign, streaming UDP goes to port 5004 (single port)
        # Random port flood targets many ports
        b_fps = sum(1 for r in benign_rates if r >= th)
        b_fpr = b_fps / max(1, len(benign_rates))

        rec_30 = sum(1 for r in pcap_data["flood_30"]["rates"] if r >= th) / max(1, len(pcap_data["flood_30"]["rates"]))
        rec_80 = sum(1 for r in pcap_data["flood_80"]["rates"] if r >= th) / max(1, len(pcap_data["flood_80"]["rates"]))
        rec_300 = sum(1 for r in pcap_data["flood_300"]["rates"] if r >= th) / max(1, len(pcap_data["flood_300"]["rates"]))

        thresh_eval.append({
            "threshold_udp_pps": th,
            "benign_fps": b_fps,
            "benign_total_sec": len(benign_rates),
            "benign_fpr": round(b_fpr, 4),
            "recall_30_pps": round(rec_30, 4),
            "recall_80_pps": round(rec_80, 4),
            "recall_300_pps": round(rec_300, 4)
        })

    # Dual-Condition UDP Rule:
    # Condition 1: Concentrated / High Volumetric (>= 40 pkts/s)
    # Condition 2: Distributed Random-Port Flood (>= 25 pkts/s AND distinct_dst_ports >= 5)
    # Let's test the Dual-Condition UDP Rule on all captures
    dual_eval = {}
    for k, pinfo in pcap_data.items():
        binned = pinfo["binned"]
        sec_keys = sorted(binned.keys())
        steady_keys = sec_keys[1:-1] if len(sec_keys) > 2 else sec_keys
        triggered_secs = 0
        for s in steady_keys:
            pkts = binned[s]
            cnt = len(pkts)
            dst_ports = len(set(p["dst_port"] for p in pkts))
            # Trigger if volumetric (>= 40) OR (>= 25 with >= 5 distinct dst ports)
            if cnt >= 40 or (cnt >= 25 and dst_ports >= 5):
                triggered_secs += 1
        dual_eval[k] = {
            "evaluated_seconds": len(steady_keys),
            "triggered_seconds": triggered_secs,
            "rate_fraction": round(triggered_secs / max(1, len(steady_keys)), 4)
        }

    out = {
        "metadata": {
            "experiment": "Session 2c UDP Multi-Protocol & Flood Benchmark",
            "benign_protocols": "DNS (UDP:53), NTP (UDP:123), Echo (UDP:7), Streaming RTP (UDP:5004, 15 pps), Bursty HTTP (TCP:80)",
            "flood_rates_tested": [30, 80, 300]
        },
        "per_scenario_udp_rates": {
            k: {
                "total_packets": v["total_udp_packets"],
                "duration_seconds": v["duration_seconds"],
                "steady_state_seconds": v["steady_state_seconds"],
                "rate_stats": v["stats"]
            }
            for k, v in pcap_data.items()
        },
        "single_threshold_sweep": thresh_eval,
        "frozen_dual_udp_rule": {
            "name": "Packet-Level Dual-Condition UDP Rule",
            "condition_volumetric": "udp_packets_per_sec >= 40",
            "condition_random_port_flood": "udp_packets_per_sec >= 25 AND distinct_dst_ports >= 5",
            "action": "Alert-Only (Passive Logging)",
            "evaluation_results": {
                "benign_fpr": dual_eval["benign"]["rate_fraction"],
                "benign_fps": dual_eval["benign"]["triggered_seconds"],
                "recall_30_pps": dual_eval["flood_30"]["rate_fraction"],
                "recall_80_pps": dual_eval["flood_80"]["rate_fraction"],
                "recall_300_pps": dual_eval["flood_300"]["rate_fraction"]
            }
        }
    }

    out_path = RESULTS_DIR / "session2c_udp_evaluation.json"
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"Saved Session 2c UDP evaluation to {out_path}")

if __name__ == "__main__":
    main()
