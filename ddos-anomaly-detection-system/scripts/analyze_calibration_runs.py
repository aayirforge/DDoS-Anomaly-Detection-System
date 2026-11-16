#!/usr/bin/env python3
"""
Analyzes calibration pcap files to compute exact offered rate metrics:
- Total attack packets
- Duration (t_last - t_first)
- Mean offered rate (pps)
- Median per-second rate (pps)
- Per-second range (min - max pps)
- Discrepancy % from nominal rate
"""

import os
import subprocess
import json
import numpy as np

CALIB_DIR = "ddos-anomaly-detection-system/lab/captures/calibration"
OUTPUT_JSON = "ddos-anomaly-detection-system/results/calibration_rates.json"

RUNS = [
    {
        "run_id": "calib_syn_50",
        "attack_type": "TCP SYN Flood",
        "pcap_file": f"{CALIB_DIR}/calib_syn_50.pcap",
        "filter": "ip.src == 172.20.0.3 && tcp.flags.syn == 1 && tcp.flags.ack == 0",
        "nominal_rate_pps": 50,
        "nominal_duration_sec": 60
    },
    {
        "run_id": "calib_syn_200",
        "attack_type": "TCP SYN Flood",
        "pcap_file": f"{CALIB_DIR}/calib_syn_200.pcap",
        "filter": "ip.src == 172.20.0.3 && tcp.flags.syn == 1 && tcp.flags.ack == 0",
        "nominal_rate_pps": 200,
        "nominal_duration_sec": 60
    },
    {
        "run_id": "calib_syn_500",
        "attack_type": "TCP SYN Flood",
        "pcap_file": f"{CALIB_DIR}/calib_syn_500.pcap",
        "filter": "ip.src == 172.20.0.3 && tcp.flags.syn == 1 && tcp.flags.ack == 0",
        "nominal_rate_pps": 500,
        "nominal_duration_sec": 60
    },
    {
        "run_id": "calib_syn_1000",
        "attack_type": "TCP SYN Flood",
        "pcap_file": f"{CALIB_DIR}/calib_syn_1000.pcap",
        "filter": "ip.src == 172.20.0.3 && tcp.flags.syn == 1 && tcp.flags.ack == 0",
        "nominal_rate_pps": 1000,
        "nominal_duration_sec": 60
    },
    {
        "run_id": "calib_udp_50",
        "attack_type": "UDP Flood",
        "pcap_file": f"{CALIB_DIR}/calib_udp_50.pcap",
        "filter": "ip.src == 172.20.0.3 && udp",
        "nominal_rate_pps": 50,
        "nominal_duration_sec": 60
    },
    {
        "run_id": "calib_udp_200",
        "attack_type": "UDP Flood",
        "pcap_file": f"{CALIB_DIR}/calib_udp_200.pcap",
        "filter": "ip.src == 172.20.0.3 && udp",
        "nominal_rate_pps": 200,
        "nominal_duration_sec": 60
    },
    {
        "run_id": "calib_udp_500",
        "attack_type": "UDP Flood",
        "pcap_file": f"{CALIB_DIR}/calib_udp_500.pcap",
        "filter": "ip.src == 172.20.0.3 && udp",
        "nominal_rate_pps": 500,
        "nominal_duration_sec": 60
    },
    {
        "run_id": "calib_udp_1000",
        "attack_type": "UDP Flood",
        "pcap_file": f"{CALIB_DIR}/calib_udp_1000.pcap",
        "filter": "ip.src == 172.20.0.3 && udp",
        "nominal_rate_pps": 1000,
        "nominal_duration_sec": 60
    }
]

def analyze_pcap(run_info):
    pcap = run_info["pcap_file"]
    dfilter = run_info["filter"]
    cmd = ["tshark", "-r", pcap, "-Y", dfilter, "-T", "fields", "-e", "frame.time_epoch"]
    
    res = subprocess.run(cmd, capture_output=True, text=True, check=True)
    timestamps = [float(line.strip()) for line in res.stdout.strip().split("\n") if line.strip()]
    
    if not timestamps:
        raise ValueError(f"No packets matched filter {dfilter} in {pcap}")
        
    ts = np.array(timestamps)
    t0 = ts[0]
    t_end = ts[-1]
    duration = t_end - t0
    total_pkts = len(ts)
    mean_rate = total_pkts / duration if duration > 0 else 0.0
    
    # 1-second binning
    rel_ts = ts - t0
    num_bins = int(np.floor(duration))
    # Count packets per 1-second interval [0, 1), [1, 2), ..., [num_bins-1, num_bins)
    bin_counts = []
    for b in range(num_bins):
        cnt = np.sum((rel_ts >= b) & (rel_ts < b + 1))
        bin_counts.append(int(cnt))
        
    median_pps = float(np.median(bin_counts)) if bin_counts else 0.0
    min_pps = int(np.min(bin_counts)) if bin_counts else 0
    max_pps = int(np.max(bin_counts)) if bin_counts else 0
    
    nominal_pps = run_info["nominal_rate_pps"]
    pct_diff = abs(mean_rate - nominal_pps) / nominal_pps * 100.0
    
    status = "PASS (< 5% error)" if pct_diff < 5.0 else f"FAIL ({pct_diff:.2f}% error)"
    
    result = {
        "run_id": run_info["run_id"],
        "attack_type": run_info["attack_type"],
        "pcap_file": pcap,
        "nominal_rate_pps": nominal_pps,
        "total_attack_packets": total_pkts,
        "duration_sec": round(duration, 3),
        "mean_measured_rate_pps": round(mean_rate, 2),
        "median_pps": round(median_pps, 1),
        "min_pps": min_pps,
        "max_pps": max_pps,
        "range_pps": f"[{min_pps}, {max_pps}]",
        "error_pct": round(pct_diff, 2),
        "status": status,
        "discrepancy_reason": f"Precision deadline scheduler (error {pct_diff:.2f}%)"
    }
    return result

def main():
    results = []
    print(f"Analyzing {len(RUNS)} calibration pcaps...")
    for r in RUNS:
        res = analyze_pcap(r)
        results.append(res)
        print(f"[{res['run_id']}] Nominal: {res['nominal_rate_pps']} pps | Packets: {res['total_attack_packets']} | "
              f"Duration: {res['duration_sec']}s | Mean: {res['mean_measured_rate_pps']} pps | "
              f"Median: {res['median_pps']} pps | Range: {res['range_pps']} | Error: {res['error_pct']}% -> {res['status']}")
              
    with open(OUTPUT_JSON, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved calibration results to {OUTPUT_JSON}")

if __name__ == "__main__":
    main()
