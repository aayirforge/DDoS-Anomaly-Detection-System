#!/usr/bin/env python3
"""
Orchestrates generator calibration captures (60 seconds each):
  - SYN: 50, 200, 500, 1000 pps
  - UDP: 50, 200, 500, 1000 pps
All captured on victim-web into /captures/calibration/
"""

import os
import subprocess
import time

CAPTURE_DIR = "/captures/calibration"

def run_cmd(cmd):
    print(f"[RUN] {cmd}")
    subprocess.run(cmd, shell=True, check=True)

def capture_calibration_run(name, pcap_name, attack_type, rate_pps, duration_sec=60):
    pcap_path = f"{CAPTURE_DIR}/{pcap_name}"
    print(f"\n==========================================")
    print(f"Starting {name} ({rate_pps} pps, {duration_sec}s) -> {pcap_path}")
    print(f"==========================================")

    # Start tshark on victim-web for duration_sec + 4 seconds
    capture_dur = duration_sec + 4
    tshark_cmd = (
        f"docker exec -d victim-web tshark -i eth0 -a duration:{capture_dur} "
        f"-w {pcap_path} -F pcap"
    )
    run_cmd(tshark_cmd)
    time.sleep(2)  # allow tshark to attach

    # Run precision generator
    gen_cmd = (
        f"docker exec traffic-generator python /app/flood.py "
        f"--type {attack_type} --target victim-web --port 80 --rate {rate_pps} --duration {duration_sec}"
    )
    print(f"[GENERATOR] {gen_cmd}")
    run_cmd(gen_cmd)

    print("Traffic finished. Waiting for tshark to flush buffer...")
    time.sleep(3)

    # Verify pcap
    run_cmd(f"docker exec victim-web ls -lh {pcap_path}")
    run_cmd(f"docker exec victim-web tshark -r {pcap_path} | wc -l")

def main():
    run_cmd("docker exec victim-web mkdir -p /captures/calibration")

    # 1. SYN Calibration Runs
    rates = [50, 200, 500, 1000]
    for r in rates:
        capture_calibration_run(
            name=f"SYN Flood Calibration ({r} pps)",
            pcap_name=f"calib_syn_{r}.pcap",
            attack_type="syn",
            rate_pps=r,
            duration_sec=60
        )

    # 2. UDP Calibration Runs
    for r in rates:
        capture_calibration_run(
            name=f"UDP Flood Calibration ({r} pps)",
            pcap_name=f"calib_udp_{r}.pcap",
            attack_type="udp",
            rate_pps=r,
            duration_sec=60
        )

    run_cmd("docker exec victim-web chmod -R 777 /captures/calibration")
    print("\n[SUCCESS] All 8 calibration captures finished successfully.")

if __name__ == "__main__":
    main()
