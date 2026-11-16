#!/usr/bin/env python3
"""
Orchestrates Session 2c captures:
  1. Benign: DNS, NTP, UDP echo, streaming UDP (15 pps), bursty HTTP clients (60s)
  2. UDP flood 30 pps (30s)
  3. UDP flood 80 pps (30s)
  4. UDP flood 300 pps (30s)
All captured on victim-web into /captures/session2c/
"""
import os
import subprocess
import time

CAPTURE_DIR = "/captures/session2c"

def run_cmd(cmd):
    print(f"[RUN] {cmd}")
    subprocess.run(cmd, shell=True, check=True)

def capture_scenario(name, pcap_name, duration_sec, client_cmd, generator_cmd=None):
    pcap_path = f"{CAPTURE_DIR}/{pcap_name}"
    print(f"\n==========================================")
    print(f"Starting {name} ({duration_sec}s) -> {pcap_path}")
    print(f"==========================================")
    
    # Start tshark in background on victim-web
    tshark_cmd = (
        f"docker exec -d victim-web tshark -i eth0 -a duration:{duration_sec} "
        f"-w {pcap_path} -F pcap"
    )
    run_cmd(tshark_cmd)
    time.sleep(2) # ensure tshark is listening
    
    # Start generator/client traffic
    procs = []
    if client_cmd:
        print(f"[CLIENT] {client_cmd}")
        p1 = subprocess.Popen(client_cmd, shell=True)
        procs.append(p1)
    
    if generator_cmd:
        print(f"[GENERATOR] {generator_cmd}")
        p2 = subprocess.Popen(generator_cmd, shell=True)
        procs.append(p2)
        
    for p in procs:
        p.wait()
        
    print(f"Traffic finished. Waiting for tshark capture completion...")
    time.sleep(3)
    
    # Verify pcap
    run_cmd(f"docker exec victim-web ls -lh {pcap_path}")
    run_cmd(f"docker exec victim-web tshark -r {pcap_path} | wc -l")

def main():
    run_cmd("docker exec victim-web mkdir -p /captures/session2c")
    
    # 1. Benign Multi-protocol (60s)
    capture_scenario(
        name="Session 2c Benign (DNS, NTP, Echo, Streaming, Bursty HTTP)",
        pcap_name="lab_session2c_benign.pcap",
        duration_sec=60,
        client_cmd="docker exec benign-client python /app/session2c_benign.py --duration 56",
        generator_cmd=None
    )
    
    # 2. UDP flood 30 pps (30s)
    capture_scenario(
        name="Session 2c UDP Flood (30 pps)",
        pcap_name="lab_session2c_udp_flood_30.pcap",
        duration_sec=30,
        client_cmd=None,
        generator_cmd="docker exec traffic-generator python /app/flood.py --type udp --target victim-web --port 0 --rate 30 --duration 26"
    )

    # 3. UDP flood 80 pps (30s)
    capture_scenario(
        name="Session 2c UDP Flood (80 pps)",
        pcap_name="lab_session2c_udp_flood_80.pcap",
        duration_sec=30,
        client_cmd=None,
        generator_cmd="docker exec traffic-generator python /app/flood.py --type udp --target victim-web --port 0 --rate 80 --duration 26"
    )

    # 4. UDP flood 300 pps (30s)
    capture_scenario(
        name="Session 2c UDP Flood (300 pps)",
        pcap_name="lab_session2c_udp_flood_300.pcap",
        duration_sec=30,
        client_cmd=None,
        generator_cmd="docker exec traffic-generator python /app/flood.py --type udp --target victim-web --port 0 --rate 300 --duration 26"
    )

    run_cmd("docker exec victim-web chmod -R 777 /captures/session2c")
    print("\nSession 2c captures completely finished.")

if __name__ == "__main__":
    main()
