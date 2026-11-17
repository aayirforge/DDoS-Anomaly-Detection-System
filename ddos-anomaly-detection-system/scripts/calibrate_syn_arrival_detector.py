"""
Measure maximum 1-second sliding-window SYN-without-ACK arrival rate and distinct sources
across Session 2, 2b, 2c, and 3 benign captures.
"""

from collections import defaultdict, deque
from pathlib import Path
import subprocess

BENIGN_PCAPS = [
    ("Session 2 Idle", "lab/captures/session2/lab_idle.pcap"),
    ("Session 2 Busy", "lab/captures/session2/lab_busy.pcap"),
    ("Session 2b Benign", "lab/captures/session2b/lab_benign_2b.pcap"),
    ("Session 2b Extended", "lab/captures/session2b/lab_benign_extended.pcap"),
    ("Session 2c Benign", "lab/captures/session2c/lab_session2c_benign.pcap"),
    ("Session 3 Benign 900s", "lab/captures/session3/session3_benign_baseline_900s.pcap"),
]

def analyze_pcap(name: str, path_str: str):
    p = Path(path_str)
    if not p.exists():
        print(f"Skipping {name}: {path_str} not found")
        return
    
    cmd = [
        "tshark", "-r", str(p),
        "-Y", "tcp.flags.syn==1 && tcp.flags.ack==0",
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    # 1.0s sliding window per dst_ip
    # dst_ip -> deque of (ts, src_ip)
    windows = defaultdict(deque)
    src_counts = defaultdict(lambda: defaultdict(int))
    
    max_syn_rate = defaultdict(int)
    max_distinct_sources = defaultdict(int)
    total_syns = 0
    
    for line in proc.stdout:
        line = line.strip()
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        ts_str, s_ip, d_ip = parts[0], parts[1], parts[2]
        try:
            ts = float(ts_str)
        except ValueError:
            continue
        
        total_syns += 1
        w = windows[d_ip]
        sc = src_counts[d_ip]
        
        w.append((ts, s_ip))
        sc[s_ip] += 1
        
        cutoff = ts - 1.0
        while w and w[0][0] <= cutoff:
            _, old_sip = w.popleft()
            sc[old_sip] -= 1
            if sc[old_sip] == 0:
                del sc[old_sip]
                
        cnt = len(w)
        dist_s = len(sc)
        if cnt > max_syn_rate[d_ip]:
            max_syn_rate[d_ip] = cnt
        if dist_s > max_distinct_sources[d_ip]:
            max_distinct_sources[d_ip] = dist_s
            
    proc.wait()
    
    overall_max_syn = max(max_syn_rate.values()) if max_syn_rate else 0
    overall_max_sources = max(max_distinct_sources.values()) if max_distinct_sources else 0
    print(f"{name:25s} | Total SYNs: {total_syns:6d} | Max 1s SYN Rate: {overall_max_syn:3d} | Max Distinct Sources: {overall_max_sources:3d} | By dst: {dict(max_syn_rate)}")

if __name__ == "__main__":
    for name, pcap in BENIGN_PCAPS:
        analyze_pcap(name, pcap)
