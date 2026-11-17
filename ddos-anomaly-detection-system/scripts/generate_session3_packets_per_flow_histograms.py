"""Regenerate packets-per-flow histogram and 5-tuple analysis from Session 3 PCAPs."""

import json
from pathlib import Path
from collections import Counter
import subprocess

CAPTURES_DIR = Path("ddos-anomaly-detection-system/lab/captures/session3")
if not CAPTURES_DIR.exists():
    CAPTURES_DIR = Path("lab/captures/session3")

OUT_FILE = Path("ddos-anomaly-detection-system/results/session3_packets_per_flow_histograms.json")
if not OUT_FILE.parent.exists():
    OUT_FILE = Path("results/session3_packets_per_flow_histograms.json")

def analyze_pcap(pcap_path: Path):
    cmd = [
        "tshark", "-r", str(pcap_path),
        "-Y", "ip.src == 172.20.0.3",
        "-T", "fields",
        "-e", "ip.proto",
        "-e", "tcp.srcport",
        "-e", "udp.srcport",
        "-e", "tcp.dstport",
        "-e", "udp.dstport"
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    counts = Counter()
    total_pkts = 0
    for line in proc.stdout:
        line = line.strip()
        if not line:
            continue
        parts = line.split("\t")
        proto = parts[0] if len(parts) > 0 else ""
        sport = parts[1] if (len(parts) > 1 and parts[1]) else (parts[2] if len(parts) > 2 else "")
        dport = parts[3] if (len(parts) > 3 and parts[3]) else (parts[4] if len(parts) > 4 else "")
        counts[(proto, sport, dport)] += 1
        total_pkts += 1
    proc.wait()
    return total_pkts, counts

def main():
    scenarios = {}
    for p in sorted(CAPTURES_DIR.glob("*.pcap")):
        if "benign" in p.name:
            continue
        parts = p.name.replace(".pcap", "").split("_")
        scen = "_".join(parts[1:-1])
        scenarios.setdefault(scen, []).append(p)

    summary = {}
    for scen, pcaps in sorted(scenarios.items()):
        per_rep_stats = []
        union_tuples = set()
        for p in pcaps:
            tot_pkts, counts = analyze_pcap(p)
            hist = Counter(counts.values())
            n_unique = len(counts)
            union_tuples.update(counts.keys())
            n_reused = sum(v for k, v in hist.items() if k >= 2)
            pkts_reused = sum(k * v for k, v in hist.items() if k >= 2)
            per_rep_stats.append({
                "pcap": p.name,
                "total_pkts": tot_pkts,
                "unique_tuples": n_unique,
                "reused_tuples": n_reused,
                "reused_pkts": pkts_reused,
                "hist": {str(k): hist[k] for k in sorted(hist.keys())}
            })
        summary[scen] = {
            "total_reps": len(pcaps),
            "union_unique_tuples": len(union_tuples),
            "per_rep_stats": per_rep_stats
        }

    with open(OUT_FILE, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"[OK] Generated {OUT_FILE} for {len(summary)} scenarios.")

if __name__ == "__main__":
    main()
