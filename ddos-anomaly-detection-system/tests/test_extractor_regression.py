"""Regression test: Extractor per-flow packet and byte counts must match tshark exactly for >= 50 flows from each pcap."""

from collections import defaultdict
from pathlib import Path
import subprocess
import pandas as pd
import pytest


def get_tshark_packets(pcap_path: Path):
    cmd = [
        "tshark", "-r", str(pcap_path),
        "-Y", "tcp",
        "-T", "fields",
        "-e", "frame.time_epoch", "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "tcp.len"
    ]
    lines = subprocess.check_output(cmd).decode().strip().split("\n")
    packets = []
    for line in lines:
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) >= 6:
            packets.append({
                "t": float(parts[0]),
                "src": parts[1],
                "dst": parts[2],
                "sport": int(parts[3]),
                "dport": int(parts[4]),
                "len": int(parts[5]),
            })
    return packets


def assert_flows_match_tshark(csv_path: Path, pcap_path: Path, min_flows: int = 50):
    df = pd.read_csv(csv_path)
    df.columns = [c.strip() for c in df.columns]
    packets = get_tshark_packets(pcap_path)

    checked = 0
    matches = 0
    mismatch_details = []

    for _, row in df.head(min_flows).iterrows():
        s_ip = str(row["Src IP"])
        d_ip = str(row["Dst IP"])
        sp = int(row["Src Port"])
        dp = int(row["Dst Port"])

        fpkts = [p for p in packets if p["src"] == s_ip and p["dst"] == d_ip and p["sport"] == sp and p["dport"] == dp]
        bpkts = [p for p in packets if p["src"] == d_ip and p["dst"] == s_ip and p["sport"] == dp and p["dport"] == sp]
        all_f = sorted(fpkts + bpkts, key=lambda x: x["t"])

        if not all_f:
            mismatch_details.append(f"No tshark packets found for {s_ip}:{sp} -> {d_ip}:{dp}")
            continue

        jf_cnt = int(row["Total Fwd Packet"])
        jb_cnt = int(row["Total Bwd packets"])
        jf_bytes = int(row["Total Length of Fwd Packet"])
        jb_bytes = int(row["Total Length of Bwd Packet"])

        matched = False
        for i in range(len(all_f)):
            sub = all_f[i: i + jf_cnt + jb_cnt]
            sub_f = [p for p in sub if p["src"] == s_ip]
            sub_b = [p for p in sub if p["src"] == d_ip]
            if (len(sub_f) == jf_cnt and len(sub_b) == jb_cnt and
                    sum(p["len"] for p in sub_f) == jf_bytes and sum(p["len"] for p in sub_b) == jb_bytes):
                matched = True
                break

        if matched:
            matches += 1
        else:
            mismatch_details.append(
                f"Flow {s_ip}:{sp} -> {d_ip}:{dp}: Java ({jf_cnt} fwd pkts, {jb_cnt} bwd pkts, {jf_bytes} fwd bytes, {jb_bytes} bwd bytes) not found in tshark packets"
            )
        checked += 1

    assert checked >= min_flows, f"Expected at least {min_flows} flows to test, found {checked}"
    assert matches == checked, f"Mismatches detected ({matches}/{checked} matched):\n" + "\n".join(mismatch_details[:5])


def test_extractor_vs_tshark_idle():
    root = Path(__file__).resolve().parent.parent
    csv_path = root / "lab/captures/session2_java/idle_classic.pcap_Flow.csv"
    pcap_path = root / "lab/captures/session2/lab_idle.pcap"
    assert_flows_match_tshark(csv_path, pcap_path, min_flows=50)


def test_extractor_vs_tshark_busy():
    root = Path(__file__).resolve().parent.parent
    csv_path = root / "lab/captures/session2_java/busy_classic.pcap_Flow.csv"
    pcap_path = root / "lab/captures/session2/lab_busy.pcap"
    assert_flows_match_tshark(csv_path, pcap_path, min_flows=50)


def test_extractor_vs_tshark_syn_flood():
    root = Path(__file__).resolve().parent.parent
    csv_path = root / "lab/captures/session2_java/syn_classic.pcap_Flow.csv"
    pcap_path = root / "lab/captures/session2/lab_syn_flood.pcap"
    assert_flows_match_tshark(csv_path, pcap_path, min_flows=50)
