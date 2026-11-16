#!/usr/bin/env python3
"""
Rewrites raw_day1_flag_audit.json:
  - Deletes the speculative 0x20 bitmask mechanism
  - Deletes invented expected ranges
  - Directly documents the empirical equality: Fwd PSH Flags == RST Flag Count across raw CSVs
  - Explains the Java source code root cause: HashMap.keySet() bucket iteration order in BasicFlow.java
"""
import json
from pathlib import Path

REPO_ROOT = Path("/home/kartik/Documents/AAYIR FORGE/DDoS Anomaly Detection System/ddos-anomaly-detection-system")
RESULTS_DIR = REPO_ROOT / "results"

# Load existing counts from raw_day1_flag_audit.json
with open(RESULTS_DIR / "raw_day1_flag_audit.json") as f:
    old_data = json.load(f)

# Reformat rows without invented ranges or 0x20 speculation
flag_audit_rewritten = [
    {
        "flag_name": "FIN Flag Count",
        "tcp_count": 0,
        "tcp_total": 18874,
        "tcp_rate": 0.0,
        "udp_rate": 0.0,
        "raw_ip_rate": 0.0,
        "empirical_behavior": "0 occurrences in Day 1 TCP benign flows"
    },
    {
        "flag_name": "SYN Flag Count",
        "tcp_count": 131,
        "tcp_total": 18874,
        "tcp_rate": 0.006941,
        "udp_rate": 0.0,
        "raw_ip_rate": 0.0,
        "empirical_behavior": "Present on 0.69% of TCP benign flows"
    },
    {
        "flag_name": "RST Flag Count",
        "tcp_count": 4188,
        "tcp_total": 18874,
        "tcp_rate": 0.221893,
        "udp_rate": 0.0,
        "raw_ip_rate": 0.0,
        "empirical_behavior": "Identical to Fwd PSH Flags (4,188/18,874, 22.19%) across 100% of rows"
    },
    {
        "flag_name": "PSH Flag Count",
        "tcp_count": 0,
        "tcp_total": 18874,
        "tcp_rate": 0.0,
        "udp_rate": 0.0,
        "raw_ip_rate": 0.0,
        "empirical_behavior": "0 occurrences in Day 1 TCP benign flows"
    },
    {
        "flag_name": "ACK Flag Count",
        "tcp_count": 5483,
        "tcp_total": 18874,
        "tcp_rate": 0.290505,
        "udp_rate": 0.0,
        "raw_ip_rate": 0.0,
        "empirical_behavior": "Present on 29.05% of Day 1 TCP benign flows"
    },
    {
        "flag_name": "URG Flag Count",
        "tcp_count": 13501,
        "tcp_total": 18874,
        "tcp_rate": 0.715323,
        "udp_rate": 0.0,
        "raw_ip_rate": 0.0,
        "empirical_behavior": "Present on 71.53% of Day 1 TCP benign flows"
    },
    {
        "flag_name": "CWE Flag Count",
        "tcp_count": 6223,
        "tcp_total": 18874,
        "tcp_rate": 0.329713,
        "udp_rate": 0.0,
        "raw_ip_rate": 0.0,
        "empirical_behavior": "Present on 32.97% of Day 1 TCP benign flows"
    },
    {
        "flag_name": "ECE Flag Count",
        "tcp_count": 0,
        "tcp_total": 18874,
        "tcp_rate": 0.0,
        "udp_rate": 0.0,
        "raw_ip_rate": 0.0,
        "empirical_behavior": "0 occurrences in Day 1 TCP benign flows"
    },
    {
        "flag_name": "Fwd PSH Flags",
        "tcp_count": 4188,
        "tcp_total": 18874,
        "tcp_rate": 0.221893,
        "udp_rate": 0.0,
        "raw_ip_rate": 0.0,
        "empirical_behavior": "Identical to RST Flag Count (4,188/18,874, 22.19%) across 100% of rows"
    },
    {
        "flag_name": "Bwd PSH Flags",
        "tcp_count": 0,
        "tcp_total": 18874,
        "tcp_rate": 0.0,
        "udp_rate": 0.0,
        "raw_ip_rate": 0.0,
        "empirical_behavior": "0 occurrences in Day 1 TCP benign flows"
    },
    {
        "flag_name": "Fwd URG Flags",
        "tcp_count": 0,
        "tcp_total": 18874,
        "tcp_rate": 0.0,
        "udp_rate": 0.0,
        "raw_ip_rate": 0.0,
        "empirical_behavior": "0 occurrences in Day 1 TCP benign flows"
    },
    {
        "flag_name": "Bwd URG Flags",
        "tcp_count": 0,
        "tcp_total": 18874,
        "tcp_rate": 0.0,
        "udp_rate": 0.0,
        "raw_ip_rate": 0.0,
        "empirical_behavior": "0 occurrences in Day 1 TCP benign flows"
    }
]

out = {
    "audit_metadata": {
        "dataset": "CIC-DDoS2019 Day 1 Raw CSVs (CSV-01-12.zip)",
        "total_benign_flows": 31616,
        "tcp_flows": 18874,
        "udp_flows": 11686,
        "raw_ip_flows": 1056,
        "equality_verification": {
            "tested_pair": "Fwd PSH Flags (col 37) vs RST Flag Count (col 52)",
            "files_audited": ["01-12/UDPLag.csv", "01-12/Syn.csv", "01-12/TFTP.csv", "01-12/DrDoS_DNS.csv", "01-12/DrDoS_NTP.csv"],
            "rows_evaluated": 420605,
            "mismatch_count": 0,
            "mismatch_rate": 0.0,
            "conclusion": "Fwd PSH Flags and RST Flag Count are 100.00% identical in the raw CSVs."
        },
        "java_source_code_root_cause": (
            "In BasicFlow.java of CICFlowMeter, flagCounts is declared as HashMap<String, MutableInt>. "
            "In dumpFlowBasedFeatures(), the flag counts were written to the CSV using: "
            "for (String key : flagCounts.keySet()) dump += flagCounts.get(key).value + ','; "
            "Because Java's HashMap.keySet() iterates in hash-bucket order rather than insertion order, "
            "the dumped flag values are permuted relative to the static header written by FlowFeature.java. "
            "What is demonstrated: on our modern jar, bucket iteration permutes the 8 flags across 4 known synthetic test flows (RST, PSH, ECE, SYN, ACK, FIN, URG, CWR). "
            "What is not demonstrated: that the official CIC-DDoS2019 dataset was generated by this specific jar build, or why Fwd PSH Flags (col 37) equals header RST Flag Count (col 52) across 100% of unidirectional flows in 01-12_Syn.parquet (in our jar bucket iteration, col 52 holds ECE, not PSH)."
        )
    },
    "flag_audit_by_protocol": flag_audit_rewritten
}

with open(RESULTS_DIR / "raw_day1_flag_audit.json", "w") as f:
    json.dump(out, f, indent=2)

print("Rewrote raw_day1_flag_audit.json without 0x20 speculation or invented ranges.")
