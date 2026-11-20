#!/usr/bin/env python3
"""
scripts/generate_unrelated_captures.py
======================================
Synthesizes 4 realistic unrelated network traffic captures using Scapy:
1. dns_heavy.pcap: High-diversity multi-domain DNS resolution.
2. video_streaming.pcap: Completed TCP TLS handshake followed by bursty streaming data segments.
3. bulk_download.pcap: Completed HTTP TCP handshake followed by large MTU payload download segments.
4. nmap_scan_lab.pcap: Multi-port TCP SYN scan against a local host (should fire ALERT_SCAN).

Runs each capture through ui_analyzer.analyze_capture_file to verify alert-only behavior.
"""

from pathlib import Path
import time
from typing import Dict, Any, List

from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw, wrpcap

from ddos_ads.ui_analyzer import analyze_capture_file

REPO_ROOT = Path(__file__).resolve().parents[1]
UNRELATED_DIR = REPO_ROOT / "lab/captures/unrelated"
UNRELATED_DIR.mkdir(parents=True, exist_ok=True)


def build_dns_heavy_pcap(out_path: Path):
    """50 DNS queries/responses across diverse domains and servers (10 pps)."""
    pkts = []
    base_ts = 1700000000.0
    domains = [
        "example.com", "google.com", "wikipedia.org", "kernel.org", "python.org",
        "ietf.org", "github.com", "cloudflare.com", "mozilla.org", "debian.org"
    ]
    dns_servers = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"]

    for i in range(50):
        ts_q = base_ts + (i * 0.1)
        ts_r = ts_q + 0.02
        dom = domains[i % len(domains)]
        srv = dns_servers[i % len(dns_servers)]
        sport = 49152 + (i % 500)

        # Query
        query = IP(src="192.168.1.10", dst=srv) / UDP(sport=sport, dport=53) / DNS(rd=1, qd=DNSQR(qname=dom))
        query.time = ts_q

        # Response
        resp = IP(src=srv, dst="192.168.1.10") / UDP(sport=53, dport=sport) / DNS(
            id=query[DNS].id, qr=1, aa=0, rd=1, ra=1,
            qd=DNSQR(qname=dom),
            an=DNSRR(rrname=dom, type='A', rdata=f"93.184.216.{10 + (i % 50)}")
        )
        resp.time = ts_r

        pkts.extend([query, resp])

    wrpcap(str(out_path), pkts)


def build_video_streaming_pcap(out_path: Path):
    """Completed TLS TCP handshake followed by 100 video data segments with ACKs at 20 pps."""
    pkts = []
    base_ts = 1700000000.0
    client_ip = "192.168.1.10"
    cdn_ip = "198.51.100.25"
    client_port = 52100
    cdn_port = 443

    # Handshake
    syn = IP(src=client_ip, dst=cdn_ip) / TCP(sport=client_port, dport=cdn_port, flags="S", seq=1000)
    syn.time = base_ts
    synack = IP(src=cdn_ip, dst=client_ip) / TCP(sport=cdn_port, dport=client_port, flags="SA", seq=5000, ack=1001)
    synack.time = base_ts + 0.015
    ack = IP(src=client_ip, dst=cdn_ip) / TCP(sport=client_port, dport=cdn_port, flags="A", seq=1001, ack=5001)
    ack.time = base_ts + 0.02
    pkts.extend([syn, synack, ack])

    # Streaming chunks
    c_seq = 1001
    s_seq = 5001
    for i in range(100):
        t = base_ts + 0.05 + (i * 0.05)  # 20 pps
        # Server sends video chunk
        data = IP(src=cdn_ip, dst=client_ip) / TCP(sport=cdn_port, dport=client_port, flags="PA", seq=s_seq, ack=c_seq) / Raw(b"\x17\x03\x03\x04\x00" + b"\xaa" * 1024)
        data.time = t
        s_seq += 1029

        # Client ACK
        client_ack = IP(src=client_ip, dst=cdn_ip) / TCP(sport=client_port, dport=cdn_port, flags="A", seq=c_seq, ack=s_seq)
        client_ack.time = t + 0.005
        pkts.extend([data, client_ack])

    wrpcap(str(out_path), pkts)


def build_bulk_download_pcap(out_path: Path):
    """Completed HTTP TCP handshake followed by 200 large download segments (100 pps)."""
    pkts = []
    base_ts = 1700000000.0
    client_ip = "192.168.1.10"
    server_ip = "203.0.113.80"
    client_port = 54321
    server_port = 80

    # Handshake
    syn = IP(src=client_ip, dst=server_ip) / TCP(sport=client_port, dport=server_port, flags="S", seq=100)
    syn.time = base_ts
    synack = IP(src=server_ip, dst=client_ip) / TCP(sport=server_port, dport=client_port, flags="SA", seq=300, ack=101)
    synack.time = base_ts + 0.01
    ack = IP(src=client_ip, dst=server_ip) / TCP(sport=client_port, dport=server_port, flags="A", seq=101, ack=301)
    ack.time = base_ts + 0.015
    pkts.extend([syn, synack, ack])

    # HTTP GET request
    get_req = IP(src=client_ip, dst=server_ip) / TCP(sport=client_port, dport=server_port, flags="PA", seq=101, ack=301) / Raw(b"GET /debian.iso HTTP/1.1\r\nHost: example.org\r\n\r\n")
    get_req.time = base_ts + 0.02
    pkts.append(get_req)
    c_seq = 101 + len(get_req[Raw])
    s_seq = 301

    # High speed download
    for i in range(200):
        t = base_ts + 0.03 + (i * 0.01)  # 100 pps
        seg = IP(src=server_ip, dst=client_ip) / TCP(sport=server_port, dport=client_port, flags="A", seq=s_seq, ack=c_seq) / Raw(b"X" * 1440)
        seg.time = t
        s_seq += 1440

        c_ack = IP(src=client_ip, dst=server_ip) / TCP(sport=client_port, dport=server_port, flags="A", seq=c_seq, ack=s_seq)
        c_ack.time = t + 0.002
        pkts.extend([seg, c_ack])

    wrpcap(str(out_path), pkts)


def build_nmap_scan_lab_pcap(out_path: Path):
    """Nmap SYN port scan against lab host: 20 ports scanned without completing handshakes."""
    pkts = []
    base_ts = 1700000000.0
    scanner_ip = "192.168.1.105"
    target_ip = "192.168.1.20"
    target_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 8080, 8443]

    for idx, dport in enumerate(target_ports):
        t = base_ts + (idx * 0.05)  # 20 pps
        sport = 40000 + idx
        syn = IP(src=scanner_ip, dst=target_ip) / TCP(sport=sport, dport=dport, flags="S", seq=1000 + idx)
        syn.time = t
        pkts.append(syn)

    wrpcap(str(out_path), pkts)


def generate_all_and_analyze():
    captures = [
        ("Normal Web Browsing", REPO_ROOT / "lab/captures/normal_web_browsing.pcap", None),
        ("DNS Heavy Resolution", UNRELATED_DIR / "dns_heavy.pcap", build_dns_heavy_pcap),
        ("Video Streaming (HTTPS)", UNRELATED_DIR / "video_streaming.pcap", build_video_streaming_pcap),
        ("Bulk ISO Download", UNRELATED_DIR / "bulk_download.pcap", build_bulk_download_pcap),
        ("Nmap Port Scan (Host)", UNRELATED_DIR / "nmap_scan_lab.pcap", build_nmap_scan_lab_pcap),
    ]

    print(f"{'Capture Name':<25} | {'Packets':<8} | {'Total Alerts':<12} | {'First Alert':<17} | {'Verdict'}")
    print("-" * 80)

    results = []
    for name, pcap_path, builder_fn in captures:
        if builder_fn and not pcap_path.is_file():
            builder_fn(pcap_path)

        run_dir = REPO_ROOT / f"results/ui_runs/test_unrelated_{pcap_path.stem}"
        res = analyze_capture_file(pcap_path, pcap_path.name, f"unrelated_{pcap_path.stem}", out_dir=run_dir, enable_posthoc_rule=True)

        pkts = res["input_metadata"]["packet_count"]
        alerts = res["results"]["total_alerts"]
        first_alert = res["results"]["first_alert_type"] or "None"
        verdict = res["results"]["verdict"]

        print(f"{name:<25} | {pkts:<8} | {alerts:<12} | {first_alert:<17} | {verdict}")

        results.append({
            "name": name,
            "path": str(pcap_path),
            "packets": pkts,
            "alerts": alerts,
            "first_alert": first_alert,
            "verdict": verdict,
        })

    return results


if __name__ == "__main__":
    generate_all_and_analyze()
