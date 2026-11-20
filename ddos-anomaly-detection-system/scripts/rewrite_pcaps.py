#!/usr/bin/env python3
"""
scripts/rewrite_pcaps.py
========================
Rewrites IP addresses from 172.20.0.0/16 to 10.50.0.0/16 using Scapy.
Evaluates both original and rewritten captures via ui_analyzer.analyze_capture_file
to prove generality across arbitrary target subnets without modifying thresholds.
"""

from pathlib import Path
import sys

from scapy.all import IP, TCP, UDP, PcapReader, PcapWriter

from ddos_ads.ui_analyzer import analyze_capture_file

REPO_ROOT = Path(__file__).resolve().parents[1]
SESSION3_DIR = REPO_ROOT / "lab/captures/session3"
OUT_DIR = REPO_ROOT / "lab/captures/rewritten"
OUT_DIR.mkdir(parents=True, exist_ok=True)

TARGET_PCAPS = [
    {
        "name": "SYN Flood 200 pps",
        "pcap": SESSION3_DIR / "session3_tcp_syn_flood_200pps_rep1.pcap",
        "rewritten": OUT_DIR / "session3_tcp_syn_flood_200pps_rep1_subnet10.pcap",
        "expected_class": "ALERT_SYN_FLOOD",
    },
    {
        "name": "UDP Flood 50 pps",
        "pcap": SESSION3_DIR / "session3_udp_flood_random_ports_50pps_rep1.pcap",
        "rewritten": OUT_DIR / "session3_udp_flood_random_ports_50pps_rep1_subnet10.pcap",
        "expected_class": "ALERT_UDP_FLOOD",
    },
    {
        "name": "Port Scan 30 pps",
        "pcap": SESSION3_DIR / "session3_reconnaissance_port_scan_30pps_rep1.pcap",
        "rewritten": OUT_DIR / "session3_reconnaissance_port_scan_30pps_rep1_subnet10.pcap",
        "expected_class": "ALERT_SCAN",
    },
]


def rewrite_subnet(in_path: Path, out_path: Path, src_prefix="172.20.", dst_prefix="10.50.") -> int:
    """Reads in_path, replaces IP prefix, and writes to out_path."""
    count = 0
    writer = PcapWriter(str(out_path), sync=True)
    with PcapReader(str(in_path)) as reader:
        for pkt in reader:
            if IP in pkt:
                if pkt[IP].src.startswith(src_prefix):
                    pkt[IP].src = pkt[IP].src.replace(src_prefix, dst_prefix, 1)
                if pkt[IP].dst.startswith(src_prefix):
                    pkt[IP].dst = pkt[IP].dst.replace(src_prefix, dst_prefix, 1)
                del pkt[IP].chksum
                if TCP in pkt:
                    del pkt[TCP].chksum
                elif UDP in pkt:
                    del pkt[UDP].chksum
            writer.write(pkt)
            count += 1
    writer.close()
    return count


def run_comparative_analysis():
    results = []
    print(f"{'Scenario':<20} | {'Type':<9} | {'Victim IP':<12} | {'Alerts':<7} | {'First Alert Type':<17} | {'First Alert Delay'}")
    print("-" * 88)

    for item in TARGET_PCAPS:
        orig_pcap = item["pcap"]
        rewr_pcap = item["rewritten"]

        # Rewrite pcap
        if not rewr_pcap.is_file():
            pkt_cnt = rewrite_subnet(orig_pcap, rewr_pcap)
            print(f"Rewrote {pkt_cnt} packets -> {rewr_pcap.name}")

        # Analyze original
        orig_run_dir = REPO_ROOT / f"results/ui_runs/test_orig_{orig_pcap.stem}"
        orig_res = analyze_capture_file(orig_pcap, orig_pcap.name, f"orig_{orig_pcap.stem}", out_dir=orig_run_dir, enable_posthoc_rule=False)

        # Analyze rewritten
        rewr_run_dir = REPO_ROOT / f"results/ui_runs/test_rewr_{rewr_pcap.stem}"
        rewr_res = analyze_capture_file(rewr_pcap, rewr_pcap.name, f"rewr_{rewr_pcap.stem}", out_dir=rewr_run_dir, enable_posthoc_rule=False)

        orig_v_ip = orig_res["results"]["alerts"][0]["destination"] if orig_res["results"]["alerts"] else "None"
        rewr_v_ip = rewr_res["results"]["alerts"][0]["destination"] if rewr_res["results"]["alerts"] else "None"

        orig_delay = orig_res["results"]["first_alert_delay_sec"]
        rewr_delay = rewr_res["results"]["first_alert_delay_sec"]

        orig_alerts = orig_res["results"]["total_alerts"]
        rewr_alerts = rewr_res["results"]["total_alerts"]

        orig_type = orig_res["results"]["first_alert_type"]
        rewr_type = rewr_res["results"]["first_alert_type"]

        print(f"{item['name']:<20} | Original  | {orig_v_ip:<12} | {orig_alerts:<7} | {orig_type:<17} | {orig_delay} s")
        print(f"{item['name']:<20} | Rewritten | {rewr_v_ip:<12} | {rewr_alerts:<7} | {rewr_type:<17} | {rewr_delay} s")
        print("-" * 88)

        # Exact parity check
        assert orig_alerts == rewr_alerts, f"Alert count mismatch: orig {orig_alerts} vs rewr {rewr_alerts}"
        assert orig_type == rewr_type, f"Alert type mismatch: orig {orig_type} vs rewr {rewr_type}"
        assert orig_delay == rewr_delay, f"Delay mismatch: orig {orig_delay} vs rewr {rewr_delay}"
        assert rewr_v_ip == "10.50.0.2", f"Rewritten victim IP expected 10.50.0.2, got {rewr_v_ip}"

        results.append({
            "scenario": item["name"],
            "orig_alerts": orig_alerts,
            "rewr_alerts": rewr_alerts,
            "orig_first_alert": orig_type,
            "rewr_first_alert": rewr_type,
            "orig_delay_s": orig_delay,
            "rewr_delay_s": rewr_delay,
            "orig_victim": orig_v_ip,
            "rewr_victim": rewr_v_ip,
        })

    return results


if __name__ == "__main__":
    run_comparative_analysis()
