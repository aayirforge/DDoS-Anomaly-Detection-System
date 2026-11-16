"""Unit tests verifying that UDP packet counting strictly excludes ICMP-quoted headers.

ICMP error responses (e.g., Destination Unreachable / Port Unreachable, Type 3 Code 3)
contain as their payload the IP header and the first 8+ bytes of the original UDP datagram.
Naive packet filters such as Wireshark 'udp' match both real UDP packets and ICMP packets
quoting UDP headers. These tests enforce that UDP counting logic strictly excludes ICMP-quoted
headers, preventing false alarms or inflated rate measurements.
"""

import tempfile
import subprocess
from pathlib import Path
import pytest
from scapy.all import IP, UDP, ICMP, wrpcap


def generate_mixed_pcap(pcap_path: str, num_udp: int = 50, num_icmp_quoted: int = 25):
    """Generates a synthetic PCAP with genuine UDP packets and ICMP Port Unreachable error packets quoting UDP headers."""
    packets = []
    base_time = 1000.0

    # 1. Genuine UDP attack packets from 172.20.0.3 to victim 172.20.0.2
    for i in range(num_udp):
        dport = 10000 + (i % 20)
        pkt = IP(src="172.20.0.3", dst="172.20.0.2") / UDP(sport=50000 + i, dport=dport)
        pkt.time = base_time + (i * 0.01)
        packets.append(pkt)

    # 2. ICMP Port Unreachable error responses from victim 172.20.0.2 to 172.20.0.3
    # quoting the incoming UDP packets
    for i in range(num_icmp_quoted):
        orig_udp = IP(src="172.20.0.3", dst="172.20.0.2") / UDP(sport=50000 + i, dport=10000 + (i % 20))
        icmp_err = IP(src="172.20.0.2", dst="172.20.0.3") / ICMP(type=3, code=3) / orig_udp
        icmp_err.time = base_time + (i * 0.01) + 0.002
        packets.append(icmp_err)

    wrpcap(pcap_path, packets)


def test_tshark_filter_excludes_icmp_quoted_udp():
    """Verifies that tshark -Y 'udp && !icmp' strictly ignores ICMP-quoted UDP headers."""
    with tempfile.NamedTemporaryFile(suffix=".pcap") as tmp:
        num_udp = 40
        num_icmp = 20
        generate_mixed_pcap(tmp.name, num_udp=num_udp, num_icmp_quoted=num_icmp)

        # Naive filter 'udp' matches both genuine UDP and ICMP-quoted UDP
        cmd_naive = ["tshark", "-r", tmp.name, "-Y", "udp", "-T", "fields", "-e", "frame.number"]
        out_naive = subprocess.check_output(cmd_naive, text=True).strip().splitlines()
        assert len(out_naive) == num_udp + num_icmp, (
            f"Naive filter should match both UDP ({num_udp}) and ICMP-quoted UDP ({num_icmp})"
        )

        # Strict filter 'udp && !icmp' excludes ICMP packets
        cmd_strict = ["tshark", "-r", tmp.name, "-Y", "udp && !icmp", "-T", "fields", "-e", "frame.number"]
        out_strict = subprocess.check_output(cmd_strict, text=True).strip().splitlines()
        assert len(out_strict) == num_udp, (
            f"Strict filter 'udp && !icmp' must match exactly genuine UDP packets ({num_udp}), got {len(out_strict)}"
        )


def test_scapy_udp_counting_layer_integrity():
    """Verifies that in Python extraction, transport layer must be UDP and outer layer must not be ICMP."""
    from scapy.all import rdpcap, UDPerror

    with tempfile.NamedTemporaryFile(suffix=".pcap") as tmp:
        num_udp = 30
        num_icmp = 15
        generate_mixed_pcap(tmp.name, num_udp=num_udp, num_icmp_quoted=num_icmp)

        packets = rdpcap(tmp.name)
        assert len(packets) == num_udp + num_icmp

        # ICMP packets encapsulate the quoted UDP header inside 'UDPerror'
        quoted_icmp_count = sum(1 for p in packets if p.haslayer(UDPerror))
        assert quoted_icmp_count == num_icmp

        # Protocol byte check: IP proto == 17 matches ONLY real UDP packets, not ICMP (proto == 1)
        real_udp_count = sum(1 for p in packets if p[IP].proto == 17 and not p.haslayer(ICMP))
        assert real_udp_count == num_udp


def test_udp_rule_rate_calculation_with_icmp_exclusion():
    """Verifies that rate calculations and condition thresholds are not triggered by returned ICMP errors."""
    with tempfile.NamedTemporaryFile(suffix=".pcap") as tmp:
        # 25 genuine UDP packets in 1 second (below 40 volumetric and below 30 random-port threshold)
        # plus 20 ICMP error responses
        num_udp = 25
        num_icmp = 20
        generate_mixed_pcap(tmp.name, num_udp=num_udp, num_icmp_quoted=num_icmp)

        cmd = [
            "tshark", "-r", tmp.name,
            "-Y", "udp && !icmp",
            "-T", "fields",
            "-e", "frame.time_epoch",
            "-e", "ip.dst",
            "-e", "udp.dstport"
        ]
        lines = subprocess.check_output(cmd, text=True).strip().splitlines()
        pkts = []
        for line in lines:
            if not line:
                continue
            parts = line.split("\t")
            pkts.append({"epoch": float(parts[0]), "dst_ip": parts[1], "dport": int(parts[2])})

        assert len(pkts) == num_udp

        # Evaluate against Frozen UDP Rule Condition 1 (>=40 pkts/s) and Condition 2 (>=30 pkts/s with >=10 ports)
        rate = len(pkts)  # in 1.0 second span
        distinct_ports = len(set(p["dport"] for p in pkts))

        cond1 = rate >= 40
        cond2 = rate >= 30 and distinct_ports >= 10

        assert not cond1, "Condition 1 should not trigger on 25 pkts/s"
        assert not cond2, "Condition 2 should not trigger on 25 pkts/s"
        assert not (cond1 or cond2), "No false alert should be produced when ICMP error responses are excluded"
