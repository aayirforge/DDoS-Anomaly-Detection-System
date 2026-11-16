#!/usr/bin/env python3
"""
Session 2c Benign Traffic Generator.
Generates:
  1. DNS queries to victim-web:53
  2. NTP queries to victim-web:123
  3. UDP echo requests to victim-web:7
  4. Streaming UDP flow: constant 15 pkts/s to victim-web:5004 (RTP-like stream)
  5. Bursty HTTP clients to victim-web:80
Runs for a specified duration (default 90 seconds).
"""
import argparse
import random
import socket
import struct
import threading
import time
import urllib.request

VICTIM_IP = "172.20.0.2"

def dns_client(stop_event):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    # Simple query for test.local
    query = b"\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04test\x05local\x00\x00\x01\x00\x01"
    while not stop_event.is_set():
        try:
            sock.sendto(query, (VICTIM_IP, 53))
            sock.recvfrom(512)
        except Exception:
            pass
        time.sleep(random.uniform(0.3, 0.8)) # 1.5 - 3 queries/s

def ntp_client(stop_event):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    req = bytearray(48)
    req[0] = 0x23  # LI=0, VN=4, Mode=3 (client)
    while not stop_event.is_set():
        try:
            sock.sendto(bytes(req), (VICTIM_IP, 123))
            sock.recvfrom(512)
        except Exception:
            pass
        time.sleep(random.uniform(2.0, 4.0)) # ~0.3 queries/s

def echo_client(stop_event):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    while not stop_event.is_set():
        try:
            payload = f"ECHO_TEST_{time.time()}".encode()
            sock.sendto(payload, (VICTIM_IP, 7))
            sock.recvfrom(512)
        except Exception:
            pass
        time.sleep(random.uniform(0.5, 1.2)) # ~1 query/s

def streaming_udp_flow(stop_event):
    """Generates continuous streaming UDP datagrams: ~15 pkts/s to port 5004."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    seq = 0
    while not stop_event.is_set():
        # RTP header (12 bytes) + 160 bytes audio payload
        rtp_hdr = struct.pack("!BBHII", 0x80, 0x00, seq & 0xFFFF, int(time.time() * 8000) & 0xFFFFFFFF, 0x12345678)
        payload = rtp_hdr + (b"\x55" * 160)
        try:
            sock.sendto(payload, (VICTIM_IP, 5004))
        except Exception:
            pass
        seq += 1
        time.sleep(1.0 / 15.0) # exactly 15 packets per second

def bursty_http_client(stop_event):
    urls = [
        f"http://{VICTIM_IP}/",
        f"http://{VICTIM_IP}/api/v1/health",
        f"http://{VICTIM_IP}/api/v1/metrics",
        f"http://{VICTIM_IP}/files/small.txt",
        f"http://{VICTIM_IP}/dashboard",
    ]
    while not stop_event.is_set():
        # Perform burst of 5-10 requests
        burst_size = random.randint(5, 10)
        for _ in range(burst_size):
            url = random.choice(urls)
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Session2c-Bursty)"})
                with urllib.request.urlopen(req, timeout=2.0) as resp:
                    resp.read()
            except Exception:
                pass
            time.sleep(random.uniform(0.02, 0.08))
        time.sleep(random.uniform(1.0, 3.0)) # pause between bursts

def main():
    parser = argparse.ArgumentParser(description="Session 2c benign generator")
    parser.add_argument("--duration", type=int, default=90, help="Duration in seconds")
    args = parser.parse_args()

    print(f"Starting Session 2c multi-protocol benign traffic for {args.duration}s...")
    stop_event = threading.Event()
    threads = [
        threading.Thread(target=dns_client, args=(stop_event,), daemon=True),
        threading.Thread(target=ntp_client, args=(stop_event,), daemon=True),
        threading.Thread(target=echo_client, args=(stop_event,), daemon=True),
        threading.Thread(target=streaming_udp_flow, args=(stop_event,), daemon=True),
        threading.Thread(target=bursty_http_client, args=(stop_event,), daemon=True),
        threading.Thread(target=bursty_http_client, args=(stop_event,), daemon=True),
    ]
    for t in threads:
        t.start()

    time.sleep(args.duration)
    stop_event.set()
    print("Session 2c benign traffic completed.")

if __name__ == "__main__":
    main()
