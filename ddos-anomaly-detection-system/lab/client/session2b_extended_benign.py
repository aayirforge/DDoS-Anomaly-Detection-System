"""5+ Minutes (300s) Diverse Benign Traffic Generator.

Traffic mix includes:
1. Continuous background HTTP requests and file downloads (ports 80).
2. Slow clients (slow HTTP keep-alive, delayed transfers).
3. Retransmitting clients (TCP SYN and data retransmissions).
4. Single-source port scans at 20, 40, and 60 SYNs/s:
   - 20 SYNs/s for 5s (ports 1000-1099)
   - 40 SYNs/s for 5s (ports 2000-2199)
   - 60 SYNs/s for 5s (ports 3000-3299)
"""

import socket
import threading
import time
import urllib.request


def background_traffic(target_ip: str, duration: int):
    t_end = time.time() + duration
    while time.time() < t_end:
        try:
            with urllib.request.urlopen(f"http://{target_ip}:80/", timeout=2.0) as resp:
                resp.read()
        except Exception:
            pass
        time.sleep(0.5)


def slow_client(target_ip: str, count: int = 10):
    for _ in range(count):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5.0)
            s.connect((target_ip, 80))
            # Send slow request header with 2-second pause
            s.send(b"GET / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n")
            time.sleep(2.0)
            s.send(b"Connection: close\r\n\r\n")
            s.recv(1024)
            s.close()
        except Exception:
            pass
        time.sleep(1.0)


def retransmitting_client(target_ip: str, count: int = 10):
    for _ in range(count):
        try:
            # Connect and send data with non-responsive socket close
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((target_ip, 80))
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
            s.send(b"GET / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n\r\n")
            s.close()  # RST teardown inducing retransmissions
        except Exception:
            pass
        time.sleep(1.0)


def port_scan(target_ip: str, rate_pps: int, duration_sec: int, start_port: int):
    print(f"Running port scan from single source at {rate_pps} SYNs/s for {duration_sec}s (starting port {start_port})...")
    interval = 1.0 / max(1, rate_pps)
    t_end = time.time() + duration_sec
    p = start_port

    while time.time() < t_end:
        t0 = time.time()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(False)
        try:
            s.connect_ex((target_ip, p))
            s.close()
        except Exception:
            pass
        p += 1
        elapsed = time.time() - t0
        to_sleep = interval - elapsed
        if to_sleep > 0:
            time.sleep(to_sleep)


def main():
    target_ip = "172.20.0.2"
    total_duration = 300  # 5 minutes
    print(f"=== Starting 5-Minute (300s) Extended Benign Traffic Generation against {target_ip} ===")

    # 1. Start continuous background threads
    t_bg1 = threading.Thread(target=background_traffic, args=(target_ip, total_duration))
    t_bg2 = threading.Thread(target=background_traffic, args=(target_ip, total_duration))
    t_bg1.start()
    t_bg2.start()

    # 2. Slow clients around t = 30s
    time.sleep(30)
    print("Launching slow clients...")
    slow_client(target_ip, count=15)

    # 3. Retransmitting clients around t = 90s
    time.sleep(20)
    print("Launching retransmitting clients...")
    retransmitting_client(target_ip, count=15)

    # 4. Single-source Port Scan at 20 SYNs/s around t = 150s
    time.sleep(30)
    port_scan(target_ip, rate_pps=20, duration_sec=5, start_port=1000)

    # 5. Single-source Port Scan at 40 SYNs/s around t = 200s
    time.sleep(40)
    port_scan(target_ip, rate_pps=40, duration_sec=5, start_port=2000)

    # 6. Single-source Port Scan at 60 SYNs/s around t = 250s
    time.sleep(40)
    port_scan(target_ip, rate_pps=60, duration_sec=5, start_port=3000)

    # Wait for completion of 300s total duration
    t_bg1.join()
    t_bg2.join()
    print("=== Extended Benign Traffic Generation Complete ===")


if __name__ == "__main__":
    main()
