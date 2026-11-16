"""Session 2b Benign Traffic Generator:
1. Closed port connections (to port 81)
2. Stopped server connections (to unbound IP 172.20.0.99)
3. 20+ short-lived concurrent HTTP clients (to port 80)
4. Scanner-like burst (rapid connect attempts across ports 20-70)
"""

import socket
import threading
import time
import urllib.request


def test_closed_port(target_ip: str = "172.20.0.2", port: int = 81, count: int = 5):
    print(f"1. Closed Port Test: Connecting {count} times to {target_ip}:{port}...")
    for i in range(count):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            s.connect((target_ip, port))
            s.close()
        except Exception:
            pass  # Expected RST/ACK
        time.sleep(0.5)


def test_stopped_server(unbound_ip: str = "172.20.0.99", port: int = 80, count: int = 5):
    print(f"2. Stopped Server Test: Connecting {count} times to {unbound_ip}:{port}...")
    for i in range(count):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            s.connect((unbound_ip, port))
            s.close()
        except Exception:
            pass  # Expected timeout
        time.sleep(0.2)


def test_short_lived_clients(target_ip: str = "172.20.0.2", port: int = 80, num_clients: int = 25):
    print(f"3. Short-Lived Clients Test: Spawning {num_clients} concurrent HTTP clients to {target_ip}:{port}...")
    url = f"http://{target_ip}:{port}/"
    results = []

    def client_worker(cid: int):
        t0 = time.time()
        try:
            with urllib.request.urlopen(url, timeout=2.0) as resp:
                data = resp.read()
                results.append((cid, True, time.time() - t0))
        except Exception as e:
            results.append((cid, False, time.time() - t0))

    threads = [threading.Thread(target=client_worker, args=(i,)) for i in range(num_clients)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    successes = sum(1 for r in results if r[1])
    print(f"Completed {successes}/{num_clients} successful HTTP requests.")


def test_scanner_burst(target_ip: str = "172.20.0.2", port_range: range = range(20, 71)):
    print(f"4. Scanner Burst Test: Rapidly scanning {len(port_range)} ports on {target_ip}...")
    for port in port_range:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.05)
        try:
            s.connect((target_ip, port))
            s.close()
        except Exception:
            pass
        # Tiny delay to produce a dense burst within ~1-2 seconds
        time.sleep(0.02)
    print("Scanner burst finished.")


def main():
    print("=== Starting Session 2b Benign Traffic Generation ===")
    time.sleep(1)
    test_closed_port()
    time.sleep(1)
    test_stopped_server()
    time.sleep(1)
    test_short_lived_clients()
    time.sleep(1)
    test_scanner_burst()
    time.sleep(1)
    print("=== Session 2b Benign Traffic Generation Complete ===")


if __name__ == "__main__":
    main()
