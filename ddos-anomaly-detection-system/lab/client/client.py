"""Scripted benign traffic client generating Idle and Busy profiles for isolated DDoS lab."""

import argparse
import random
import time
import urllib.request
import urllib.parse
from concurrent.futures import ThreadPoolExecutor


ENDPOINTS_PAGES = ["/", "/index.html", "/about", "/contact", "/dashboard"]
ENDPOINTS_FILES = ["/files/small.txt", "/files/medium.bin", "/files/large.bin"]
ENDPOINTS_API = ["/api/v1/health", "/api/v1/metrics", "/api/v1/users"]
ENDPOINT_POST = "/api/v1/data"


def make_request(base_url: str, path: str, method: str = "GET") -> bool:
    url = f"{base_url.rstrip('/')}{path}"
    try:
        if method == "GET":
            req = urllib.request.Request(url, headers={"User-Agent": "LabBenignClient/1.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                resp.read()
                return True
        elif method == "POST":
            payload = f"data_payload_{time.time()}_{random.randint(1000, 9999)}".encode()
            req = urllib.request.Request(url, data=payload, headers={"User-Agent": "LabBenignClient/1.0", "Content-Type": "text/plain"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                resp.read()
                return True
    except Exception as e:
        return False
    return False


def run_idle_session(base_url: str, duration_sec: int) -> int:
    """Idle profile: sporadic browsing, health check, occasional small download with 1.0-3.0s pauses."""
    print(f"Starting IDLE benign profile against {base_url} for {duration_sec}s...")
    start = time.time()
    req_count = 0
    while time.time() - start < duration_sec:
        r = random.random()
        if r < 0.50:
            make_request(base_url, random.choice(ENDPOINTS_PAGES))
        elif r < 0.80:
            make_request(base_url, "/api/v1/health")
        elif r < 0.95:
            make_request(base_url, "/files/small.txt")
        else:
            make_request(base_url, ENDPOINT_POST, method="POST")
        req_count += 1
        time.sleep(random.uniform(0.5, 2.0))
    print(f"IDLE profile completed: {req_count} requests generated.")
    return req_count


def worker_busy_thread(base_url: str, stop_event_time: float) -> int:
    count = 0
    while time.time() < stop_event_time:
        r = random.random()
        if r < 0.30:
            make_request(base_url, random.choice(ENDPOINTS_FILES))
        elif r < 0.60:
            make_request(base_url, random.choice(ENDPOINTS_API))
        elif r < 0.85:
            make_request(base_url, random.choice(ENDPOINTS_PAGES))
        else:
            make_request(base_url, ENDPOINT_POST, method="POST")
        count += 1
        time.sleep(random.uniform(0.01, 0.10))
    return count


def run_busy_profile(base_url: str, duration_sec: int, concurrency: int = 6) -> int:
    """Busy profile: concurrent workers downloading medium/large files, polling APIs with minimal delay."""
    print(f"Starting BUSY benign profile against {base_url} (concurrency={concurrency}) for {duration_sec}s...")
    start = time.time()
    stop_time = start + duration_sec
    total_reqs = 0

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(worker_busy_thread, base_url, stop_time) for _ in range(concurrency)]
        for f in futures:
            total_reqs += f.result()

    print(f"BUSY profile completed: {total_reqs} requests generated across {concurrency} threads.")
    return total_reqs


def main():
    parser = argparse.ArgumentParser(description="Benign client traffic generator.")
    parser.add_argument("--profile", choices=["idle", "busy"], default="idle", help="Traffic profile.")
    parser.add_argument("--target", default="http://victim-web", help="Target base URL.")
    parser.add_argument("--duration", type=int, default=60, help="Duration in seconds.")
    parser.add_argument("--concurrency", type=int, default=6, help="Concurrency for busy profile.")
    args = parser.parse_args()

    if args.profile == "idle":
        run_idle_session(args.target, args.duration)
    else:
        run_busy_profile(args.target, args.duration, concurrency=args.concurrency)


if __name__ == "__main__":
    main()
