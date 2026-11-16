"""Lightweight mock Web & API server for isolated DDoS lab testing."""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import os
import time

PORT = 80
DATA_DIR = "/app/files"

os.makedirs(DATA_DIR, exist_ok=True)

# Generate mock files of varying sizes for file download testing
with open(os.path.join(DATA_DIR, "small.txt"), "wb") as f:
    f.write(b"X" * 1024)  # 1 KB

with open(os.path.join(DATA_DIR, "medium.bin"), "wb") as f:
    f.write(os.urandom(64 * 1024))  # 64 KB

with open(os.path.join(DATA_DIR, "large.bin"), "wb") as f:
    f.write(os.urandom(512 * 1024))  # 512 KB


class LabHTTPHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Silent logging to prevent console flooding
        pass

    def do_GET(self):
        path = self.path.split("?")[0]

        if path in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><head><title>Victim Web Server</title></head><body><h1>Enterprise Web Portal</h1><p>Running isolated lab benchmark.</p></body></html>")

        elif path in ("/about", "/contact", "/dashboard"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(f"<html><body><h1>Page: {path}</h1><p>Timestamp: {time.time()}</p></body></html>".encode())

        elif path == "/api/v1/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "healthy", "uptime_sec": int(time.time()), "load": 0.12}).encode())

        elif path == "/api/v1/metrics":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            metrics = {f"metric_{i}": i * 1.5 for i in range(20)}
            self.wfile.write(json.dumps({"metrics": metrics, "timestamp": time.time()}).encode())

        elif path == "/api/v1/users":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            users = [{"id": i, "name": f"User_{i}", "role": "engineer"} for i in range(10)]
            self.wfile.write(json.dumps({"users": users}).encode())

        elif path.startswith("/files/"):
            fname = os.path.basename(path)
            fpath = os.path.join(DATA_DIR, fname)
            if os.path.isfile(fpath):
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(os.path.getsize(fpath)))
                self.end_headers()
                with open(fpath, "rb") as f:
                    while chunk := f.read(65536):
                        self.wfile.write(chunk)
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"File not found")

        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

    def do_POST(self):
        path = self.path.split("?")[0]
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length > 0 else b""

        if path in ("/api/v1/data", "/api/v1/submit"):
            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"received_bytes": len(body), "status": "processed", "time": time.time()}).encode())
        else:
            self.send_response(404)
            self.end_headers()


def run():
    server = HTTPServer(("0.0.0.0", PORT), LabHTTPHandler)
    print(f"Mock Web & API Server listening on port {PORT}...")
    server.serve_forever()


if __name__ == "__main__":
    run()
