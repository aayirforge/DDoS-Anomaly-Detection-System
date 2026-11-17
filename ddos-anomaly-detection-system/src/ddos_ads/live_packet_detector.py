"""
Phase 7 Live Packet-Rule Detector & Streaming Monitor.
======================================================
Implements real-time packet-level anomaly detection:
1. Live streaming from tshark/dumpcap with automated process supervisor and crash restart.
2. Replay mode supporting original timing (--pace 1.0) and full-speed packet-driven simulation.
3. Structured dual output: JSONL streaming log + SQLite database.
4. Bounded state tracking with documented capacity eviction via RuleEngine.
5. Strict safety guarantee: alert-only, dry-run mitigation only (blocking code disabled).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import queue
import select
import shutil
import signal
import sqlite3
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Set

from ddos_ads.config import Config, load_config
from ddos_ads.mitigation import MitigationManager
from ddos_ads.rule_engine import Alert, RuleEngine
from ddos_ads.utils import setup_logger

logger = setup_logger("ddos_ads.live_packet_detector")

DEFAULT_BPF = "(ip or ip6) and not multicast and not broadcast and not port 1900 and not port 5353"


def init_sqlite_db(db_path: Path) -> sqlite3.Connection:
    """Initialize SQLite database schema for live packet rule alerts."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                wall_time REAL NOT NULL,
                packet_ts REAL NOT NULL,
                alert_type TEXT NOT NULL,
                rule TEXT NOT NULL,
                victim_ip TEXT NOT NULL,
                details TEXT NOT NULL,
                latency_ms REAL NOT NULL
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_packet_ts ON alerts(packet_ts);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(alert_type);")
    return conn


class LivePacketDetector:
    """
    Live streaming and replay packet-level anomaly detector.
    """

    def __init__(
        self,
        config: Optional[Config] = None,
        victim_ip: str = "172.20.0.2",
        interface: str = "eth0",
        bpf_filter: str = DEFAULT_BPF,
        jsonl_path: Optional[Path] = None,
        sqlite_path: Optional[Path] = None,
        max_handshakes: int = 100_000,
        ring_buffer_size: int = 100_000,
        exempt_destinations: Optional[Set[str]] = None,
    ) -> None:
        if config is None:
            # Check default locations
            default_cfg = Path("config.yaml")
            alt_cfg = Path(__file__).resolve().parents[2] / "config.yaml"
            if default_cfg.is_file():
                self.config = load_config(default_cfg)
            elif alt_cfg.is_file():
                self.config = load_config(alt_cfg)
            else:
                self.config = load_config()
        else:
            self.config = config
        self.victim_ip = victim_ip
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.running = False
        self.ring_buffer_size = ring_buffer_size
        self.ring_buffer: queue.Queue = queue.Queue(maxsize=ring_buffer_size)

        # Exempt destinations list (default empty)
        self.exempt_destinations: Set[str] = set(exempt_destinations or [])

        # Output paths
        logs_dir = self.config.get_path("logs_dir")
        logs_dir.mkdir(parents=True, exist_ok=True)
        self.jsonl_path = jsonl_path or (logs_dir / "alerts.jsonl")
        self.sqlite_path = sqlite_path or (logs_dir / "alerts.db")

        # Initialize SQLite DB
        self.db_conn = init_sqlite_db(self.sqlite_path)

        # Core Rule Engine
        self.engine = RuleEngine(victim_ip=victim_ip, max_handshakes=max_handshakes)

        # Mitigation Manager (Guaranteed dry-run only, blocking strictly disabled)
        self.mitigation = MitigationManager(self.config, enable_blocking=False, dry_run=True)

        # Metrics and State
        self.tshark_restarts: int = 0
        self.tshark_drops: int = 0
        self.detector_blind: bool = False
        self.total_packets_processed: int = 0
        self.total_alerts_emitted: int = 0
        self.latencies_ms: List[float] = []

    def log_blind_event(self, reason: str, gap_ms: float = 0.0) -> None:
        """Record detector blind event when tshark drops packets or process restarts."""
        self.detector_blind = True
        blind_alert = Alert(
            wall_time=time.time(),
            packet_ts=self.engine.last_processed_ts if self.engine.last_processed_ts is not None else time.time(),
            alert_type="DETECTOR_BLIND",
            rule="process_supervisor",
            victim_ip=self.victim_ip,
            details={
                "reason": reason,
                "restart_gap_ms": round(gap_ms, 2),
                "tshark_drops": self.tshark_drops,
                "tshark_restarts": self.tshark_restarts,
                "detector_blind": True,
            },
            latency_ms=0.0,
        )
        self.log_alert(blind_alert)

    def log_alert(self, alert: Alert) -> None:
        """Record alert to JSONL log and SQLite database, and invoke dry-run mitigation."""
        # Update blind state
        if self.tshark_drops > 0 or self.tshark_restarts > 0:
            self.detector_blind = True

        alert.details["tshark_drops"] = self.tshark_drops
        alert.details["tshark_restarts"] = self.tshark_restarts
        alert.details["detector_blind"] = self.detector_blind

        action_suppressed = alert.victim_ip in self.exempt_destinations
        alert.details["action_suppressed"] = action_suppressed

        self.total_alerts_emitted += 1
        self.latencies_ms.append(alert.latency_ms)

        # 1. Append to JSONL - ALWAYS LOGGED
        with open(self.jsonl_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(alert.to_dict()) + "\n")

        # 2. Insert into SQLite - ALWAYS LOGGED
        with self.db_conn:
            self.db_conn.execute("""
                INSERT INTO alerts (wall_time, packet_ts, alert_type, rule, victim_ip, details, latency_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                alert.wall_time,
                alert.packet_ts,
                alert.alert_type,
                alert.rule,
                alert.victim_ip,
                json.dumps(alert.details),
                alert.latency_ms,
            ))

        # 3. Dry-run mitigation action - SUPPRESSED IF DESTINATION IS EXEMPT
        if action_suppressed:
            logger.info(f"[EXEMPT-SUPPRESSED] Alert action suppressed for exempt destination {alert.victim_ip}")
        else:
            logger.info(
                f"[LIVE-ALERT] {alert.alert_type} on {alert.victim_ip} (pkt_ts={alert.packet_ts:.4f}, "
                f"latency={alert.latency_ms:.2f}ms, drops={self.tshark_drops}, blind={self.detector_blind}): {alert.details}"
            )

    def _parse_and_process_line(self, line: str, t_start: Optional[float] = None) -> List[Alert]:
        """Parse raw tshark field line and process through rule engine."""
        parts = line.strip().split("\t")
        if len(parts) < 4:
            return []

        ts = float(parts[0])
        s_ip = parts[1]
        d_ip = parts[2]
        proto = parts[3]

        if proto in ("6", "tcp"):
            sp = int(parts[4]) if len(parts) > 4 and parts[4] else 0
            dp = int(parts[5]) if len(parts) > 5 and parts[5] else 0
            syn = 1 if len(parts) > 6 and parts[6] in ("1", "True") else 0
            ack = 1 if len(parts) > 7 and parts[7] in ("1", "True") else 0
            rst = 1 if len(parts) > 8 and parts[8] in ("1", "True") else 0
        else:
            sp = int(parts[9]) if len(parts) > 9 and parts[9] else 0
            dp = int(parts[10]) if len(parts) > 10 and parts[10] else 0
            syn = ack = rst = 0

        self.total_packets_processed += 1
        alerts = self.engine.process_packet(ts, s_ip, d_ip, sp, dp, proto, syn=syn, ack=ack, rst=rst, t_start=t_start)
        for a in alerts:
            self.log_alert(a)
        return alerts

    def replay_pcap(
        self,
        pcap_path: Path,
        pace: float = 0.0,
        duration_sec: Optional[int] = None,
        max_packets: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Replay packets from a PCAP file.
        - pace == 0.0: full speed driven strictly by packet timestamps.
        - pace == 1.0: paced at original timing.
        """
        self.engine.reset()
        cmd = [
            "tshark", "-r", str(pcap_path), "-Y", "(tcp || udp) && !icmp",
            "-T", "fields",
            "-e", "frame.time_epoch",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "ip.proto",
            "-e", "tcp.srcport",
            "-e", "tcp.dstport",
            "-e", "tcp.flags.syn",
            "-e", "tcp.flags.ack",
            "-e", "tcp.flags.reset",
            "-e", "udp.srcport",
            "-e", "udp.dstport"
        ]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if proc.stdout is None:
            raise RuntimeError(f"Unable to launch tshark reader for {pcap_path}")

        first_pkt_ts: Optional[float] = None
        last_pkt_ts: Optional[float] = None
        first_attack_ts: Optional[float] = None
        attack_gen_ip = "172.20.0.3"

        t_wall_start = time.perf_counter()
        stop_reader = threading.Event()

        def _pipe_reader():
            try:
                for line in proc.stdout:
                    if stop_reader.is_set():
                        break
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        self.ring_buffer.put(line, timeout=0.05)
                    except queue.Full:
                        self.tshark_drops += 1
                        self.detector_blind = True
            finally:
                self.ring_buffer.put(None)

        reader_thread = threading.Thread(target=_pipe_reader, daemon=True)
        reader_thread.start()

        try:
            while True:
                try:
                    line = self.ring_buffer.get(timeout=1.0)
                except queue.Empty:
                    if proc.poll() is not None:
                        break
                    continue

                if line is None:  # EOF sentinel
                    break

                parts = line.split("\t")
                if len(parts) < 4:
                    continue
                ts = float(parts[0])

                if first_pkt_ts is None:
                    first_pkt_ts = ts
                if parts[1] == attack_gen_ip and first_attack_ts is None:
                    first_attack_ts = ts

                # Pacing support
                if pace > 0.0 and last_pkt_ts is not None:
                    delta_pkt = ts - last_pkt_ts
                    if delta_pkt > 0:
                        sleep_time = delta_pkt / pace
                        if sleep_time > 0.0001:
                            time.sleep(sleep_time)

                last_pkt_ts = ts
                target_t_start = first_attack_ts if first_attack_ts is not None else first_pkt_ts
                self._parse_and_process_line(line, t_start=target_t_start)

                if max_packets is not None and self.total_packets_processed >= max_packets:
                    break
        finally:
            stop_reader.set()
            proc.terminate()
            proc.wait()
            reader_thread.join(timeout=2.0)

        target_t_start = first_attack_ts if first_attack_ts is not None else first_pkt_ts
        final_alerts = self.engine.flush(t_start=target_t_start)
        for a in final_alerts:
            self.log_alert(a)

        wall_dur = time.perf_counter() - t_wall_start
        rate_pps = self.total_packets_processed / max(0.001, wall_dur)

        delay = None
        if self.engine.first_alert_ts is not None and target_t_start is not None:
            delay = round(self.engine.first_alert_ts - target_t_start, 4)

        return {
            "pcap": pcap_path.name,
            "packets_processed": self.total_packets_processed,
            "duration_wall_sec": round(wall_dur, 4),
            "throughput_pps": round(rate_pps, 2),
            "alerts_emitted": self.total_alerts_emitted,
            "first_detection_delay_sec": delay,
            "first_alert_type": self.engine.first_alert_type,
            "alert_seconds_count": len(self.engine.alert_seconds),
            "capacity_evictions": self.engine.capacity_evictions,
            "completed_handshakes": self.engine.completed_handshakes,
        }

    def run_live(
        self,
        duration_sec: Optional[int] = None,
        max_restarts: int = 10,
    ) -> Dict[str, Any]:
        """
        Live streaming detection loop with automated process supervisor.
        If tshark crashes or exits unexpectedly, supervisor restarts it and preserves engine state.
        """
        self.running = True
        t_start = time.time()
        tshark_cmd = [
            "tshark", "-l", "-n", "-i", self.interface,
            "-f", self.bpf_filter,
            "-Y", "(tcp || udp) && !icmp",
            "-T", "fields",
            "-e", "frame.time_epoch",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "ip.proto",
            "-e", "tcp.srcport",
            "-e", "tcp.dstport",
            "-e", "tcp.flags.syn",
            "-e", "tcp.flags.ack",
            "-e", "tcp.flags.reset",
            "-e", "udp.srcport",
            "-e", "udp.dstport"
        ]

        logger.info(f"Starting LivePacketDetector on interface {self.interface}...")
        proc: Optional[subprocess.Popen] = None

        while self.running:
            if duration_sec and (time.time() - t_start) >= duration_sec:
                break

            try:
                proc = subprocess.Popen(
                    tshark_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                )
                logger.info(f"Spawned tshark worker (PID={proc.pid})")

                while self.running:
                    if duration_sec and (time.time() - t_start) >= duration_sec:
                        self.running = False
                        break

                    line = proc.stdout.readline() if proc.stdout else ""
                    if not line:
                        # Check if process died
                        ret = proc.poll()
                        if ret is not None:
                            logger.warning(f"tshark process terminated unexpectedly with code {ret}!")
                            self.tshark_restarts += 1
                            self.log_blind_event(f"tshark_worker_exit_code_{ret}", gap_ms=10.0)
                            if self.tshark_restarts > max_restarts:
                                raise RuntimeError(f"Exceeded max tshark restarts ({max_restarts})")
                            break
                        time.sleep(0.01)
                        continue

                    self._parse_and_process_line(line, t_start=t_start)

            except Exception as e:
                logger.error(f"Error in live loop: {e}")
                if not self.running:
                    break
                time.sleep(1.0)
            finally:
                if proc and proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=2.0)
                    except subprocess.TimeoutExpired:
                        proc.kill()

        self.engine.flush(t_start=t_start)
        return {
            "status": "STOPPED",
            "runtime_sec": round(time.time() - t_start, 2),
            "packets_processed": self.total_packets_processed,
            "alerts_emitted": self.total_alerts_emitted,
            "tshark_restarts": self.tshark_restarts,
            "tshark_drops": self.tshark_drops,
            "capacity_evictions": self.engine.capacity_evictions,
        }


def main():
    parser = argparse.ArgumentParser(description="Live Packet Detector & Replay Monitor (Phase 7)")
    parser.add_argument("--interface", default="eth0", help="Network interface to monitor")
    parser.add_argument("--replay-pcap", type=Path, default=None, help="Replay packets from PCAP file")
    parser.add_argument("--pace", type=float, default=0.0, help="Replay pacing factor (1.0 = original timing, 0.0 = full speed)")
    parser.add_argument("--duration", type=int, default=None, help="Monitoring duration in seconds")
    parser.add_argument("--victim-ip", default="172.20.0.2", help="Victim server IP address")
    parser.add_argument("--max-handshakes", type=int, default=100_000, help="Capacity bound for active handshakes")

    args = parser.parse_args()
    detector = LivePacketDetector(
        victim_ip=args.victim_ip,
        interface=args.interface,
        max_handshakes=args.max_handshakes,
    )

    if args.replay_pcap:
        logger.info(f"Replaying PCAP: {args.replay_pcap} with pace={args.pace}")
        stats = detector.replay_pcap(args.replay_pcap, pace=args.pace, duration_sec=args.duration)
        print("\nReplay Summary:")
        print(json.dumps(stats, indent=2))
    else:
        logger.info("Starting live detection loop...")
        stats = detector.run_live(duration_sec=args.duration)
        print("\nLive Monitoring Summary:")
        print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()
