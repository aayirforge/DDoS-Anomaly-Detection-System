#!/usr/bin/env python3
"""Convenience CLI wrapper to replay PCAPs through LivePacketDetector.

Usage:
  .venv/bin/python3 scripts/replay_pcap_live.py --pcap lab/captures/session3/session3_tcp_syn_flood_200pps_rep1.pcap --pace 0.0
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from ddos_ads.live_packet_detector import LivePacketDetector


def main():
    parser = argparse.ArgumentParser(description="Replay PCAP through Live Packet Detector")
    parser.add_argument("--pcap", type=Path, required=True, help="Path to PCAP file")
    parser.add_argument("--db", type=Path, default=REPO_ROOT / "data/detection_events.db", help="Path to SQLite database")
    parser.add_argument("--pace", "--rate-multiplier", dest="pace", type=float, default=0.0,
                        help="Pacing factor (1.0 = real-time, 0.0 = maximum speed)")
    parser.add_argument("--duration", type=int, default=None, help="Duration in seconds")
    parser.add_argument("--victim-ip", default="172.20.0.2", help="Victim server IP")
    args = parser.parse_args()

    if not args.pcap.is_file():
        print(f"Error: PCAP file not found: {args.pcap}")
        sys.exit(1)

    detector = LivePacketDetector(
        victim_ip=args.victim_ip,
        sqlite_path=args.db,
    )

    stats = detector.replay_pcap(args.pcap, pace=args.pace, duration_sec=args.duration)
    print("\nReplay Summary:")
    print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()
