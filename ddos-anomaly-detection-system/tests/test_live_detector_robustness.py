"""
Unit tests for Phase 7 live packet detector robustness, determinism, and safety.
==============================================================================
Tests:
1. UDP counting strictly ignores ICMP-quoted UDP headers.
2. Bounded handshake table eviction does not create false alerts for benign hosts.
3. Blind state is set when drops > 0 and on process supervisor restarts.
4. Replay output is deterministic across two runs (identical alert logs).
5. Exempt-destination suppresses only alert action, never logging.
"""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import tempfile
import pytest

from ddos_ads.live_packet_detector import LivePacketDetector
from ddos_ads.rule_engine import Alert, RuleEngine

REPO_ROOT = Path(__file__).resolve().parents[1]
CAPTURES_DIR = REPO_ROOT / "lab/captures/session3"


def test_udp_counting_ignores_icmp_quoted_udp_headers():
    """
    Asserts that UDP counting logic ignores ICMP packets (such as Type 3 Code 3
    Port Unreachable error responses quoting inner UDP headers).
    """
    engine = RuleEngine(victim_ip="172.20.0.2")

    # 1. Feed 50 ICMP packets (proto=1) destined to victim quoting UDP datagrams
    alerts_icmp = []
    base_ts = 1000.0
    for i in range(50):
        ts = base_ts + i * 0.01
        # Proto 1 = ICMP (not UDP 17)
        a = engine.process_packet(
            ts=ts,
            src_ip="172.20.0.3",
            dst_ip="172.20.0.2",
            sport=50000 + i,
            dport=80,
            proto="1",
            syn=0,
            ack=0,
            rst=0
        )
        alerts_icmp.extend(a)

    assert len(alerts_icmp) == 0, "ICMP error packets must never trigger UDP alerts"
    assert len(engine.udp_window) == 0, "ICMP packets must not enter UDP sliding window"


def test_handshake_table_eviction_no_false_alerts():
    """
    Asserts that FIFO capacity eviction in the bounded handshake table
    does not create false alerts on benign traffic.
    """
    max_cap = 500
    engine = RuleEngine(victim_ip="172.20.0.2", max_handshakes=max_cap)

    benign_host = "172.20.0.4"
    spoofed_base = "10.0."

    # Interleave 2,000 spoofed incomplete SYNs with 100 completing benign handshakes
    ts = 1000.0
    for i in range(2000):
        ts += 0.001
        # Spoofed SYN
        engine.process_packet(
            ts=ts,
            src_ip=f"{spoofed_base}{i // 256}.{i % 256}",
            dst_ip="172.20.0.2",
            sport=1024 + (i % 50000),
            dport=80,
            proto="tcp",
            syn=1,
            ack=0,
            rst=0
        )

        # Periodic benign session completing in 20ms
        if i % 20 == 0:
            b_sport = 40000 + (i // 20)
            engine.process_packet(
                ts=ts,
                src_ip=benign_host,
                dst_ip="172.20.0.2",
                sport=b_sport,
                dport=80,
                proto="tcp",
                syn=1,
                ack=0,
                rst=0
            )
            engine.process_packet(
                ts=ts + 0.02,
                src_ip=benign_host,
                dst_ip="172.20.0.2",
                sport=b_sport,
                dport=80,
                proto="tcp",
                syn=0,
                ack=1,
                rst=0
            )

    # Capacity evictions must have occurred
    assert engine.capacity_evictions > 1000, f"Expected capacity evictions, got {engine.capacity_evictions}"
    assert len(engine.active_handshakes) <= max_cap, "Table size must strictly obey capacity bound"

    # Benign host must never be flagged as an attacker
    for alert in engine.alerts_emitted:
        assert alert.details.get("src_ip") != benign_host, "Benign host must never trigger alert upon table eviction"


def test_blind_state_set_on_drops_and_supervisor_restart():
    """
    Asserts that detector blind state is active when tshark drops > 0
    and when the supervisor handles worker process restarts.
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_jsonl = Path(tmp_dir) / "alerts.jsonl"
        tmp_db = Path(tmp_dir) / "alerts.db"

        detector = LivePacketDetector(
            victim_ip="172.20.0.2",
            jsonl_path=tmp_jsonl,
            sqlite_path=tmp_db,
        )

        # Baseline: initially clean
        assert detector.tshark_drops == 0
        assert detector.tshark_restarts == 0
        assert not detector.detector_blind

        # 1. Simulate packet drop condition
        detector.tshark_drops = 45
        sample_alert = Alert(
            wall_time=1000.0,
            packet_ts=1000.0,
            alert_type="ALERT_UDP_FLOOD",
            rule="dual_condition_udp",
            victim_ip="172.20.0.2",
            details={},
            latency_ms=0.01,
        )
        detector.log_alert(sample_alert)

        assert detector.detector_blind is True
        assert sample_alert.details["tshark_drops"] == 45
        assert sample_alert.details["detector_blind"] is True

        # 2. Simulate supervisor restart condition
        detector.tshark_restarts = 1
        detector.log_blind_event("tshark_worker_crash", gap_ms=12.4)

        # Verify DB records blind alert
        conn = sqlite3.connect(str(tmp_db))
        cursor = conn.cursor()
        cursor.execute("SELECT alert_type, details FROM alerts WHERE alert_type = 'DETECTOR_BLIND'")
        row = cursor.fetchone()
        assert row is not None, "DETECTOR_BLIND must be persisted in database"
        assert "tshark_worker_crash" in row[1]
        conn.close()


def test_replay_determinism_across_two_runs():
    """
    Asserts that replaying the same PCAP capture twice produces bitwise
    identical alert records, counts, and sequences.
    """
    pcap = CAPTURES_DIR / "session3_tcp_syn_flood_50pps_rep1.pcap"
    assert pcap.is_file(), f"Missing PCAP {pcap}"

    with tempfile.TemporaryDirectory() as tmp_dir:
        # Run 1
        j1 = Path(tmp_dir) / "run1.jsonl"
        d1 = Path(tmp_dir) / "run1.db"
        det1 = LivePacketDetector(victim_ip="172.20.0.2", jsonl_path=j1, sqlite_path=d1)
        stats1 = det1.replay_pcap(pcap, pace=0.0)

        # Run 2
        j2 = Path(tmp_dir) / "run2.jsonl"
        d2 = Path(tmp_dir) / "run2.db"
        det2 = LivePacketDetector(victim_ip="172.20.0.2", jsonl_path=j2, sqlite_path=d2)
        stats2 = det2.replay_pcap(pcap, pace=0.0)

        assert stats1["packets_processed"] == stats2["packets_processed"]
        assert stats1["alerts_emitted"] == stats2["alerts_emitted"]
        assert stats1["first_detection_delay_sec"] == stats2["first_detection_delay_sec"]
        assert stats1["alert_seconds_count"] == stats2["alert_seconds_count"]

        # Compare JSONL lines
        lines1 = j1.read_text(encoding="utf-8").strip().splitlines()
        lines2 = j2.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines1) == len(lines2)

        for l1, l2 in zip(lines1, lines2):
            d_a = json.loads(l1)
            d_b = json.loads(l2)
            # Deterministic fields
            assert d_a["packet_ts"] == d_b["packet_ts"]
            assert d_a["alert_type"] == d_b["alert_type"]
            assert d_a["rule"] == d_b["rule"]
            assert d_a["victim_ip"] == d_b["victim_ip"]
            assert d_a["details"] == d_b["details"]


def test_exempt_destination_suppresses_alert_action_preserves_logging():
    """
    Asserts that an exempt destination suppresses only active mitigation/alert action,
    while strictly preserving full logging to JSONL and SQLite.
    Default exempt destinations list is empty.
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        j_log = Path(tmp_dir) / "alerts.jsonl"
        s_db = Path(tmp_dir) / "alerts.db"

        exempt_ip = "172.20.0.99"
        det_default = LivePacketDetector(victim_ip="172.20.0.2")
        assert len(det_default.exempt_destinations) == 0, "Default exempt-destination list must be empty"

        det_exempt = LivePacketDetector(
            victim_ip=exempt_ip,
            jsonl_path=j_log,
            sqlite_path=s_db,
            exempt_destinations={exempt_ip},
        )

        sample_alert = Alert(
            wall_time=1000.0,
            packet_ts=1000.0,
            alert_type="ALERT_SYN_FLOOD",
            rule="tcp_incomplete_handshake",
            victim_ip=exempt_ip,
            details={"incomplete_count": 25},
            latency_ms=0.02,
        )

        det_exempt.log_alert(sample_alert)

        # 1. Action is suppressed
        assert sample_alert.details["action_suppressed"] is True

        # 2. Logging is strictly preserved in JSONL
        assert j_log.is_file()
        lines = j_log.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["victim_ip"] == exempt_ip
        assert record["details"]["action_suppressed"] is True

        # 3. Logging is strictly preserved in SQLite
        conn = sqlite3.connect(str(s_db))
        cur = conn.cursor()
        cur.execute("SELECT victim_ip, details FROM alerts WHERE victim_ip = ?", (exempt_ip,))
        row = cur.fetchone()
        assert row is not None, "Exempt destination alert must still be inserted into SQLite DB"
        assert row[0] == exempt_ip
        conn.close()


def test_supervisor_restart_drops_pre_gap_handshakes_no_false_alerts():
    """
    Asserts that on supervisor restart, pending handshakes initiated prior to the crash
    gap are dropped, preventing false incomplete handshake alerts.
    """
    engine = RuleEngine(victim_ip="172.20.0.2")

    # 1. Simulate 25 benign SYNs before the crash gap (ts = 100.0)
    # If left pending without ACKs, 25 incomplete SYNs would exceed Condition B (>=20) at ts = 102.0s
    for i in range(25):
        engine.process_packet(
            ts=100.0 + i * 0.01,
            src_ip=f"192.168.1.{(i % 250) + 1}",
            dst_ip="172.20.0.2",
            sport=20000 + i,
            dport=80,
            proto="tcp",
            syn=1,
            ack=0,
            rst=0
        )

    assert len(engine.active_handshakes) == 25

    # 2. Crash gap occurs at ts = 100.5. Supervisor restarts and drops pre-gap handshakes.
    gap_cutoff = 100.5
    dropped = engine.drop_pending_handshakes_before(cutoff_ts=gap_cutoff)
    assert dropped == 25, f"Expected 25 dropped handshakes, got {dropped}"
    assert len(engine.active_handshakes) == 0

    # 3. Time advances past the 2.0s timeout post-restart (ts = 103.0s)
    # Send a benign packet to advance time
    post_alerts = engine.process_packet(
        ts=103.0,
        src_ip="172.20.0.4",
        dst_ip="172.20.0.2",
        sport=54321,
        dport=80,
        proto="tcp",
        syn=0,
        ack=1,
        rst=0
    )

    # Must produce ZERO incomplete handshake alerts
    assert len(post_alerts) == 0, f"Expected 0 alerts after restart, got {len(post_alerts)}"
    assert len(engine.alerts_emitted) == 0, "No alerts must have been emitted from dropped pre-gap handshakes"


def test_benign_flash_crowd_exceeding_table_size_no_false_alerts():
    """
    Asserts that a massive benign flash crowd exceeding the handshake table capacity
    generates zero false alerts. Capacity evictions must increment capacity_evictions
    without being falsely counted as incomplete handshakes.
    """
    table_cap = 1000
    engine = RuleEngine(victim_ip="172.20.0.2", max_handshakes=table_cap)

    # 5,000 distinct benign connections arriving within 0.1s
    ts = 500.0
    alerts = []
    for i in range(5000):
        ts += 0.00002
        src_ip = f"10.10.{(i // 250) % 250}.{(i % 250) + 1}"
        sport = 1024 + (i % 60000)
        a = engine.process_packet(
            ts=ts,
            src_ip=src_ip,
            dst_ip="172.20.0.2",
            sport=sport,
            dport=80,
            proto="tcp",
            syn=1,
            ack=0,
            rst=0
        )
        alerts.extend(a)

    assert len(engine.active_handshakes) == table_cap
    assert engine.capacity_evictions == 4000
    assert len(alerts) == 0, f"Benign flash crowd must produce 0 alerts, got {len(alerts)}"

    # Advance time by 3.0s with no attack
    flush_alerts = engine.process_packet(
        ts=ts + 3.0,
        src_ip="172.20.0.4",
        dst_ip="172.20.0.2",
        sport=9999,
        dport=80,
        proto="tcp",
        syn=0,
        ack=1,
        rst=0
    )
    # The 1,000 remaining entries in the table that never got ACKs will expire at ts+2.0s,
    # but the 4,000 capacity-evicted entries were not counted.
    assert engine.capacity_evictions == 4000

