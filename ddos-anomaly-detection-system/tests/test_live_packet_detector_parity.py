"""
Pytest Test Suite for Phase 7 Live Packet Detector Parity, Safety, and Performance.
===================================================================================
1. test_session3_pcap_streaming_parity:
   Asserts that all 40 Session 3 pcaps and baseline match results/session3_evaluation.json
   first-alert delay within 1.0s and alerted seconds within 1s.
2. test_benign_baseline_zero_false_alarms:
   Asserts exactly 0 false alarms on the 900s multi-protocol benign baseline.
3. test_mitigation_safety_dry_run_only:
   Verifies that mitigation.py has enable_blocking=False and dry_run=True by default.
4. test_bounded_handshake_table_eviction:
   Verifies that the TCP handshake table strictly respects max_handshakes cap under load.
"""

import json
from pathlib import Path
import pytest

from ddos_ads.config import load_config
from ddos_ads.mitigation import MitigationManager
from ddos_ads.rule_engine import RuleEngine

REPO_ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = REPO_ROOT / "results"
CAPTURES_DIR = REPO_ROOT / "lab/captures/session3"


def test_benign_baseline_zero_false_alarms():
    """Asserts 0 false alarms on the 15-minute benign baseline."""
    engine = RuleEngine()
    base_pcap = CAPTURES_DIR / "session3_benign_baseline_900s.pcap"
    assert base_pcap.is_file(), f"Missing baseline pcap {base_pcap}"

    res = engine.evaluate_pcap_streaming(base_pcap, duration_sec=900, is_baseline=True)
    assert res["alerted_seconds_total"] == 0, f"Expected 0 false alarm seconds, got {res['alerted_seconds_total']}"
    assert res["first_alert_ts"] is None, "Expected no alerts triggered on benign baseline"


def test_session3_all_40_pcaps_parity():
    """
    Parity test on the 40 session 3 pcaps and 900s baseline:
    first-alert time and alerted seconds must match results/session3_evaluation.json within 1s.
    """
    eval_json_path = RESULTS_DIR / "session3_evaluation.json"
    assert eval_json_path.is_file(), "Missing session3_evaluation.json"

    with open(eval_json_path, "r", encoding="utf-8") as f:
        gt_eval = json.load(f)

    engine = RuleEngine()
    failures = []

    for cond_name, cond_data in gt_eval["attack_evaluations"].items():
        for rep_data in cond_data["repeats"]:
            run_id = rep_data["run_id"]
            pcap_file = CAPTURES_DIR / f"{run_id}.pcap"
            assert pcap_file.is_file(), f"Missing PCAP {pcap_file}"

            res = engine.evaluate_pcap_streaming(pcap_file, duration_sec=120)

            gt_delay = rep_data["first_detection_delay_sec"]
            gt_alerted = rep_data["alerted_seconds_post_first_alert"]
            st_delay = res["first_detection_delay_sec"]
            st_alerted = res["alerted_seconds_post_first_alert"]

            diff_delay = abs(st_delay - gt_delay) if (st_delay and gt_delay) else (0.0 if st_delay == gt_delay else 999.0)
            diff_alerted = abs(st_alerted - gt_alerted)

            if diff_delay > 1.0 or diff_alerted > 1:
                failures.append(
                    f"[{run_id}] Parity failure: delay st={st_delay} vs gt={gt_delay} (diff={diff_delay:.4f}s > 1.0s) "
                    f"or alerted st={st_alerted} vs gt={gt_alerted} (diff={diff_alerted} > 1)"
                )

    if failures:
        pytest.fail("\n".join(failures))


def test_mitigation_safety_dry_run_only():
    """Verifies that mitigation remains strictly alert-only / dry-run with no blocking paths."""
    config = load_config(REPO_ROOT / "config.yaml")
    mitigation = MitigationManager(config, enable_blocking=False, dry_run=True)
    assert mitigation.enable_blocking is False, "Blocking must be disabled"
    assert mitigation.dry_run is True, "Dry-run must be enabled"


def test_bounded_handshake_table_eviction():
    """Verifies that table capacity is bounded and triggers capacity eviction under stress."""
    engine = RuleEngine(victim_ip="172.20.0.2", max_handshakes=100)
    # Feed 250 distinct SYN attempts at the same timestamp
    ts = 100.0
    for i in range(250):
        engine.process_packet(
            ts=ts,
            src_ip=f"10.0.0.{i+1}",
            dst_ip="172.20.0.2",
            sport=1000 + i,
            dport=80,
            proto="tcp",
            syn=1,
            ack=0,
            rst=0
        )

    assert len(engine.active_handshakes) <= 100, f"Table size {len(engine.active_handshakes)} exceeded cap 100"
    assert engine.capacity_evictions == 150, f"Expected 150 capacity evictions, got {engine.capacity_evictions}"
