"""Tests for mitigation decision logic, whitelist enforcement, consecutive counters, and cooldowns."""

import pytest
from ddos_ads.config import Config
from ddos_ads.mitigation import MitigationManager, is_rfc1918


def create_mock_config(
    enable_blocking: bool = True,
    exempt_rfc1918: bool = False,
    consecutive_windows: int = 3,
    cooldown_sec: int = 300,
    whitelist: list[str] = None,
) -> Config:
    """Create a mock Config instance for testing mitigation decisions."""
    cfg_dict = {
        "paths": {"models_dir": "models"},
        "mitigation": {
            "enable_blocking": enable_blocking,
            "dry_run": True,  # Always dry-run in tests to avoid needing root nft privileges
            "nftables_table": "test_table",
            "nftables_chain": "test_chain",
            "rule_timeout_sec": 3600,
            "exempt_rfc1918": exempt_rfc1918,
            "whitelist_ips": whitelist or ["198.51.100.1"],
        },
        "live_detection": {
            "consecutive_suspicious_windows": consecutive_windows,
            "per_ip_cooldown_sec": cooldown_sec,
        },
    }
    from pathlib import Path
    return Config(cfg_dict, Path("/tmp"))


def test_whitelist_suppresses_blocking_never_alerts() -> None:
    """
    CRITICAL USER CHANGE 1 REQUIREMENT:
    Whitelist must ONLY suppress blocking; it must NEVER suppress logging or alerts!
    """
    cfg = create_mock_config(enable_blocking=True, consecutive_windows=2)
    manager = MitigationManager(cfg, enable_blocking=True, dry_run=True)

    # 127.0.0.1 is mandatorily whitelisted
    assert manager.check_whitelist("127.0.0.1")[0] is True

    # 1st anomaly window for localhost
    dec1 = manager.evaluate_flow("127.0.0.1", is_anomaly=True, anomaly_score=0.95, timestamp=100.0)
    assert dec1["action"] == "ALERT"
    assert dec1["logged"] is True  # Alert logged!

    # 2nd anomaly window for localhost (threshold reached)
    dec2 = manager.evaluate_flow("127.0.0.1", is_anomaly=True, anomaly_score=0.98, timestamp=105.0)
    # Action MUST be ALERT (blocking suppressed), and logged must be True
    assert dec2["action"] == "ALERT"
    assert dec2["logged"] is True
    assert "blocking_suppressed_by_whitelist" in dec2["reason"]


def test_mandatory_infrastructure_protection() -> None:
    """Verify localhost (IPv4/IPv6), 0.0.0.0, and default resolvers are protected."""
    cfg = create_mock_config()
    manager = MitigationManager(cfg, enable_blocking=True, dry_run=True)

    for ip in ["127.0.0.1", "::1", "0.0.0.0", "localhost"]:
        is_wl, reason = manager.check_whitelist(ip)
        assert is_wl is True
        assert "mandatory" in reason


def test_rfc1918_exemption_toggle() -> None:
    """Verify RFC 1918 behavior respects config option (default: False)."""
    # 1. Default: exempt_rfc1918 is False -> Private IP is NOT automatically whitelisted
    cfg_default = create_mock_config(exempt_rfc1918=False)
    mgr_default = MitigationManager(cfg_default, enable_blocking=True, dry_run=True)
    is_wl, _ = mgr_default.check_whitelist("10.0.0.5")
    assert is_wl is False

    # 2. When exempt_rfc1918 is True -> Private IP IS whitelisted
    cfg_exempt = create_mock_config(exempt_rfc1918=True)
    mgr_exempt = MitigationManager(cfg_exempt, enable_blocking=True, dry_run=True)
    is_wl_ex, reason = mgr_exempt.check_whitelist("10.0.0.5")
    assert is_wl_ex is True
    assert "rfc1918" in reason


def test_consecutive_windows_and_blocking_trigger() -> None:
    """Verify IP is only blocked once K consecutive suspicious windows are observed."""
    cfg = create_mock_config(enable_blocking=True, consecutive_windows=3)
    manager = MitigationManager(cfg, enable_blocking=True, dry_run=True)

    target_ip = "203.0.113.50"  # Non-whitelisted public test IP

    # Window 1: Anomaly
    d1 = manager.evaluate_flow(target_ip, is_anomaly=True, anomaly_score=0.85, timestamp=10.0)
    assert d1["action"] == "ALERT"
    assert d1["consecutive_count"] == 1

    # Window 2: Anomaly
    d2 = manager.evaluate_flow(target_ip, is_anomaly=True, anomaly_score=0.90, timestamp=15.0)
    assert d2["action"] == "ALERT"
    assert d2["consecutive_count"] == 2

    # Window 3: Anomaly (hits K=3) -> BLOCKED
    d3 = manager.evaluate_flow(target_ip, is_anomaly=True, anomaly_score=0.92, timestamp=20.0)
    assert d3["action"] == "BLOCKED"
    assert d3["consecutive_count"] == 3
    assert target_ip in manager.active_blocked_ips


def test_cooldown_timer_prevents_duplicate_actions() -> None:
    """Verify cooldown period suppresses repeated block commands while continuing alerts."""
    cfg = create_mock_config(enable_blocking=True, consecutive_windows=1, cooldown_sec=60)
    manager = MitigationManager(cfg, enable_blocking=True, dry_run=True)

    target_ip = "203.0.113.99"

    # 1st window at t=100 -> BLOCKED
    d1 = manager.evaluate_flow(target_ip, is_anomaly=True, anomaly_score=0.9, timestamp=100.0)
    assert d1["action"] == "BLOCKED"

    # 2nd window at t=120 (< 60s cooldown elapsed) -> ALERT with cooldown_active
    d2 = manager.evaluate_flow(target_ip, is_anomaly=True, anomaly_score=0.9, timestamp=120.0)
    assert d2["action"] == "ALERT"
    assert "cooldown_active" in d2["reason"]
    assert d2["logged"] is True


def test_destination_aggregator_consecutive_windows_alert_only() -> None:
    """Verify destination aggregator enforces anomaly fraction and consecutive windows, alert-only."""
    from ddos_ads.live_detector import DestinationAggregator

    agg = DestinationAggregator(
        time_bin_sec=30.0,
        anomaly_fraction_threshold=0.50,
        min_flows_per_bin=5,
        consecutive_windows=2,
        alert_only=True,
    )

    dst = "192.168.1.100"

    # Window 1 (t=10s): 6 flows total, 4 anomaly (fraction = 4/6 = 0.67 >= 0.50)
    for _ in range(4):
        agg.record_flow(dst, is_anomaly=True, timestamp=10.0)
    for _ in range(2):
        agg.record_flow(dst, is_anomaly=False, timestamp=10.0)

    # 1st consecutive window: condition met, but count=1 < required=2 -> No alert yet
    alert1 = agg.evaluate_destination(dst, current_time=10.0)
    assert alert1 is None
    assert agg.consecutive_counts[dst] == 1

    # Window 2 (t=15s): 6 more flows, 4 anomaly
    for _ in range(4):
        agg.record_flow(dst, is_anomaly=True, timestamp=15.0)
    for _ in range(2):
        agg.record_flow(dst, is_anomaly=False, timestamp=15.0)

    # 2nd consecutive window: count=2 >= required=2 -> Triggers DEST_ALERT (alert-only)
    alert2 = agg.evaluate_destination(dst, current_time=15.0)
    assert alert2 is not None
    assert alert2["action"] == "DEST_ALERT"
    assert alert2["alert_only"] is True
    assert alert2["consecutive_count"] == 2
    assert "destination_ddos_surge" in alert2["reason"]


def test_destination_aggregator_insufficient_flows_no_alert() -> None:
    """Verify destination aggregator ignores destinations with fewer than min_flows_per_bin."""
    from ddos_ads.live_detector import DestinationAggregator

    agg = DestinationAggregator(
        time_bin_sec=30.0,
        anomaly_fraction_threshold=0.50,
        min_flows_per_bin=10,
        consecutive_windows=1,
    )

    dst = "10.0.0.1"
    # Only 3 flows, even if 100% anomaly
    for _ in range(3):
        agg.record_flow(dst, is_anomaly=True, timestamp=5.0)

    alert = agg.evaluate_destination(dst, current_time=5.0)
    assert alert is None
