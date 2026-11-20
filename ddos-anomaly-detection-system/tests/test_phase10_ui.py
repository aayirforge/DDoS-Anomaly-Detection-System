"""
Phase 10 Test Suite for Upload Safety, Command Builder, Report Consistency, and Regression Parity.
==================================================================================================
Covers:
1. test_ui_upload:
   - Valid pcap and pcapng accepted.
   - Renamed .exe rejected with clear error message.
   - Path traversal attempt (../../x.pcap) sanitized to input.pcap in run dir.
   - Oversized upload rejected.
   - Truncated pcap marks run blind without crashing.
2. test_ui_command_builder:
   - dumpcap command matches fixed template.
   - Duration strictly capped (30s to 900s).
   - Start refused without user permission checkbox.
   - Disallowed interface rejected.
3. test_ui_report_consistency:
   - Generates report.html and asserts every number equals analysis.json.
   - Tamper test: modifying a number in a scratch copy of analysis.json causes report generation to fail.
4. test_ui_regression_known_pcaps_and_baseline:
   - Evaluates SYN 200 pps, UDP 50 pps, Scan 30 pps, and 900s baseline.
   - Asserts first-alert times equal the parity ground-truth values.
5. test_ui_regression_normal_browsing_upload:
   - Uploads unrelated normal capture (web browsing pcap).
   - Asserts 0 alerts triggered.
"""

from __future__ import annotations

import copy
import io
import json
from pathlib import Path
import pytest

from ddos_ads.rule_engine import RuleEngine
from ddos_ads.ui_analyzer import (
    analyze_capture_file,
    calculate_sha256,
    validate_and_stream_upload,
)
from ddos_ads.ui_capture import (
    build_dumpcap_command,
    get_allowed_interfaces,
)
from ddos_ads.ui_report import (
    generate_ui_report,
    verify_analysis_integrity,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
CAPTURES_DIR = REPO_ROOT / "lab/captures"
SESSION3_DIR = CAPTURES_DIR / "session3"


def test_ui_upload(tmp_path):
    """
    Asserts:
    1. Valid pcap is accepted.
    2. Renamed .exe is rejected with specific diagnostic message.
    3. Path traversal attempts are sanitized (saved strictly as input.pcap).
    4. Uploads exceeding size cap are rejected.
    5. Truncated pcap flags detector_blind without crashing.
    """
    run_dir = tmp_path / "run_upload"
    normal_pcap = CAPTURES_DIR / "normal_web_browsing.pcap"
    assert normal_pcap.is_file(), f"Missing test capture {normal_pcap}"

    # 1. Real pcap accepted
    with open(normal_pcap, "rb") as f:
        saved_path, ext, size_bytes, sha256 = validate_and_stream_upload(
            f, "web_browsing.pcap", run_dir
        )
    assert saved_path.is_file()
    assert ext == ".pcap"
    assert size_bytes > 0
    assert len(sha256) == 64

    # 2. Renamed .exe rejected
    exe_stream = io.BytesIO(b"MZ\x90\x00" + b"\x00" * 256)
    with pytest.raises(ValueError, match="Executable file signature"):
        validate_and_stream_upload(exe_stream, "evil.pcap", tmp_path / "run_exe")

    # 3. Path traversal attempt sanitized
    with open(normal_pcap, "rb") as f:
        traversal_path, _, _, _ = validate_and_stream_upload(
            f, "../../../../etc/shadow.pcap", tmp_path / "run_traversal"
        )
    assert traversal_path.resolve() == (tmp_path / "run_traversal/input.pcap").resolve()
    assert traversal_path.is_file()

    # 4. Oversized upload rejected
    oversized_stream = io.BytesIO(b"\xa1\xb2\xc3\xd4" + b"\x00" * 1024)
    with pytest.raises(ValueError, match="Upload size exceeds"):
        validate_and_stream_upload(
            oversized_stream, "big.pcap", tmp_path / "run_oversized", max_bytes=512
        )

    # 5. Truncated pcap handled and marked blind
    trunc_pcap = tmp_path / "truncated.pcap"
    trunc_pcap.write_bytes(b"\xa1\xb2\xc3\xd4\x00\x02\x00\x04")  # 8 bytes < 24 bytes pcap header
    analysis_res = analyze_capture_file(trunc_pcap, "truncated.pcap", "run_trunc", out_dir=tmp_path / "run_trunc")
    assert analysis_res["detector_health"]["is_truncated"] is True
    assert analysis_res["detector_health"]["detector_blind"] is True


def test_ui_command_builder(tmp_path):
    """
    Asserts:
    1. Fixed dumpcap template with argument list (NO shell).
    2. Start refused without permission checkbox.
    3. Disallowed interface rejected.
    4. Duration cap enforced between 30 and 900 seconds.
    """
    out_file = tmp_path / "test.pcapng"

    # Refused without permission checkbox
    with pytest.raises(PermissionError, match="Start refused"):
        build_dumpcap_command("eth0", 60, out_file, permission_acknowledged=False)

    # Disallowed interface rejected
    with pytest.raises(ValueError, match="not in allowlist"):
        build_dumpcap_command(
            "unauthorized_iface",
            60,
            out_file,
            permission_acknowledged=True,
            allowed_ifaces=["eth0", "lo"],
        )

    # Duration below minimum (<30s) rejected
    with pytest.raises(ValueError, match="between 30 s and 900 s"):
        build_dumpcap_command("eth0", 15, out_file, permission_acknowledged=True)

    # Duration above maximum (>900s) rejected
    with pytest.raises(ValueError, match="between 30 s and 900 s"):
        build_dumpcap_command("eth0", 1200, out_file, permission_acknowledged=True)

    # Valid command matches fixed template
    cmd = build_dumpcap_command("eth0", 120, out_file, filesize_kb=500_000, permission_acknowledged=True)
    expected_cmd = [
        "dumpcap",
        "-i",
        "eth0",
        "-a",
        "duration:120",
        "-b",
        "filesize:500000",
        "-w",
        str(out_file),
    ]
    assert cmd == expected_cmd


def test_ui_report_consistency(tmp_path):
    """
    Asserts:
    1. Every number in report.html equals the value in analysis.json.
    2. Tamper test: modifying a number in scratch copy causes report generation to fail.
    """
    test_pcap = CAPTURES_DIR / "normal_web_browsing.pcap"
    run_id = "test_consistency_run"
    run_dir = tmp_path / run_id

    analysis_res = analyze_capture_file(test_pcap, "normal_web_browsing.pcap", run_id, out_dir=run_dir)
    html_path, pdf_path, docx_path = generate_ui_report(analysis_res, run_dir)
    assert html_path.is_file()

    html_text = html_path.read_text(encoding="utf-8")

    # Verify that key numbers from analysis.json exist verbatim in report.html
    pkt_count = analysis_res["input_metadata"]["packet_count"]
    dur = analysis_res["input_metadata"]["duration_sec"]
    size_bytes = analysis_res["input_metadata"]["size_bytes"]
    total_alerts = analysis_res["results"]["total_alerts"]

    assert f"{pkt_count} packets" in html_text
    assert f"{size_bytes} bytes" in html_text
    assert f"{dur} seconds" in html_text
    assert f"{total_alerts} alerts total" in html_text

    # Tamper test: change a number in a scratch copy -> report generation MUST fail
    tampered_data = copy.deepcopy(analysis_res)
    tampered_data["input_metadata"]["packet_count"] = 888888
    with pytest.raises(ValueError, match="tampered number or modified field"):
        generate_ui_report(tampered_data, run_dir)

    # Invariant tamper: change total_alerts count without altering list
    tampered_alerts = copy.deepcopy(analysis_res)
    tampered_alerts.pop("integrity_checksum", None)
    tampered_alerts["results"]["total_alerts"] = 42
    with pytest.raises(ValueError, match="total_alerts"):
        generate_ui_report(tampered_alerts, run_dir)


def test_ui_regression_known_pcaps_and_baseline(tmp_path):
    """
    Evaluates 3 known pcaps (SYN 200 pps, UDP 50 pps, Scan 30 pps) and 900s baseline.
    Asserts UI analysis first-alert times equal parity values and baseline reports 0 alerts.
    """
    syn_pcap = SESSION3_DIR / "session3_tcp_syn_flood_200pps_rep1.pcap"
    udp_pcap = SESSION3_DIR / "session3_udp_flood_volumetric_port80_50pps_rep1.pcap"
    scan_pcap = SESSION3_DIR / "session3_reconnaissance_port_scan_30pps_rep1.pcap"
    benign_pcap = SESSION3_DIR / "session3_benign_baseline_900s.pcap"

    # Reference parity calculations
    engine = RuleEngine()
    ref_syn = engine.evaluate_pcap_streaming(syn_pcap, duration_sec=120)
    ref_udp = engine.evaluate_pcap_streaming(udp_pcap, duration_sec=120)
    ref_scan = engine.evaluate_pcap_streaming(scan_pcap, duration_sec=120)
    ref_benign = engine.evaluate_pcap_streaming(benign_pcap, duration_sec=900, is_baseline=True)

    # UI analysis runs (pre-registered mode parity comparison)
    ui_syn = analyze_capture_file(syn_pcap, syn_pcap.name, "reg_syn_200", enable_posthoc_rule=False, out_dir=tmp_path / "reg_syn_200")
    ui_udp = analyze_capture_file(udp_pcap, udp_pcap.name, "reg_udp_50", enable_posthoc_rule=False, out_dir=tmp_path / "reg_udp_50")
    ui_scan = analyze_capture_file(scan_pcap, scan_pcap.name, "reg_scan_30", enable_posthoc_rule=False, out_dir=tmp_path / "reg_scan_30")
    ui_benign = analyze_capture_file(benign_pcap, benign_pcap.name, "reg_benign_900", enable_posthoc_rule=False, out_dir=tmp_path / "reg_benign_900")

    # Parity assertions
    assert ui_syn["results"]["first_alert_delay_sec"] == ref_syn["first_detection_delay_sec"]
    assert ui_udp["results"]["first_alert_delay_sec"] == ref_udp["first_detection_delay_sec"]
    assert ui_scan["results"]["first_alert_delay_sec"] == ref_scan["first_detection_delay_sec"]

    assert ref_benign["alerted_seconds_total"] == 0
    assert ui_benign["results"]["total_alerts"] == 0
    assert ui_benign["results"]["verdict"] == "no alerts"


def test_ui_regression_normal_browsing_upload(tmp_path):
    """
    Asserts that an unrelated normal capture (sample web browsing traffic)
    produces exactly 0 alerts and verdict 'no alerts'.
    """
    browsing_pcap = CAPTURES_DIR / "normal_web_browsing.pcap"
    assert browsing_pcap.is_file(), f"Missing browsing pcap {browsing_pcap}"

    ui_res = analyze_capture_file(
        browsing_pcap,
        "normal_web_browsing.pcap",
        "reg_browsing_test",
        enable_posthoc_rule=True,
        out_dir=tmp_path / "reg_browsing_test",
    )

    assert ui_res["results"]["total_alerts"] == 0
    assert ui_res["results"]["verdict"] == "no alerts"
    assert ui_res["results"]["first_alert_delay_sec"] is None
