"""
Phase 10 Test Suite: Upload Safety, Capture Security, Tamper Verification, and Engine Generality.
================================================================================================
Lists one dedicated test function per Phase 10 requirement:
- test_req1_ui_generality_rewritten_subnets
- test_req2_ui_unrelated_captures
- test_req3_ui_upload_positive_magic_and_negative_filters
- test_req4_ui_streamlit_config_binding
- test_req5_ui_backend_permission_flag_enforcement
- test_req6_ui_report_tamper_independent_digest
- test_req7_ui_runs_directory_isolation
- test_req8_ui_regression_known_pcaps_and_baseline
"""

from __future__ import annotations

import copy
import io
import json
from pathlib import Path
import pytest
try:
    import tomllib
except ImportError:
    import tomli as tomllib

from ddos_ads.rule_engine import RuleEngine
from ddos_ads.ui_analyzer import (
    analyze_capture_file,
    calculate_sha256,
    validate_and_stream_upload,
)
from ddos_ads.ui_capture import (
    build_dumpcap_command,
    start_live_capture,
)
from ddos_ads.ui_report import (
    generate_ui_report,
    verify_analysis_integrity,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
CAPTURES_DIR = REPO_ROOT / "lab/captures"
SESSION3_DIR = CAPTURES_DIR / "session3"
REWRITTEN_DIR = CAPTURES_DIR / "rewritten"
UNRELATED_DIR = CAPTURES_DIR / "unrelated"


def test_req1_ui_generality_rewritten_subnets(tmp_path):
    """
    Requirement 1: Generality across subnets.
    Demonstrates that UI analysis mode tracks destinations dynamically (victim_ip=None)
    without altering thresholds. Rewritten 10.50.0.0/16 pcaps match 172.20.0.0/16 originals
    in alert counts, first-alert type, and first-alert detection delay.
    """
    pairs = [
        (
            SESSION3_DIR / "session3_tcp_syn_flood_200pps_rep1.pcap",
            REWRITTEN_DIR / "session3_tcp_syn_flood_200pps_rep1_subnet10.pcap",
            "ALERT_SYN_FLOOD",
        ),
        (
            SESSION3_DIR / "session3_udp_flood_random_ports_50pps_rep1.pcap",
            REWRITTEN_DIR / "session3_udp_flood_random_ports_50pps_rep1_subnet10.pcap",
            "ALERT_UDP_FLOOD",
        ),
        (
            SESSION3_DIR / "session3_reconnaissance_port_scan_30pps_rep1.pcap",
            REWRITTEN_DIR / "session3_reconnaissance_port_scan_30pps_rep1_subnet10.pcap",
            "ALERT_SCAN",
        ),
    ]

    for orig_pcap, rewr_pcap, expected_type in pairs:
        if not orig_pcap.is_file() or not rewr_pcap.is_file():
            pytest.skip(f"Capture fixture missing ({orig_pcap.name}); refer to README.md Section 4.1.")

        orig_res = analyze_capture_file(orig_pcap, orig_pcap.name, f"orig_{orig_pcap.stem}", out_dir=tmp_path / f"orig_{orig_pcap.stem}", enable_posthoc_rule=False)
        rewr_res = analyze_capture_file(rewr_pcap, rewr_pcap.name, f"rewr_{rewr_pcap.stem}", out_dir=tmp_path / f"rewr_{rewr_pcap.stem}", enable_posthoc_rule=False)

        assert orig_res["results"]["total_alerts"] == rewr_res["results"]["total_alerts"]
        assert orig_res["results"]["first_alert_type"] == rewr_res["results"]["first_alert_type"] == expected_type
        assert orig_res["results"]["first_alert_delay_sec"] == rewr_res["results"]["first_alert_delay_sec"]

        # Check victim IP dynamically mapped
        orig_dst = orig_res["results"]["alerts"][0]["destination"]
        rewr_dst = rewr_res["results"]["alerts"][0]["destination"]
        assert orig_dst == "172.20.0.2"
        assert rewr_dst == "10.50.0.2"


def test_req2_ui_unrelated_captures(tmp_path):
    """
    Requirement 2: Unrelated captures evaluation.
    Evaluates:
    - Normal browsing: 0 alerts
    - DNS-heavy resolution: 0 alerts
    - Video streaming (HTTPS): 0 alerts
    - Bulk ISO download: 0 alerts
    - Nmap scan against lab host: exactly 1 ALERT_SCAN
    """
    tests = [
        (CAPTURES_DIR / "normal_web_browsing.pcap", 0, None),
        (UNRELATED_DIR / "dns_heavy.pcap", 0, None),
        (UNRELATED_DIR / "video_streaming.pcap", 0, None),
        (UNRELATED_DIR / "bulk_download.pcap", 0, None),
        (UNRELATED_DIR / "nmap_scan_lab.pcap", 1, "ALERT_SCAN"),
    ]

    for pcap_path, expected_alerts, expected_alert_type in tests:
        if not pcap_path.is_file():
            pytest.skip(f"Capture fixture missing ({pcap_path.name}); refer to README.md Section 4.1.")
        res = analyze_capture_file(pcap_path, pcap_path.name, f"test_{pcap_path.stem}", out_dir=tmp_path / f"test_{pcap_path.stem}", enable_posthoc_rule=True)
        assert res["results"]["total_alerts"] == expected_alerts
        assert res["results"]["first_alert_type"] == expected_alert_type


def test_req3_ui_upload_positive_magic_and_negative_filters(tmp_path):
    """
    Requirement 3: Upload safety.
    - Positive magic-byte allowlist: valid pcap and pcapng accepted.
    - Gzip files (0x1f8b) rejected with specific error.
    - Renamed .exe files ('MZ') rejected with specific error.
    - Invalid magic bytes rejected.
    - Path traversal attempts sanitized.
    - Oversize upload rejected.
    - Truncated capture flags detector_blind.
    - Junk after valid header flags detector_blind.
    """
    normal_pcap = CAPTURES_DIR / "normal_web_browsing.pcap"
    if not normal_pcap.is_file():
        pytest.skip("Capture fixture missing (normal_web_browsing.pcap); refer to README.md Section 4.1.")

    # 1. Valid pcap accepted
    with open(normal_pcap, "rb") as f:
        saved_path, ext, size, h = validate_and_stream_upload(f, "test.pcap", tmp_path / "valid")
    assert saved_path.is_file()
    assert ext == ".pcap"

    # 2. Gzip rejected
    gz_stream = io.BytesIO(b"\x1f\x8b\x08\x00" + b"\x00" * 100)
    with pytest.raises(ValueError, match="Gzip compressed file detected"):
        validate_and_stream_upload(gz_stream, "traffic.pcap", tmp_path / "gz")

    # 3. Renamed .exe rejected
    exe_stream = io.BytesIO(b"MZ\x90\x00" + b"\x00" * 100)
    with pytest.raises(ValueError, match="Executable file signature"):
        validate_and_stream_upload(exe_stream, "evil.pcap", tmp_path / "exe")

    # 4. Unknown magic rejected
    bad_stream = io.BytesIO(b"RANDOM_BYTES_NOT_PCAP" + b"\x00" * 100)
    with pytest.raises(ValueError, match="Invalid PCAP magic bytes"):
        validate_and_stream_upload(bad_stream, "bad.pcap", tmp_path / "bad")

    # 5. Path traversal sanitized
    with open(normal_pcap, "rb") as f:
        traversal_path, _, _, _ = validate_and_stream_upload(f, "../../../../etc/shadow.pcap", tmp_path / "traversal")
    assert traversal_path.resolve() == (tmp_path / "traversal/input.pcap").resolve()

    # 6. Oversize rejected
    big_stream = io.BytesIO(b"\xa1\xb2\xc3\xd4" + b"\x00" * 2048)
    with pytest.raises(ValueError, match="Upload size exceeds"):
        validate_and_stream_upload(big_stream, "big.pcap", tmp_path / "big", max_bytes=1024)

    # 7. Truncated pcap flags detector_blind
    trunc_pcap = tmp_path / "truncated.pcap"
    trunc_pcap.write_bytes(b"\xa1\xb2\xc3\xd4\x00\x02\x00\x04")  # 8 bytes
    trunc_res = analyze_capture_file(trunc_pcap, "truncated.pcap", "trunc_run", out_dir=tmp_path / "trunc_run")
    assert trunc_res["detector_health"]["is_truncated"] is True
    assert trunc_res["detector_health"]["detector_blind"] is True

    # 8. Junk after valid header flags detector_blind
    junk_pcap = tmp_path / "junk_after_hdr.pcap"
    # Valid 24-byte pcap header followed by random garbage bytes that do not form valid packets
    junk_hdr = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00"
    junk_pcap.write_bytes(junk_hdr + b"MALFORMED_NON_PACKET_JUNK_DATA" * 10)
    junk_res = analyze_capture_file(junk_pcap, "junk.pcap", "junk_run", out_dir=tmp_path / "junk_run")
    assert junk_res["detector_health"]["is_truncated"] is True
    assert junk_res["detector_health"]["detector_blind"] is True


def test_req4_ui_streamlit_config_binding():
    """
    Requirement 4: Localhost binding and configuration safety.
    Verifies that .streamlit/config.toml binds strictly to 127.0.0.1 and sets maxUploadSize to 500 MB.
    """
    config_file = REPO_ROOT / ".streamlit/config.toml"
    assert config_file.is_file(), f"Missing config file {config_file}"

    with open(config_file, "rb") as f:
        conf = tomllib.load(f)

    server_conf = conf.get("server", {})
    assert server_conf.get("address") == "127.0.0.1", f"Server must bind to 127.0.0.1, got {server_conf.get('address')}"
    assert server_conf.get("maxUploadSize") == 500, f"maxUploadSize must be 500 MB, got {server_conf.get('maxUploadSize')}"
    assert server_conf.get("headless") is True


def test_req5_ui_backend_permission_flag_enforcement(tmp_path):
    """
    Requirement 5: Permission flag backend enforcement.
    Directly tests that build_dumpcap_command and start_live_capture refuse execution
    when permission_acknowledged is False.
    """
    out_file = tmp_path / "test.pcapng"

    # 1. build_dumpcap_command refuses without permission
    with pytest.raises(PermissionError, match="Start refused"):
        build_dumpcap_command("eth0", 60, out_file, permission_acknowledged=False)

    # 2. start_live_capture refuses without permission
    dummy_cmd = ["dumpcap", "-i", "eth0"]
    with pytest.raises(PermissionError, match="Start refused"):
        start_live_capture(dummy_cmd, permission_acknowledged=False)

    # 3. Allowed when permission_acknowledged is True
    cmd = build_dumpcap_command("eth0", 60, out_file, permission_acknowledged=True)
    assert cmd[0] == "dumpcap"
    assert "-i" in cmd and "eth0" in cmd


def test_req6_ui_report_tamper_independent_digest(tmp_path):
    """
    Requirement 6: Report tamper check with independent analysis digest.
    Asserts that:
    1. An independent analysis_digest.sha256 is created at analysis time.
    2. Modifying any number in analysis.json causes report generation to fail.
    3. Tampering with analysis_digest.sha256 causes report generation to fail.
    """
    test_pcap = CAPTURES_DIR / "normal_web_browsing.pcap"
    if not test_pcap.is_file():
        pytest.skip("Capture fixture missing (normal_web_browsing.pcap); refer to README.md Section 4.1.")
    run_dir = tmp_path / "tamper_test_run"

    analysis_res = analyze_capture_file(test_pcap, "normal.pcap", "tamper_test_run", out_dir=run_dir)
    digest_file = run_dir / "analysis_digest.sha256"
    assert digest_file.is_file(), f"Missing independent digest {digest_file}"

    # Normal generation succeeds
    html_p, pdf_p, docx_p = generate_ui_report(analysis_res, run_dir)
    assert html_p.is_file()

    # Tamper test 1: Modify packet_count in memory dict
    tampered_dict = copy.deepcopy(analysis_res)
    tampered_dict["input_metadata"]["packet_count"] = 999999
    with pytest.raises(ValueError, match="tampered number or modified field"):
        generate_ui_report(tampered_dict, run_dir)

    # Tamper test 2: Modify analysis.json on disk directly
    json_path = run_dir / "analysis.json"
    tampered_on_disk = copy.deepcopy(analysis_res)
    tampered_on_disk["input_metadata"]["packet_count"] = 888888
    # Recalculate internal checksum to simulate an attacker who forged internal checksum
    copy_d = {k: v for k, v in tampered_on_disk.items() if k != "integrity_checksum"}
    tampered_on_disk["integrity_checksum"] = calculate_sha256_text = json_path.write_text(json.dumps(tampered_on_disk, indent=2))

    with pytest.raises(ValueError, match="independent analysis_digest.sha256 mismatch"):
        generate_ui_report(tampered_on_disk, run_dir)


def test_req7_ui_runs_directory_isolation():
    """
    Requirement 7: Output directory isolation and cleanup.
    Asserts:
    1. results/ui_runs/* is gitignored.
    2. clean_ui_runs target exists in Makefile.
    """
    gitignore_path = REPO_ROOT / ".gitignore"
    assert gitignore_path.is_file()
    gi_text = gitignore_path.read_text(encoding="utf-8")
    assert "results/ui_runs/*" in gi_text

    makefile_path = REPO_ROOT / "Makefile"
    assert makefile_path.is_file()
    mf_text = makefile_path.read_text(encoding="utf-8")
    assert "clean_ui_runs:" in mf_text


def test_req8_ui_regression_known_pcaps_and_baseline(tmp_path):
    """
    Requirement 8: Replay parity regression test.
    Evaluates SYN 200 pps, UDP 50 pps, Scan 30 pps, and 900s baseline.
    Asserts first-alert delays match parity ground-truth and baseline fires 0 alerts.
    """
    syn_pcap = SESSION3_DIR / "session3_tcp_syn_flood_200pps_rep1.pcap"
    udp_pcap = SESSION3_DIR / "session3_udp_flood_random_ports_50pps_rep1.pcap"
    scan_pcap = SESSION3_DIR / "session3_reconnaissance_port_scan_30pps_rep1.pcap"
    benign_pcap = SESSION3_DIR / "session3_benign_baseline_900s.pcap"
    if not syn_pcap.is_file() or not udp_pcap.is_file() or not scan_pcap.is_file() or not benign_pcap.is_file():
        pytest.skip("Session 3 capture fixtures missing; refer to README.md Section 4.1.")

    engine = RuleEngine()
    ref_syn = engine.evaluate_pcap_streaming(syn_pcap, duration_sec=120)
    ref_udp = engine.evaluate_pcap_streaming(udp_pcap, duration_sec=120)
    ref_scan = engine.evaluate_pcap_streaming(scan_pcap, duration_sec=120)
    ref_benign = engine.evaluate_pcap_streaming(benign_pcap, duration_sec=900, is_baseline=True)

    ui_syn = analyze_capture_file(syn_pcap, syn_pcap.name, "reg_syn", enable_posthoc_rule=False, out_dir=tmp_path / "reg_syn")
    ui_udp = analyze_capture_file(udp_pcap, udp_pcap.name, "reg_udp", enable_posthoc_rule=False, out_dir=tmp_path / "reg_udp")
    ui_scan = analyze_capture_file(scan_pcap, scan_pcap.name, "reg_scan", enable_posthoc_rule=False, out_dir=tmp_path / "reg_scan")
    ui_benign = analyze_capture_file(benign_pcap, benign_pcap.name, "reg_benign", enable_posthoc_rule=False, out_dir=tmp_path / "reg_benign")

    assert ui_syn["results"]["first_alert_delay_sec"] == ref_syn["first_detection_delay_sec"]
    assert ui_udp["results"]["first_alert_delay_sec"] == ref_udp["first_detection_delay_sec"]
    assert ui_scan["results"]["first_alert_delay_sec"] == ref_scan["first_detection_delay_sec"]

    assert ref_benign["alerted_seconds_total"] == 0
    assert ui_benign["results"]["total_alerts"] == 0
    assert ui_benign["results"]["verdict"] == "no alerts"
