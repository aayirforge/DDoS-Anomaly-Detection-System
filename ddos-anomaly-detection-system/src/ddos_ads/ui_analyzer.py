"""
Phase 10 UI Analysis Engine.
============================
Strict Safety Guarantees:
1. Rejects uploads without valid pcap/pcapng magic bytes.
2. Specifically detects and rejects renamed executable files (.exe).
3. Enforces streaming to disk with a 500 MB cap, never loading whole files to memory.
4. Ignores user filenames for storage paths (no path traversal, saves as input.pcap/input.pcapng).
5. All runs isolated under results/ui_runs/<run_id>/.
6. Evaluates traffic using the exact RuleEngine from the replay parity test.
7. Flags detector blindness on drops or truncation.
8. Labels post-hoc ALERT_SYN_RATE as 'post-hoc, unregistered'.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import time
from typing import Any, BinaryIO, Dict, List, Optional, Tuple
import uuid

from ddos_ads.rule_engine import RuleEngine
from ddos_ads.ui_capture import get_pcap_metadata_and_packets

VALID_PCAP_MAGICS = [
    b"\xa1\xb2\xc3\xd4",  # Standard pcap (big-endian)
    b"\xd4\xc3\xb2\xa1",  # Standard pcap (little-endian)
    b"\xa1\xb2\x3c\x4d",  # Nanosecond pcap (big-endian)
    b"\x4d\x3c\xb2\xa1",  # Nanosecond pcap (little-endian)
]
VALID_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"  # pcapng section header block
GZIP_MAGIC = b"\x1f\x8b"  # Gzip compression header
EXE_MAGIC = b"\x4d\x5a"  # 'MZ' DOS/PE executable header

DEFAULT_MAX_UPLOAD_BYTES = 500 * 1024 * 1024  # 500 MB
CHUNK_SIZE_BYTES = 64 * 1024  # 64 KB streaming chunk

REPO_ROOT = Path(__file__).resolve().parents[2]
UI_RUNS_DIR = REPO_ROOT / "results/ui_runs"


def calculate_sha256(filepath: Path) -> str:
    """Computes SHA-256 hash of a file on disk."""
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(CHUNK_SIZE_BYTES):
            hasher.update(chunk)
    return hasher.hexdigest()


def validate_and_stream_upload(
    file_obj: BinaryIO,
    original_filename: str,
    run_dir: Path,
    max_bytes: int = DEFAULT_MAX_UPLOAD_BYTES,
) -> Tuple[Path, str, int, str]:
    """
    Validates uploaded file extension, magic bytes, and streams to disk.
    Enforces size limit and path containment.
    
    Returns (saved_path, sanitized_extension, size_bytes, sha256_hash).
    """
    # 1. Extension check
    orig_lower = original_filename.lower()
    if orig_lower.endswith(".pcapng"):
        ext = ".pcapng"
    elif orig_lower.endswith(".pcap"):
        ext = ".pcap"
    else:
        raise ValueError(
            f"Rejected: Invalid file extension for '{original_filename}'. Only .pcap and .pcapng files are accepted."
        )

    run_dir.mkdir(parents=True, exist_ok=True)
    # Strictly ignore user's filename to prevent directory traversal
    dest_path = run_dir / f"input{ext}"

    hasher = hashlib.sha256()
    total_bytes = 0
    header_checked = False

    try:
        with open(dest_path, "wb") as out_f:
            while True:
                chunk = file_obj.read(CHUNK_SIZE_BYTES)
                if not chunk:
                    break

                total_bytes += len(chunk)
                if total_bytes > max_bytes:
                    raise ValueError(
                        f"Rejected: Upload size exceeds {max_bytes // (1024 * 1024)} MB limit."
                    )

                if not header_checked and len(chunk) >= 4:
                    magic4 = chunk[:4]
                    if magic4.startswith(GZIP_MAGIC):
                        raise ValueError(
                            "Rejected: Gzip compressed file detected. Only uncompressed .pcap/.pcapng files are accepted."
                        )
                    if magic4.startswith(EXE_MAGIC):
                        raise ValueError(
                            "Rejected: Executable file signature (.exe 'MZ') detected. This file is not a valid packet capture."
                        )

                    is_pcap = any(magic4 == m for m in VALID_PCAP_MAGICS)
                    is_pcapng = (magic4 == VALID_PCAPNG_MAGIC)

                    if ext == ".pcap" and not is_pcap:
                        if is_pcapng:
                            pass  # pcapng content uploaded with .pcap name is accepted as pcapng
                        else:
                            raise ValueError(
                                f"Rejected: Invalid PCAP magic bytes ({magic4.hex()}). File is not a valid packet capture."
                            )
                    elif ext == ".pcapng" and not is_pcapng:
                        if is_pcap:
                            pass
                        else:
                            raise ValueError(
                                f"Rejected: Invalid PCAPNG magic bytes ({magic4.hex()}). File is not a valid packet capture."
                            )

                    header_checked = True

                hasher.update(chunk)
                out_f.write(chunk)

        if total_bytes == 0:
            raise ValueError("Rejected: Uploaded file is empty (0 bytes).")

    except Exception:
        if dest_path.is_file():
            dest_path.unlink()
        raise

    return dest_path, ext, total_bytes, hasher.hexdigest()


def load_frozen_thresholds() -> Dict[str, Any]:
    """Reads frozen detection thresholds and provenance metadata."""
    th_path = REPO_ROOT / "results/thresholds.json"
    if not th_path.is_file():
        th_path = REPO_ROOT / "models/thresholds.json"
    if not th_path.is_file():
        return {}
    with open(th_path, "r", encoding="utf-8") as f:
        return json.load(f)


def analyze_capture_file(
    pcap_path: Path,
    original_filename: str,
    run_id: str,
    dropped_packets: int = 0,
    enable_posthoc_rule: bool = True,
    out_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """
    Executes offline replay analysis on the saved capture file using the exact RuleEngine.
    Produces comprehensive analysis data adhering strictly to Phase 10 requirements.
    Writes results/ui_runs/<run_id>/analysis.json.
    """
    run_dir = out_dir if out_dir is not None else (UI_RUNS_DIR / run_id)
    run_dir.mkdir(parents=True, exist_ok=True)

    file_size = pcap_path.stat().st_size
    file_sha256 = calculate_sha256(pcap_path)

    # 1. Packet metadata & basic timeseries
    meta = get_pcap_metadata_and_packets(pcap_path)
    packet_count = meta["packet_count"]
    first_pkt_ts = meta["first_pkt_ts"]
    last_pkt_ts = meta["last_pkt_ts"]
    duration_sec = meta["duration_sec"]
    is_truncated = meta["is_truncated"]

    # 2. Detector Blindness condition
    detector_blind = (dropped_packets > 0 or is_truncated)

    # 3. Replay through RuleEngine
    # We configure RuleEngine with victim_ip=None to track any destination in UI mode,
    # and enable_syn_arrival_rule to allow post-hoc detection if enabled
    engine = RuleEngine(victim_ip=None, enable_syn_arrival_rule=enable_posthoc_rule)
    # Stream through pcap
    analysis_duration = max(1, int(round(duration_sec))) if duration_sec > 0 else 120
    # Run streaming evaluation
    res = engine.evaluate_pcap_streaming(
        pcap_path,
        duration_sec=analysis_duration,
        preregistered_only=not enable_posthoc_rule,
    )

    # 4. Formulate alerts table and timeline
    raw_alerts = engine.alerts_emitted
    alerts_table: List[Dict[str, Any]] = []
    class_summary: Dict[str, Dict[str, Any]] = {
        "ALERT_SYN_FLOOD": {"count": 0, "first_alert_ts": None, "alerted_seconds": 0, "peak_rate": 0, "max_sources": 0, "status": "pre-registered"},
        "ALERT_UDP_FLOOD": {"count": 0, "first_alert_ts": None, "alerted_seconds": 0, "peak_rate": 0, "max_sources": 0, "status": "pre-registered"},
        "ALERT_SCAN": {"count": 0, "first_alert_ts": None, "alerted_seconds": 0, "peak_rate": 0, "max_sources": 0, "status": "pre-registered"},
        "ALERT_SYN_RATE": {"count": 0, "first_alert_ts": None, "alerted_seconds": 0, "peak_rate": 0, "max_sources": 0, "status": "post-hoc, unregistered"},
    }

    alerted_seconds_by_class: Dict[str, set] = {k: set() for k in class_summary}

    for alert in raw_alerts:
        a_type = alert.alert_type
        a_ts = alert.packet_ts
        details = alert.details or {}
        victim = alert.victim_ip

        rate = (
            details.get("incomplete_count")
            or details.get("udp_count_1s")
            or details.get("syn_arrival_count")
            or details.get("packet_count")
            or 0
        )
        distinct_sources = details.get("distinct_src_ips", 1)
        distinct_ports = details.get("distinct_dst_ports", 1)
        rule_name = alert.rule

        status_tag = "post-hoc, unregistered" if a_type == "ALERT_SYN_RATE" else "pre-registered"

        record = {
            "time_epoch": round(a_ts, 4),
            "relative_time_sec": round(a_ts - first_pkt_ts, 4) if first_pkt_ts else 0.0,
            "rule": rule_name,
            "alert_class": a_type,
            "status": status_tag,
            "destination": victim,
            "rate_pps": int(rate),
            "distinct_sources": int(distinct_sources),
            "distinct_ports": int(distinct_ports),
            "details": details,
        }
        alerts_table.append(record)

        if a_type in class_summary:
            cs = class_summary[a_type]
            cs["count"] += 1
            if cs["first_alert_ts"] is None or a_ts < cs["first_alert_ts"]:
                cs["first_alert_ts"] = round(a_ts, 4)
            if rate > cs["peak_rate"]:
                cs["peak_rate"] = int(rate)
            if distinct_sources > cs["max_sources"]:
                cs["max_sources"] = int(distinct_sources)

            if first_pkt_ts:
                bin_idx = int(a_ts - first_pkt_ts)
                alerted_seconds_by_class[a_type].add(bin_idx)

    for k in class_summary:
        class_summary[k]["alerted_seconds"] = len(alerted_seconds_by_class[k])

    # 5. Top Destinations and Rates
    top_destinations = sorted(
        meta["destination_counts"].items(), key=lambda x: x[1], reverse=True
    )[:5]

    # Destination rate time-series (1-second bins)
    per_dst_rates: Dict[str, Dict[str, Any]] = {}
    if first_pkt_ts is not None and last_pkt_ts is not None:
        total_bins = max(1, int(last_pkt_ts - first_pkt_ts) + 1)
        for dst_ip, ts_list in meta["destination_timeseries"].items():
            if len(ts_list) < 5 and dst_ip not in [d[0] for d in top_destinations]:
                continue
            bins = [0] * total_bins
            for t in ts_list:
                b = int(t - first_pkt_ts)
                if 0 <= b < total_bins:
                    bins[b] += 1
            per_dst_rates[dst_ip] = {
                "bins": bins,
                "max_rate": max(bins) if bins else 0,
            }

    # 6. Load thresholds info
    frozen_th = load_frozen_thresholds()
    thresholds_sha256 = calculate_sha256(REPO_ROOT / "results/thresholds.json") if (REPO_ROOT / "results/thresholds.json").is_file() else "unknown"

    # Overall verdict
    total_alerts = len(alerts_table)
    verdict = f"{total_alerts} alerts found" if total_alerts > 0 else "no alerts"

    first_alert_time_relative = round(res["first_detection_delay_sec"], 4) if res["first_detection_delay_sec"] is not None else None
    first_alert_time_epoch = round(res["first_alert_ts"], 4) if res["first_alert_ts"] is not None else None

    analysis_data: Dict[str, Any] = {
        "run_id": run_id,
        "timestamp_analyzed": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "input_metadata": {
            "original_filename": original_filename,
            "size_bytes": file_size,
            "size_mb": round(file_size / (1024 * 1024), 2),
            "sha256": file_sha256,
            "packet_count": packet_count,
            "first_packet_ts": first_pkt_ts,
            "last_packet_ts": last_pkt_ts,
            "duration_sec": duration_sec,
        },
        "detector_health": {
            "dropped_packets": dropped_packets,
            "is_truncated": is_truncated,
            "detector_blind": detector_blind,
        },
        "thresholds_used": {
            "sha256": thresholds_sha256,
            "rules": {
                "packet_incomplete_tcp_handshake_rule": {
                    "status": "pre-registered",
                    "incomplete_syn_threshold": 20,
                    "min_incomplete_rate": 15,
                    "handshake_timeout_sec": 2.0,
                },
                "packet_dual_condition_udp_rule": {
                    "status": "pre-registered",
                    "volumetric_threshold_pps": 40,
                    "random_port_threshold_pps": 30,
                    "distinct_ports_threshold": 10,
                },
                "packet_syn_arrival_rate_rule": {
                    "status": "post-hoc, unregistered",
                    "stateless_syn_threshold_pps": 150,
                    "min_sources": 3,
                },
            },
        },
        "results": {
            "verdict": verdict,
            "total_alerts": total_alerts,
            "first_alert_delay_sec": first_alert_time_relative,
            "first_alert_epoch": first_alert_time_epoch,
            "first_alert_type": res["first_alert_type"],
            "total_alerted_seconds": res["alerted_seconds_total"],
            "class_summary": class_summary,
            "top_destinations": [
                {"ip": ip, "packet_count": count} for ip, count in top_destinations
            ],
            "per_destination_rates": per_dst_rates,
            "alerts": alerts_table,
        },
    }

    # Internal data integrity checksum
    data_str = json.dumps(analysis_data, sort_keys=True)
    analysis_data["integrity_checksum"] = hashlib.sha256(data_str.encode("utf-8")).hexdigest()

    # Write analysis.json
    out_json = run_dir / "analysis.json"
    json_bytes = json.dumps(analysis_data, indent=2).encode("utf-8")
    with open(out_json, "wb") as f:
        f.write(json_bytes)

    # Independent file digest stored at analysis time (Requirement 6)
    independent_digest = hashlib.sha256(json_bytes).hexdigest()
    digest_path = run_dir / "analysis_digest.sha256"
    digest_path.write_text(f"{independent_digest}  analysis.json\n", encoding="utf-8")

    return analysis_data
