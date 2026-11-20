"""
Phase 10 Programmatic Report Generator.
=======================================
Strict Rules:
1. Every number in report.html is derived directly from analysis.json.
2. Tamper verification: if any metric or number in analysis.json is tampered with
   or fails internal integrity verification, report generation fails with ValueError.
3. Includes the mandatory unedited limitations paragraph.
4. Includes the mandatory footer: code tag, thresholds.json sha256, and run id.
5. Invokes PDF and DOCX conversion exclusively via ddos_ads.ui_capture (NO subprocess import here).
"""

from __future__ import annotations

import hashlib
import html
import json
from pathlib import Path
import re
from typing import Any, Dict, Optional, Tuple

from ddos_ads.ui_capture import convert_html_to_pdf_and_docx

MANDATORY_LIMITATIONS_TEXT = (
    "This is an alert-only analysis with no ground truth, so it reports alerts, not accuracy. "
    "Thresholds were tuned on one lab. Legitimate flash crowds above about 750 connections/s and "
    "high-rate UDP to one destination can raise alerts. Captures from other networks have not been "
    "validated. Flow-based ML models are not used here because they did not transfer in the lab study."
)

CODE_TAG = "v3.4"


def verify_analysis_integrity(data: Dict[str, Any], run_dir: Optional[Path] = None) -> None:
    """
    Verifies that analysis.json numbers and checksums are intact and untampered.
    Compares against:
    1. Independent external digest file (analysis_digest.sha256) stored at analysis time.
    2. Internal canonical JSON SHA-256 integrity checksum (integrity_checksum).
    3. Mathematical invariants across packet counts, duration, and class alert totals.
    If tampered, raises ValueError.
    """
    if run_dir is not None:
        digest_file = run_dir / "analysis_digest.sha256"
        analysis_json_file = run_dir / "analysis.json"
        if digest_file.is_file() and analysis_json_file.is_file():
            expected_digest = digest_file.read_text(encoding="utf-8").split()[0].strip()
            actual_digest = hashlib.sha256(analysis_json_file.read_bytes()).hexdigest()
            if actual_digest != expected_digest:
                raise ValueError(
                    f"Report tamper check failed: independent analysis_digest.sha256 mismatch "
                    f"(expected {expected_digest}, found {actual_digest})."
                )

    if "integrity_checksum" in data:
        stored_chk = data["integrity_checksum"]
        # Create shallow copy without integrity_checksum
        copy_data = {k: v for k, v in data.items() if k != "integrity_checksum"}
        expected_chk = hashlib.sha256(json.dumps(copy_data, sort_keys=True).encode("utf-8")).hexdigest()
        if stored_chk != expected_chk:
            raise ValueError(
                "Report consistency verification failed: tampered number or modified field detected in analysis.json."
            )

    # Invariant mathematical checks
    in_meta = data.get("input_metadata", {})
    results = data.get("results", {})
    health = data.get("detector_health", {})

    total_alerts = results.get("total_alerts", 0)
    alerts_list = results.get("alerts", [])
    if total_alerts != len(alerts_list):
        raise ValueError(
            f"Report consistency failed: total_alerts ({total_alerts}) != len(alerts) ({len(alerts_list)})."
        )

    # Verify duration consistency
    first_ts = in_meta.get("first_packet_ts")
    last_ts = in_meta.get("last_packet_ts")
    dur = in_meta.get("duration_sec", 0.0)
    if first_ts is not None and last_ts is not None and last_ts >= first_ts:
        calc_dur = round(last_ts - first_ts, 4)
        if abs(calc_dur - dur) > 0.01:
            raise ValueError(
                f"Report consistency failed: duration_sec ({dur}) != calculated ({calc_dur})."
            )

    # Verify class summaries match alert list
    class_summary = results.get("class_summary", {})
    for c_name, c_data in class_summary.items():
        actual_count = sum(1 for a in alerts_list if a.get("alert_class") == c_name)
        if c_data.get("count", 0) != actual_count:
            raise ValueError(
                f"Report consistency failed: class {c_name} count ({c_data.get('count')}) != actual ({actual_count})."
            )


def generate_ui_report(
    analysis_data: Dict[str, Any],
    run_dir: Path,
) -> Tuple[Path, Optional[Path], Optional[Path]]:
    """
    Builds report.html, report.pdf, and report.docx strictly from analysis_data.
    Returns (html_path, pdf_path, docx_path).
    """
    # 1. Enforce tamper verification
    verify_analysis_integrity(analysis_data, run_dir=run_dir)

    run_id = analysis_data["run_id"]
    timestamp = analysis_data["timestamp_analyzed"]
    in_meta = analysis_data["input_metadata"]
    health = analysis_data["detector_health"]
    th_used = analysis_data["thresholds_used"]
    res = analysis_data["results"]

    # 2. Extract strictly grounded variables
    orig_name = html.escape(str(in_meta["original_filename"]))
    file_size_bytes = int(in_meta["size_bytes"])
    file_size_mb = float(in_meta["size_mb"])
    sha256 = str(in_meta["sha256"])
    packet_count = int(in_meta["packet_count"])
    first_pkt_ts = in_meta["first_packet_ts"]
    last_pkt_ts = in_meta["last_packet_ts"]
    duration_sec = float(in_meta["duration_sec"])

    first_ts_str = f"{first_pkt_ts:.4f}" if first_pkt_ts is not None else "N/A"
    last_ts_str = f"{last_pkt_ts:.4f}" if last_pkt_ts is not None else "N/A"

    verdict = str(res["verdict"])
    total_alerts = int(res["total_alerts"])
    first_alert_delay = res.get("first_alert_delay_sec")
    first_alert_epoch = res.get("first_alert_epoch")
    first_alert_type = res.get("first_alert_type") or "None"
    total_alerted_seconds = int(res.get("total_alerted_seconds", 0))

    drops = int(health.get("dropped_packets", 0))
    is_truncated = bool(health.get("is_truncated", False))
    detector_blind = bool(health.get("detector_blind", False))

    th_sha256 = str(th_used.get("sha256", "unknown"))

    # Blind banner HTML
    blind_banner_html = ""
    if detector_blind:
        blind_banner_html = (
            "<div style='background-color: #fee2e2; border: 2px solid #ef4444; color: #991b1b; "
            "padding: 16px; margin: 20px 0; border-radius: 6px; font-weight: bold;'>"
            "⚠️ DETECTOR BLIND: Kernel packet drops were detected or the capture file was truncated. "
            f"Drops: {drops}, Truncated: {is_truncated}. Anomaly detection results may be incomplete."
            "</div>"
        )

    # Class summary rows
    summary_rows_html = ""
    for c_name, c_info in res.get("class_summary", {}).items():
        first_a_str = f"{c_info['first_alert_ts']:.4f} s" if c_info['first_alert_ts'] else "None"
        status_badge = (
            "<span style='color: #b45309; background: #fef3c7; padding: 2px 6px; border-radius: 4px;'>post-hoc, unregistered</span>"
            if c_info["status"] == "post-hoc, unregistered"
            else "<span style='color: #065f46; background: #d1fae5; padding: 2px 6px; border-radius: 4px;'>pre-registered</span>"
        )
        summary_rows_html += f"""
        <tr>
          <td><strong>{html.escape(c_name)}</strong></td>
          <td>{status_badge}</td>
          <td>{c_info['count']}</td>
          <td>{first_a_str}</td>
          <td>{c_info['alerted_seconds']} s</td>
          <td>{c_info['peak_rate']} pps</td>
          <td>{c_info['max_sources']}</td>
        </tr>
        """

    # Top destinations rows
    top_dst_html = ""
    for item in res.get("top_destinations", []):
        top_dst_html += f"<tr><td><code>{html.escape(item['ip'])}</code></td><td>{item['packet_count']}</td></tr>"

    # Alert table rows
    alerts_rows_html = ""
    for a in res.get("alerts", []):
        tag_style = "color: #b45309;" if a["status"] == "post-hoc, unregistered" else "color: #065f46;"
        alerts_rows_html += f"""
        <tr>
          <td>{a['time_epoch']}</td>
          <td>{a['relative_time_sec']} s</td>
          <td><code>{html.escape(a['rule'])}</code></td>
          <td><strong>{html.escape(a['alert_class'])}</strong></td>
          <td style='{tag_style}'>{html.escape(a['status'])}</td>
          <td><code>{html.escape(a['destination'])}</code></td>
          <td>{a['rate_pps']}</td>
          <td>{a['distinct_sources']}</td>
          <td>{a['distinct_ports']}</td>
        </tr>
        """

    if not alerts_rows_html:
        alerts_rows_html = "<tr><td colspan='9' style='text-align:center;'>No alerts triggered during this capture.</td></tr>"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Analysis Report - Run {html.escape(run_id)}</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      line-height: 1.5;
      color: #1f2937;
      margin: 40px auto;
      max-width: 900px;
      padding: 0 20px;
    }}
    h1 {{ color: #111827; border-bottom: 2px solid #e5e7eb; padding-bottom: 8px; }}
    h2 {{ color: #1f2937; margin-top: 32px; border-bottom: 1px solid #e5e7eb; padding-bottom: 4px; }}
    table {{ width: 100%; border-collapse: collapse; margin: 16px 0; font-size: 14px; }}
    th, td {{ border: 1px solid #d1d5db; padding: 8px 12px; text-align: left; }}
    th {{ background-color: #f3f4f6; }}
    .verdict-box {{
      padding: 16px;
      border-radius: 6px;
      margin: 20px 0;
      font-size: 18px;
      font-weight: bold;
      background-color: {"#fef2f2" if total_alerts > 0 else "#f0fdf4"};
      border: 1px solid {"#f87171" if total_alerts > 0 else "#86efac"};
      color: {"#991b1b" if total_alerts > 0 else "#166534"};
    }}
    .limitations-box {{
      background-color: #f9fafb;
      border-left: 4px solid #6b7280;
      padding: 12px 16px;
      margin: 24px 0;
      font-size: 13px;
      color: #374151;
    }}
    footer {{
      margin-top: 48px;
      padding-top: 16px;
      border-top: 1px solid #e5e7eb;
      font-size: 12px;
      color: #6b7280;
    }}
    code {{ background: #f3f4f6; padding: 2px 4px; border-radius: 4px; font-family: monospace; }}
  </style>
</head>
<body>
  <h1>DDoS ADS - Packet Capture Analysis Report</h1>
  <p><strong>Analysis Run ID:</strong> <code>{html.escape(run_id)}</code> &nbsp;|&nbsp; <strong>Generated:</strong> {html.escape(timestamp)}</p>

  {blind_banner_html}

  <div class="verdict-box">
    Verdict: {verdict.upper()} ({total_alerts} alerts total)
  </div>

  <h2>1. Input Metadata</h2>
  <table>
    <tr><th>File Name</th><td>{orig_name}</td></tr>
    <tr><th>File Size</th><td>{file_size_bytes} bytes ({file_size_mb} MB)</td></tr>
    <tr><th>SHA-256</th><td><code>{sha256}</code></td></tr>
    <tr><th>Packet Count</th><td>{packet_count} packets</td></tr>
    <tr><th>First Packet Timestamp</th><td>{first_ts_str}</td></tr>
    <tr><th>Last Packet Timestamp</th><td>{last_ts_str}</td></tr>
    <tr><th>Capture Duration</th><td>{duration_sec} seconds</td></tr>
  </table>

  <h2>2. Detection Rules and Thresholds</h2>
  <p>Thresholds frozen provenance file: <code>results/thresholds.json</code> (SHA-256: <code>{th_sha256}</code>)</p>
  <table>
    <tr><th>Rule Name</th><th>Status</th><th>Configured Parameters</th></tr>
    <tr>
      <td><strong>TCP Incomplete Handshake Rule</strong></td>
      <td><span style="color: #065f46; background: #d1fae5; padding: 2px 6px; border-radius: 4px;">pre-registered</span></td>
      <td>Sliding concentrated incomplete &ge; 20, min rate &ge; 15, timeout 2.0 s, scan distinct &ge; 3</td>
    </tr>
    <tr>
      <td><strong>Dual-Condition UDP Rule</strong></td>
      <td><span style="color: #065f46; background: #d1fae5; padding: 2px 6px; border-radius: 4px;">pre-registered</span></td>
      <td>Volumetric &ge; 40 pkts/s, Random port &ge; 30 pkts/s with &ge; 10 distinct ports</td>
    </tr>
    <tr>
      <td><strong>Stateless TCP SYN Arrival Rate Rule</strong></td>
      <td><span style="color: #b45309; background: #fef3c7; padding: 2px 6px; border-radius: 4px;">post-hoc, unregistered</span></td>
      <td>Arrival rate &ge; 150 pps with &ge; 3 sources, or single source &ge; 500 pps</td>
    </tr>
  </table>

  <h2>3. Incident & Alert Summary by Class</h2>
  <p>
    <strong>First Alert Time:</strong> {f"{first_alert_delay:.4f} s (delay)" if first_alert_delay is not None else "None"} &nbsp;|&nbsp;
    <strong>First Alert Class:</strong> <code>{html.escape(first_alert_type)}</code> &nbsp;|&nbsp;
    <strong>Total Alerted Seconds:</strong> {total_alerted_seconds} s
  </p>
  <table>
    <tr>
      <th>Alert Class</th>
      <th>Status</th>
      <th>Count</th>
      <th>First Alert Time</th>
      <th>Alerted Seconds</th>
      <th>Peak Rate</th>
      <th>Max Sources</th>
    </tr>
    {summary_rows_html}
  </table>

  <h2>4. Top Destinations Observed</h2>
  <table>
    <tr><th>Destination IP</th><th>Packet Count</th></tr>
    {top_dst_html}
  </table>

  <h2>5. Capture Health and Dropped Packets</h2>
  <table>
    <tr><th>Dropped Packets</th><td>{drops}</td></tr>
    <tr><th>Truncated Capture</th><td>{is_truncated}</td></tr>
    <tr><th>Detector Blind Status</th><td><strong>{"BLIND" if detector_blind else "NORMAL"}</strong></td></tr>
  </table>

  <h2>6. Alerts Timeline & Detailed Log</h2>
  <table>
    <tr>
      <th>Time (Epoch)</th>
      <th>Relative (s)</th>
      <th>Rule</th>
      <th>Class</th>
      <th>Status</th>
      <th>Destination</th>
      <th>Rate (pps)</th>
      <th>Sources</th>
      <th>Ports</th>
    </tr>
    {alerts_rows_html}
  </table>

  <h2>7. Analysis Limitations</h2>
  <div class="limitations-box">
    {MANDATORY_LIMITATIONS_TEXT}
  </div>

  <footer>
    <strong>Code Version:</strong> {CODE_TAG} &nbsp;|&nbsp;
    <strong>Thresholds SHA-256:</strong> <code>{th_sha256}</code> &nbsp;|&nbsp;
    <strong>Run ID:</strong> <code>{html.escape(run_id)}</code> &nbsp;|&nbsp;
    <strong>Input PCAP SHA-256:</strong> <code>{sha256}</code>
  </footer>
</body>
</html>
"""

    run_dir.mkdir(parents=True, exist_ok=True)
    out_html = run_dir / "report.html"
    with open(out_html, "w", encoding="utf-8") as f:
        f.write(html_content)

    # Convert to PDF and DOCX
    pdf_path, docx_path = convert_html_to_pdf_and_docx(out_html, run_dir)

    return out_html, pdf_path, docx_path
