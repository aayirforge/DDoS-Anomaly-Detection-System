"""
Phase 10 Streamlit Interactive Analysis & Monitoring Dashboard.
==============================================================
SAFETY GUARANTEES:
1. Alert-only throughout: ZERO blocking, ZERO mitigation imports.
2. AST safety: Does NOT import subprocess directly (imports ui_capture exclusively for capture management).
3. Zero shell execution: NO calls to firewall tools (iptables/nftables) or OS system commands anywhere in UI code.
4. Upload safety: Magic bytes validation, 500 MB stream cap, path traversal immunization.
5. Live capture safety: dumpcap fixed template, allowlisted interfaces only, duration capped (30s-15min),
   mandatory user permission confirmation checkbox.
6. Offline replay mode: Runs the SAME RuleEngine used by replay parity tests.
7. Prominent 'DETECTOR BLIND' warning if drops > 0 or pcap is truncated.
8. Post-hoc ALERT_SYN_RATE rule explicitly tagged as 'post-hoc, unregistered'.
9. Programmatic reports (HTML, PDF, DOCX) generated strictly from analysis.json.
10. Preserves legacy read-only incident monitor under 'Advanced' page.
"""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple
import uuid

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from ddos_ads.config import load_config
from ddos_ads.ui_analyzer import (
    analyze_capture_file,
    calculate_sha256,
    load_frozen_thresholds,
    validate_and_stream_upload,
)
from ddos_ads.ui_capture import (
    UNPRIVILEGED_CAPTURE_MSG,
    build_dumpcap_command,
    check_dumpcap_privileges,
    get_allowed_interfaces,
    parse_dumpcap_drops,
    start_live_capture,
    stop_live_capture,
)
from ddos_ads.ui_report import generate_ui_report

REPO_ROOT = Path(__file__).resolve().parents[2]
UI_RUNS_DIR = REPO_ROOT / "results/ui_runs"

# Page configuration
st.set_page_config(
    page_title="DDoS ADS - Capture Analysis & Alert Monitor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


def load_thresholds_readonly() -> Dict[str, Any]:
    """Read frozen detection thresholds from disk for display only."""
    th_path = REPO_ROOT / "results/thresholds.json"
    if not th_path.is_file():
        th_path = REPO_ROOT / "models/thresholds.json"
    if th_path.is_file():
        try:
            with open(th_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("packet_rules", {})
        except Exception as e:
            st.sidebar.error(f"Error reading thresholds.json: {e}")
    return {}


def load_alerts_from_db_readonly(db_path: Path) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """Connect to SQLite strictly in READ-ONLY mode using SQLite URI mode=ro."""
    if not db_path.is_file():
        return pd.DataFrame(), {"drops": 0, "restarts": 0, "evictions": 0, "table_size": 0, "detector_blind": False}

    uri = f"file:{db_path.resolve().as_posix()}?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
        query = "SELECT * FROM alerts ORDER BY packet_ts ASC"
        df = pd.read_sql_query(query, conn)
        conn.close()

        meta = {"drops": 0, "restarts": 0, "evictions": 0, "table_size": 0, "detector_blind": False}
        if not df.empty and "details" in df.columns:
            parsed_details = []
            for d in df["details"]:
                try:
                    obj = json.loads(d) if isinstance(d, str) else d
                    parsed_details.append(obj)
                    if isinstance(obj, dict) and obj.get("detector_blind", False):
                        meta["detector_blind"] = True
                except Exception:
                    parsed_details.append({})
            df["details_dict"] = parsed_details

        return df, meta
    except sqlite3.OperationalError:
        raise
    except Exception as e:
        st.warning(f"Unable to read alerts database: {e}")
        return pd.DataFrame(), {"drops": 0, "restarts": 0, "evictions": 0, "table_size": 0, "detector_blind": False}


def load_ground_truth_for_run(run_stem: str) -> Dict[str, Any]:
    """Load frozen evaluation ground truth metrics for an incident run."""
    eval_json = REPO_ROOT / "results/session3_evaluation.json"
    parity_json = REPO_ROOT / "results/phase7_parity_eval.json"
    bench_json = REPO_ROOT / "results/phase7_live_detector_benchmark.json"

    meta: Dict[str, Any] = {
        "first_alert_delay_sec": None,
        "first_alert_time": None,
        "alerted_duration_sec": 0,
        "peak_rate_pps": 0,
        "first_alert_type": "N/A",
        "ground_truth_delay_sec": None,
        "delay_diff_sec": 0.0,
        "drops": 0,
        "restarts": 0,
        "evictions": 0,
        "table_occupancy": 0,
        "table_capacity": 100_000,
        "detector_blind": False,
    }

    if eval_json.is_file():
        try:
            with open(eval_json, "r", encoding="utf-8") as f:
                s3_eval = json.load(f)
                for scen_name, scen_data in s3_eval.get("attack_evaluations", {}).items():
                    for rep in scen_data.get("repeats", []):
                        if rep.get("pcap_name", "") == f"{run_stem}.pcap" or run_stem.endswith(rep.get("pcap_name", "").replace(".pcap", "")):
                            meta["ground_truth_delay_sec"] = rep.get("first_detection_delay_sec")
                            meta["first_alert_type"] = rep.get("first_alert_type", "N/A")
                            meta["alerted_duration_sec"] = rep.get("alerted_seconds_post_first_alert", 0)
                            meta["peak_rate_pps"] = rep.get("nominal_rate_pps", 0)
                            break
        except Exception:
            pass

    if parity_json.is_file():
        try:
            with open(parity_json, "r", encoding="utf-8") as f:
                p_eval = json.load(f)
                for item in p_eval.get("evaluations", []):
                    if run_stem in item.get("pcap", ""):
                        meta["first_alert_delay_sec"] = item.get("streaming_delay_sec")
                        meta["first_alert_time"] = f"{item.get('streaming_delay_sec', 0.0):.4f}s"
                        if meta["ground_truth_delay_sec"] is not None and meta["first_alert_delay_sec"] is not None:
                            meta["delay_diff_sec"] = meta["first_alert_delay_sec"] - meta["ground_truth_delay_sec"]
                        break
        except Exception:
            pass

    if bench_json.is_file():
        try:
            with open(bench_json, "r", encoding="utf-8") as f:
                b_eval = json.load(f)
                meta["restarts"] = b_eval.get("tshark_supervisor", {}).get("restarts_successfully_handled", 0)
                if "1000pps" in run_stem:
                    meta["evictions"] = b_eval.get("benchmark_1000pps", {}).get("capacity_evictions", 0)
                    meta["table_occupancy"] = 20_000
                elif "200pps" in run_stem:
                    meta["table_occupancy"] = 200
                elif "50pps" in run_stem:
                    meta["table_occupancy"] = 50
        except Exception:
            pass

    return meta


# -----------------------------------------------------------------------------
# Main Application
# -----------------------------------------------------------------------------

def render_analysis_ui() -> None:
    """One-page analysis UI: Upload or Live Capture -> Results -> Download Report."""
    st.title("🛡️ DDoS Anomaly Detection System — Traffic Analysis")
    st.caption("Offline Replay Anomaly Analysis & Live Packet Capture (Alert-Only)")

    # 1. Analyze a capture file
    st.markdown("### 1. Analyze a Capture File")
    uploaded_file = st.file_uploader(
        "Upload a packet capture (.pcap or .pcapng, max 500 MB)",
        type=["pcap", "pcapng"],
        help="Streams capture directly to disk. Executable signatures (.exe) and invalid magic bytes are rejected.",
    )

    if uploaded_file is not None:
        file_key = f"{uploaded_file.name}_{uploaded_file.size}"
        if st.session_state.get("last_uploaded_key") != file_key:
            run_id = uuid.uuid4().hex[:12]
            run_dir = UI_RUNS_DIR / run_id
            with st.spinner("Validating and streaming capture to disk..."):
                try:
                    saved_path, ext, size_bytes, sha256 = validate_and_stream_upload(
                        uploaded_file, uploaded_file.name, run_dir
                    )
                    st.success(
                        f"**Upload Accepted**: `{uploaded_file.name}` ({size_bytes:,} bytes, {size_bytes / (1024*1024):.2f} MB)"
                    )
                    st.code(f"SHA-256: {sha256}", language="text")

                    # Run offline analysis via RuleEngine
                    with st.spinner("Analyzing capture traffic against frozen detection rules..."):
                        analysis_res = analyze_capture_file(
                            saved_path,
                            uploaded_file.name,
                            run_id,
                            dropped_packets=0,
                            enable_posthoc_rule=True,
                        )
                        # Generate HTML, PDF, DOCX
                        generate_ui_report(analysis_res, run_dir)
                        st.session_state["current_analysis"] = analysis_res
                        st.session_state["current_run_dir"] = str(run_dir)
                        st.session_state["last_uploaded_key"] = file_key
                except Exception as e:
                    st.error(f"Upload Analysis Failed: {e}")

    st.markdown("---")

    # 2. Capture live traffic
    st.markdown("### 2. Capture Live Traffic")
    st.info(
        "ℹ️ **Legal & Operational Notice**: Only capture traffic on networks you own or are explicitly authorized to monitor."
    )

    # Check dumpcap privilege status
    has_privs, priv_msg = check_dumpcap_privileges()
    if not has_privs:
        st.warning(f"⚠️ **Capture Privileges Warning**:\n{priv_msg}")

    # Interface selection
    available_interfaces = get_allowed_interfaces()
    iface_options = [iface[0] for iface in available_interfaces] if available_interfaces else ["eth0", "lo"]
    iface_labels = {iface[0]: iface[1] for iface in available_interfaces}

    col_c1, col_c2 = st.columns(2)
    with col_c1:
        selected_iface = st.selectbox(
            "Capture Interface",
            iface_options,
            format_func=lambda x: iface_labels.get(x, x),
            help="Only network interfaces enumerated by dumpcap -D are selectable.",
        )
    with col_c2:
        capture_duration = st.slider(
            "Capture Duration (seconds)",
            min_value=30,
            max_value=900,
            value=60,
            step=10,
            help="Live capture is strictly capped between 30 s and 15 minutes (900 s).",
        )

    permission_box = st.checkbox(
        "I own this network or have permission to capture on it",
        value=False,
        help="Mandatory safety acknowledgment. Capture cannot start without this confirmation.",
    )

    btn_col1, btn_col2 = st.columns([1, 1])
    is_capturing = st.session_state.get("is_capturing", False)

    with btn_col1:
        start_btn = st.button(
            "▶️ Start Capture",
            disabled=(not permission_box or is_capturing or not has_privs),
            help="Start dumpcap background capture." if permission_box else "Tick permission checkbox to enable.",
        )
    with btn_col2:
        stop_btn = st.button(
            "⏹️ Stop Capture",
            disabled=(not is_capturing),
            help="Send SIGTERM to stop capture and analyze output.",
        )

    # Handle Start Capture
    if start_btn:
        run_id = uuid.uuid4().hex[:12]
        run_dir = UI_RUNS_DIR / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        out_pcapng = run_dir / "capture.pcapng"

        allowed_list = [i[0] for i in available_interfaces] if available_interfaces else None
        try:
            cmd = build_dumpcap_command(
                iface=selected_iface,
                duration_sec=capture_duration,
                out_pcapng=out_pcapng,
                permission_acknowledged=permission_box,
                allowed_ifaces=allowed_list,
            )
            proc = start_live_capture(cmd, permission_acknowledged=permission_box)
            st.session_state["is_capturing"] = True
            st.session_state["capture_proc"] = proc
            st.session_state["capture_pcapng"] = str(out_pcapng)
            st.session_state["capture_run_dir"] = str(run_dir)
            st.session_state["capture_run_id"] = run_id
            st.session_state["capture_start_time"] = time.time()
            st.session_state["capture_duration"] = capture_duration
            st.rerun()
        except Exception as e:
            st.error(f"Failed to start live capture: {e}")

    # Display active capture progress
    if is_capturing:
        start_t = st.session_state.get("capture_start_time", time.time())
        dur_target = st.session_state.get("capture_duration", 60)
        elapsed = time.time() - start_t
        progress_val = min(1.0, elapsed / dur_target)
        st.progress(progress_val)
        st.caption(f"Capture in progress... {int(elapsed)}s / {dur_target}s on `{selected_iface}`")

        # Auto-finish if duration elapsed
        proc = st.session_state.get("capture_proc")
        if proc and proc.poll() is not None:
            stop_btn = True

    # Handle Stop Capture
    if stop_btn and is_capturing:
        proc = st.session_state.get("capture_proc")
        pcapng_path = Path(st.session_state.get("capture_pcapng"))
        run_dir = Path(st.session_state.get("capture_run_dir"))
        run_id = st.session_state.get("capture_run_id")

        with st.spinner("Stopping capture and finalizing packets..."):
            ret_code, stdout, stderr = stop_live_capture(proc)
            drops = parse_dumpcap_drops(stderr)
            st.session_state["is_capturing"] = False

            if pcapng_path.is_file():
                st.success(f"Capture complete. Saved to `{pcapng_path}` (Drops: {drops})")
                with st.spinner("Analyzing capture traffic..."):
                    analysis_res = analyze_capture_file(
                        pcapng_path,
                        "live_capture.pcapng",
                        run_id,
                        dropped_packets=drops,
                        enable_posthoc_rule=True,
                    )
                    generate_ui_report(analysis_res, run_dir)
                    st.session_state["current_analysis"] = analysis_res
                    st.session_state["current_run_dir"] = str(run_dir)
            else:
                st.error("Capture file was not created. Verify permissions.")
        st.rerun()

    # 3. Results Section
    current_analysis = st.session_state.get("current_analysis")
    if current_analysis:
        st.markdown("---")
        st.markdown("### 3. Analysis Results")

        res = current_analysis["results"]
        health = current_analysis["detector_health"]
        in_meta = current_analysis["input_metadata"]
        run_id = current_analysis["run_id"]
        run_dir = Path(st.session_state.get("current_run_dir", UI_RUNS_DIR / run_id))

        total_alerts = res["total_alerts"]
        verdict = res["verdict"]

        # Detector Blind Warning Banner
        if health.get("detector_blind", False):
            st.error(
                f"🚨 **DETECTOR BLIND WARNING**: Packet drops ({health.get('dropped_packets', 0)}) "
                f"or truncated capture detected ({health.get('is_truncated', False)}). "
                "The detector may have missed anomalies."
            )

        # Verdict Line
        if total_alerts > 0:
            st.error(f"⚠️ **Verdict**: {verdict.upper()} ({total_alerts} alerts triggered)")
        else:
            st.success("✅ **Verdict**: NO ALERTS FOUND (Traffic rates remained within calibrated baseline thresholds)")

        # Metrics cards
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Packets Analyzed", f"{in_meta['packet_count']:,}")
        m2.metric("Duration", f"{in_meta['duration_sec']} s")
        m3.metric("First Alert", f"{res['first_alert_delay_sec']} s" if res['first_alert_delay_sec'] is not None else "None")
        m4.metric("Alerted Seconds", f"{res['total_alerted_seconds']} s")

        # Alert Timeline Chart
        st.markdown("#### Alert Timeline by Rule")
        alerts_list = res.get("alerts", [])
        if alerts_list:
            df_timeline = pd.DataFrame(alerts_list)
            fig_timeline = px.scatter(
                df_timeline,
                x="relative_time_sec",
                y="rate_pps",
                color="alert_class",
                symbol="status",
                hover_data=["rule", "destination", "distinct_sources", "distinct_ports"],
                title="Alert Occurrence Over Capture Timeline",
                labels={"relative_time_sec": "Time (seconds from start)", "rate_pps": "Trigger Rate (pps)"},
            )
            st.plotly_chart(fig_timeline, use_container_width=True)
        else:
            st.info("No alert events to display on timeline.")

        # Table of Alerts
        st.markdown("#### Detected Alerts")
        if alerts_list:
            df_display = pd.DataFrame(alerts_list)[
                ["time_epoch", "relative_time_sec", "rule", "alert_class", "status", "destination", "rate_pps", "distinct_sources", "distinct_ports"]
            ]
            st.dataframe(df_display, use_container_width=True)
        else:
            st.write("No alerts recorded.")

        # Per-destination Rate Charts with Frozen Threshold Lines
        st.markdown("#### Per-Destination Traffic Rates vs. Frozen Thresholds")
        dst_rates = res.get("per_destination_rates", {})
        if dst_rates:
            for dst_ip, rate_info in dst_rates.items():
                bins = rate_info["bins"]
                x_vals = list(range(len(bins)))
                fig_rate = go.Figure()
                fig_rate.add_trace(go.Scatter(x=x_vals, y=bins, mode="lines+markers", name=f"Rate to {dst_ip} (pps)"))
                # Frozen threshold horizontal lines
                fig_rate.add_hline(y=40, line_dash="dash", line_color="orange", annotation_text="UDP Volumetric Threshold (40 pps)")
                fig_rate.add_hline(y=20, line_dash="dash", line_color="red", annotation_text="SYN Incomplete Concentrated (20 inc/s)")
                fig_rate.add_hline(y=150, line_dash="dash", line_color="purple", annotation_text="Post-Hoc SYN Rate (150 pps)")
                fig_rate.update_layout(
                    title=f"Destination {dst_ip} Traffic Rate vs. Detection Thresholds",
                    xaxis_title="Time Bin (seconds)",
                    yaxis_title="Packets / Incompletes per Second",
                )
                st.plotly_chart(fig_rate, use_container_width=True)

        # 4. Download Report Section
        st.markdown("---")
        st.markdown("### 4. Download Analysis Report")
        d_col1, d_col2, d_col3 = st.columns(3)

        html_file = run_dir / "report.html"
        pdf_file = run_dir / "report.pdf"
        docx_file = run_dir / "report.docx"

        with d_col1:
            if html_file.is_file():
                with open(html_file, "r", encoding="utf-8") as f:
                    st.download_button(
                        "📄 Download HTML Report",
                        data=f.read(),
                        file_name=f"analysis_report_{run_id}.html",
                        mime="text/html",
                    )
        with d_col2:
            if pdf_file.is_file():
                with open(pdf_file, "rb") as f:
                    st.download_button(
                        "📑 Download PDF Report",
                        data=f.read(),
                        file_name=f"analysis_report_{run_id}.pdf",
                        mime="application/pdf",
                    )
            else:
                st.caption("PDF conversion requires LibreOffice.")
        with d_col3:
            if docx_file.is_file():
                with open(docx_file, "rb") as f:
                    st.download_button(
                        "📝 Download DOCX Report",
                        data=f.read(),
                        file_name=f"analysis_report_{run_id}.docx",
                        mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    )


def render_advanced_monitor_ui() -> None:
    """Preserved Phase 8 read-only monitoring dashboard."""
    thresholds = load_thresholds_readonly()
    hs_rules = thresholds.get("packet_incomplete_tcp_handshake_rule", {})
    udp_rules = thresholds.get("packet_dual_condition_udp_rule", {})
    syn_arrival_rules = thresholds.get("packet_syn_arrival_rate_rule", {})

    th_syn_flood = hs_rules.get("condition_b_sliding_concentrated_incomplete_syns_threshold", 20)
    th_scan = hs_rules.get("condition_a_min_incomplete_rate", 15)
    th_udp_vol = udp_rules.get("condition_1_volumetric_udp_pkts_per_sec", 40)
    th_udp_rnd = udp_rules.get("condition_2_random_port_udp_pkts_per_sec", 30)
    th_syn_arr_multi = syn_arrival_rules.get("syn_arrival_thresh", 150)
    th_syn_arr_single = syn_arrival_rules.get("syn_arrival_single_source_thresh", 1500)

    logs_dir = REPO_ROOT / "results"
    default_db_path = REPO_ROOT / "logs/alerts.db"
    if not default_db_path.is_file():
        default_db_path = logs_dir / "alerts.db"

    st.title("🛡️ DDoS Anomaly Detection System — Real-Time Alert Monitor")
    st.caption("Live Packet-Rule Anomaly Defense Dashboard (Strictly Read-Only)")

    with st.sidebar:
        st.header("📂 Data Source & Incident Replay")
        s3_captures = sorted((REPO_ROOT / "lab/captures/session3").glob("session3_*.pcap"))
        replay_options = ["Live Alert Database (alerts.db)"] + [f"Replay: {p.stem}" for p in s3_captures]
        selected_source = st.selectbox("Select Incident / Replay Stream", replay_options)

        st.markdown("---")
        st.subheader("🔒 Immutable Exempt Destinations")
        exempt_list = [
            "127.0.0.1 (Localhost)",
            "::1 (IPv6 Loopback)",
            "0.0.0.0 (Unspecified)",
            "172.20.0.1 (Gateway)",
            "127.0.0.11 (Embedded DNS)",
        ]
        for ip in exempt_list:
            st.markdown(f"- `{ip}`")
        st.caption("Status: Whitelist active. All modifications and response controls disabled.")

        st.markdown("---")
        st.subheader("📏 Frozen Detection Thresholds (thresholds.json)")
        st.markdown(f"**SYN Flood Threshold (Cond B)**: `≥{th_syn_flood} inc/s`")
        st.markdown(f"**Port Scan Threshold (Cond A)**: `≥{th_scan} inc/s` (≥3 ports)")
        st.markdown(f"**UDP Volumetric**: `≥{th_udp_vol} pkts/s`")
        st.markdown(f"**UDP Random Port**: `≥{th_udp_rnd} pkts/s` (≥10 ports)")
        st.markdown(f"**SYN Arrival Multi-Source**: `≥{th_syn_arr_multi} unacked/s` (≥3 src)")
        st.markdown(f"**SYN Arrival Single-Source**: `≥{th_syn_arr_single} unacked/s`")

    df_alerts = pd.DataFrame()
    incident_meta: Dict[str, Any] = {
        "drops": 0,
        "restarts": 0,
        "evictions": 0,
        "table_occupancy": 0,
        "table_capacity": 100_000,
        "first_alert_delay_sec": None,
        "ground_truth_delay_sec": None,
        "delay_diff_sec": 0.0,
        "detector_blind": False,
        "peak_rate_pps": 0,
        "alerted_duration_sec": 0,
        "first_alert_type": "N/A",
    }

    if selected_source == "Live Alert Database (alerts.db)":
        df_alerts, db_meta = load_alerts_from_db_readonly(default_db_path)
        incident_meta.update(db_meta)
        if not df_alerts.empty:
            if "rule_name" in df_alerts.columns:
                incident_meta["first_alert_type"] = str(df_alerts["rule_name"].iloc[0])
            elif "alert_type" in df_alerts.columns:
                incident_meta["first_alert_type"] = str(df_alerts["alert_type"].iloc[0])
            if "packet_ts" in df_alerts.columns:
                ts_vals = df_alerts["packet_ts"].dropna().tolist()
                if len(ts_vals) > 0:
                    incident_meta["alerted_duration_sec"] = int(max(ts_vals) - min(ts_vals))
    else:
        run_stem = selected_source.replace("Replay: ", "")
        gt_meta = load_ground_truth_for_run(run_stem)
        incident_meta.update(gt_meta)

    drops = incident_meta.get("drops", 0)
    restarts = incident_meta.get("restarts", 0)
    is_blind = drops > 0 or restarts > 0 or incident_meta.get("detector_blind", False)
    if is_blind:
        st.error(
            f"🚨 **DETECTOR BLIND WARNING**: Kernel packet drops ({drops} dropped), "
            f"supervisor auto-restarts ({restarts} restarts), or detector_blind event detected! "
            "Traffic volumes exceeded processing limits. Active defense response must treat this interval as compromised."
        )

    st.subheader(f"Incident Overview: {selected_source}")
    kpi1, kpi2, kpi3, kpi4 = st.columns(4)
    delay_val = incident_meta.get("first_alert_delay_sec")
    delay_str = f"{delay_val:.4f}s" if delay_val is not None else "N/A"
    kpi1.metric("First Alert Delay", delay_str)
    kpi2.metric("Alerted Duration", f"{incident_meta.get('alerted_duration_sec', 0)}s")
    kpi3.metric("Peak Attack Rate", f"{incident_meta.get('peak_rate_pps', 0)} pps")
    kpi4.metric("First Alert Class", str(incident_meta.get("first_alert_type", "N/A")))

    st.markdown("---")
    st.subheader("Incident Alerts Stream")
    if not df_alerts.empty:
        st.dataframe(df_alerts, use_container_width=True)
    else:
        st.info("No alert records found for the selected data source.")


def main() -> None:
    # Sidebar navigation to switch between modern Phase 10 Analysis UI and Phase 8 Advanced Monitor
    with st.sidebar:
        st.title("🛡️ Navigation")
        app_mode = st.radio(
            "Select Dashboard View",
            ["Traffic Analysis UI", "Advanced: Live Incident Monitor (Read-Only)"],
            index=0,
        )
        st.markdown("---")

    if app_mode == "Traffic Analysis UI":
        render_analysis_ui()
    else:
        render_advanced_monitor_ui()


if __name__ == "__main__":
    main()
