"""Streamlit Interactive Monitoring and Model Evaluation Dashboard."""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from ddos_ads.config import load_config
from ddos_ads.utils import check_models_exist

# Configure page layout
st.set_page_config(
    page_title="DDoS Anomaly Detection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


def load_detection_logs(db_path: Path) -> pd.DataFrame:
    """Load detections from SQLite database."""
    if not db_path.is_file():
        return pd.DataFrame()
    try:
        conn = sqlite3.connect(str(db_path))
        df = pd.read_sql_query("SELECT * FROM detections ORDER BY id DESC LIMIT 5000", conn)
        conn.close()
        if not df.empty and "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"])
        return df
    except Exception as e:
        st.error(f"Error reading SQLite database: {e}")
        return pd.DataFrame()


def load_evaluation_metrics(metrics_json_path: Path) -> dict:
    """Load evaluation metrics JSON file."""
    if not metrics_json_path.is_file():
        return {}
    try:
        with open(metrics_json_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        st.error(f"Error reading metrics JSON: {e}")
        return {}


def main() -> None:
    config = load_config()
    logs_dir = config.get_path("logs_dir")
    results_dir = config.get_path("results_dir")
    models_dir = config.get_path("models_dir")

    db_path = logs_dir / "detections.db"
    metrics_path = results_dir / "metrics.json"

    # Header
    st.title("🛡️ DDoS Anomaly Detection System")
    st.caption("Real-Time Flow Monitoring, Defense Mitigation & ML Model Benchmark")

    # Sidebar System Status
    with st.sidebar:
        st.header("⚙️ System Status")
        models_ready = check_models_exist(models_dir, ["features.json", "scaler.joblib"])
        if models_ready:
            st.success("✅ Models Deployed in `models/`")
        else:
            st.warning("⚠️ Models not trained yet (`make train`)")

        st.markdown("---")
        st.subheader("Mitigation Policy")
        blocking_enabled = config.get("mitigation.enable_blocking", False)
        dry_run = config.get("mitigation.dry_run", False)
        exempt_rfc1918 = config.get("mitigation.exempt_rfc1918", False)

        if blocking_enabled and not dry_run:
            st.error("🚨 Active Dropping (nftables)")
        elif dry_run:
            st.info("🧪 Dry-Run Simulation")
        else:
            st.success("👁️ Alert-Only Mode (Passive)")

        st.write(f"**Consecutive Windows:** {config.get('live_detection.consecutive_suspicious_windows', 3)}")
        st.write(f"**Cooldown Period:** {config.get('live_detection.per_ip_cooldown_sec', 300)}s")
        st.write(f"**RFC 1918 Exemption:** {'Enabled' if exempt_rfc1918 else 'Disabled'}")

        st.markdown("---")
        if st.button("🔄 Refresh Data", use_container_width=True):
            st.rerun()

    # Main Tabs
    tab_live, tab_eval, tab_rules = st.tabs([
        "📡 Live Traffic & Detections",
        "📊 Model Benchmarks & Metrics",
        "📜 System & Safety Architecture",
    ])

    # --------------------------------------------------------------------------
    # Tab 1: Live Traffic & Detections
    # --------------------------------------------------------------------------
    with tab_live:
        df_logs = load_detection_logs(db_path)

        if df_logs.empty:
            st.info("ℹ️ **No live traffic detections recorded yet.**")
            st.markdown(
                """
                To start monitoring live traffic or scoring flows:
                1. Start the live detection daemon: `make live`
                2. Or stream flow data via the REST API: `POST /score`
                3. The events will dynamically appear here in real time.
                """
            )
        else:
            total_records = len(df_logs)
            attack_records = int((df_logs["is_anomaly"] == 1).sum())
            blocked_records = int((df_logs["action"] == "BLOCKED").sum())
            unique_attackers = df_logs[df_logs["is_anomaly"] == 1]["src_ip"].nunique()

            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Total Events Logged", f"{total_records:,}")
            col2.metric("Detected Anomalies", f"{attack_records:,}", delta=f"{attack_records/max(1, total_records)*100:.1f}%")
            col3.metric("Blocked Attacker IPs", f"{blocked_records:,}")
            col4.metric("Unique Suspicious Sources", f"{unique_attackers:,}")

            st.markdown("---")

            # Timeline of anomaly scores with threshold
            thresh = config.get("live_detection.threshold", 0.50)
            st.subheader("📈 Anomaly Probability Timeline")

            df_sorted = df_logs.sort_values(by="timestamp").copy()
            fig_timeline = px.scatter(
                df_sorted,
                x="timestamp",
                y="anomaly_score",
                color="action",
                hover_data=["src_ip", "dst_ip", "protocol", "reason"],
                color_discrete_map={"BLOCKED": "red", "ALERT": "orange", "NORMAL": "green"},
                title="Flow Anomaly Scores vs Decision Threshold",
            )
            fig_timeline.add_hline(
                y=thresh,
                line_dash="dash",
                line_color="red",
                annotation_text=f"Decision Threshold ({thresh})",
                annotation_position="bottom right",
            )
            fig_timeline.update_layout(yaxis_range=[0, 1.05])
            st.plotly_chart(fig_timeline, use_container_width=True)

            # Table of recent flagged IPs
            st.subheader("📋 Recent Detection Audit Log")
            st.dataframe(
                df_logs[["timestamp", "src_ip", "dst_ip", "model_used", "anomaly_score", "action", "consecutive_count", "reason"]].head(100),
                use_container_width=True,
                height=350,
            )

    # --------------------------------------------------------------------------
    # Tab 2: Model Benchmarks & Metrics
    # --------------------------------------------------------------------------
    with tab_eval:
        metrics_data = load_evaluation_metrics(metrics_path)

        if not metrics_data:
            st.warning("⚠️ **No evaluation metrics found in `results/metrics.json`.**")
            st.markdown(
                """
                Train models and run offline evaluation to view performance metrics:
                ```bash
                make train
                make evaluate
                ```
                """
            )
        else:
            st.subheader("🏆 Model Performance Summary (CIC-DDoS2019)")

            rows = []
            for name, m in metrics_data.items():
                rows.append({
                    "Model": m.get("model", name),
                    "Split": m.get("split", "Same-Day"),
                    "Threshold": m.get("threshold", 0.5),
                    "Precision": m.get("precision", 0.0),
                    "Recall": m.get("recall", 0.0),
                    "F1 Score": m.get("f1", 0.0),
                    "FPR (target <= 1%)": m.get("fpr", 0.0),
                    "ROC-AUC": m.get("roc_auc", 0.0),
                    "PR-AUC": m.get("pr_auc", 0.0),
                    "Latency (ms / 1k flows)": m.get("latency_ms_per_1k", 0.0),
                    "Size (MB)": m.get("model_size_mb", 0.0),
                })
            st.dataframe(pd.DataFrame(rows), use_container_width=True)

            # Plots
            st.markdown("---")
            col_roc, col_pr = st.columns(2)

            with col_roc:
                st.subheader("ROC Curves")
                fig_roc = go.Figure()
                for name, m in metrics_data.items():
                    if "fpr_curve" in m and "tpr_curve" in m:
                        fig_roc.add_trace(go.Scatter(
                            x=m["fpr_curve"], y=m["tpr_curve"],
                            mode="lines", name=f"{name} (AUC={m.get('roc_auc', 0):.3f})"
                        ))
                fig_roc.add_trace(go.Scatter(x=[0, 1], y=[0, 1], mode="lines", line=dict(dash="dash", color="grey"), name="Chance"))
                fig_roc.update_layout(xaxis_title="False Positive Rate", yaxis_title="True Positive Rate")
                st.plotly_chart(fig_roc, use_container_width=True)

            with col_pr:
                st.subheader("Precision-Recall Curves")
                fig_pr = go.Figure()
                for name, m in metrics_data.items():
                    if "pr_precision" in m and "pr_recall" in m:
                        fig_pr.add_trace(go.Scatter(
                            x=m["pr_recall"], y=m["pr_precision"],
                            mode="lines", name=f"{name} (PR-AUC={m.get('pr_auc', 0):.3f})"
                        ))
                fig_pr.update_layout(xaxis_title="Recall", yaxis_title="Precision")
                st.plotly_chart(fig_pr, use_container_width=True)

    # --------------------------------------------------------------------------
    # Tab 3: System Architecture & Safety
    # --------------------------------------------------------------------------
    with tab_rules:
        st.subheader("🛡️ Safety Constraints & System Guarantees")
        st.markdown(
            """
            ### Safety Enforcements
            1. **Alert-Only by Default**: The system operates strictly as a passive sensor unless explicitly configured with `--enable-blocking`.
            2. **Whitelist Protection**: Localhost (`127.0.0.1`, `::1`), default gateways, and system DNS resolvers are automatically detected and exempt from blocking.
            3. **Whitelist Alerting Integrity**: The whitelist **only suppresses active packet dropping**; it never suppresses anomaly alerting or audit logging.
            4. **Kernel Auto-Expiring Rules**: All `nftables` drop elements include an explicit kernel timeout (`3600s`) to prevent indefinite isolation.
            5. **Clean Session Exit**: On termination (SIGINT), the system executes a clean teardown to flush active firewall rules.
            """
        )


if __name__ == "__main__":
    main()
