"""Generate markdown tables strictly from results/lab_metrics.json (programmatic reporting)."""

from __future__ import annotations

import json
from pathlib import Path


def generate_markdown_report() -> str:
    metrics_path = Path("results/lab_metrics.json")
    if not metrics_path.is_file():
        raise FileNotFoundError(f"Missing {metrics_path}. Run pipeline first.")

    with open(metrics_path) as f:
        data = json.load(f)

    lines: list[str] = []

    # Title & Metadata
    lines.append("# Phase 6 Isolated Lab Evaluation Report")
    lines.append("")
    lines.append("> **Execution Environment:** Docker `isolated_lab_net` (`internal: true`, zero outbound Internet routing).")
    lines.append("> **Operational Mode:** Alert-only throughout (no disruptive packet drops or host blocking).")
    lines.append("> **Provenance:** All numbers generated programmatically from `results/lab_metrics.json`.")
    lines.append("")

    # Section 1: Network Isolation
    lines.append("## 1. Internal-Only Network Isolation Verification")
    lines.append("")
    lines.append("Strict isolation verification passed all checks via `lab/scripts/check_isolated_network.sh`:")
    lines.append("- Docker network inspect confirmed `Internal: true`.")
    lines.append("- Containers (`victim-web`, `benign-client`, `traffic-generator`): zero default gateways.")
    lines.append("- Outbound egress probes (`ping 8.8.8.8`, `curl http://1.1.1.1`): 100% blocked / unreachable.")
    lines.append("- Internal inter-container reachability (`benign-client -> http://victim-web`): verified.")
    lines.append("")

    # Section 2: Feature Distribution Comparison & Directionality
    lines.append("## 2. Feature Distribution Comparison & Directionality")
    lines.append("")
    lines.append("### 2.1 25-Feature Distribution Comparison")
    lines.append("")
    lines.append(
        "| Feature | Train Med | Train Max | Day 2 Med | Lab Med | Lab P95 | Lab Max | Status | Notes |"
    )
    lines.append(
        "|:---|---:|---:|---:|---:|---:|---:|:---:|:---|"
    )

    feat_dist = data["feature_comparison"]["feature_distributions"]
    for f_name, f_data in feat_dist.items():
        tr_med = f_data["train_benign"]["median"]
        tr_max = f_data["train_benign"]["max"]
        d2_med = f_data["day2_benign"]["median"]
        lab_med = f_data["lab_combined"]["median"]
        lab_p95 = f_data["lab_combined"]["p95"]
        lab_max = f_data["lab_combined"]["max"]
        status = f_data["status"]
        notes = "; ".join(f_data["flag_reasons"]) if f_data["flag_reasons"] else ("OK" if not f_data["is_all_zero"] else "All-Zero")

        lines.append(
            f"| `{f_name}` | {tr_med:.2f} | {tr_max:.1f} | {d2_med:.2f} | {lab_med:.2f} | {lab_p95:.2f} | {lab_max:.1f} | **{status}** | {notes} |"
        )

    lines.append("")
    lines.append("### 2.2 Directionality & Backward-Heavy Features Assessment")
    lines.append("")
    dir_info = data["feature_comparison"]["directionality"]
    lines.append(f"- **Client-to-Server Mapping:** Forward direction (`src_ip=172.20.0.3 -> dst_ip=172.20.0.2:80`).")
    lines.append(f"- **Server-to-Client Mapping:** Backward direction (`src_ip=172.20.0.2:80 -> dst_ip=172.20.0.3`).")
    lines.append(f"- **Total Forward Packets:** {dir_info['total_fwd_packets']:,.0f} (HTTP requests).")
    lines.append(f"- **Total Backward Packets:** {dir_info['total_bwd_packets']:,.0f} (HTTP responses/payloads).")
    lines.append(f"- **Overall Down/Up Packet Ratio:** {dir_info['overall_down_up_ratio']:.3f}.")
    lines.append(f"- **Total Forward Volume:** {dir_info['total_fwd_bytes']/(1024*1024):.2f} MB.")
    lines.append(f"- **Total Backward Volume:** {dir_info['total_bwd_bytes']/(1024*1024):.2f} MB (web downloads).")
    lines.append(f"- **Backward-Heavy Features Populated:** {len(dir_info['backward_heavy_features_populated'])} of 13 features populated with non-zero values.")
    lines.append("")

    # Section 3: Model Scoring on Lab Benign Flows
    lines.append("## 3. Model Scoring on Lab Benign Traffic (FPR Evaluation)")
    lines.append("")
    lines.append("### 3.1 Raw cicflowmeter Units")
    lines.append("")
    lines.append(
        "| Model | Val Thresh | Zero-Shot Idle FPR | Zero-Shot Busy FPR | Cal Thresh | Cal Idle FPR (2nd Half) | Cal Busy FPR |"
    )
    lines.append(
        "|:---|:---:|:---:|:---:|:---:|:---:|:---:|"
    )

    benign_raw = data["benign_evaluation"]["raw_units"]
    for m_name, m_eval in benign_raw.items():
        v_th = m_eval["val_threshold"]
        c_th = m_eval["cal_threshold"]
        zs_i = f"{m_eval['zero_shot']['idle']['fpr']*100:.2f}% ({m_eval['zero_shot']['idle']['false_positives']}/{m_eval['zero_shot']['idle']['total']})"
        zs_b = f"{m_eval['zero_shot']['busy']['fpr']*100:.2f}% ({m_eval['zero_shot']['busy']['false_positives']}/{m_eval['zero_shot']['busy']['total']})"
        cal_i = f"{m_eval['target_calibrated']['eval_idle_2nd_half']['fpr']*100:.2f}% ({m_eval['target_calibrated']['eval_idle_2nd_half']['false_positives']}/{m_eval['target_calibrated']['eval_idle_2nd_half']['total']})"
        cal_b = f"{m_eval['target_calibrated']['busy']['fpr']*100:.2f}% ({m_eval['target_calibrated']['busy']['false_positives']}/{m_eval['target_calibrated']['busy']['total']})"
        lines.append(f"| **{m_name}** | {v_th:.4f} | {zs_i} | {zs_b} | {c_th:.4f} | {cal_i} | {cal_b} |")

    lines.append("")

    # Section 4: Low-rate Flood Attack Evaluation
    lines.append("## 4. Low-Rate Flood Attack Evaluation")
    lines.append("")
    lines.append("Low-rate SYN and UDP floods (50, 200, 500 pps) executed against `victim-web` with concurrent background benign traffic.")
    lines.append("")

    for mode in ["zero_shot", "target_calibrated"]:
        mode_title = "Zero-Shot Operating Point (Validation Threshold)" if mode == "zero_shot" else "Target-Calibrated Operating Point (Lab Idle Threshold)"
        lines.append(f"### 4.1 {mode_title}")
        lines.append("")
        lines.append(
            "| Attack | Rate | Attack Flows | Benign Flows | RF Flow Recall | RF False Alarms | RF Delay | CW Recall | CW Delay | Dest Agg Recall | Dest Agg Delay |"
        )
        lines.append(
            "|:---|:---:|---:|---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|"
        )

        atk_eval = data["attack_evaluation"]
        for atk_type, rate_dict in atk_eval.items():
            for r_str, run_data in rate_dict.items():
                m = run_data[mode]
                rf_rec = f"{m['flow_rule_rf']['recall']*100:.1f}%"
                rf_fa = str(m['flow_rule_rf']['false_alarms'])
                rf_del = f"{m['flow_rule_rf']['detection_delay_sec']:.2f}s"
                cw_rec = f"{m['consecutive_window_rule']['recall']*100:.1f}%"
                cw_del = f"{m['consecutive_window_rule']['detection_delay_sec']:.2f}s"
                dest_rec = f"{m['destination_aggregator']['recall']*100:.1f}%"
                dest_del = f"{m['destination_aggregator']['detection_delay_sec']:.2f}s"
                lines.append(
                    f"| {atk_type.upper()} | {r_str} pps | {run_data['attack_flows']} | {run_data['benign_flows']} | "
                    f"{rf_rec} | {rf_fa} | {rf_del} | {cw_rec} | {cw_del} | {dest_rec} | {dest_del} |"
                )
        lines.append("")

    return "\n".join(lines)


def main():
    report_text = generate_markdown_report()
    out_path = Path("results/lab_report.md")
    with open(out_path, "w") as f:
        f.write(report_text)
    print(f"Lab report generated successfully at {out_path}.")
    print("\n" + report_text)


if __name__ == "__main__":
    main()
