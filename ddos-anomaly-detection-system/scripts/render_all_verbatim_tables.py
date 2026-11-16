#!/usr/bin/env python3
"""
Renders all requested tables verbatim from authoritative JSON files.
"""
import json
from pathlib import Path

BASE = Path("/home/kartik/Documents/AAYIR FORGE/DDoS Anomaly Detection System/ddos-anomaly-detection-system/results")

def render_table_1():
    with open(BASE / "freeze_checksum_comparison.json") as f:
        data = json.load(f)
    print("### Table 1A: Checksums of Models and Thresholds against Freeze Tag (`v1.0-phase5-freeze`)")
    print("| Artifact File | Freeze Tag SHA-256 | Current Working Copy SHA-256 | Status |")
    print("| :--- | :---: | :---: | :---: |")
    for r in data["model_and_metric_checksums"]:
        print(f"| `{r['file']}` | `{r['freeze_tag_sha256']}` | `{r['current_disk_sha256']}` | **{r['status']}** |")
    print()
    print("### Table 1B: Fixed Day 1 Validation Thresholds Frozen in `metrics.json`")
    print("| Model / Detection Head | Threshold Type / Scale | Value | Source / Derivation |")
    print("| :--- | :--- | :---: | :--- |")
    for k, v in data["frozen_thresholds"].items():
        note = "Probability space [0, 1]" if "logit" not in k else "Logit space (-inf, +inf): ln(0.9919 / 0.0081)"
        print(f"| `{k}` | Fixed Day 1 Validation | {v} | {note} |")
    print()
    print("### Table 1C: Artifacts Changed Since Freeze Tag (`v1.0-phase5-freeze`)")
    print("| Changed Artifact / Directory | Classification | Reason for Change |")
    print("| :--- | :--- | :--- |")
    for a in data["artifacts_changed_since_freeze"]:
        print(f"| `{a['artifact']}` | {a['type']} | {a['reason']} |")
    print()

def render_table_2():
    with open(BASE / "knn_preprocessing_experiment.json") as f:
        data = json.load(f)
    print("### Table 2: KNN Preprocessing Experiment vs Frozen Baseline (`models/knn.joblib`)")
    print("| Experiment Variant | Features ($D$) | Preprocessing Pipeline | Same-Day AUC | Cross-Day ZS Recall | Cross-Day ZS FPR | Cross-Day Cal Recall | Cross-Day Cal FPR | Cross-Day AUC |")
    print("| :--- | :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: |")
    for name, exp in data["experiments"].items():
        d = 25 if "Full 25" in name else 14
        sd_auc = exp["same_day_zero_shot"]["roc_auc"]
        zs_rec = exp["cross_day_zero_shot"]["recall"]
        zs_fpr = exp["cross_day_zero_shot"]["fpr"]
        cal_rec = exp["cross_day_calibrated"]["recall"]
        cal_fpr = exp["cross_day_calibrated"]["fpr"]
        cd_auc = exp["cross_day_zero_shot"]["roc_auc"]
        print(f"| **{name}** | {d} | Standard + Signed Log1p + Clip [-5, 5] | {sd_auc:.4f} | {zs_rec:.4f} | {zs_fpr:.4f} | {cal_rec:.4f} | {cal_fpr:.4f} | {cd_auc:.4f} |")
    print()

def render_table_3():
    with open(BASE / "candidate_model_selection.json") as f:
        data = json.load(f)
    print("### Table 3: Pre-Registered Model Selection Table (FPR <= 1.0% Constraint Applied Mechanically)")
    print("| Candidate Model | Eval Level | Fixed Day 1 Thresh | S2 Benign Windows | S2 False Pos | S2 Benign FPR | S2 Flood Windows | S2 Flood TPs | S2 Flood Recall | S2 ROC-AUC | Day 2 ZS Recall | Day 2 ZS FPR | Day 2 Cal Recall | Day 2 Cal FPR | Day 2 AUC | Meets FPR <= 1.0% |")
    print("| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |")
    for name, cand in data["candidates"].items():
        lvl = "Flow" if "Flow" in name else "Window (Step 5)"
        th = cand["threshold"]
        th_str = f"{th:.4f}" if isinstance(th, float) else str(th)
        s2 = cand["session2"]
        d2 = cand["day2_cross_day"]
        meets = "**YES (PASS)**" if s2["meets_preregistered_rule"] else "NO (FAIL)"
        print(f"| **{name}** | {lvl} | {th_str} | {s2['total_benign_windows']} | {s2['combined_false_positives']} | {s2['combined_benign_fpr']:.4f} ({s2['combined_benign_fpr']*100:.2f}%) | {s2['flood_windows']} | {s2['flood_true_positives']} | {s2['flood_window_recall']:.4f} ({s2['flood_window_recall']*100:.2f}%) | {s2['roc_auc']:.4f} | {d2['zs_rec']:.4f} | {d2['zs_fpr']:.4f} | {d2['cal_rec']:.4f} | {d2['cal_fpr']:.4f} | {d2['auc']:.4f} | {meets} |")
    print()

def render_table_4():
    with open(BASE / "session2b_handshake_rule_eval.json") as f:
        data = json.load(f)
    print("### Table 4A: Incomplete TCP Handshake Rule — Real Detection Delays")
    print("| Attack Scenario | Packet Arrival Offset | Handshake Timeout ($N$) | Real Detection Delay ($\Delta t_{\\text{real}}$) | Triggered Rule Condition |")
    print("| :--- | :---: | :---: | :---: | :--- |")
    for k, v in data["real_detection_delay_metrics"].items():
        scen_name = "Single-Source SYN Flood (100 pps)" if "single_source" in k else "Multi-Source Spoofed SYN Flood (200 pps)"
        arr_ms = v["packet_arrival_offset_ms"]
        to_ms = v["handshake_completion_timeout_ms"]
        tot_ms = v["real_detection_delay_ms"]
        tot_s = v["real_detection_delay_sec"]
        cond = "Condition B (>= 50 incomplete/s)" if "single_source" in k else "Condition A (>= 15 inc/s and >= 3 sources)"
        print(f"| **{scen_name}** | {arr_ms:.1f} ms | {to_ms:.1f} ms | **{tot_ms:.1f} ms ({tot_s:.3f} s)** | {cond} |")
    print()
    print("### Table 4B: Incomplete TCP Handshake Rule — Extended 5+ Min Benign & Scan Evaluation")
    print("| Traffic Scenario / Condition | Duration ($T$) | Mean Inc SYNs/s | Max Inc SYNs/s | Cond A False Alarms | Cond B False Alarms | Combined False Alarms | Attack Recall |")
    print("| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |")
    for sc in data["scenario_evaluations"]:
        name = sc["scenario"]
        dur = f"{sc['duration_seconds']} s"
        mean_inc = f"{sc['incomplete_syns_per_sec']['mean']:.2f}"
        max_inc = f"{sc['incomplete_syns_per_sec']['max']}"
        fa_a = sc["false_alarms_condition_A"]
        fa_b = sc["false_alarms_condition_B"]
        fa_comb = sc["false_alarms_combined"]
        rec = sc["attack_recall"]
        print(f"| **{name}** | {dur} | {mean_inc} | {max_inc} | {fa_a} | {fa_b} | {fa_comb} | {rec} |")
    print()

def render_table_5():
    with open(BASE / "raw_day1_flag_audit.json") as f:
        data = json.load(f)
    print("### Table 5: Day 1 Raw CSV Flag Audit by Protocol (CSV-01-12) vs Expected Behaviour")
    print("| Flag Name | TCP Count / Total | TCP Rate | Expected TCP Behaviour | Column Diagnosis | UDP Rate | Raw IP Rate |")
    print("| :--- | :---: | :---: | :--- | :--- | :---: | :---: |")
    for fl in data["flag_audit_by_protocol"]:
        name = fl["flag_name"]
        tcp_cnt = f"{fl['tcp_count']:,} / {fl['tcp_total']:,}"
        tcp_rate = f"{fl['tcp_rate']:.4f} ({fl['tcp_rate']*100:.2f}%)"
        exp = fl["expected_tcp_behaviour"]
        diag = fl["column_shifted_diagnosis"]
        udp = f"{fl['udp_rate']:.4f}"
        raw = f"{fl['raw_ip_rate']:.4f}"
        print(f"| **{name}** | {tcp_cnt} | {tcp_rate} | {exp} | **{diag}** | {udp} | {raw} |")
    print()

def render_table_6():
    print("### Table 6: Session 3 Pre-Registered Success Criteria (lab/session3_plan.md)")
    print("| Evaluation Dimension | Metric Target | Evaluation Basis |")
    print("| :--- | :---: | :--- |")
    print("| **Benign False Alarm Rate (FPR)** | **<= 1.0%** per-bin FPR | Evaluated across all >= 15 minutes of diverse multi-protocol benign traffic (1-second bins for packet rules, step-5 windows for flow models). |")
    print("| **High-Rate Attack Recall (200, 500, 1000 pps)** | **>= 95.0%** recall | Evaluated on TCP SYN floods, UDP floods, and UDP reflection attacks across all 3 repeats. |")
    print("| **Low-Rate Attack Recall (50 pps)** | **>= 80.0%** recall | Evaluated on 50 pps attack runs across all 3 repeats. |")
    print("| **Packet-Rule Real Detection Delay** | **<= 2.5 seconds** | Real detection delay including the 2.0s TCP handshake completion timeout for SYN floods; <= 1.0 s for UDP floods. |")
    print("| **Flow-Model Detection Delay** | **<= 5.0 seconds** | From first attack packet arrival to the first window alert crossing where flows exist. |")
    print()

if __name__ == "__main__":
    render_table_1()
    render_table_2()
    render_table_3()
    render_table_4()
    render_table_5()
    render_table_6()
