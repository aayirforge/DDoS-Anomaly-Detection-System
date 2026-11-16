import json

# Item 2: Flag Audit
d2 = json.load(open("results/raw_day1_flag_audit.json"))
print("### Item 2 Table 1: Raw Day 1 Protocol & Flag Probabilities")
print("| Metric | Value | Breakdown / Formula |")
print("| :--- | :--- | :--- |")
for p, v in d2["protocol_breakdown"].items():
    cnt = v["count"]
    pct = v["fraction"] * 100
    print(f"| Total {p} | {cnt:,} | {pct:.2f}% of Day 1 benign |")
for k, v in d2["tcp_flag_probabilities"].items():
    prob = v["probability"]
    cnt = v["count"]
    tot = v["total"]
    form = v["formula"]
    print(f"| {form} | {prob:.6f} | {cnt:,} / {tot:,} flows |")

print("\n### Item 2 Table 2: TCP Flag Combination Cross-Tabulation")
print("| FIN | SYN | RST | PSH | ACK | URG | Flow Count | % of TCP Benign |")
print("| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |")
for row in d2["tcp_flag_crosstab_fin_syn_rst_psh_ack_urg"]:
    print(f"| {row['FIN']} | {row['SYN']} | {row['RST']} | {row['PSH']} | {row['ACK']} | {row['URG']} | {row['count']:,} | {row['pct_of_tcp_benign']:.3f}% |")

# Item 3: KNN Preprocessing Experiment
d3 = json.load(open("results/knn_preprocessing_experiment.json"))
print("\n### Item 3 Table: KNN Preprocessing Experiment (Day 1 Only)")
print("| Configuration | Val Thresh | Same-Day ZS Recall | Same-Day ZS FPR | Same-Day ZS AUC | Cross-Day ZS Recall | Cross-Day ZS FPR | Cross-Day ZS AUC | Cross-Day Cal Recall | Cross-Day Cal FPR | Cross-Day Cal AUC |")
print("| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |")
for name, exp in d3["experiments"].items():
    s_same = exp["same_day_zero_shot"]
    s_czs = exp["cross_day_zero_shot"]
    s_ccal = exp["cross_day_calibrated"]
    print(f"| {name} | {exp['validation_threshold']:.4f} | {s_same['recall']:.4f} | {s_same['fpr']:.4f} | {s_same['roc_auc']:.4f} | {s_czs['recall']:.4f} | {s_czs['fpr']:.4f} | {s_czs['roc_auc']:.4f} | {s_ccal['recall']:.4f} | {s_ccal['fpr']:.4f} | {s_ccal['roc_auc']:.4f} |")

# Item 4: Candidate Scoring on Session 2 Java Flows
d4 = json.load(open("results/candidate_model_selection.json"))
print("\n### Item 4 Table: Candidate Models & Feature Sets on Session 2 Java Flows")
print("| Candidate Model & Feature Set | Fixed Thresh | Idle FPR (n=21) | Busy FPR (n=1179) | Combined Benign FPR (n=1200) | SYN Flood Window Recall (n=54) | Per-Second Flood Detection (56 bins) | ROC-AUC |")
print("| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |")
for name, c in d4["candidate_evaluations"].items():
    s = c["session2_evaluation"]
    print(f"| {name} | {c['threshold']:>7.4f} | {s['idle_fpr']:>7.4f} ({s['idle_false_positives']}/{s['idle_windows']}) | {s['busy_fpr']:>7.4f} ({s['busy_false_positives']}/{s['busy_windows']}) | {s['benign_fpr']:>7.4f} ({s['combined_false_positives']}/{s['combined_benign_windows']}) | {s['syn_flood_window_recall']:>7.4f} ({s['syn_flood_true_positives']}/{s['syn_flood_windows']}) | {s['per_second_flood_detection_rate']*100:>5.1f}% ({s['detected_attack_1s_bins']}/{s['total_attack_1s_bins']}) | {s['roc_auc']:>6.4f} |")

# Item 5: Handshake Rule on Session 2/2b
d5 = json.load(open("results/session2b_handshake_rule_eval.json"))
print("\n### Item 5 Table: Incomplete Handshake Rule Evaluation on Session 2 & Session 2b")
print("| Scenario | Duration (s) | Incomplete Handshakes/s (Min/Med/Max) | Distinct Incomplete Sources/s (Min/Med/Max) | Alerted Seconds | False Alarms | Recall |")
print("| :--- | :---: | :---: | :---: | :---: | :---: | :---: |")
sc_map = [
    ("Session 2 Idle Benign", "session2_idle", "Benign"),
    ("Session 2 Busy Benign", "session2_busy", "Benign"),
    ("Session 2b Combined Benign (Closed port, Stopped server, 25 clients, Scanner)", "session2b_benign_mixed", "Benign"),
    ("Session 2 Single-Source SYN Flood (100 pps)", "session2_single_source_syn_flood", "Attack"),
    ("Session 2b Multi-Source Spoofed SYN Flood (200 pps)", "session2b_multi_source_spoofed_flood", "Attack")
]
for label, key, kind in sc_map:
    sc = d5["scenario_details"][key]
    inc = sc["incomplete_syns_per_sec"]
    src = sc["distinct_sources_per_sec"]
    dur = sc["duration_seconds"]
    th_syn = d5["frozen_rule_configuration"]["multi_source_threshold_incomplete_syns_per_sec"]
    th_src = d5["frozen_rule_configuration"]["multi_source_threshold_distinct_sources"]
    th_vol = d5["frozen_rule_configuration"]["volumetric_single_source_threshold_incomplete_syns_per_sec"]
    alerts = sum(1 for b in sc["time_series"] if (b["incomplete_syns"] >= th_syn and b["distinct_incomplete_sources"] >= th_src) or (b["incomplete_syns"] >= th_vol))
    fa = alerts if kind == "Benign" else 0
    rec = f"{alerts/dur*100:.1f}% ({alerts}/{dur})" if kind == "Attack" else "N/A"
    print(f"| {label} | {dur}s | {inc['min']}/{inc['median']}/{inc['max']} | {src['min']}/{src['median']}/{src['max']} | {alerts} | {fa} | {rec} |")
