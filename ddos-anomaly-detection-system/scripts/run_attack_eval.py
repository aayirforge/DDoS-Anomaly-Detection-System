"""Automated attack evaluation harness: low-rate SYN/UDP floods with concurrent benign traffic.
Evaluates both Zero-Shot (validation threshold) and Target-Calibrated operating points.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Tuple
import joblib
import numpy as np
import pandas as pd
import torch

from ddos_ads.config import load_config
from ddos_ads.features import load_selected_features
from ddos_ads.live_detector import DestinationAggregator
from ddos_ads.pcap_to_flows import align_flow_dataframe
from ddos_ads.train_lstm import LSTMAnomalyClassifier


TARGET_RATES = [50, 200, 500]
ATTACK_TYPES = ["syn", "udp"]


def evaluate_attack_run(
    attack_type: str,
    rate_pps: int,
    thresholds: Dict[str, float],
) -> Dict:
    pcap_name = f"attack_{attack_type}_{rate_pps}.pcap"
    csv_host_path = Path(f"lab/captures/{pcap_name.replace('.pcap', '_flows.csv')}")

    if not csv_host_path.is_file():
        raise FileNotFoundError(f"Extracted flow CSV not found at {csv_host_path}")

    config = load_config()
    feats = load_selected_features(config.get_path("models_dir") / "features.json")
    raw_df = pd.read_csv(csv_host_path)

    feat_df, meta_df = align_flow_dataframe(raw_df, feats)

    # Ground truth: traffic from/to 172.20.0.4 is attack, 172.20.0.3 is benign
    is_attack = (meta_df["Source IP"] == "172.20.0.4") | (meta_df["Destination IP"] == "172.20.0.4")
    meta_df["Label_Binary"] = is_attack.astype(int)

    n_attack = int(is_attack.sum())
    n_benign = int((~is_attack).sum())

    # Model inference
    scaler = joblib.load(config.get_path("models_dir") / "scaler.joblib")
    rf = joblib.load(config.get_path("models_dir") / "rf.joblib")
    knn = joblib.load(config.get_path("models_dir") / "knn.joblib")

    ckpt = torch.load(config.get_path("models_dir") / "lstm.pt", map_location="cpu")
    lstm = LSTMAnomalyClassifier(ckpt["input_dim"], ckpt["hidden_dim"], ckpt["num_layers"], 0.0)
    lstm.load_state_dict(ckpt["model_state_dict"])
    lstm.eval()

    X_scaled = scaler.transform(feat_df[feats].values)
    rf_probs = rf.predict_proba(X_scaled)[:, 1]
    knn_probs = knn.predict_proba(X_scaled)[:, 1]

    # Windows
    win_size = 10
    step_size = 1
    n_flows = len(X_scaled)
    win_labels = []
    win_times = []
    lstm_win_probs = []

    timestamps = pd.to_datetime(meta_df["Timestamp"]).values.astype("datetime64[ms]").astype(float) / 1000.0
    first_attack_time = float(np.min(timestamps[is_attack])) if n_attack > 0 else 0.0

    if n_flows >= win_size:
        wins = [X_scaled[i : i + win_size] for i in range(0, n_flows - win_size + 1, step_size)]
        wins_tensor = torch.from_numpy(np.array(wins, dtype=np.float32))
        with torch.no_grad():
            lstm_win_probs = torch.sigmoid(lstm(wins_tensor)).detach().cpu().numpy().flatten()

        for i in range(0, n_flows - win_size + 1, step_size):
            win_y = is_attack.iloc[i : i + win_size].values
            win_labels.append(bool(np.any(win_y)))
            win_times.append(timestamps[i + win_size - 1])

    # Evaluate each operating mode
    run_modes = {}
    for mode in ["zero_shot", "target_calibrated"]:
        rf_th = thresholds[f"rf_{mode}"]
        knn_th = thresholds[f"knn_{mode}"]
        lstm_th = thresholds[f"lstm_{mode}"]

        # (a) Flow-level rule (RF)
        rf_flagged = rf_probs >= rf_th
        rf_tp = int(np.sum(rf_flagged & is_attack))
        rf_fp = int(np.sum(rf_flagged & (~is_attack)))
        rf_recall = float(rf_tp / max(1, n_attack))
        rf_detected_times = timestamps[rf_flagged & is_attack]
        rf_delay = float(np.min(rf_detected_times) - first_attack_time) if len(rf_detected_times) > 0 else 0.0

        # (a) Flow-level rule (KNN)
        knn_flagged = knn_probs >= knn_th
        knn_tp = int(np.sum(knn_flagged & is_attack))
        knn_fp = int(np.sum(knn_flagged & (~is_attack)))
        knn_recall = float(knn_tp / max(1, n_attack))
        knn_detected_times = timestamps[knn_flagged & is_attack]
        knn_delay = float(np.min(knn_detected_times) - first_attack_time) if len(knn_detected_times) > 0 else 0.0

        # (b) Consecutive-window rule (K=2)
        consecutive_k = 2
        cw_alerts = []
        current_consec = 0
        for i, p in enumerate(lstm_win_probs):
            flag = bool(p >= lstm_th)
            if flag:
                current_consec += 1
                if current_consec >= consecutive_k:
                    cw_alerts.append((i, win_times[i], win_labels[i]))
            else:
                current_consec = 0

        cw_tp = sum(1 for _, _, has_atk in cw_alerts if has_atk)
        cw_fp = sum(1 for _, _, has_atk in cw_alerts if not has_atk)
        cw_recall = 1.0 if cw_tp > 0 else 0.0
        cw_atk_times = [t for _, t, has_atk in cw_alerts if has_atk]
        cw_delay = float(np.min(cw_atk_times) - first_attack_time) if cw_atk_times else 0.0

        # (c) Destination Aggregator
        # Monitored destination: 172.20.0.2
        aggregator = DestinationAggregator(
            time_bin_sec=10.0,
            anomaly_fraction_threshold=0.50,
            min_flows_per_bin=5,
            consecutive_windows=2,
            alert_only=True,
        )
        dest_alerts = []
        for i in range(n_flows):
            dst = str(meta_df["Destination IP"].iloc[i])
            t_flow = timestamps[i]
            is_anom = bool(rf_flagged[i])
            aggregator.record_flow(dst, is_anom, t_flow)
            alert = aggregator.evaluate_destination(dst, t_flow)
            if alert:
                dest_alerts.append((t_flow, is_attack.iloc[i]))

        dest_tp = sum(1 for _, is_atk in dest_alerts if is_atk)
        dest_fp = sum(1 for _, is_atk in dest_alerts if not is_atk)
        dest_recall = 1.0 if dest_tp > 0 else 0.0
        dest_atk_times = [t for t, is_atk in dest_alerts if is_atk]
        dest_delay = float(np.min(dest_atk_times) - first_attack_time) if dest_atk_times else 0.0

        run_modes[mode] = {
            "flow_rule_rf": {
                "threshold": round(rf_th, 4),
                "tp": rf_tp,
                "fp": rf_fp,
                "recall": round(rf_recall, 4),
                "false_alarms": rf_fp,
                "detection_delay_sec": round(max(0.0, rf_delay), 3),
            },
            "flow_rule_knn": {
                "threshold": round(knn_th, 4),
                "tp": knn_tp,
                "fp": knn_fp,
                "recall": round(knn_recall, 4),
                "false_alarms": knn_fp,
                "detection_delay_sec": round(max(0.0, knn_delay), 3),
            },
            "consecutive_window_rule": {
                "threshold": round(lstm_th, 4),
                "consecutive_k": consecutive_k,
                "total_windows": len(win_labels),
                "alerts_triggered": len(cw_alerts),
                "tp_alerts": cw_tp,
                "false_alarms": cw_fp,
                "recall": round(cw_recall, 4),
                "detection_delay_sec": round(max(0.0, cw_delay), 3),
            },
            "destination_aggregator": {
                "time_bin_sec": 10.0,
                "anomaly_fraction_threshold": 0.50,
                "consecutive_windows": 2,
                "alerts_triggered": len(dest_alerts),
                "tp_alerts": dest_tp,
                "false_alarms": dest_fp,
                "recall": round(dest_recall, 4),
                "detection_delay_sec": round(max(0.0, dest_delay), 3),
            },
        }

    return {
        "attack_type": attack_type,
        "rate_pps": rate_pps,
        "total_flows": len(meta_df),
        "attack_flows": n_attack,
        "benign_flows": n_benign,
        "attack_score_distribution": {
            "rf_min": float(np.min(rf_probs[is_attack])) if n_attack > 0 else 0.0,
            "rf_median": float(np.median(rf_probs[is_attack])) if n_attack > 0 else 0.0,
            "rf_max": float(np.max(rf_probs[is_attack])) if n_attack > 0 else 0.0,
            "knn_max": float(np.max(knn_probs[is_attack])) if n_attack > 0 else 0.0,
        },
        "zero_shot": run_modes["zero_shot"],
        "target_calibrated": run_modes["target_calibrated"],
    }


def main():
    thresholds = {
        "rf_zero_shot": 0.1288,
        "knn_zero_shot": 0.1268,
        "lstm_zero_shot": 0.9919,
        "rf_target_calibrated": 0.4036,
        "knn_target_calibrated": 0.2900,
        "lstm_target_calibrated": 0.1477,
    }

    all_results = {}
    for atk in ATTACK_TYPES:
        all_results[atk] = {}
        for r in TARGET_RATES:
            all_results[atk][str(r)] = evaluate_attack_run(atk, r, thresholds)

    out_file = Path("results/lab_attack_evaluation.json")
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w") as f:
        json.dump(all_results, f, indent=2)

    for mode in ["zero_shot", "target_calibrated"]:
        mode_label = "ZERO-SHOT (Validation Threshold)" if mode == "zero_shot" else "TARGET-CALIBRATED (Lab Idle Threshold)"
        print("\n" + "=" * 135)
        print(f"               ISOLATED LAB ATTACK EVALUATION SUMMARY: {mode_label}")
        print("=" * 135)
        hdr = (
            f"| {'Attack':<8} | {'Rate':<5} | {'Atk Flows':<9} | {'Benign':<6} | "
            f"{'RF Flow Rec':<11} | {'RF FA':<6} | {'RF Delay':<9} | "
            f"{'CW Rec':<8} | {'CW Delay':<8} | {'Dest Rec':<9} | {'Dest Delay':<10} |"
        )
        sep = f"|{'-'*10}|{'-'*7}|{'-'*11}|{'-'*8}|{'-'*13}|{'-'*8}|{'-'*11}|{'-'*10}|{'-'*10}|{'-'*11}|{'-'*12}|"
        print(hdr)
        print(sep)
        for atk, rates in all_results.items():
            for r_str, m in rates.items():
                m_sub = m[mode]
                rf_rec = f"{m_sub['flow_rule_rf']['recall']*100:.1f}%"
                rf_fa = str(m_sub['flow_rule_rf']['false_alarms'])
                rf_del = f"{m_sub['flow_rule_rf']['detection_delay_sec']:.2f}s"
                cw_rec = f"{m_sub['consecutive_window_rule']['recall']*100:.1f}%"
                cw_del = f"{m_sub['consecutive_window_rule']['detection_delay_sec']:.2f}s"
                dest_rec = f"{m_sub['destination_aggregator']['recall']*100:.1f}%"
                dest_del = f"{m_sub['destination_aggregator']['detection_delay_sec']:.2f}s"
                print(
                    f"| {atk.upper():<8} | {r_str:<5} | {m['attack_flows']:<9} | {m['benign_flows']:<6} | "
                    f"{rf_rec:<11} | {rf_fa:<6} | {rf_del:<9} | "
                    f"{cw_rec:<8} | {cw_del:<8} | {dest_rec:<9} | {dest_del:<12} |"
                )
        print(sep)


if __name__ == "__main__":
    main()
