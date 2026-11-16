"""Score lab benign flows with RF, KNN, and LSTM-window under Zero-Shot and Target-Calibrated protocols."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Tuple
import joblib
import numpy as np
import pandas as pd
import torch

from ddos_ads.config import load_config
from ddos_ads.features import load_selected_features, build_lstm_windows
from ddos_ads.train_lstm import LSTMAnomalyClassifier


IAT_FEATURES = [
    "Bwd IAT Total",
    "Bwd IAT Min",
    "Bwd IAT Max",
    "Bwd IAT Mean",
]


def load_and_prepare_flows(scale_iat_to_us: bool = False):
    config = load_config()
    feats = load_selected_features(config.get_path("models_dir") / "features.json")
    scaler = joblib.load(config.get_path("models_dir") / "scaler.joblib")

    df_idle = pd.read_csv("lab/captures/lab_idle_aligned.csv")
    df_busy = pd.read_csv("lab/captures/lab_busy_aligned.csv")

    if scale_iat_to_us:
        for f in IAT_FEATURES:
            if f in df_idle.columns:
                df_idle[f] = df_idle[f] * 1e6
            if f in df_busy.columns:
                df_busy[f] = df_busy[f] * 1e6

    X_idle_raw = df_idle[feats].values
    X_busy_raw = df_busy[feats].values

    X_idle_scaled = scaler.transform(X_idle_raw)
    X_busy_scaled = scaler.transform(X_busy_raw)

    return feats, scaler, df_idle, df_busy, X_idle_scaled, X_busy_scaled


def evaluate_models_on_benign(scale_iat_to_us: bool = False) -> Dict:
    feats, scaler, df_idle, df_busy, X_idle, X_busy = load_and_prepare_flows(scale_iat_to_us)
    config = load_config()
    models_dir = config.get_path("models_dir")

    # Load validation thresholds from results/metrics.json
    with open("results/metrics.json") as f:
        metrics_all = json.load(f)

    rf_thresh_val = metrics_all.get("Random Forest (Same-Day Zero-Shot)", {}).get("threshold", 0.1288)
    knn_thresh_val = metrics_all.get("KNN (Same-Day Zero-Shot)", {}).get("threshold", 0.1268)
    lstm_thresh_val = metrics_all.get("LSTM (Same-Day Zero-Shot)", {}).get("threshold", 0.9919)

    # 1. Flow-level Models: RF & KNN
    rf = joblib.load(models_dir / "rf.joblib")
    knn = joblib.load(models_dir / "knn.joblib")

    rf_idle_probs = rf.predict_proba(X_idle)[:, 1]
    rf_busy_probs = rf.predict_proba(X_busy)[:, 1]

    # KNN batch prediction
    bs = 50000
    knn_busy_probs_list = []
    for i in range(0, len(X_busy), bs):
        knn_busy_probs_list.append(knn.predict_proba(X_busy[i : i + bs])[:, 1])
    knn_busy_probs = np.concatenate(knn_busy_probs_list)
    knn_idle_probs = knn.predict_proba(X_idle)[:, 1]

    # 2. Window-level LSTM
    ckpt = torch.load(models_dir / "lstm.pt", map_location="cpu")
    lstm_model = LSTMAnomalyClassifier(ckpt["input_dim"], ckpt["hidden_dim"], ckpt["num_layers"], 0.0)
    lstm_model.load_state_dict(ckpt["model_state_dict"])
    lstm_model.eval()

    # Build windows with step=1 for detailed evaluation
    # Split idle chronologically in half
    n_idle_flows = len(X_idle)
    half_idle = n_idle_flows // 2

    X_idle_first_half = X_idle[:half_idle]
    X_idle_second_half = X_idle[half_idle:]

    # Window creation
    win_size = 10
    step_size = 1

    def make_windows(X_arr):
        if len(X_arr) < win_size:
            return np.empty((0, win_size, X_arr.shape[1]), dtype=np.float32)
        wins = [X_arr[i : i + win_size] for i in range(0, len(X_arr) - win_size + 1, step_size)]
        return np.array(wins, dtype=np.float32)

    wins_idle_all = make_windows(X_idle)
    wins_idle_cal = make_windows(X_idle_first_half)
    wins_idle_eval = make_windows(X_idle_second_half)
    wins_busy = make_windows(X_busy)

    with torch.no_grad():
        lstm_idle_cal_probs = torch.sigmoid(lstm_model(torch.from_numpy(wins_idle_cal))).detach().cpu().numpy().flatten()
        lstm_idle_eval_probs = torch.sigmoid(lstm_model(torch.from_numpy(wins_idle_eval))).detach().cpu().numpy().flatten()
        lstm_idle_all_probs = torch.sigmoid(lstm_model(torch.from_numpy(wins_idle_all))).detach().cpu().numpy().flatten()

        # Batch LSTM busy
        lstm_busy_chunks = []
        for i in range(0, len(wins_busy), 2048):
            chunk = torch.from_numpy(wins_busy[i : i + 2048])
            lstm_busy_chunks.append(torch.sigmoid(lstm_model(chunk)).detach().cpu().numpy().flatten())
        lstm_busy_probs = np.concatenate(lstm_busy_chunks) if lstm_busy_chunks else np.array([])

    # Compute Window-Aggregated RF and KNN
    def compute_win_aggs(probs_arr, n_total_flows):
        # probs for each flow, aggregate over sliding windows
        if n_total_flows < win_size:
            return np.array([]), np.array([])
        max_scores = []
        mean_scores = []
        for i in range(0, n_total_flows - win_size + 1, step_size):
            win_p = probs_arr[i : i + win_size]
            max_scores.append(float(np.max(win_p)))
            mean_scores.append(float(np.mean(win_p)))
        return np.array(max_scores), np.array(mean_scores)

    rf_win_idle_cal_max, rf_win_idle_cal_mean = compute_win_aggs(rf_idle_probs[:half_idle], half_idle)
    rf_win_idle_eval_max, rf_win_idle_eval_mean = compute_win_aggs(rf_idle_probs[half_idle:], n_idle_flows - half_idle)
    rf_win_busy_max, rf_win_busy_mean = compute_win_aggs(rf_busy_probs, len(rf_busy_probs))

    knn_win_idle_cal_max, knn_win_idle_cal_mean = compute_win_aggs(knn_idle_probs[:half_idle], half_idle)
    knn_win_idle_eval_max, knn_win_idle_eval_mean = compute_win_aggs(knn_idle_probs[half_idle:], n_idle_flows - half_idle)
    knn_win_busy_max, knn_win_busy_mean = compute_win_aggs(knn_busy_probs, len(knn_busy_probs))

    # Target Calibration (on first half of idle capture, max FPR <= 1.0%)
    # Calibrated threshold = 99th percentile of scores on calibration set
    def get_cal_thresh(scores_cal: np.ndarray) -> float:
        if len(scores_cal) == 0:
            return 1.0
        return float(np.percentile(scores_cal, 99.0))

    rf_cal_thresh = get_cal_thresh(rf_idle_probs[:half_idle])
    knn_cal_thresh = get_cal_thresh(knn_idle_probs[:half_idle])
    lstm_cal_thresh = get_cal_thresh(lstm_idle_cal_probs)

    models_eval = {
        "Random Forest (Flow)": {
            "type": "flow",
            "val_threshold": rf_thresh_val,
            "cal_threshold": rf_cal_thresh,
            "cal_scores": rf_idle_probs[:half_idle],
            "eval_idle_scores": rf_idle_probs[half_idle:],
            "idle_all_scores": rf_idle_probs,
            "busy_scores": rf_busy_probs,
        },
        "KNN (Flow)": {
            "type": "flow",
            "val_threshold": knn_thresh_val,
            "cal_threshold": knn_cal_thresh,
            "cal_scores": knn_idle_probs[:half_idle],
            "eval_idle_scores": knn_idle_probs[half_idle:],
            "idle_all_scores": knn_idle_probs,
            "busy_scores": knn_busy_probs,
        },
        "LSTM (Window)": {
            "type": "window",
            "val_threshold": lstm_thresh_val,
            "cal_threshold": lstm_cal_thresh,
            "cal_scores": lstm_idle_cal_probs,
            "eval_idle_scores": lstm_idle_eval_probs,
            "idle_all_scores": lstm_idle_all_probs,
            "busy_scores": lstm_busy_probs,
        },
        "RF Window-Max": {
            "type": "window",
            "val_threshold": rf_thresh_val,
            "cal_threshold": get_cal_thresh(rf_win_idle_cal_max),
            "cal_scores": rf_win_idle_cal_max,
            "eval_idle_scores": rf_win_idle_eval_max,
            "idle_all_scores": compute_win_aggs(rf_idle_probs, len(rf_idle_probs))[0],
            "busy_scores": rf_win_busy_max,
        },
        "RF Window-Mean": {
            "type": "window",
            "val_threshold": rf_thresh_val,
            "cal_threshold": get_cal_thresh(rf_win_idle_cal_mean),
            "cal_scores": rf_win_idle_cal_mean,
            "eval_idle_scores": rf_win_idle_eval_mean,
            "idle_all_scores": compute_win_aggs(rf_idle_probs, len(rf_idle_probs))[1],
            "busy_scores": rf_win_busy_mean,
        },
        "KNN Window-Mean": {
            "type": "window",
            "val_threshold": knn_thresh_val,
            "cal_threshold": get_cal_thresh(knn_win_idle_cal_mean),
            "cal_scores": knn_win_idle_cal_mean,
            "eval_idle_scores": knn_win_idle_eval_mean,
            "idle_all_scores": compute_win_aggs(knn_idle_probs, len(knn_idle_probs))[1],
            "busy_scores": knn_win_busy_mean,
        },
    }

    results = {}
    for name, m in models_eval.items():
        v_th = m["val_threshold"]
        c_th = m["cal_threshold"]

        # Zero-shot FPR
        zs_idle_fp = int(np.sum(m["idle_all_scores"] >= v_th))
        zs_idle_total = len(m["idle_all_scores"])
        zs_idle_fpr = float(zs_idle_fp / max(1, zs_idle_total))

        zs_busy_fp = int(np.sum(m["busy_scores"] >= v_th))
        zs_busy_total = len(m["busy_scores"])
        zs_busy_fpr = float(zs_busy_fp / max(1, zs_busy_total))

        # Target-calibrated FPR
        # Evaluate on second half of idle
        cal_eval_idle_fp = int(np.sum(m["eval_idle_scores"] >= c_th))
        cal_eval_idle_total = len(m["eval_idle_scores"])
        cal_eval_idle_fpr = float(cal_eval_idle_fp / max(1, cal_eval_idle_total))

        # Evaluate on busy capture
        cal_busy_fp = int(np.sum(m["busy_scores"] >= c_th))
        cal_busy_total = len(m["busy_scores"])
        cal_busy_fpr = float(cal_busy_fp / max(1, cal_busy_total))

        results[name] = {
            "model_type": m["type"],
            "val_threshold": round(v_th, 4),
            "cal_threshold": round(c_th, 4),
            "zero_shot": {
                "idle": {
                    "total": zs_idle_total,
                    "false_positives": zs_idle_fp,
                    "fpr": round(zs_idle_fpr, 4),
                },
                "busy": {
                    "total": zs_busy_total,
                    "false_positives": zs_busy_fp,
                    "fpr": round(zs_busy_fpr, 4),
                },
            },
            "target_calibrated": {
                "cal_set_size": len(m["cal_scores"]),
                "eval_idle_2nd_half": {
                    "total": cal_eval_idle_total,
                    "false_positives": cal_eval_idle_fp,
                    "fpr": round(cal_eval_idle_fpr, 4),
                },
                "busy": {
                    "total": cal_busy_total,
                    "false_positives": cal_busy_fp,
                    "fpr": round(cal_busy_fpr, 4),
                },
            },
        }

    return results


def main():
    print("\n--- Evaluating Models with Raw cicflowmeter Units ---")
    raw_results = evaluate_models_on_benign(scale_iat_to_us=False)

    print("\n--- Evaluating Models with Microsecond-Aligned IAT Units (x10^6) ---")
    aligned_results = evaluate_models_on_benign(scale_iat_to_us=True)

    summary_output = {
        "raw_units": raw_results,
        "aligned_iat_units": aligned_results,
    }

    out_file = Path("results/lab_benign_evaluation.json")
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w") as f:
        json.dump(summary_output, f, indent=2)

    for mode_name, res in [("RAW cicflowmeter Units", raw_results), ("MICROSECOND-ALIGNED IAT Units", aligned_results)]:
        print("\n" + "=" * 125)
        print(f"               LAB BENIGN EVALUATION RESULTS ({mode_name})")
        print("=" * 125)
        hdr = f"| {'Model':<20} | {'Val Thresh':<10} | {'ZS Idle FPR':<12} | {'ZS Busy FPR':<12} | {'Cal Thresh':<10} | {'Cal Idle FPR':<14} | {'Cal Busy FPR':<14} |"
        sep = f"|{'-'*22}|{'-'*12}|{'-'*14}|{'-'*14}|{'-'*12}|{'-'*16}|{'-'*16}|"
        print(hdr)
        print(sep)
        for m_name, d in res.items():
            v_th = d["val_threshold"]
            c_th = d["cal_threshold"]
            zs_i = f"{d['zero_shot']['idle']['fpr']*100:.2f}% ({d['zero_shot']['idle']['false_positives']}/{d['zero_shot']['idle']['total']})"
            zs_b = f"{d['zero_shot']['busy']['fpr']*100:.2f}% ({d['zero_shot']['busy']['false_positives']}/{d['zero_shot']['busy']['total']})"
            cal_i = f"{d['target_calibrated']['eval_idle_2nd_half']['fpr']*100:.2f}% ({d['target_calibrated']['eval_idle_2nd_half']['false_positives']}/{d['target_calibrated']['eval_idle_2nd_half']['total']})"
            cal_b = f"{d['target_calibrated']['busy']['fpr']*100:.2f}% ({d['target_calibrated']['busy']['false_positives']}/{d['target_calibrated']['busy']['total']})"
            print(f"| {m_name:<20} | {v_th:<10.4f} | {zs_i:<12} | {zs_b:<12} | {c_th:<10.4f} | {cal_i:<14} | {cal_b:<14} |")
        print(sep)


if __name__ == "__main__":
    main()
