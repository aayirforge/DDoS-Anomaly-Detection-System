"""Re-evaluate Lab Benign traffic, compute ROC-AUC vs Lab SYN-flood flows, and consolidate all metrics."""

from __future__ import annotations

import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score
import torch

from ddos_ads.config import load_config
from ddos_ads.features import load_selected_features
from ddos_ads.train_lstm import LSTMAnomalyClassifier


def make_windows(X: np.ndarray, win_size: int = 10, step_size: int = 1) -> np.ndarray:
    if len(X) < win_size:
        return np.empty((0, win_size, X.shape[1]), dtype=np.float32)
    return np.array([X[i : i + win_size] for i in range(0, len(X) - win_size + 1, step_size)], dtype=np.float32)


def get_win_aggs(p: np.ndarray, win_size: int = 10, step_size: int = 1) -> tuple[np.ndarray, np.ndarray]:
    if len(p) < win_size:
        return np.array([]), np.array([])
    mx = np.array([np.max(p[i : i + win_size]) for i in range(0, len(p) - win_size + 1, step_size)])
    mn = np.array([np.mean(p[i : i + win_size]) for i in range(0, len(p) - win_size + 1, step_size)])
    return mx, mn


def compute_roc_auc_safe(y_neg_scores: np.ndarray, y_pos_scores: np.ndarray) -> float:
    if len(y_neg_scores) == 0 or len(y_pos_scores) == 0:
        return 0.5
    y_true = np.concatenate([np.zeros(len(y_neg_scores)), np.ones(len(y_pos_scores))])
    y_scores = np.concatenate([y_neg_scores, y_pos_scores])
    # Handle cases where all scores are identical
    if len(np.unique(y_scores)) <= 1:
        return 0.5
    return float(roc_auc_score(y_true, y_scores))


def run_re_evaluation():
    config = load_config()
    feats = load_selected_features(config.get_path("models_dir") / "features.json")
    scaler = joblib.load(config.get_path("models_dir") / "scaler.joblib")
    rf = joblib.load(config.get_path("models_dir") / "rf.joblib")
    knn = joblib.load(config.get_path("models_dir") / "knn.joblib")

    ckpt = torch.load(config.get_path("models_dir") / "lstm.pt", map_location="cpu")
    lstm = LSTMAnomalyClassifier(ckpt["input_dim"], ckpt["hidden_dim"], ckpt["num_layers"], 0.0)
    lstm.load_state_dict(ckpt["model_state_dict"])
    lstm.eval()

    # Load Benign Data
    df_idle = pd.read_csv("lab/captures/lab_idle_aligned.csv")
    df_busy = pd.read_csv("lab/captures/lab_busy_aligned.csv")
    df_benign_combined = pd.concat([df_idle, df_busy], ignore_index=True)

    X_idle = scaler.transform(df_idle[feats].values)
    X_busy = scaler.transform(df_busy[feats].values)
    X_benign = scaler.transform(df_benign_combined[feats].values)

    # Load SYN Flood Data
    syn_dfs = [pd.read_csv(f"lab/captures/attack_syn_{r}_aligned.csv") for r in [50, 200, 500]]
    df_syn_all = pd.concat(syn_dfs, ignore_index=True)
    syn_mask = (df_syn_all["Source IP"] == "172.20.0.4") | (df_syn_all["Destination IP"] == "172.20.0.4")
    df_syn_atk = df_syn_all[syn_mask]

    X_syn_atk = scaler.transform(df_syn_atk[feats].values)

    # Predictions: Flow
    rf_idle_p = rf.predict_proba(X_idle)[:, 1]
    rf_busy_p = rf.predict_proba(X_busy)[:, 1]
    rf_benign_p = rf.predict_proba(X_benign)[:, 1]
    rf_syn_p = rf.predict_proba(X_syn_atk)[:, 1]

    # KNN batch prediction
    bs = 50000
    def predict_knn_batch(X_mat):
        res = []
        for i in range(0, len(X_mat), bs):
            res.append(knn.predict_proba(X_mat[i : i + bs])[:, 1])
        return np.concatenate(res) if res else np.array([])

    knn_idle_p = predict_knn_batch(X_idle)
    knn_busy_p = predict_knn_batch(X_busy)
    knn_benign_p = predict_knn_batch(X_benign)
    knn_syn_p = predict_knn_batch(X_syn_atk)

    # Windows
    half_idle = len(df_idle) // 2
    w_idle_cal = make_windows(X_idle[:half_idle])
    w_idle_eval = make_windows(X_idle[half_idle:])
    w_idle_all = make_windows(X_idle)
    w_busy = make_windows(X_busy)
    w_benign = make_windows(X_benign)
    w_syn = make_windows(X_syn_atk)

    def predict_lstm_batch(W_mat):
        if len(W_mat) == 0:
            return np.array([])
        res = []
        with torch.no_grad():
            for i in range(0, len(W_mat), 2048):
                res.append(torch.sigmoid(lstm(torch.from_numpy(W_mat[i : i + 2048]))).detach().cpu().numpy().flatten())
        return np.concatenate(res)

    lstm_idle_cal_p = predict_lstm_batch(w_idle_cal)
    lstm_idle_eval_p = predict_lstm_batch(w_idle_eval)
    lstm_idle_all_p = predict_lstm_batch(w_idle_all)
    lstm_busy_p = predict_lstm_batch(w_busy)
    lstm_benign_p = predict_lstm_batch(w_benign)
    lstm_syn_p = predict_lstm_batch(w_syn)

    # Window Aggregations
    rf_mx_i_cal, rf_mn_i_cal = get_win_aggs(rf_idle_p[:half_idle])
    rf_mx_i_eval, rf_mn_i_eval = get_win_aggs(rf_idle_p[half_idle:])
    rf_mx_i, rf_mn_i = get_win_aggs(rf_idle_p)
    rf_mx_b, rf_mn_b = get_win_aggs(rf_busy_p)
    rf_mx_all, rf_mn_all = get_win_aggs(rf_benign_p)
    rf_mx_syn, rf_mn_syn = get_win_aggs(rf_syn_p)

    knn_mx_i_cal, knn_mn_i_cal = get_win_aggs(knn_idle_p[:half_idle])
    knn_mx_i_eval, knn_mn_i_eval = get_win_aggs(knn_idle_p[half_idle:])
    knn_mx_i, knn_mn_i = get_win_aggs(knn_idle_p)
    knn_mx_b, knn_mn_b = get_win_aggs(knn_busy_p)
    knn_mx_all, knn_mn_all = get_win_aggs(knn_benign_p)
    knn_mx_syn, knn_mn_syn = get_win_aggs(knn_syn_p)

    # Model evaluation dict
    model_defs = {
        "Random Forest (Flow)": {
            "type": "flow",
            "val_threshold": 0.1288,
            "cal_scores": rf_idle_p[:half_idle],
            "eval_idle_scores": rf_idle_p[half_idle:],
            "idle_all_scores": rf_idle_p,
            "busy_scores": rf_busy_p,
            "benign_all_scores": rf_benign_p,
            "syn_scores": rf_syn_p,
        },
        "KNN (Flow)": {
            "type": "flow",
            "val_threshold": 0.1268,
            "cal_scores": knn_idle_p[:half_idle],
            "eval_idle_scores": knn_idle_p[half_idle:],
            "idle_all_scores": knn_idle_p,
            "busy_scores": knn_busy_p,
            "benign_all_scores": knn_benign_p,
            "syn_scores": knn_syn_p,
        },
        "LSTM (Window)": {
            "type": "window",
            "val_threshold": 0.9919,
            "cal_scores": lstm_idle_cal_p,
            "eval_idle_scores": lstm_idle_eval_p,
            "idle_all_scores": lstm_idle_all_p,
            "busy_scores": lstm_busy_p,
            "benign_all_scores": lstm_benign_p,
            "syn_scores": lstm_syn_p,
        },
        "RF Window-Max": {
            "type": "window",
            "val_threshold": 0.1288,
            "cal_scores": rf_mx_i_cal,
            "eval_idle_scores": rf_mx_i_eval,
            "idle_all_scores": rf_mx_i,
            "busy_scores": rf_mx_b,
            "benign_all_scores": rf_mx_all,
            "syn_scores": rf_mx_syn,
        },
        "RF Window-Mean": {
            "type": "window",
            "val_threshold": 0.1288,
            "cal_scores": rf_mn_i_cal,
            "eval_idle_scores": rf_mn_i_eval,
            "idle_all_scores": rf_mn_i,
            "busy_scores": rf_mn_b,
            "benign_all_scores": rf_mn_all,
            "syn_scores": rf_mn_syn,
        },
        "KNN Window-Mean": {
            "type": "window",
            "val_threshold": 0.1268,
            "cal_scores": knn_mn_i_cal,
            "eval_idle_scores": knn_mn_i_eval,
            "idle_all_scores": knn_mn_i,
            "busy_scores": knn_mn_b,
            "benign_all_scores": knn_mn_all,
            "syn_scores": knn_mn_syn,
        },
        "KNN Window-Max": {
            "type": "window",
            "val_threshold": 0.1268,
            "cal_scores": knn_mx_i_cal,
            "eval_idle_scores": knn_mx_i_eval,
            "idle_all_scores": knn_mx_i,
            "busy_scores": knn_mx_b,
            "benign_all_scores": knn_mx_all,
            "syn_scores": knn_mx_syn,
        },
    }

    benign_results = {}
    roc_results = {}

    for name, m in model_defs.items():
        v_th = m["val_threshold"]
        c_th = float(np.percentile(m["cal_scores"], 99.0))

        # Zero-shot
        zs_i_fp = int(np.sum(m["idle_all_scores"] >= v_th))
        zs_i_tot = len(m["idle_all_scores"])
        zs_i_fpr = float(zs_i_fp / max(1, zs_i_tot))

        zs_b_fp = int(np.sum(m["busy_scores"] >= v_th))
        zs_b_tot = len(m["busy_scores"])
        zs_b_fpr = float(zs_b_fp / max(1, zs_b_tot))

        # Target-calibrated
        cal_i_fp = int(np.sum(m["eval_idle_scores"] >= c_th))
        cal_i_tot = len(m["eval_idle_scores"])
        cal_i_fpr = float(cal_i_fp / max(1, cal_i_tot))

        cal_b_fp = int(np.sum(m["busy_scores"] >= c_th))
        cal_b_tot = len(m["busy_scores"])
        cal_b_fpr = float(cal_b_fp / max(1, cal_b_tot))

        benign_results[name] = {
            "model_type": m["type"],
            "val_threshold": round(v_th, 4),
            "cal_threshold": round(c_th, 4),
            "zero_shot": {
                "idle": {"total": zs_i_tot, "fp": zs_i_fp, "fpr": round(zs_i_fpr, 4)},
                "busy": {"total": zs_b_tot, "fp": zs_b_fp, "fpr": round(zs_b_fpr, 4)},
            },
            "target_calibrated": {
                "cal_set_size": len(m["cal_scores"]),
                "eval_idle_2nd_half": {"total": cal_i_tot, "fp": cal_i_fp, "fpr": round(cal_i_fpr, 4)},
                "busy": {"total": cal_b_tot, "fp": cal_b_fp, "fpr": round(cal_b_fpr, 4)},
            },
        }

        # ROC-AUC vs Lab SYN-flood flows
        auc_vs_idle = compute_roc_auc_safe(m["idle_all_scores"], m["syn_scores"])
        auc_vs_busy = compute_roc_auc_safe(m["busy_scores"], m["syn_scores"])
        auc_vs_combined = compute_roc_auc_safe(m["benign_all_scores"], m["syn_scores"])

        roc_results[name] = {
            "roc_auc_vs_idle": round(auc_vs_idle, 4),
            "roc_auc_vs_busy": round(auc_vs_busy, 4),
            "roc_auc_vs_combined_benign": round(auc_vs_combined, 4),
            "syn_sample_size": len(m["syn_scores"]),
            "benign_sample_size": len(m["benign_all_scores"]),
        }

    return benign_results, roc_results


def main():
    benign_results, roc_results = run_re_evaluation()

    # Save to lab_re_evaluation.json
    out_data = {
        "lab_benign_re_evaluation": benign_results,
        "roc_auc_vs_lab_syn_flood": roc_results,
    }
    out_file = Path("results/lab_re_evaluation.json")
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w") as fp:
        json.dump(out_data, fp, indent=2)

    # Update consolidated results/lab_metrics.json
    lab_metrics_file = Path("results/lab_metrics.json")
    if lab_metrics_file.is_file():
        with open(lab_metrics_file) as f:
            lm = json.load(f)
        lm["benign_re_evaluation"] = benign_results
        lm["roc_auc_vs_lab_syn_flood"] = roc_results
        with open(lab_metrics_file, "w") as f:
            json.dump(lm, f, indent=2)

    # Print Benign Evaluation Table
    print("\n" + "=" * 135)
    print("                     RE-EVALUATED LAB BENIGN FALSE POSITIVE RATE (FPR) BENCHMARKS")
    print("=" * 135)
    hdr = f"| {'Model':<22} | {'Val Thresh':<10} | {'ZS Idle FPR':<18} | {'ZS Busy FPR':<18} | {'Cal Thresh':<10} | {'Cal Idle FPR (2nd Half)':<24} | {'Cal Busy FPR':<18} |"
    sep = f"|{'-'*24}|{'-'*12}|{'-'*20}|{'-'*20}|{'-'*12}|{'-'*26}|{'-'*20}|"
    print(hdr)
    print(sep)
    for m_name, d in benign_results.items():
        v_th = d["val_threshold"]
        c_th = d["cal_threshold"]
        zs_i = f"{d['zero_shot']['idle']['fpr']*100:>5.2f}% ({d['zero_shot']['idle']['fp']}/{d['zero_shot']['idle']['total']})"
        zs_b = f"{d['zero_shot']['busy']['fpr']*100:>5.2f}% ({d['zero_shot']['busy']['fp']}/{d['zero_shot']['busy']['total']})"
        cal_i = f"{d['target_calibrated']['eval_idle_2nd_half']['fpr']*100:>5.2f}% ({d['target_calibrated']['eval_idle_2nd_half']['fp']}/{d['target_calibrated']['eval_idle_2nd_half']['total']})"
        cal_b = f"{d['target_calibrated']['busy']['fpr']*100:>5.2f}% ({d['target_calibrated']['busy']['fp']}/{d['target_calibrated']['busy']['total']})"
        print(f"| {m_name:<22} | {v_th:<10.4f} | {zs_i:<18} | {zs_b:<18} | {c_th:<10.4f} | {cal_i:<24} | {cal_b:<18} |")
    print(sep)

    # Print ROC-AUC Table
    print("\n" + "=" * 115)
    print("                 ROC-AUC PERFORMANCE: LAB BENIGN vs LAB SYN-FLOOD FLOWS PER MODEL")
    print("=" * 115)
    hdr_roc = f"| {'Model':<22} | {'Model Type':<11} | {'ROC-AUC (vs Idle)':<18} | {'ROC-AUC (vs Busy)':<18} | {'ROC-AUC (vs Combined)':<22} |"
    sep_roc = f"|{'-'*24}|{'-'*13}|{'-'*20}|{'-'*20}|{'-'*24}|"
    print(hdr_roc)
    print(sep_roc)
    for m_name, r in roc_results.items():
        m_type = benign_results[m_name]["model_type"]
        print(f"| {m_name:<22} | {m_type:<11} | {r['roc_auc_vs_idle']:<18.4f} | {r['roc_auc_vs_busy']:<18.4f} | {r['roc_auc_vs_combined_benign']:<22.4f} |")
    print(sep_roc)
    print("=" * 115 + "\n")


if __name__ == "__main__":
    main()
