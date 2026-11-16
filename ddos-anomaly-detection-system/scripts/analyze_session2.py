"""Comprehensive evaluation of Session 2 (TSO/GSO disabled, tc netem 5ms/1ms jitter)."""

from __future__ import annotations

import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score
import scipy.stats
import torch

from ddos_ads.config import load_config
from ddos_ads.features import load_selected_features
from ddos_ads.train_lstm import LSTMAnomalyClassifier


def make_windows(X: np.ndarray, win_size: int = 10, step_size: int = 1) -> np.ndarray:
    if len(X) < win_size:
        return np.empty((0, win_size, X.shape[1]), dtype=np.float32)
    return np.array([X[i : i + win_size] for i in range(0, len(X) - win_size + 1, step_size)], dtype=np.float32)


def get_window_stats(X_win: np.ndarray) -> np.ndarray:
    if len(X_win) == 0:
        return np.empty((0, 50), dtype=np.float32)
    m = np.mean(X_win, axis=1)
    s = np.std(X_win, axis=1)
    return np.hstack([m, s])


def compute_roc_auc_safe(neg_scores: np.ndarray, pos_scores: np.ndarray) -> float:
    if len(neg_scores) == 0 or len(pos_scores) == 0:
        return 0.5
    y_true = np.concatenate([np.zeros(len(neg_scores)), np.ones(len(pos_scores))])
    y_scores = np.concatenate([neg_scores, pos_scores])
    if len(np.unique(y_scores)) <= 1:
        return 0.5
    return float(roc_auc_score(y_true, y_scores))


def main():
    config = load_config()
    feats = load_selected_features(config.get_path("models_dir") / "features.json")
    scaler = joblib.load(config.get_path("models_dir") / "scaler.joblib")
    rf = joblib.load(config.get_path("models_dir") / "rf.joblib")
    knn = joblib.load(config.get_path("models_dir") / "knn.joblib")

    # Load LSTM checkpoint
    ckpt = torch.load(config.get_path("models_dir") / "lstm.pt", map_location="cpu")
    lstm = LSTMAnomalyClassifier(ckpt["input_dim"], ckpt["hidden_dim"], ckpt["num_layers"], 0.0)
    lstm.load_state_dict(ckpt["model_state_dict"])
    lstm.eval()

    # Load Train & Day 2 (unscaled)
    df_train = pd.read_parquet(config.get_path("processed_data_dir") / "train.parquet")
    train_b = pd.DataFrame(scaler.inverse_transform(df_train[df_train["Label_Binary"] == 0][feats].values), columns=feats)

    df_cross = pd.read_parquet(config.get_path("processed_data_dir") / "test_cross_day.parquet")
    cross_b = pd.DataFrame(scaler.inverse_transform(df_cross[df_cross["Label_Binary"] == 0][feats].values), columns=feats)

    # Load Session 2
    df_idle2 = pd.read_csv("lab/captures/session2/lab_idle_aligned.csv")
    df_busy2 = pd.read_csv("lab/captures/session2/lab_busy_aligned.csv")
    df_lab2 = pd.concat([df_idle2, df_busy2], ignore_index=True)

    df_syn2_raw = pd.read_csv("lab/captures/session2/lab_syn_flood_aligned.csv")
    syn2_mask = (df_syn2_raw["Source IP"] == "172.20.0.3") | (df_syn2_raw["Destination IP"] == "172.20.0.3")
    df_syn2 = df_syn2_raw[syn2_mask]

    # Session 2 strict feature comparison
    tol = 1e-4
    s2_features = {}
    for f in feats:
        lab_v = df_lab2[f].to_numpy(dtype=float)
        tr_v = train_b[f].to_numpy(dtype=float)
        d2_v = cross_b[f].to_numpy(dtype=float)

        lab_p5, lab_p50, lab_p95 = float(np.percentile(lab_v, 5)), float(np.percentile(lab_v, 50)), float(np.percentile(lab_v, 95))
        tr_p5, tr_p50, tr_p95 = float(np.percentile(tr_v, 5)), float(np.percentile(tr_v, 50)), float(np.percentile(tr_v, 95))
        d2_p5, d2_p50, d2_p95 = float(np.percentile(d2_v, 5)), float(np.percentile(d2_v, 50)), float(np.percentile(d2_v, 95))

        tr_overlap = bool(min(lab_p95, tr_p95) + tol >= max(lab_p5, tr_p5))
        d2_overlap = bool(min(lab_p95, d2_p95) + tol >= max(lab_p5, d2_p5))

        tr_unique = np.unique(np.round(tr_v, 4))
        lab_unique = np.unique(np.round(lab_v, 4))
        is_tr_binary = bool(set(tr_unique).issubset({0.0, 1.0, -0.0}))
        is_lab_binary = bool(set(lab_unique).issubset({0.0, 1.0}))
        binary_mismatch = bool(is_tr_binary != is_lab_binary)

        ks_tr = float(scipy.stats.ks_2samp(lab_v, tr_v).statistic)
        ks_d2 = float(scipy.stats.ks_2samp(lab_v, d2_v).statistic)

        if binary_mismatch:
            status = "MISMATCH"
        elif not tr_overlap and not d2_overlap:
            status = "DISJOINT"
        elif ks_tr >= 0.70 and ks_d2 >= 0.70:
            status = "HIGH_SHIFT"
        elif ks_tr >= 0.35 or ks_d2 >= 0.35:
            status = "MOD_SHIFT"
        else:
            status = "ALIGNED"

        s2_features[f] = {
            "train_p5": tr_p5, "train_p95": tr_p95,
            "day2_p5": d2_p5, "day2_p95": d2_p95,
            "lab_p5": lab_p5, "lab_p50": lab_p50, "lab_p95": lab_p95,
            "tr_overlap": tr_overlap, "d2_overlap": d2_overlap,
            "ks_train": round(ks_tr, 4), "ks_day2": round(ks_d2, 4),
            "binary_mismatch": binary_mismatch, "status": status,
        }

    # Session 2 ROC-AUC
    X_i2 = scaler.transform(df_idle2[feats].values)
    X_b2 = scaler.transform(df_busy2[feats].values)
    X_all2 = scaler.transform(df_lab2[feats].values)
    X_syn2 = scaler.transform(df_syn2[feats].values)

    w_i2 = make_windows(X_i2)
    w_b2 = make_windows(X_b2)
    w_all2 = make_windows(X_all2)
    w_syn2 = make_windows(X_syn2)

    # LSTM Logits
    def get_logits(W_mat):
        res = []
        with torch.no_grad():
            for i in range(0, len(W_mat), 2048):
                res.append(lstm(torch.from_numpy(W_mat[i : i + 2048])).detach().cpu().numpy().flatten())
        return np.concatenate(res) if res else np.array([])

    l_i2 = get_logits(w_i2)
    l_b2 = get_logits(w_b2)
    l_all2 = get_logits(w_all2)
    l_syn2 = get_logits(w_syn2)

    lstm_auc_i = compute_roc_auc_safe(l_i2, l_syn2)
    lstm_auc_b = compute_roc_auc_safe(l_b2, l_syn2)
    lstm_auc_all = compute_roc_auc_safe(l_all2, l_syn2)

    # Window stats LR
    processed_dir = config.get_path("processed_data_dir")
    train_npz = np.load(processed_dir / "lstm_train.npz")
    stats_scaler = StandardScaler()
    X_tr_stats = stats_scaler.fit_transform(get_window_stats(train_npz["X"]))
    lr = LogisticRegression(max_iter=1000, random_state=42)
    lr.fit(X_tr_stats, train_npz["y"].astype(int))

    lr_st_i2 = stats_scaler.transform(get_window_stats(w_i2))
    lr_st_b2 = stats_scaler.transform(get_window_stats(w_b2))
    lr_st_all2 = stats_scaler.transform(get_window_stats(w_all2))
    lr_st_syn2 = stats_scaler.transform(get_window_stats(w_syn2))

    lr_log_i = lr.decision_function(lr_st_i2)
    lr_log_b = lr.decision_function(lr_st_b2)
    lr_log_all = lr.decision_function(lr_st_all2)
    lr_log_syn = lr.decision_function(lr_st_syn2)

    lr_auc_i = compute_roc_auc_safe(lr_log_i, lr_log_syn)
    lr_auc_b = compute_roc_auc_safe(lr_log_b, lr_log_syn)
    lr_auc_all = compute_roc_auc_safe(lr_log_all, lr_log_syn)

    # RF & KNN flow
    rf_p_i = rf.predict_proba(X_i2)[:, 1]
    rf_p_b = rf.predict_proba(X_b2)[:, 1]
    rf_p_all = rf.predict_proba(X_all2)[:, 1]
    rf_p_syn = rf.predict_proba(X_syn2)[:, 1]

    rf_auc_i = compute_roc_auc_safe(rf_p_i, rf_p_syn)
    rf_auc_b = compute_roc_auc_safe(rf_p_b, rf_p_syn)
    rf_auc_all = compute_roc_auc_safe(rf_p_all, rf_p_syn)

    bs = 50000
    def p_knn(X):
        r = [knn.predict_proba(X[i:i+bs])[:, 1] for i in range(0, len(X), bs)]
        return np.concatenate(r) if r else np.array([])

    knn_p_i = p_knn(X_i2)
    knn_p_b = p_knn(X_b2)
    knn_p_all = p_knn(X_all2)
    knn_p_syn = p_knn(X_syn2)

    knn_auc_i = compute_roc_auc_safe(knn_p_i, knn_p_syn)
    knn_auc_b = compute_roc_auc_safe(knn_p_b, knn_p_syn)
    knn_auc_all = compute_roc_auc_safe(knn_p_all, knn_p_syn)

    s2_summary = {
        "network_parameters": {
            "mtu": 1500,
            "tso_gso_gro": "disabled",
            "tc_netem": "delay 5ms jitter 1ms",
            "max_packet_length_observed": 1514,
        },
        "sample_sizes": {
            "idle_flows": len(df_idle2),
            "busy_flows": len(df_busy2),
            "total_benign_flows": len(df_lab2),
            "syn_attack_flows": len(df_syn2),
            "idle_windows": len(w_i2),
            "busy_windows": len(w_b2),
            "total_benign_windows": len(w_all2),
            "syn_attack_windows": len(w_syn2),
        },
        "feature_audit": s2_features,
        "roc_auc": {
            "LSTM (Logit Space)": {"idle": round(lstm_auc_i, 4), "busy": round(lstm_auc_b, 4), "combined": round(lstm_auc_all, 4)},
            "Logistic Regression (Window Stats)": {"idle": round(lr_auc_i, 4), "busy": round(lr_auc_b, 4), "combined": round(lr_auc_all, 4)},
            "Random Forest (Flow)": {"idle": round(rf_auc_i, 4), "busy": round(rf_auc_b, 4), "combined": round(rf_auc_all, 4)},
            "KNN (Flow)": {"idle": round(knn_auc_i, 4), "busy": round(knn_auc_b, 4), "combined": round(knn_auc_all, 4)},
        },
    }

    out_file = Path("results/lab_session2_metrics.json")
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w") as fp:
        json.dump(s2_summary, fp, indent=2)

    print(f"Session 2 analysis complete. Saved to {out_file}.")


if __name__ == "__main__":
    main()
