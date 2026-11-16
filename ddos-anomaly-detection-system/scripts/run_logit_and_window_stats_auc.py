"""Compute ROC-AUC in logit space for LSTM and for Logistic Regression on 50 window stats."""

from __future__ import annotations

import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score
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

    # Load LSTM checkpoint
    ckpt = torch.load(config.get_path("models_dir") / "lstm.pt", map_location="cpu")
    lstm = LSTMAnomalyClassifier(ckpt["input_dim"], ckpt["hidden_dim"], ckpt["num_layers"], 0.0)
    lstm.load_state_dict(ckpt["model_state_dict"])
    lstm.eval()

    # Load Benign flows (Session 1)
    df_idle = pd.read_csv("lab/captures/lab_idle_aligned.csv")
    df_busy = pd.read_csv("lab/captures/lab_busy_aligned.csv")
    df_benign = pd.concat([df_idle, df_busy], ignore_index=True)

    # Load SYN flood flows (Session 1)
    syn_dfs = [pd.read_csv(f"lab/captures/attack_syn_{r}_aligned.csv") for r in [50, 200, 500]]
    df_syn_all = pd.concat(syn_dfs, ignore_index=True)
    syn_mask = (df_syn_all["Source IP"] == "172.20.0.4") | (df_syn_all["Destination IP"] == "172.20.0.4")
    df_syn = df_syn_all[syn_mask]

    X_idle = scaler.transform(df_idle[feats].values)
    X_busy = scaler.transform(df_busy[feats].values)
    X_benign = scaler.transform(df_benign[feats].values)
    X_syn = scaler.transform(df_syn[feats].values)

    w_idle = make_windows(X_idle)
    w_busy = make_windows(X_busy)
    w_benign = make_windows(X_benign)
    w_syn = make_windows(X_syn)

    # 1. LSTM in Logit Space
    def get_lstm_logits(W_mat):
        res = []
        with torch.no_grad():
            for i in range(0, len(W_mat), 2048):
                logits = lstm(torch.from_numpy(W_mat[i : i + 2048])).detach().cpu().numpy().flatten()
                res.append(logits)
        return np.concatenate(res) if res else np.array([])

    lstm_logits_idle = get_lstm_logits(w_idle)
    lstm_logits_busy = get_lstm_logits(w_busy)
    lstm_logits_benign = get_lstm_logits(w_benign)
    lstm_logits_syn = get_lstm_logits(w_syn)

    lstm_auc_idle = compute_roc_auc_safe(lstm_logits_idle, lstm_logits_syn)
    lstm_auc_busy = compute_roc_auc_safe(lstm_logits_busy, lstm_logits_syn)
    lstm_auc_combined = compute_roc_auc_safe(lstm_logits_benign, lstm_logits_syn)

    # 2. Train Logistic Regression on 50 Window Stats from train data
    processed_dir = config.get_path("processed_data_dir")
    train_npz = np.load(processed_dir / "lstm_train.npz")
    val_npz = np.load(processed_dir / "lstm_val.npz")

    X_train_w = train_npz["X"]
    y_train_w = train_npz["y"].astype(int)

    X_train_stats = get_window_stats(X_train_w)
    stats_scaler = StandardScaler()
    X_train_stats_scaled = stats_scaler.fit_transform(X_train_stats)

    lr_model = LogisticRegression(max_iter=1000, random_state=42)
    lr_model.fit(X_train_stats_scaled, y_train_w)

    # Evaluate LR on lab windows
    stats_idle = stats_scaler.transform(get_window_stats(w_idle))
    stats_busy = stats_scaler.transform(get_window_stats(w_busy))
    stats_benign = stats_scaler.transform(get_window_stats(w_benign))
    stats_syn = stats_scaler.transform(get_window_stats(w_syn))

    lr_p_idle = lr_model.predict_proba(stats_idle)[:, 1]
    lr_p_busy = lr_model.predict_proba(stats_busy)[:, 1]
    lr_p_benign = lr_model.predict_proba(stats_benign)[:, 1]
    lr_p_syn = lr_model.predict_proba(stats_syn)[:, 1]

    # LR in probability and logit space
    lr_auc_idle = compute_roc_auc_safe(lr_p_idle, lr_p_syn)
    lr_auc_busy = compute_roc_auc_safe(lr_p_busy, lr_p_syn)
    lr_auc_combined = compute_roc_auc_safe(lr_p_benign, lr_p_syn)

    lr_logits_idle = lr_model.decision_function(stats_idle)
    lr_logits_busy = lr_model.decision_function(stats_busy)
    lr_logits_benign = lr_model.decision_function(stats_benign)
    lr_logits_syn = lr_model.decision_function(stats_syn)

    lr_logit_auc_idle = compute_roc_auc_safe(lr_logits_idle, lr_logits_syn)
    lr_logit_auc_busy = compute_roc_auc_safe(lr_logits_busy, lr_logits_syn)
    lr_logit_auc_combined = compute_roc_auc_safe(lr_logits_benign, lr_logits_syn)

    # 3. KNN Window Mean and Max
    knn = joblib.load(config.get_path("models_dir") / "knn.joblib")
    bs = 50000
    def predict_knn(X_mat):
        res = []
        for i in range(0, len(X_mat), bs):
            res.append(knn.predict_proba(X_mat[i : i + bs])[:, 1])
        return np.concatenate(res)

    p_knn_i = predict_knn(X_idle)
    p_knn_b = predict_knn(X_busy)
    p_knn_all = predict_knn(X_benign)
    p_knn_syn = predict_knn(X_syn)

    def aggs(p):
        mx = np.array([np.max(p[i : i + 10]) for i in range(len(p) - 9)])
        mn = np.array([np.mean(p[i : i + 10]) for i in range(len(p) - 9)])
        return mx, mn

    knn_mx_i, knn_mn_i = aggs(p_knn_i)
    knn_mx_b, knn_mn_b = aggs(p_knn_b)
    knn_mx_all, knn_mn_all = aggs(p_knn_all)
    knn_mx_syn, knn_mn_syn = aggs(p_knn_syn)

    knn_mn_auc_idle = compute_roc_auc_safe(knn_mn_i, knn_mn_syn)
    knn_mn_auc_busy = compute_roc_auc_safe(knn_mn_b, knn_mn_syn)
    knn_mn_auc_combined = compute_roc_auc_safe(knn_mn_all, knn_mn_syn)

    knn_mx_auc_idle = compute_roc_auc_safe(knn_mx_i, knn_mx_syn)
    knn_mx_auc_busy = compute_roc_auc_safe(knn_mx_b, knn_mx_syn)
    knn_mx_auc_combined = compute_roc_auc_safe(knn_mx_all, knn_mx_syn)

    results = {
        "LSTM (Logit Space)": {
            "roc_auc_vs_idle": round(lstm_auc_idle, 4),
            "roc_auc_vs_busy": round(lstm_auc_busy, 4),
            "roc_auc_vs_combined": round(lstm_auc_combined, 4),
            "space": "raw logits",
        },
        "Logistic Regression (Window Stats)": {
            "roc_auc_vs_idle": round(lr_auc_idle, 4),
            "roc_auc_vs_busy": round(lr_auc_busy, 4),
            "roc_auc_vs_combined": round(lr_auc_combined, 4),
            "space": "probabilities",
        },
        "Logistic Regression (Window Stats - Logit Space)": {
            "roc_auc_vs_idle": round(lr_logit_auc_idle, 4),
            "roc_auc_vs_busy": round(lr_logit_auc_busy, 4),
            "roc_auc_vs_combined": round(lr_logit_auc_combined, 4),
            "space": "decision function (logits)",
        },
        "KNN Window-Mean": {
            "roc_auc_vs_idle": round(knn_mn_auc_idle, 4),
            "roc_auc_vs_busy": round(knn_mn_auc_busy, 4),
            "roc_auc_vs_combined": round(knn_mn_auc_combined, 4),
            "space": "window mean",
        },
        "KNN Window-Max": {
            "roc_auc_vs_idle": round(knn_mx_auc_idle, 4),
            "roc_auc_vs_busy": round(knn_mx_auc_busy, 4),
            "roc_auc_vs_combined": round(knn_mx_auc_combined, 4),
            "space": "window max",
        },
    }

    out_file = Path("results/lab_logit_and_window_stats_auc.json")
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w") as fp:
        json.dump(results, fp, indent=2)

    print("\n" + "=" * 125)
    print("        ROC-AUC AUDIT: LOGIT-SPACE LSTM, WINDOW-STATS LOGISTIC REGRESSION, AND KNN AGGREGATIONS")
    print("=" * 125)
    hdr = f"| {'Model / Space':<45} | {'ROC-AUC (vs Idle)':<18} | {'ROC-AUC (vs Busy)':<18} | {'ROC-AUC (vs Combined)':<22} |"
    sep = f"|{'-'*47}|{'-'*20}|{'-'*20}|{'-'*24}|"
    print(hdr)
    print(sep)
    for m_name, d in results.items():
        print(f"| {m_name:<45} | {d['roc_auc_vs_idle']:<18.4f} | {d['roc_auc_vs_busy']:<18.4f} | {d['roc_auc_vs_combined']:<22.4f} |")
    print(sep)


if __name__ == "__main__":
    main()
