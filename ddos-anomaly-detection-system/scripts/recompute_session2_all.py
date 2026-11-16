"""Unified evaluation of Session 1 and Session 2.

Covers:
1. Unified ROC-AUC code path for Session 1 & 2 (Flow, Window, KNN aggregations).
2. Session 2 25-feature comparison (Benign and SYN flood) with unscaled source and P(train=1) for binary features.
3. Scoring Session 2 at FIXED Day 1 validation thresholds only, with FP protocol/destination breakdown.
"""

from __future__ import annotations

import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score, confusion_matrix
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

    # Load LSTM checkpoint (Seed 42 primary)
    ckpt = torch.load(config.get_path("models_dir") / "lstm.pt", map_location="cpu")
    lstm = LSTMAnomalyClassifier(ckpt["input_dim"], ckpt["hidden_dim"], ckpt["num_layers"], 0.0)
    lstm.load_state_dict(ckpt["model_state_dict"])
    lstm.eval()

    # Train Logistic Regression on Day 1 training window stats
    processed_dir = config.get_path("processed_data_dir")
    train_npz = np.load(processed_dir / "lstm_train.npz")
    stats_scaler = StandardScaler()
    X_tr_stats = stats_scaler.fit_transform(get_window_stats(train_npz["X"]))
    lr = LogisticRegression(max_iter=1000, random_state=42)
    lr.fit(X_tr_stats, train_npz["y"].astype(int))

    # =========================================================================
    # PART 1: Unified ROC-AUC for Session 1 and Session 2
    # =========================================================================
    # Helper to batch KNN
    bs = 50000
    def p_knn(X):
        r = [knn.predict_proba(X[i:i+bs])[:, 1] for i in range(0, len(X), bs)]
        return np.concatenate(r) if r else np.array([])

    def get_lstm_logits(W_mat):
        res = []
        with torch.no_grad():
            for i in range(0, len(W_mat), 2048):
                res.append(lstm(torch.from_numpy(W_mat[i : i + 2048])).detach().cpu().numpy().flatten())
        return np.concatenate(res) if res else np.array([])

    def get_win_aggs(p: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        if len(p) < 10:
            return np.array([]), np.array([])
        mx = np.array([np.max(p[i : i + 10]) for i in range(len(p) - 9)])
        mn = np.array([np.mean(p[i : i + 10]) for i in range(len(p) - 9)])
        return mx, mn

    sessions = {}
    for sess_name, paths in [
        ("Session 1", {
            "idle": "lab/captures/lab_idle_aligned.csv",
            "busy": "lab/captures/lab_busy_aligned.csv",
            "syn": ["lab/captures/attack_syn_50_aligned.csv", "lab/captures/attack_syn_200_aligned.csv", "lab/captures/attack_syn_500_aligned.csv"],
            "syn_filter": lambda df: df[df["Source IP"] == "172.20.0.4"],
        }),
        ("Session 2", {
            "idle": "lab/captures/session2/lab_idle_aligned.csv",
            "busy": "lab/captures/session2/lab_busy_aligned.csv",
            "syn": ["lab/captures/session2/lab_syn_flood_aligned.csv"],
            "syn_filter": lambda df: df[df["Source IP"] == "172.20.0.3"],
        }),
    ]:
        df_idle = pd.read_csv(paths["idle"])
        df_busy = pd.read_csv(paths["busy"])
        df_benign = pd.concat([df_idle, df_busy], ignore_index=True)

        syn_raw = pd.concat([pd.read_csv(p) for p in paths["syn"]], ignore_index=True)
        df_syn = paths["syn_filter"](syn_raw)

        # Scaled feature matrices
        X_i = scaler.transform(df_idle[feats].values)
        X_b = scaler.transform(df_busy[feats].values)
        X_all = scaler.transform(df_benign[feats].values)
        X_s = scaler.transform(df_syn[feats].values)

        # Flow probabilities
        rf_p_i = rf.predict_proba(X_i)[:, 1]
        rf_p_b = rf.predict_proba(X_b)[:, 1]
        rf_p_all = rf.predict_proba(X_all)[:, 1]
        rf_p_s = rf.predict_proba(X_s)[:, 1]

        knn_p_i = p_knn(X_i)
        knn_p_b = p_knn(X_b)
        knn_p_all = p_knn(X_all)
        knn_p_s = p_knn(X_s)

        # Windows
        w_i = make_windows(X_i)
        w_b = make_windows(X_b)
        w_all = make_windows(X_all)
        w_s = make_windows(X_s)

        # LSTM Logits
        lstm_l_i = get_lstm_logits(w_i)
        lstm_l_b = get_lstm_logits(w_b)
        lstm_l_all = get_lstm_logits(w_all)
        lstm_l_s = get_lstm_logits(w_s)

        # Window stats LR
        lr_s_i = lr.decision_function(stats_scaler.transform(get_window_stats(w_i)))
        lr_s_b = lr.decision_function(stats_scaler.transform(get_window_stats(w_b)))
        lr_s_all = lr.decision_function(stats_scaler.transform(get_window_stats(w_all)))
        lr_s_s = lr.decision_function(stats_scaler.transform(get_window_stats(w_s)))

        # KNN window aggregations
        knn_mx_i, knn_mn_i = get_win_aggs(knn_p_i)
        knn_mx_b, knn_mn_b = get_win_aggs(knn_p_b)
        knn_mx_all, knn_mn_all = get_win_aggs(knn_p_all)
        knn_mx_s, knn_mn_s = get_win_aggs(knn_p_s)

        # RF window aggregations
        rf_mx_i, rf_mn_i = get_win_aggs(rf_p_i)
        rf_mx_b, rf_mn_b = get_win_aggs(rf_p_b)
        rf_mx_all, rf_mn_all = get_win_aggs(rf_p_all)
        rf_mx_s, rf_mn_s = get_win_aggs(rf_p_s)

        models_auc = {
            "Random Forest (Flow)": {
                "idle": round(compute_roc_auc_safe(rf_p_i, rf_p_s), 4),
                "busy": round(compute_roc_auc_safe(rf_p_b, rf_p_s), 4),
                "combined": round(compute_roc_auc_safe(rf_p_all, rf_p_s), 4),
            },
            "KNN (Flow)": {
                "idle": round(compute_roc_auc_safe(knn_p_i, knn_p_s), 4),
                "busy": round(compute_roc_auc_safe(knn_p_b, knn_p_s), 4),
                "combined": round(compute_roc_auc_safe(knn_p_all, knn_p_s), 4),
            },
            "RF Window-Mean": {
                "idle": round(compute_roc_auc_safe(rf_mn_i, rf_mn_s), 4),
                "busy": round(compute_roc_auc_safe(rf_mn_b, rf_mn_s), 4),
                "combined": round(compute_roc_auc_safe(rf_mn_all, rf_mn_s), 4),
            },
            "RF Window-Max": {
                "idle": round(compute_roc_auc_safe(rf_mx_i, rf_mx_s), 4),
                "busy": round(compute_roc_auc_safe(rf_mx_b, rf_mx_s), 4),
                "combined": round(compute_roc_auc_safe(rf_mx_all, rf_mx_s), 4),
            },
            "KNN Window-Mean": {
                "idle": round(compute_roc_auc_safe(knn_mn_i, knn_mn_s), 4),
                "busy": round(compute_roc_auc_safe(knn_mn_b, knn_mn_s), 4),
                "combined": round(compute_roc_auc_safe(knn_mn_all, knn_mn_s), 4),
            },
            "KNN Window-Max": {
                "idle": round(compute_roc_auc_safe(knn_mx_i, knn_mx_s), 4),
                "busy": round(compute_roc_auc_safe(knn_mx_b, knn_mx_s), 4),
                "combined": round(compute_roc_auc_safe(knn_mx_all, knn_mx_s), 4),
            },
            "LSTM (Logit Space)": {
                "idle": round(compute_roc_auc_safe(lstm_l_i, lstm_l_s), 4),
                "busy": round(compute_roc_auc_safe(lstm_l_b, lstm_l_s), 4),
                "combined": round(compute_roc_auc_safe(lstm_l_all, lstm_l_s), 4),
            },
            "Logistic Regression (Window Stats)": {
                "idle": round(compute_roc_auc_safe(lr_s_i, lr_s_s), 4),
                "busy": round(compute_roc_auc_safe(lr_s_b, lr_s_s), 4),
                "combined": round(compute_roc_auc_safe(lr_s_all, lr_s_s), 4),
            },
        }

        sessions[sess_name] = {
            "counts": {
                "idle_flows": len(df_idle),
                "busy_flows": len(df_busy),
                "combined_benign_flows": len(df_benign),
                "syn_attack_flows": len(df_syn),
                "idle_windows": len(w_i),
                "busy_windows": len(w_b),
                "combined_benign_windows": len(w_all),
                "syn_attack_windows": len(w_s),
            },
            "roc_auc": models_auc,
        }

    # =========================================================================
    # PART 2: Session 2 Feature Comparison with Unscaled Train / Day 2
    # =========================================================================
    df_train = pd.read_parquet(processed_dir / "train.parquet")
    train_benign_unscaled = pd.DataFrame(
        np.round(scaler.inverse_transform(df_train[df_train["Label_Binary"] == 0][feats].values), 6),
        columns=feats,
    )
    train_attack_unscaled = pd.DataFrame(
        np.round(scaler.inverse_transform(df_train[df_train["Label_Binary"] == 1][feats].values), 6),
        columns=feats,
    )

    df_cross = pd.read_parquet(processed_dir / "test_cross_day.parquet")
    day2_benign_unscaled = pd.DataFrame(
        np.round(scaler.inverse_transform(df_cross[df_cross["Label_Binary"] == 0][feats].values), 6),
        columns=feats,
    )

    df_s2_idle = pd.read_csv("lab/captures/session2/lab_idle_aligned.csv")
    df_s2_busy = pd.read_csv("lab/captures/session2/lab_busy_aligned.csv")
    df_s2_benign = pd.concat([df_s2_idle, df_s2_busy], ignore_index=True)

    df_s2_syn_raw = pd.read_csv("lab/captures/session2/lab_syn_flood_aligned.csv")
    df_s2_syn = df_s2_syn_raw[df_s2_syn_raw["Source IP"] == "172.20.0.3"]

    s2_feature_comp = {}
    for f in feats:
        v_tr = train_benign_unscaled[f].to_numpy(dtype=float)
        v_d2 = day2_benign_unscaled[f].to_numpy(dtype=float)
        v_lab_b = df_s2_benign[f].to_numpy(dtype=float)
        v_lab_s = df_s2_syn[f].to_numpy(dtype=float)

        # Check binary
        u_tr = np.unique(v_tr)
        is_binary = bool(set(u_tr).issubset({0.0, 1.0}))
        p_tr_1 = float((v_tr == 1.0).mean()) if is_binary else None
        p_d2_1 = float((v_d2 == 1.0).mean()) if is_binary else None
        p_lab_b_1 = float((v_lab_b == 1.0).mean()) if is_binary else None
        p_lab_s_1 = float((v_lab_s == 1.0).mean()) if is_binary else None

        tr_p5, tr_p50, tr_p95 = float(np.percentile(v_tr, 5)), float(np.percentile(v_tr, 50)), float(np.percentile(v_tr, 95))
        d2_p5, d2_p50, d2_p95 = float(np.percentile(v_d2, 5)), float(np.percentile(v_d2, 50)), float(np.percentile(v_d2, 95))
        lab_b_p5, lab_b_p50, lab_b_p95 = float(np.percentile(v_lab_b, 5)), float(np.percentile(v_lab_b, 50)), float(np.percentile(v_lab_b, 95))
        lab_s_p5, lab_s_p50, lab_s_p95 = float(np.percentile(v_lab_s, 5)), float(np.percentile(v_lab_s, 50)), float(np.percentile(v_lab_s, 95))

        # Overlap with tolerance
        tol = 1e-4
        tr_overlap = bool(min(lab_b_p95, tr_p95) + tol >= max(lab_b_p5, tr_p5))
        d2_overlap = bool(min(lab_b_p95, d2_p95) + tol >= max(lab_b_p5, d2_p5))

        ks_tr = float(scipy.stats.ks_2samp(v_lab_b, v_tr).statistic)
        ks_d2 = float(scipy.stats.ks_2samp(v_lab_b, v_d2).statistic)

        s2_feature_comp[f] = {
            "is_binary": is_binary,
            "p_train_1": round(p_tr_1, 4) if p_tr_1 is not None else None,
            "p_day2_1": round(p_d2_1, 4) if p_d2_1 is not None else None,
            "p_lab_benign_1": round(p_lab_b_1, 4) if p_lab_b_1 is not None else None,
            "p_lab_syn_1": round(p_lab_s_1, 4) if p_lab_s_1 is not None else None,
            "train_p5": tr_p5, "train_p95": tr_p95,
            "day2_p5": d2_p5, "day2_p95": d2_p95,
            "lab_benign_p5": lab_b_p5, "lab_benign_p50": lab_b_p50, "lab_benign_p95": lab_b_p95,
            "lab_syn_p5": lab_s_p5, "lab_syn_p50": lab_s_p50, "lab_syn_p95": lab_s_p95,
            "tr_overlap": tr_overlap,
            "d2_overlap": d2_overlap,
            "ks_train": round(ks_tr, 4),
            "ks_day2": round(ks_d2, 4),
        }

    # =========================================================================
    # PART 3: Score Session 2 at FIXED Day 1 Validation Thresholds Only
    # =========================================================================
    val_thresholds = {
        "Random Forest (Flow)": {"type": "flow", "th": 0.1288},
        "KNN (Flow)": {"type": "flow", "th": 0.1268},
        "LSTM": {"type": "window", "th": 0.9919},
        "Logistic Regression (Window Stats)": {"type": "window_lr", "th": 0.6206},
    }

    X_s2_b = scaler.transform(df_s2_benign[feats].values)
    X_s2_s = scaler.transform(df_s2_syn[feats].values)

    w_s2_b = make_windows(X_s2_b)
    w_s2_s = make_windows(X_s2_s)

    # Predictions
    preds = {
        "Random Forest (Flow)": {
            "b_scores": rf.predict_proba(X_s2_b)[:, 1],
            "s_scores": rf.predict_proba(X_s2_s)[:, 1],
        },
        "KNN (Flow)": {
            "b_scores": p_knn(X_s2_b),
            "s_scores": p_knn(X_s2_s),
        },
        "LSTM": {
            "b_scores": torch.sigmoid(torch.from_numpy(get_lstm_logits(w_s2_b))).numpy(),
            "s_scores": torch.sigmoid(torch.from_numpy(get_lstm_logits(w_s2_s))).numpy(),
        },
        "Logistic Regression (Window Stats)": {
            "b_scores": lr.predict_proba(stats_scaler.transform(get_window_stats(w_s2_b)))[:, 1],
            "s_scores": lr.predict_proba(stats_scaler.transform(get_window_stats(w_s2_s)))[:, 1],
        },
    }

    scoring_results = {}
    fp_breakdown = {}

    for model_name, info in val_thresholds.items():
        th = info["th"]
        b_sc = preds[model_name]["b_scores"]
        s_sc = preds[model_name]["s_scores"]

        fp_idx = np.where(b_sc > th)[0]
        tp_idx = np.where(s_sc > th)[0]

        n_benign = len(b_sc)
        n_syn = len(s_sc)

        fp = len(fp_idx)
        tn = n_benign - fp
        tp = len(tp_idx)
        fn = n_syn - tp

        fpr = fp / n_benign if n_benign > 0 else 0.0
        recall = tp / n_syn if n_syn > 0 else 0.0

        scoring_results[model_name] = {
            "threshold": th,
            "total_benign": n_benign,
            "total_syn": n_syn,
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "benign_fpr": round(fpr, 4),
            "syn_recall": round(recall, 4),
        }

        # Breakdown false positives for flow models
        if info["type"] == "flow":
            fp_flows = df_s2_benign.iloc[fp_idx]
            proto_dst = fp_flows.groupby(["Protocol", "Destination IP", "Destination Port"]).size().reset_index(name="count")
            proto_dst_list = proto_dst.to_dict(orient="records")
            fp_breakdown[model_name] = {
                "total_fp": fp,
                "breakdown": proto_dst_list,
            }
        else:
            # Window models: map window index to middle flow in window
            fp_breakdown[model_name] = {
                "total_fp_windows": fp,
                "note": f"{fp} out of {n_benign} sliding windows exceeded threshold {th}",
            }

    final_payload = {
        "unified_sessions_roc_auc": sessions,
        "session2_feature_comparison": s2_feature_comp,
        "session2_fixed_threshold_scoring": scoring_results,
        "session2_false_positive_breakdown": fp_breakdown,
    }

    out_file = Path("results/session2_unified_eval.json")
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w") as fp:
        json.dump(final_payload, fp, indent=2)

    print(f"Unified evaluation successfully written to {out_file}")


if __name__ == "__main__":
    main()
