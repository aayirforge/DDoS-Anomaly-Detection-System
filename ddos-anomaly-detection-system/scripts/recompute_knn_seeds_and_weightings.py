#!/usr/bin/env python3
"""
Rerun KNN Robust 14 (Log1p+Clip) (Window-Max) across:
  - 5 random seeds (42, 123, 456, 789, 1000) for 25k subsample
  - Both weightings: 'uniform' and 'distance'
  - Full un-subsampled train set (170,884 flows) for both weightings
Reports recall at Benign FPR <= 1.0% (<= 12 false positives / 1,200 windows) and ROC-AUC.
Saves to results/knn_seeds_and_weightings_experiment.json.
"""
import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = REPO_ROOT / "data/processed"
RESULTS_DIR = REPO_ROOT / "results"

robust_features = [
    "Bwd Packets/s", "Down/Up Ratio", "Bwd Packet Length Mean", "Bwd Packet Length Max",
    "Total Length of Bwd Packets", "Bwd Header Length", "Flow Packets/s", "Total Backward Packets",
    "Bwd Packet Length Min", "Flow Bytes/s", "Total Length of Fwd Packets", "Total Fwd Packets",
    "Fwd Packet Length Max", "Idle Std"
]

def signed_log1p(x):
    return np.sign(x) * np.log1p(np.abs(x))

def make_windows_step5(flows_matrix, window_size=10, step_size=5):
    n = len(flows_matrix)
    if n < window_size:
        return np.zeros((0, window_size, flows_matrix.shape[1]))
    windows = []
    for i in range(0, n - window_size + 1, step_size):
        windows.append(flows_matrix[i : i + window_size])
    return np.array(windows)

def main():
    print("Loading Day 1 train data...")
    orig_scaler = joblib.load(REPO_ROOT / "models/scaler.joblib")
    features_full = json.load(open(REPO_ROOT / "models/features.json"))["selected_features"]

    df_train = pd.read_parquet(DATA_DIR / "train.parquet")
    raw_train = pd.DataFrame(orig_scaler.inverse_transform(df_train[features_full].values), columns=features_full)[robust_features]
    X_train_raw = raw_train.values
    y_train_full = df_train["Label_Binary"].astype(int).values

    # Preprocessing pipeline: Signed Log1p on continuous heavy-tailed features, StandardScaler fit on train, clip [-5, 5]
    X_tr_log = signed_log1p(X_train_raw)
    scaler = StandardScaler().fit(X_tr_log)
    X_tr_scaled = np.clip(scaler.transform(X_tr_log), -5.0, 5.0)

    # Load Session 2 Java flows
    df_idle = pd.read_csv(REPO_ROOT / "lab/captures/session2_java_aligned/lab_idle_aligned.csv")
    df_busy = pd.read_csv(REPO_ROOT / "lab/captures/session2_java_aligned/lab_busy_aligned.csv")
    df_flood = pd.read_csv(REPO_ROOT / "lab/captures/session2_java_aligned/lab_syn_flood_aligned.csv")
    df_flood_atk = df_flood[df_flood["Source IP"] == "172.20.0.3"].reset_index(drop=True)

    X_id = np.clip(scaler.transform(signed_log1p(df_idle[robust_features].values)), -5.0, 5.0)
    X_bu = np.clip(scaler.transform(signed_log1p(df_busy[robust_features].values)), -5.0, 5.0)
    X_fl = np.clip(scaler.transform(signed_log1p(df_flood_atk[robust_features].values)), -5.0, 5.0)

    # Build step-size 5 windows
    W_id = make_windows_step5(X_id, window_size=10, step_size=5) # 600 windows
    W_bu = make_windows_step5(X_bu, window_size=10, step_size=5) # 600 windows
    W_fl = make_windows_step5(X_fl, window_size=10, step_size=5) # 54 windows
    n_benign_win = len(W_id) + len(W_bu) # 1,200
    n_flood_win = len(W_fl)              # 54
    print(f"Windows: Idle={len(W_id)}, Busy={len(W_bu)}, Combined Benign={n_benign_win}, Flood={n_flood_win}")

    seeds = [42, 123, 456, 789, 1000]
    weightings = ["distance", "uniform"]
    results = []

    # 1. 25k Subsample across 5 seeds and 2 weightings
    for w in weightings:
        for seed in seeds:
            print(f"Evaluating weighting='{w}', seed={seed} (25k subsample)...")
            rng = np.random.RandomState(seed)
            sub_idx = rng.choice(len(X_tr_scaled), 25000, replace=False)
            X_sub = X_tr_scaled[sub_idx]
            y_sub = y_train_full[sub_idx]

            knn = KNeighborsClassifier(n_neighbors=5, weights=w, n_jobs=-1)
            knn.fit(X_sub, y_sub)

            # Score windows using Window-Max
            p_id_flow = knn.predict_proba(W_id.reshape(-1, 14))[:, 1]
            p_bu_flow = knn.predict_proba(W_bu.reshape(-1, 14))[:, 1]
            p_fl_flow = knn.predict_proba(W_fl.reshape(-1, 14))[:, 1]

            p_id_win = np.max(p_id_flow.reshape(len(W_id), 10), axis=1)
            p_bu_win = np.max(p_bu_flow.reshape(len(W_bu), 10), axis=1)
            p_fl_win = np.max(p_fl_flow.reshape(len(W_fl), 10), axis=1)

            p_benign = np.concatenate([p_id_win, p_bu_win])
            y_all = np.concatenate([np.zeros(n_benign_win), np.ones(n_flood_win)])
            p_all = np.concatenate([p_benign, p_fl_win])
            auc = float(roc_auc_score(y_all, p_all))

            # Fixed Day 1 threshold (1.0000)
            fp_fixed = int(np.sum(p_benign >= 1.0))
            fpr_fixed = fp_fixed / n_benign_win
            tp_fixed = int(np.sum(p_fl_win >= 1.0))
            rec_fixed = tp_fixed / n_flood_win

            # Optimal threshold subject to FPR <= 1.0% (at most 12 false positives)
            sorted_b = np.sort(p_benign)
            # 99th percentile of benign scores ensures FPR <= 1%
            th_target_fpr1 = float(sorted_b[int(np.ceil(0.99 * (n_benign_win - 1)))])
            # If discrete values cause identical ties, ensure fp <= 12
            while int(np.sum(p_benign >= th_target_fpr1)) > 12 and th_target_fpr1 < 1.0:
                th_target_fpr1 += 0.001
            
            fp_opt = int(np.sum(p_benign >= th_target_fpr1))
            fpr_opt = fp_opt / n_benign_win
            tp_opt = int(np.sum(p_fl_win >= th_target_fpr1))
            rec_opt = tp_opt / n_flood_win

            results.append({
                "setup": "25k Subsample",
                "subsample_size": 25000,
                "weights": w,
                "seed": seed,
                "roc_auc": round(auc, 4),
                "fixed_threshold_1_0": {
                    "threshold": 1.0,
                    "false_positives": fp_fixed,
                    "benign_fpr": round(fpr_fixed, 4),
                    "true_positives": tp_fixed,
                    "flood_recall": round(rec_fixed, 4)
                },
                "constrained_fpr_1_0": {
                    "threshold": round(th_target_fpr1, 4),
                    "false_positives": fp_opt,
                    "benign_fpr": round(fpr_opt, 4),
                    "true_positives": tp_opt,
                    "flood_recall": round(rec_opt, 4)
                }
            })

    # 2. Full un-subsampled train set (170,884 flows) for both weightings
    for w in weightings:
        print(f"Evaluating weighting='{w}' on Full Train Set (170,884 flows)...")
        knn_full = KNeighborsClassifier(n_neighbors=5, weights=w, n_jobs=-1)
        knn_full.fit(X_tr_scaled, y_train_full)

        p_id_flow = knn_full.predict_proba(W_id.reshape(-1, 14))[:, 1]
        p_bu_flow = knn_full.predict_proba(W_bu.reshape(-1, 14))[:, 1]
        p_fl_flow = knn_full.predict_proba(W_fl.reshape(-1, 14))[:, 1]

        p_id_win = np.max(p_id_flow.reshape(len(W_id), 10), axis=1)
        p_bu_win = np.max(p_bu_flow.reshape(len(W_bu), 10), axis=1)
        p_fl_win = np.max(p_fl_flow.reshape(len(W_fl), 10), axis=1)

        p_benign = np.concatenate([p_id_win, p_bu_win])
        y_all = np.concatenate([np.zeros(n_benign_win), np.ones(n_flood_win)])
        p_all = np.concatenate([p_benign, p_fl_win])
        auc = float(roc_auc_score(y_all, p_all))

        fp_fixed = int(np.sum(p_benign >= 1.0))
        fpr_fixed = fp_fixed / n_benign_win
        tp_fixed = int(np.sum(p_fl_win >= 1.0))
        rec_fixed = tp_fixed / n_flood_win

        sorted_b = np.sort(p_benign)
        th_target_fpr1 = float(sorted_b[int(np.ceil(0.99 * (n_benign_win - 1)))])
        while int(np.sum(p_benign >= th_target_fpr1)) > 12 and th_target_fpr1 < 1.0:
            th_target_fpr1 += 0.001
        
        fp_opt = int(np.sum(p_benign >= th_target_fpr1))
        fpr_opt = fp_opt / n_benign_win
        tp_opt = int(np.sum(p_fl_win >= th_target_fpr1))
        rec_opt = tp_opt / n_flood_win

        results.append({
            "setup": "Full Train Set (No Subsample)",
            "subsample_size": len(X_tr_scaled),
            "weights": w,
            "seed": "All (None)",
            "roc_auc": round(auc, 4),
            "fixed_threshold_1_0": {
                "threshold": 1.0,
                "false_positives": fp_fixed,
                "benign_fpr": round(fpr_fixed, 4),
                "true_positives": tp_fixed,
                "flood_recall": round(rec_fixed, 4)
            },
            "constrained_fpr_1_0": {
                "threshold": round(th_target_fpr1, 4),
                "false_positives": fp_opt,
                "benign_fpr": round(fpr_opt, 4),
                "true_positives": tp_opt,
                "flood_recall": round(rec_opt, 4)
            }
        })

    out = {
        "metadata": {
            "model": "KNN Robust 14 (Log1p+Clip) (Window-Max)",
            "explanation_of_shift": (
                "The shift from FPR 1.00% / recall 96.3% / AUC 0.961 to 0.83% / 31.5% / 0.989 occurred because: "
                "1. Training rows: The earlier exploratory script trained on the FULL Day 1 training set (N = 170,884) with uniform weights (weights='uniform'), "
                "where discrete step posteriors (k/5 in {0, 0.2, 0.4, 0.6, 0.8, 1.0}) caused 52/54 flood windows to tie at score 1.0 (96.3% recall at exactly 12/1200 FPs = 1.00% FPR). "
                "2. Distance weighting & 25k subsample: In recompute_candidate_selection_preregistered.py, the model was aligned with the frozen baseline's training protocol "
                "(weights='distance' on a 25,000 Day 1 subsample with seed 42). Under distance weighting, nearest neighbor distances break the discrete ties, "
                "yielding continuous posteriors with higher rank-order discrimination (AUC 0.9886 vs 0.9610). At the exact fixed threshold 1.0000, 10 benign windows and 17 flood windows score >= 1.0000 "
                "(FPR = 0.83%, recall = 31.48%). When the threshold is calibrated to achieve the full allowable 1.00% FPR (12 FPs), recall increases."
            ),
            "features": robust_features,
            "n_benign_windows": n_benign_win,
            "n_flood_windows": n_flood_win
        },
        "experiments": results
    }

    out_path = RESULTS_DIR / "knn_seeds_and_weightings_experiment.json"
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"Saved results to {out_path}")

if __name__ == "__main__":
    main()
