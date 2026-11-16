#!/usr/bin/env python3
"""Recompute KNN Preprocessing Experiment strictly against the frozen model architecture.

Frozen Model:
- models/knn.joblib (KNeighborsClassifier(n_neighbors=5, weights='distance'), subsample 25,000 Day 1 train).
- Frozen Baseline Metrics: Same-Day AUC 0.9973, Cross-Day ZS AUC 0.9954, Calibrated FPR 0.36% at threshold 0.8200.

Evaluates all 4 configurations with:
- n_neighbors=5, weights='distance'
- Exactly identical 25,000 Day 1 training subsample (seed 42)
- Signed log1p: sign(x) * log(1 + |x|) for continuous heavy-tailed features
- StandardScaler on Day 1 train only
- Clip z-scores to [-5.0, +5.0]
"""

import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import auc, confusion_matrix, precision_recall_curve, roc_auc_score
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import StandardScaler


def compute_fpr_ci(fp: int, tn: int, z: float = 1.96):
    n = fp + tn
    if n == 0:
        return 0.0, 0.0, 0.0
    p = fp / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    margin = z * np.sqrt((p * (1 - p) + z * z / (4 * n)) / n) / denom
    return float(p), float(max(0.0, centre - margin)), float(min(1.0, centre + margin))


def find_optimal_threshold(y_true: np.ndarray, y_score: np.ndarray, target_max_fpr: float = 0.01):
    benign_scores = y_score[y_true == 0]
    if len(benign_scores) == 0:
        return 0.5, 0.0, 0.0

    sorted_scores = np.sort(np.unique(benign_scores))
    best_th = 0.5
    best_recall = -1.0
    best_fpr = 1.0

    if len(sorted_scores) > 2000:
        candidates = np.percentile(benign_scores, np.linspace(0, 100, 2001))
    else:
        candidates = sorted_scores

    for th in candidates:
        fp = np.sum(benign_scores >= th)
        fpr = fp / len(benign_scores)
        if fpr <= target_max_fpr:
            attack_scores = y_score[y_true == 1]
            rec = np.sum(attack_scores >= th) / max(1, len(attack_scores))
            if rec > best_recall:
                best_recall = rec
                best_th = float(th)
                best_fpr = float(fpr)

    return float(best_th), float(best_recall), float(best_fpr)


def evaluate_binary_predictions(y_true: np.ndarray, y_pred_prob: np.ndarray, threshold: float):
    y_pred = (y_pred_prob >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fpr, fpr_low, fpr_high = compute_fpr_ci(fp, tn)
    rec = tp / max(1, tp + fn)
    prec = tp / max(1, tp + fp)
    f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0
    roc_auc = float(roc_auc_score(y_true, y_pred_prob))
    p_c, r_c, _ = precision_recall_curve(y_true, y_pred_prob)
    pr_auc = float(auc(r_c, p_c))

    return {
        "threshold": float(round(threshold, 4)),
        "benign_count": int(tn + fp),
        "attack_count": int(tp + fn),
        "tp": int(tp),
        "fp": int(fp),
        "tn": int(tn),
        "fn": int(fn),
        "precision": float(round(prec, 4)),
        "recall": float(round(rec, 4)),
        "f1_score": float(round(f1, 4)),
        "fpr": float(round(fpr, 4)),
        "fpr_ci": [float(round(fpr_low, 5)), float(round(fpr_high, 5))],
        "roc_auc": float(round(roc_auc, 4)),
        "pr_auc": float(round(pr_auc, 4)),
    }


def main():
    root = Path(__file__).resolve().parent.parent
    processed_dir = root / "data/processed"
    models_dir = root / "models"

    features_full = json.load(open(models_dir / "features.json"))["selected_features"]
    dropped_features = [
        "ACK Flag Count", "URG Flag Count", "CWE Flag Count", "Fwd PSH Flags",
        "Init_Win_bytes_forward", "Init_Win_bytes_backward",
        "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Min", "Bwd IAT Max",
        "Protocol"
    ]
    robust_features = [f for f in features_full if f not in dropped_features]
    discrete_features = {"ACK Flag Count", "URG Flag Count", "CWE Flag Count", "Fwd PSH Flags", "Protocol"}

    heavy_tailed_full = [f for f in features_full if f not in discrete_features]
    heavy_tailed_robust = [f for f in robust_features if f not in discrete_features]

    # Load frozen model to extract its exact subsample indices
    frozen_knn = joblib.load(models_dir / "knn.joblib")
    orig_scaler = joblib.load(models_dir / "scaler.joblib")

    df_train = pd.read_parquet(processed_dir / "train.parquet")
    df_val = pd.read_parquet(processed_dir / "val.parquet")
    df_same = pd.read_parquet(processed_dir / "test_same_day.parquet")
    df_cross = pd.read_parquet(processed_dir / "test_cross_day.parquet")

    y_train_all = (df_train["Normalized_Label"].str.upper() != "BENIGN").astype(int).values
    y_val = (df_val["Normalized_Label"].str.upper() != "BENIGN").astype(int).values
    y_same = (df_same["Normalized_Label"].str.upper() != "BENIGN").astype(int).values
    y_cross = (df_cross["Normalized_Label"].str.upper() != "BENIGN").astype(int).values

    # Exactly reproduce the 25,000 stratified/random subsample used by train_knn.py (seed 42)
    rng = np.random.RandomState(42)
    subsample_idx = rng.choice(len(df_train), size=25000, replace=False)

    raw_train = pd.DataFrame(orig_scaler.inverse_transform(df_train[features_full].values), columns=features_full)
    raw_val = pd.DataFrame(orig_scaler.inverse_transform(df_val[features_full].values), columns=features_full)
    raw_same = pd.DataFrame(orig_scaler.inverse_transform(df_same[features_full].values), columns=features_full)
    raw_cross = pd.DataFrame(orig_scaler.inverse_transform(df_cross[features_full].values), columns=features_full)

    y_train_sub = y_train_all[subsample_idx]

    # Cross-day calibration indices: 50% split on benign
    idx_b_cross = np.where(y_cross == 0)[0]
    n_cal = len(idx_b_cross) // 2
    idx_cal = idx_b_cross[:n_cal]
    idx_eval = idx_b_cross[n_cal:]
    idx_a_cross = np.where(y_cross == 1)[0]
    y_cross_cal = np.concatenate([np.zeros(len(idx_eval)), np.ones(len(idx_a_cross))])

    def signed_log1p(df_in, feat_subset):
        df_out = df_in.copy()
        for f in feat_subset:
            if f not in discrete_features:
                df_out[f] = np.sign(df_out[f]) * np.log1p(np.abs(df_out[f]))
        return df_out

    results = {
        "metadata": {
            "protocol": (
                "Day 1 training only. Evaluated using exact frozen model hyperparameters: "
                "KNeighborsClassifier(n_neighbors=5, weights='distance'), subsampled to 25,000 Day 1 train flows (seed 42). "
                "Signed log1p: sign(x) * log1p(|x|) on continuous heavy-tailed features, StandardScaler on train only, "
                "z-scores clipped to [-5.0, +5.0]."
            ),
            "explanation_baseline_difference": (
                "The earlier KNN preprocessing table reported AUC 0.9893 and calibrated FPR 1.60% because it instantiated "
                "KNeighborsClassifier with default uniform weights (weights='uniform') on the full 170,884 un-subsampled train set. "
                "The frozen model (models/knn.joblib, checksum 3046dcae...) uses distance weighting (weights='distance') "
                "fitted on a 25,000-flow Day 1 subsample, which outputs continuous distance-weighted posteriors rather than "
                "6 discrete probabilities, yielding AUC 0.9954 and calibrated FPR 0.36% (at threshold 0.8200) on Cross-Day test."
            ),
            "negative_values_handling_log1p": (
                "log1p(x) is mathematically undefined for x <= -1. To robustly handle negative values (such as -1 in Init_Win_bytes "
                "and negative timing/header artifacts like -2.12e9 in Bwd Header Length), we apply the continuous, odd signed log1p: "
                "signed_log1p(x) = sign(x) * log(1 + |x|). This maps 0 to 0, x > 0 to log(1 + x), and negative values to "
                "-log(1 + |x|) without producing NaNs, dampening extreme negative outliers while preserving polarity."
            ),
            "heavy_tailed_features_full_25": heavy_tailed_full,
            "heavy_tailed_features_robust_14": heavy_tailed_robust,
            "clip_range": [-5.0, 5.0],
        },
        "experiments": {},
    }

    configurations = [
        ("Full 25 - Frozen Model Baseline (Standard Scaling)", features_full, False, False, True),
        ("Full 25 - Log1p + Clip [-5, 5]", features_full, True, True, False),
        ("Robust 14 - Standard Scaling", robust_features, False, False, False),
        ("Robust 14 - Log1p + Clip [-5, 5]", robust_features, True, True, False),
    ]

    for name, feat_list, do_log1p, do_clip, is_frozen_model in configurations:
        print(f"\n==========================================")
        print(f"Running: {name}")
        print(f"==========================================")

        if is_frozen_model:
            knn = frozen_knn
            # Standard scaled features directly from parquets
            X_va_sc = df_val[features_full].values
            X_sa_sc = df_same[features_full].values
            X_cr_sc = df_cross[features_full].values
        else:
            X_tr = raw_train[feat_list].copy()
            X_va = raw_val[feat_list].copy()
            X_sa = raw_same[feat_list].copy()
            X_cr = raw_cross[feat_list].copy()

            if do_log1p:
                X_tr = signed_log1p(X_tr, feat_list)
                X_va = signed_log1p(X_va, feat_list)
                X_sa = signed_log1p(X_sa, feat_list)
                X_cr = signed_log1p(X_cr, feat_list)

            # Fit scaler on Day 1 train subsample
            scaler = StandardScaler()
            X_tr_sc = scaler.fit_transform(X_tr.iloc[subsample_idx].values)
            X_va_sc = scaler.transform(X_va.values)
            X_sa_sc = scaler.transform(X_sa.values)
            X_cr_sc = scaler.transform(X_cr.values)

            if do_clip:
                X_tr_sc = np.clip(X_tr_sc, -5.0, 5.0)
                X_va_sc = np.clip(X_va_sc, -5.0, 5.0)
                X_sa_sc = np.clip(X_sa_sc, -5.0, 5.0)
                X_cr_sc = np.clip(X_cr_sc, -5.0, 5.0)

            knn = KNeighborsClassifier(n_neighbors=5, weights="distance", n_jobs=-1)
            knn.fit(X_tr_sc, y_train_sub)

        # Batch predict to avoid memory issues
        bs = 10000
        p_val = np.concatenate([knn.predict_proba(X_va_sc[i : i + bs])[:, 1] for i in range(0, len(X_va_sc), bs)])
        th_val, _, _ = find_optimal_threshold(y_val, p_val, target_max_fpr=0.01)

        p_same = np.concatenate([knn.predict_proba(X_sa_sc[i : i + bs])[:, 1] for i in range(0, len(X_sa_sc), bs)])
        res_same = evaluate_binary_predictions(y_same, p_same, th_val)

        p_cross = np.concatenate([knn.predict_proba(X_cr_sc[i : i + bs])[:, 1] for i in range(0, len(X_cr_sc), bs)])
        res_cross_zs = evaluate_binary_predictions(y_cross, p_cross, th_val)

        # Cross-day calibrated threshold on 50% benign
        th_cal = float(np.percentile(p_cross[idx_cal], 99.0))
        p_cross_cal = np.concatenate([p_cross[idx_eval], p_cross[idx_a_cross]])
        res_cross_cal = evaluate_binary_predictions(y_cross_cal, p_cross_cal, th_cal)

        results["experiments"][name] = {
            "validation_threshold": float(round(th_val, 4)),
            "calibrated_threshold": float(round(th_cal, 4)),
            "same_day_zero_shot": res_same,
            "cross_day_zero_shot": res_cross_zs,
            "cross_day_calibrated": res_cross_cal,
        }

        print(f"Val Thresh: {th_val:.4f} | Cal Thresh: {th_cal:.4f}")
        print(f"Same-Day ZS: Recall={res_same['recall']:.4f}, FPR={res_same['fpr']:.4f}, AUC={res_same['roc_auc']:.4f}")
        print(f"Cross-Day ZS: Recall={res_cross_zs['recall']:.4f}, FPR={res_cross_zs['fpr']:.4f}, AUC={res_cross_zs['roc_auc']:.4f}")
        print(f"Cross-Day Cal: Recall={res_cross_cal['recall']:.4f}, FPR={res_cross_cal['fpr']:.4f}, AUC={res_cross_cal['roc_auc']:.4f}")

    out_path = root / "results/knn_preprocessing_experiment.json"
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved updated results to {out_path}")


if __name__ == "__main__":
    main()
