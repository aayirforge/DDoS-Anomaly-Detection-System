#!/usr/bin/env python3
"""KNN Preprocessing Experiment (Day 1 only).

Evaluates KNN with:
1. log1p on heavy-tailed features: sign(x) * log1p(|x|)
2. StandardScaler fitted on Day 1 train only
3. z-score clipping to [-5.0, +5.0]

Tested on:
- Full 25 features
- Robust 14 features

Protocol:
- Same-day zero-shot (threshold tuned on Day 1 val at target FPR <= 0.01)
- Cross-day zero-shot (val threshold)
- Cross-day target-calibrated (50% cross-day benign calibration, 50% holdout eval)
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

    return best_th, best_recall, best_fpr


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

    # Non-heavy-tailed features: binary flags and protocol
    discrete_features = {"ACK Flag Count", "URG Flag Count", "CWE Flag Count", "Fwd PSH Flags", "Protocol"}
    heavy_tailed_full = [f for f in features_full if f not in discrete_features]
    heavy_tailed_robust = [f for f in robust_features if f not in discrete_features]

    print(f"Full 25 features: {len(features_full)}")
    print(f"Heavy-tailed in Full ({len(heavy_tailed_full)}): {heavy_tailed_full}")
    print(f"Robust 14 features: {len(robust_features)}")
    print(f"Heavy-tailed in Robust ({len(heavy_tailed_robust)}): {heavy_tailed_robust}")

    # Load original standard scaler to recover raw unscaled features
    orig_scaler = joblib.load(models_dir / "scaler.joblib")

    df_train = pd.read_parquet(processed_dir / "train.parquet")
    df_val = pd.read_parquet(processed_dir / "val.parquet")
    df_same = pd.read_parquet(processed_dir / "test_same_day.parquet")
    df_cross = pd.read_parquet(processed_dir / "test_cross_day.parquet")

    # Unscale all sets to raw domain
    raw_train = pd.DataFrame(orig_scaler.inverse_transform(df_train[features_full].values), columns=features_full)
    raw_val = pd.DataFrame(orig_scaler.inverse_transform(df_val[features_full].values), columns=features_full)
    raw_same = pd.DataFrame(orig_scaler.inverse_transform(df_same[features_full].values), columns=features_full)
    raw_cross = pd.DataFrame(orig_scaler.inverse_transform(df_cross[features_full].values), columns=features_full)

    y_train = (df_train["Normalized_Label"].str.upper() != "BENIGN").astype(int).values
    y_val = (df_val["Normalized_Label"].str.upper() != "BENIGN").astype(int).values
    y_same = (df_same["Normalized_Label"].str.upper() != "BENIGN").astype(int).values
    y_cross = (df_cross["Normalized_Label"].str.upper() != "BENIGN").astype(int).values

    # Cross-day calibration indices: 50% split on benign
    idx_b_cross = np.where(y_cross == 0)[0]
    n_cal = len(idx_b_cross) // 2
    idx_cal = idx_b_cross[:n_cal]
    idx_eval = idx_b_cross[n_cal:]
    idx_a_cross = np.where(y_cross == 1)[0]
    y_cross_cal = np.concatenate([np.zeros(len(idx_eval)), np.ones(len(idx_a_cross))])

    results = {
        "metadata": {
            "protocol": "Day 1 training only. log1p on heavy-tailed features, StandardScaler on train only, clip z-scores to [-5, +5].",
            "heavy_tailed_features_full_25": heavy_tailed_full,
            "heavy_tailed_features_robust_14": heavy_tailed_robust,
            "clip_range": [-5.0, 5.0],
        },
        "experiments": {},
    }

    configurations = [
        ("Full 25 - Standard Scaling (Baseline)", features_full, False, False),
        ("Full 25 - Log1p + Clip [-5, 5]", features_full, True, True),
        ("Robust 14 - Standard Scaling (Baseline)", robust_features, False, False),
        ("Robust 14 - Log1p + Clip [-5, 5]", robust_features, True, True),
    ]

    for name, feat_list, do_log1p, do_clip in configurations:
        print(f"\n==========================================")
        print(f"Running: {name}")
        print(f"==========================================")

        X_tr = raw_train[feat_list].copy()
        X_va = raw_val[feat_list].copy()
        X_sa = raw_same[feat_list].copy()
        X_cr = raw_cross[feat_list].copy()

        if do_log1p:
            ht_feats = [f for f in feat_list if f not in discrete_features]
            for f in ht_feats:
                X_tr[f] = np.sign(X_tr[f]) * np.log1p(np.abs(X_tr[f]))
                X_va[f] = np.sign(X_va[f]) * np.log1p(np.abs(X_va[f]))
                X_sa[f] = np.sign(X_sa[f]) * np.log1p(np.abs(X_sa[f]))
                X_cr[f] = np.sign(X_cr[f]) * np.log1p(np.abs(X_cr[f]))

        # Fit scaler on train only
        scaler = StandardScaler()
        X_tr_sc = scaler.fit_transform(X_tr.values)
        X_va_sc = scaler.transform(X_va.values)
        X_sa_sc = scaler.transform(X_sa.values)
        X_cr_sc = scaler.transform(X_cr.values)

        if do_clip:
            X_tr_sc = np.clip(X_tr_sc, -5.0, 5.0)
            X_va_sc = np.clip(X_va_sc, -5.0, 5.0)
            X_sa_sc = np.clip(X_sa_sc, -5.0, 5.0)
            X_cr_sc = np.clip(X_cr_sc, -5.0, 5.0)

        knn = KNeighborsClassifier(n_neighbors=5, n_jobs=-1)
        knn.fit(X_tr_sc, y_train)

        # Validation threshold
        p_val = knn.predict_proba(X_va_sc)[:, 1]
        th_val, _, _ = find_optimal_threshold(y_val, p_val, target_max_fpr=0.01)

        # Same-day zero-shot
        p_same = knn.predict_proba(X_sa_sc)[:, 1]
        res_same = evaluate_binary_predictions(y_same, p_same, th_val)

        # Cross-day zero-shot
        p_cross = knn.predict_proba(X_cr_sc)[:, 1]
        res_cross_zs = evaluate_binary_predictions(y_cross, p_cross, th_val)

        # Cross-day calibrated
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
    print(f"\nSaved results to {out_path}")


if __name__ == "__main__":
    main()
