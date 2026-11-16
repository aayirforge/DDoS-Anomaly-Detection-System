#!/usr/bin/env python3
"""Item 5: Robust-Subset Experiment (Day 1 training only).

Drops flag features, Init_Win_*, Bwd IAT*, and Protocol.
Retrains RF, KNN, and Window-Stats LR on the remaining 14 features using Day 1 training only.
Evaluates Same-Day and Cross-Day (zero-shot and target-calibrated) next to full 25-feature models.
"""

import json
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
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

    # Grid search candidate thresholds
    sorted_scores = np.sort(np.unique(benign_scores))
    best_th = 0.5
    best_recall = -1.0
    best_fpr = 1.0

    # Use percentiles or unique scores
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

    # 1. Define Robust Feature Subset (14 features)
    features_full = json.load(open(root / "models/features.json"))["selected_features"]
    dropped_features = [
        # Flag features
        "ACK Flag Count", "URG Flag Count", "CWE Flag Count", "Fwd PSH Flags",
        # Init Win features
        "Init_Win_bytes_forward", "Init_Win_bytes_backward",
        # Bwd IAT features
        "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Min", "Bwd IAT Max",
        # Protocol
        "Protocol"
    ]
    robust_features = [f for f in features_full if f not in dropped_features]

    print(f"Full feature count: {len(features_full)}")
    print(f"Dropped features ({len(dropped_features)}): {dropped_features}")
    print(f"Robust subset ({len(robust_features)}): {robust_features}")

    # 2. Load Day 1 Train, Val, Same-Day Test, and Cross-Day Test splits
    df_train = pd.read_parquet(processed_dir / "train.parquet")
    df_val = pd.read_parquet(processed_dir / "val.parquet")
    df_same = pd.read_parquet(processed_dir / "test_same_day.parquet")
    df_cross = pd.read_parquet(processed_dir / "test_cross_day.parquet")

    y_train = (df_train["Normalized_Label"].str.upper() != "BENIGN").astype(int).values
    y_val = (df_val["Normalized_Label"].str.upper() != "BENIGN").astype(int).values
    y_same = (df_same["Normalized_Label"].str.upper() != "BENIGN").astype(int).values
    y_cross = (df_cross["Normalized_Label"].str.upper() != "BENIGN").astype(int).values

    # Fit a new scaler on Day 1 training data ONLY for the robust 14 features
    scaler_robust = StandardScaler()
    X_train_rob = scaler_robust.fit_transform(df_train[robust_features].values)
    X_val_rob = scaler_robust.transform(df_val[robust_features].values)
    X_same_rob = scaler_robust.transform(df_same[robust_features].values)
    X_cross_rob = scaler_robust.transform(df_cross[robust_features].values)

    # Cross-day calibration indices: 50% split on benign
    idx_b_cross = np.where(y_cross == 0)[0]
    n_cal = len(idx_b_cross) // 2
    idx_cal = idx_b_cross[:n_cal]
    idx_eval = idx_b_cross[n_cal:]
    idx_a_cross = np.where(y_cross == 1)[0]

    results_models = {}

    # --- MODEL 1: Random Forest (Flow) ---
    print("\n--- Training Robust Random Forest (14 features) on Day 1 ---")
    rf_robust = RandomForestClassifier(n_estimators=100, max_depth=15, n_jobs=-1, random_state=42)
    rf_robust.fit(X_train_rob, y_train)

    p_val_rf = rf_robust.predict_proba(X_val_rob)[:, 1]
    th_val_rf, _, _ = find_optimal_threshold(y_val, p_val_rf, target_max_fpr=0.01)

    p_same_rf = rf_robust.predict_proba(X_same_rob)[:, 1]
    res_same_rf = evaluate_binary_predictions(y_same, p_same_rf, th_val_rf)

    p_cross_rf = rf_robust.predict_proba(X_cross_rob)[:, 1]
    res_cross_zs_rf = evaluate_binary_predictions(y_cross, p_cross_rf, th_val_rf)

    # Calibrated threshold on cross-day benign
    th_cal_rf = float(np.percentile(p_cross_rf[idx_cal], 99.0))
    # Evaluate calibrated on holdout eval benign + all attack
    y_cross_cal = np.concatenate([np.zeros(len(idx_eval)), np.ones(len(idx_a_cross))])
    p_cross_cal_rf = np.concatenate([p_cross_rf[idx_eval], p_cross_rf[idx_a_cross]])
    res_cross_cal_rf = evaluate_binary_predictions(y_cross_cal, p_cross_cal_rf, th_cal_rf)

    results_models["Random Forest (Robust 14-Feat)"] = {
        "feature_set": "Robust 14 Features (No flags, No Init_Win, No Bwd IAT, No Protocol)",
        "level": "Flow",
        "same_day_zero_shot": res_same_rf,
        "cross_day_zero_shot": res_cross_zs_rf,
        "cross_day_calibrated": res_cross_cal_rf,
    }

    # --- MODEL 2: KNN (Flow) ---
    print("\n--- Training Robust KNN (14 features) on Day 1 ---")
    knn_robust = KNeighborsClassifier(n_neighbors=5, n_jobs=-1)
    knn_robust.fit(X_train_rob, y_train)

    p_val_knn = knn_robust.predict_proba(X_val_rob)[:, 1]
    th_val_knn, _, _ = find_optimal_threshold(y_val, p_val_knn, target_max_fpr=0.01)

    p_same_knn = knn_robust.predict_proba(X_same_rob)[:, 1]
    res_same_knn = evaluate_binary_predictions(y_same, p_same_knn, th_val_knn)

    p_cross_knn = knn_robust.predict_proba(X_cross_rob)[:, 1]
    res_cross_zs_knn = evaluate_binary_predictions(y_cross, p_cross_knn, th_val_knn)

    th_cal_knn = float(np.percentile(p_cross_knn[idx_cal], 99.0))
    p_cross_cal_knn = np.concatenate([p_cross_knn[idx_eval], p_cross_knn[idx_a_cross]])
    res_cross_cal_knn = evaluate_binary_predictions(y_cross_cal, p_cross_cal_knn, th_cal_knn)

    results_models["KNN (Robust 14-Feat)"] = {
        "feature_set": "Robust 14 Features (No flags, No Init_Win, No Bwd IAT, No Protocol)",
        "level": "Flow",
        "same_day_zero_shot": res_same_knn,
        "cross_day_zero_shot": res_cross_zs_knn,
        "cross_day_calibrated": res_cross_cal_knn,
    }

    # --- MODEL 3: Logistic Regression on Window Statistics (28 window stats: 14 mean + 14 std) ---
    print("\n--- Training Robust Window-Stats Logistic Regression (28 window stats) on Day 1 ---")
    train_npz = np.load(processed_dir / "lstm_train.npz")
    val_npz = np.load(processed_dir / "lstm_val.npz")
    same_npz = np.load(processed_dir / "lstm_test_same_day.npz")
    cross_npz = np.load(processed_dir / "lstm_test_cross_day.npz")

    # Indices of robust features in full 25
    robust_indices = [features_full.index(f) for f in robust_features]

    def extract_robust_window_stats(X_windows):
        X_sub = X_windows[:, :, robust_indices]
        m = np.mean(X_sub, axis=1)
        s = np.std(X_sub, axis=1)
        return np.hstack([m, s])

    W_train = extract_robust_window_stats(train_npz["X"])
    yw_train = train_npz["y"].astype(int)
    W_val = extract_robust_window_stats(val_npz["X"])
    yw_val = val_npz["y"].astype(int)
    W_same = extract_robust_window_stats(same_npz["X"])
    yw_same = same_npz["y"].astype(int)
    W_cross = extract_robust_window_stats(cross_npz["X"])
    yw_cross = cross_npz["y"].astype(int)

    scaler_ws = StandardScaler()
    W_train_sc = scaler_ws.fit_transform(W_train)
    W_val_sc = scaler_ws.transform(W_val)
    W_same_sc = scaler_ws.transform(W_same)
    W_cross_sc = scaler_ws.transform(W_cross)

    lr_robust = LogisticRegression(max_iter=1000, random_state=42)
    lr_robust.fit(W_train_sc, yw_train)

    p_val_lr = lr_robust.predict_proba(W_val_sc)[:, 1]
    th_val_lr, _, _ = find_optimal_threshold(yw_val, p_val_lr, target_max_fpr=0.01)

    p_same_lr = lr_robust.predict_proba(W_same_sc)[:, 1]
    res_same_lr = evaluate_binary_predictions(yw_same, p_same_lr, th_val_lr)

    p_cross_lr = lr_robust.predict_proba(W_cross_sc)[:, 1]
    res_cross_zs_lr = evaluate_binary_predictions(yw_cross, p_cross_lr, th_val_lr)

    idx_bw_cross = np.where(yw_cross == 0)[0]
    n_cal_w = len(idx_bw_cross) // 2
    idx_cal_w = idx_bw_cross[:n_cal_w]
    idx_eval_w = idx_bw_cross[n_cal_w:]
    idx_aw_cross = np.where(yw_cross == 1)[0]

    th_cal_lr = float(np.percentile(p_cross_lr[idx_cal_w], 99.0))
    yw_cross_cal = np.concatenate([np.zeros(len(idx_eval_w)), np.ones(len(idx_aw_cross))])
    p_cross_cal_lr = np.concatenate([p_cross_lr[idx_eval_w], p_cross_lr[idx_aw_cross]])
    res_cross_cal_lr = evaluate_binary_predictions(yw_cross_cal, p_cross_cal_lr, th_cal_lr)

    results_models["Logistic Regression Window-Stats (Robust 28-Stat)"] = {
        "feature_set": "Robust 14 Features (28 Window Stats: 14 Mean + 14 Std)",
        "level": "Window",
        "same_day_zero_shot": res_same_lr,
        "cross_day_zero_shot": res_cross_zs_lr,
        "cross_day_calibrated": res_cross_cal_lr,
    }

    # Load Full 25-feature models baseline for comparison from metrics.json
    metrics_path = root / "results/metrics.json"
    full_metrics = json.load(open(metrics_path))

    comparison_table = [
        {
            "model": "Random Forest (Flow)",
            "same_day_zero_shot": {
                "full_25_feat": {
                    "threshold": full_metrics["Random Forest (Same-Day Zero-Shot)"]["threshold"],
                    "recall": full_metrics["Random Forest (Same-Day Zero-Shot)"]["recall"],
                    "fpr": full_metrics["Random Forest (Same-Day Zero-Shot)"]["fpr"],
                    "roc_auc": full_metrics["Random Forest (Same-Day Zero-Shot)"]["roc_auc"],
                    "f1": full_metrics["Random Forest (Same-Day Zero-Shot)"]["f1"],
                },
                "robust_14_feat": {
                    "threshold": res_same_rf["threshold"],
                    "recall": res_same_rf["recall"],
                    "fpr": res_same_rf["fpr"],
                    "roc_auc": res_same_rf["roc_auc"],
                    "f1": res_same_rf["f1_score"],
                }
            },
            "cross_day_zero_shot": {
                "full_25_feat": {
                    "threshold": full_metrics["Random Forest (Cross-Day Zero-Shot)"]["threshold"],
                    "recall": full_metrics["Random Forest (Cross-Day Zero-Shot)"]["recall"],
                    "fpr": full_metrics["Random Forest (Cross-Day Zero-Shot)"]["fpr"],
                    "roc_auc": full_metrics["Random Forest (Cross-Day Zero-Shot)"]["roc_auc"],
                    "f1": full_metrics["Random Forest (Cross-Day Zero-Shot)"]["f1"],
                },
                "robust_14_feat": {
                    "threshold": res_cross_zs_rf["threshold"],
                    "recall": res_cross_zs_rf["recall"],
                    "fpr": res_cross_zs_rf["fpr"],
                    "roc_auc": res_cross_zs_rf["roc_auc"],
                    "f1": res_cross_zs_rf["f1_score"],
                }
            },
            "cross_day_target_calibrated": {
                "full_25_feat": {
                    "threshold": full_metrics["Random Forest (Cross-Day Target-Calibrated)"]["threshold"],
                    "recall": full_metrics["Random Forest (Cross-Day Target-Calibrated)"]["recall"],
                    "fpr": full_metrics["Random Forest (Cross-Day Target-Calibrated)"]["fpr"],
                    "roc_auc": full_metrics["Random Forest (Cross-Day Target-Calibrated)"]["roc_auc"],
                    "f1": full_metrics["Random Forest (Cross-Day Target-Calibrated)"]["f1"],
                },
                "robust_14_feat": {
                    "threshold": res_cross_cal_rf["threshold"],
                    "recall": res_cross_cal_rf["recall"],
                    "fpr": res_cross_cal_rf["fpr"],
                    "roc_auc": res_cross_cal_rf["roc_auc"],
                    "f1": res_cross_cal_rf["f1_score"],
                }
            }
        },
        {
            "model": "KNN (Flow)",
            "same_day_zero_shot": {
                "full_25_feat": {
                    "threshold": full_metrics["KNN (Same-Day Zero-Shot)"]["threshold"],
                    "recall": full_metrics["KNN (Same-Day Zero-Shot)"]["recall"],
                    "fpr": full_metrics["KNN (Same-Day Zero-Shot)"]["fpr"],
                    "roc_auc": full_metrics["KNN (Same-Day Zero-Shot)"]["roc_auc"],
                    "f1": full_metrics["KNN (Same-Day Zero-Shot)"]["f1"],
                },
                "robust_14_feat": {
                    "threshold": res_same_knn["threshold"],
                    "recall": res_same_knn["recall"],
                    "fpr": res_same_knn["fpr"],
                    "roc_auc": res_same_knn["roc_auc"],
                    "f1": res_same_knn["f1_score"],
                }
            },
            "cross_day_zero_shot": {
                "full_25_feat": {
                    "threshold": full_metrics["KNN (Cross-Day Zero-Shot)"]["threshold"],
                    "recall": full_metrics["KNN (Cross-Day Zero-Shot)"]["recall"],
                    "fpr": full_metrics["KNN (Cross-Day Zero-Shot)"]["fpr"],
                    "roc_auc": full_metrics["KNN (Cross-Day Zero-Shot)"]["roc_auc"],
                    "f1": full_metrics["KNN (Cross-Day Zero-Shot)"]["f1"],
                },
                "robust_14_feat": {
                    "threshold": res_cross_zs_knn["threshold"],
                    "recall": res_cross_zs_knn["recall"],
                    "fpr": res_cross_zs_knn["fpr"],
                    "roc_auc": res_cross_zs_knn["roc_auc"],
                    "f1": res_cross_zs_knn["f1_score"],
                }
            },
            "cross_day_target_calibrated": {
                "full_25_feat": {
                    "threshold": full_metrics["KNN (Cross-Day Target-Calibrated)"]["threshold"],
                    "recall": full_metrics["KNN (Cross-Day Target-Calibrated)"]["recall"],
                    "fpr": full_metrics["KNN (Cross-Day Target-Calibrated)"]["fpr"],
                    "roc_auc": full_metrics["KNN (Cross-Day Target-Calibrated)"]["roc_auc"],
                    "f1": full_metrics["KNN (Cross-Day Target-Calibrated)"]["f1"],
                },
                "robust_14_feat": {
                    "threshold": res_cross_cal_knn["threshold"],
                    "recall": res_cross_cal_knn["recall"],
                    "fpr": res_cross_cal_knn["fpr"],
                    "roc_auc": res_cross_cal_knn["roc_auc"],
                    "f1": res_cross_cal_knn["f1_score"],
                }
            }
        },
        {
            "model": "Logistic Regression (Window-Stats)",
            "same_day_zero_shot": {
                "full_25_feat": {
                    "threshold": full_metrics["smooth_model_baselines"]["logistic_regression"]["same_day_zero_shot"]["threshold"],
                    "recall": full_metrics["smooth_model_baselines"]["logistic_regression"]["same_day_zero_shot"]["recall"],
                    "fpr": full_metrics["smooth_model_baselines"]["logistic_regression"]["same_day_zero_shot"]["fpr"],
                    "roc_auc": full_metrics["smooth_model_baselines"]["logistic_regression"]["same_day_zero_shot"]["roc_auc"],
                    "f1": full_metrics["smooth_model_baselines"]["logistic_regression"]["same_day_zero_shot"]["f1"],
                },
                "robust_14_feat": {
                    "threshold": res_same_lr["threshold"],
                    "recall": res_same_lr["recall"],
                    "fpr": res_same_lr["fpr"],
                    "roc_auc": res_same_lr["roc_auc"],
                    "f1": res_same_lr["f1_score"],
                }
            },
            "cross_day_zero_shot": {
                "full_25_feat": {
                    "threshold": full_metrics["smooth_model_baselines"]["logistic_regression"]["cross_day_zero_shot"]["threshold"],
                    "recall": full_metrics["smooth_model_baselines"]["logistic_regression"]["cross_day_zero_shot"]["recall"],
                    "fpr": full_metrics["smooth_model_baselines"]["logistic_regression"]["cross_day_zero_shot"]["fpr"],
                    "roc_auc": full_metrics["smooth_model_baselines"]["logistic_regression"]["cross_day_zero_shot"]["roc_auc"],
                    "f1": full_metrics["smooth_model_baselines"]["logistic_regression"]["cross_day_zero_shot"]["f1"],
                },
                "robust_14_feat": {
                    "threshold": res_cross_zs_lr["threshold"],
                    "recall": res_cross_zs_lr["recall"],
                    "fpr": res_cross_zs_lr["fpr"],
                    "roc_auc": res_cross_zs_lr["roc_auc"],
                    "f1": res_cross_zs_lr["f1_score"],
                }
            },
            "cross_day_target_calibrated": {
                "full_25_feat": {
                    "threshold": full_metrics["smooth_model_baselines"]["logistic_regression"]["cross_day_calibrated"]["threshold"],
                    "recall": full_metrics["smooth_model_baselines"]["logistic_regression"]["cross_day_calibrated"]["recall"],
                    "fpr": full_metrics["smooth_model_baselines"]["logistic_regression"]["cross_day_calibrated"]["fpr"],
                    "roc_auc": full_metrics["smooth_model_baselines"]["logistic_regression"]["cross_day_calibrated"]["roc_auc"],
                    "f1": full_metrics["smooth_model_baselines"]["logistic_regression"]["cross_day_calibrated"]["f1"],
                },
                "robust_14_feat": {
                    "threshold": res_cross_cal_lr["threshold"],
                    "recall": res_cross_cal_lr["recall"],
                    "fpr": res_cross_cal_lr["fpr"],
                    "roc_auc": res_cross_cal_lr["roc_auc"],
                    "f1": res_cross_cal_lr["f1_score"],
                }
            }
        }
    ]

    out_data = {
        "protocol_note": "Day 1 training only. Validation threshold chosen at target FPR <= 0.01. No lab data used to select the subset.",
        "dropped_features": dropped_features,
        "robust_features_14": robust_features,
        "models_evaluated": results_models,
        "comparison_table": comparison_table
    }

    out_file = root / "results/robust_subset_benchmark.json"
    with open(out_file, "w") as f:
        json.dump(out_data, f, indent=2)
    print(f"Wrote robust-subset benchmark to {out_file}")


if __name__ == "__main__":
    main()
