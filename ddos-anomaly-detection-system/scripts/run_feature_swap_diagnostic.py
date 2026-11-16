"""Feature-swap diagnostic: replace each of the 25 features one at a time with the train-benign median and report the mean change in RF and KNN scores."""

from __future__ import annotations

import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd

from ddos_ads.config import load_config
from ddos_ads.features import load_selected_features


def run_feature_swap_diagnostic():
    config = load_config()
    feats = load_selected_features(config.get_path("models_dir") / "features.json")
    scaler = joblib.load(config.get_path("models_dir") / "scaler.joblib")
    rf = joblib.load(config.get_path("models_dir") / "rf.joblib")
    knn = joblib.load(config.get_path("models_dir") / "knn.joblib")

    # 1. Train benign medians (unscaled)
    df_train = pd.read_parquet(config.get_path("processed_data_dir") / "train.parquet")
    train_benign = df_train[df_train["Label_Binary"] == 0]
    unscaled_train_b = pd.DataFrame(scaler.inverse_transform(train_benign[feats].values), columns=feats)
    train_medians = {f: float(unscaled_train_b[f].median()) for f in feats}

    # 2. Lab benign flows (unscaled)
    df_idle = pd.read_csv("lab/captures/lab_idle_aligned.csv")
    df_busy = pd.read_csv("lab/captures/lab_busy_aligned.csv")
    df_lab = pd.concat([df_idle, df_busy], ignore_index=True)

    X_lab_raw = df_lab[feats].values
    X_lab_scaled = scaler.transform(X_lab_raw)

    # Baseline scores
    rf_orig_p = rf.predict_proba(X_lab_scaled)[:, 1]

    bs = 50000
    def predict_knn(X_mat):
        res = []
        for i in range(0, len(X_mat), bs):
            res.append(knn.predict_proba(X_mat[i : i + bs])[:, 1])
        return np.concatenate(res)

    knn_orig_p = predict_knn(X_lab_scaled)

    rf_base_mean = float(np.mean(rf_orig_p))
    knn_base_mean = float(np.mean(knn_orig_p))

    diagnostic_rows = []
    structured_results = {
        "baseline_scores": {
            "rf_mean": round(rf_base_mean, 6),
            "knn_mean": round(knn_base_mean, 6),
            "sample_size": len(df_lab),
        },
        "feature_swaps": {},
    }

    for idx, f in enumerate(feats):
        X_swap_raw = X_lab_raw.copy()
        X_swap_raw[:, idx] = train_medians[f]
        X_swap_scaled = scaler.transform(X_swap_raw)

        rf_swap_p = rf.predict_proba(X_swap_scaled)[:, 1]
        knn_swap_p = predict_knn(X_swap_scaled)

        rf_new_mean = float(np.mean(rf_swap_p))
        knn_new_mean = float(np.mean(knn_swap_p))

        delta_rf = rf_new_mean - rf_base_mean
        delta_knn = knn_new_mean - knn_base_mean

        record = {
            "feature": f,
            "train_median": round(train_medians[f], 4),
            "lab_median": round(float(df_lab[f].median()), 4),
            "rf_mean_score": round(rf_new_mean, 6),
            "rf_delta": round(delta_rf, 6),
            "knn_mean_score": round(knn_new_mean, 6),
            "knn_delta": round(delta_knn, 6),
        }
        structured_results["feature_swaps"][f] = record

        diagnostic_rows.append({
            "Feature": f,
            "Train Median": train_medians[f],
            "Lab Median": float(df_lab[f].median()),
            "RF Baseline": rf_base_mean,
            "RF Swapped": rf_new_mean,
            "RF Delta": delta_rf,
            "KNN Baseline": knn_base_mean,
            "KNN Swapped": knn_new_mean,
            "KNN Delta": delta_knn,
        })

    # Sort rows by largest absolute impact on RF
    diagnostic_rows.sort(key=lambda r: abs(r["RF Delta"]), reverse=True)

    out_file = Path("results/lab_feature_swap_diagnostic.json")
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w") as fp:
        json.dump(structured_results, fp, indent=2)

    print("\n" + "=" * 135)
    print(f"             FEATURE-SWAP DIAGNOSTIC (Baseline RF Mean: {rf_base_mean:.4f} | KNN Mean: {knn_base_mean:.4f})")
    print("=" * 135)
    hdr = f"| {'Feature':<28} | {'Tr Med':<10} | {'Lab Med':<10} | {'RF New':<10} | {'RF Delta':<12} | {'KNN New':<10} | {'KNN Delta':<12} |"
    sep = f"|{'-'*30}|{'-'*12}|{'-'*12}|{'-'*12}|{'-'*14}|{'-'*12}|{'-'*14}|"
    print(hdr)
    print(sep)
    for r in diagnostic_rows:
        d_rf_str = f"{r['RF Delta']:+.6f}"
        d_knn_str = f"{r['KNN Delta']:+.6f}"
        print(
            f"| {r['Feature']:<28} | {r['Train Median']:<10.2f} | {r['Lab Median']:<10.2f} | "
            f"{r['RF Swapped']:<10.4f} | {d_rf_str:<12} | {r['KNN Swapped']:<10.4f} | {d_knn_str:<12} |"
        )
    print(sep)


if __name__ == "__main__":
    run_feature_swap_diagnostic()
