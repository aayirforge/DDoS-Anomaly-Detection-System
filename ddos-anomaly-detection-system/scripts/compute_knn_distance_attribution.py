#!/usr/bin/env python3
"""Item 3: KNN per-feature contribution to distance to 5 nearest neighbors for lab benign flows."""

import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd


def main():
    root = Path(__file__).resolve().parent.parent
    knn = joblib.load(root / "models/knn.joblib")
    scaler = joblib.load(root / "models/scaler.joblib")
    features = json.load(open(root / "models/features.json"))["selected_features"]

    # Load session 2 benign flows (Java extracted aligned)
    idle = pd.read_csv(root / "lab/captures/session2_java_aligned/lab_idle_aligned.csv")
    busy = pd.read_csv(root / "lab/captures/session2_java_aligned/lab_busy_aligned.csv")
    lab_benign = pd.concat([idle, busy], ignore_index=True)

    X = lab_benign[features].values
    Z = scaler.transform(X)

    # 5 nearest neighbors
    distances, indices = knn.kneighbors(Z, n_neighbors=5)
    X_train_scaled = knn._fit_X

    N = len(Z)
    n_feats = len(features)
    sq_diffs = np.zeros((N, 5, n_feats))
    abs_diffs = np.zeros((N, 5, n_feats))

    for k in range(5):
        neighbor_indices = indices[:, k]
        diff = Z - X_train_scaled[neighbor_indices]
        sq_diffs[:, k, :] = diff ** 2
        abs_diffs[:, k, :] = np.abs(diff)

    mean_sq_contrib = sq_diffs.mean(axis=(0, 1))
    mean_abs_contrib = abs_diffs.mean(axis=(0, 1))
    total_sq_dist = mean_sq_contrib.sum()
    pct_sq_contrib = (mean_sq_contrib / total_sq_dist) * 100.0

    # Sort descending
    sorted_idx = np.argsort(mean_sq_contrib)[::-1]

    feature_breakdown = []
    for rank, idx in enumerate(sorted_idx, 1):
        feat_name = features[idx]
        feature_breakdown.append({
            "rank": rank,
            "feature": feat_name,
            "mean_squared_distance_contribution": float(round(mean_sq_contrib[idx], 4)),
            "percentage_of_total_squared_distance": float(round(pct_sq_contrib[idx], 4)),
            "mean_absolute_difference_zscore": float(round(mean_abs_contrib[idx], 4)),
            "scaler_std_on_train": float(scaler.scale_[idx]),
            "scaler_mean_on_train": float(scaler.mean_[idx])
        })

    top_5 = feature_breakdown[:5]

    out_data = {
        "lab_benign_flows_evaluated": N,
        "n_neighbors": 5,
        "total_mean_squared_euclidean_distance": float(round(total_sq_dist, 4)),
        "mean_euclidean_distance": float(round(np.mean(distances), 4)),
        "top_5_features": top_5,
        "all_25_features": feature_breakdown,
        "takeaway": (
            f"The single feature '{top_5[0]['feature']}' accounts for {top_5[0]['percentage_of_total_squared_distance']:.2f}% "
            f"of the total squared distance between lab benign flows and their 5 nearest training neighbors. "
            f"This occurs because '{top_5[0]['feature']}' has an extremely small empirical standard deviation "
            f"on Day 1 training ({scaler.scale_[features.index(top_5[0]['feature'])]:.6f}), amplifying even minor millisecond-scale "
            f"network timing fluctuations by a factor of 1/sigma^2."
        )
    }

    out_file = root / "results/knn_distance_attribution.json"
    with open(out_file, "w") as f:
        json.dump(out_data, f, indent=2)
    print(f"Wrote KNN distance attribution to {out_file}")


if __name__ == "__main__":
    main()
