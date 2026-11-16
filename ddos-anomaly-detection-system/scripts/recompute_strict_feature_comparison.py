"""Strict 25-feature comparison on raw (unscaled) arrays with floating-point tolerance on overlap, sample sizes, and no speculative Notes."""

from __future__ import annotations

import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
import scipy.stats

from ddos_ads.config import load_config
from ddos_ads.features import load_selected_features


def compute_feature_metrics(
    lab_vals: np.ndarray,
    train_vals: np.ndarray,
    day2_vals: np.ndarray,
    tol: float = 1e-4,
) -> dict:
    lab_p5, lab_p50, lab_p95 = float(np.percentile(lab_vals, 5)), float(np.percentile(lab_vals, 50)), float(np.percentile(lab_vals, 95))
    tr_p5, tr_p50, tr_p95 = float(np.percentile(train_vals, 5)), float(np.percentile(train_vals, 50)), float(np.percentile(train_vals, 95))
    d2_p5, d2_p50, d2_p95 = float(np.percentile(day2_vals, 5)), float(np.percentile(day2_vals, 50)), float(np.percentile(day2_vals, 95))

    # Binary check: values strictly in {0, 1}
    tr_unique = np.unique(np.round(train_vals, 4))
    lab_unique = np.unique(np.round(lab_vals, 4))
    is_tr_binary = bool(set(tr_unique).issubset({0.0, 1.0, -0.0}))
    is_lab_binary = bool(set(lab_unique).issubset({0.0, 1.0}))
    binary_mismatch = bool(is_tr_binary != is_lab_binary)

    # p5-p95 Overlap checks with numerical tolerance
    # Overlap occurs if min(p95_1, p95_2) + tol >= max(p5_1, p5_2)
    tr_overlap = bool(min(lab_p95, tr_p95) + tol >= max(lab_p5, tr_p5))
    d2_overlap = bool(min(lab_p95, d2_p95) + tol >= max(lab_p5, d2_p5))

    # Two-sample KS test
    ks_tr = float(scipy.stats.ks_2samp(lab_vals, train_vals).statistic)
    ks_d2 = float(scipy.stats.ks_2samp(lab_vals, day2_vals).statistic)

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

    return {
        "train_p5": tr_p5,
        "train_p50": tr_p50,
        "train_p95": tr_p95,
        "day2_p5": d2_p5,
        "day2_p50": d2_p50,
        "day2_p95": d2_p95,
        "lab_p5": lab_p5,
        "lab_p50": lab_p50,
        "lab_p95": lab_p95,
        "tr_overlap": tr_overlap,
        "d2_overlap": d2_overlap,
        "ks_train": round(ks_tr, 4),
        "ks_day2": round(ks_d2, 4),
        "binary_mismatch": binary_mismatch,
        "status": status,
    }


def main():
    config = load_config()
    feats = load_selected_features(config.get_path("models_dir") / "features.json")
    scaler = joblib.load(config.get_path("models_dir") / "scaler.joblib")

    # Load unscaled Train Benign
    df_train = pd.read_parquet(config.get_path("processed_data_dir") / "train.parquet")
    train_benign = df_train[df_train["Label_Binary"] == 0]
    unscaled_train_benign = pd.DataFrame(
        scaler.inverse_transform(train_benign[feats].values),
        columns=feats,
    )

    # Load unscaled Day 2 Cross-Day Benign
    df_cross = pd.read_parquet(config.get_path("processed_data_dir") / "test_cross_day.parquet")
    day2_benign = df_cross[df_cross["Label_Binary"] == 0]
    unscaled_day2_benign = pd.DataFrame(
        scaler.inverse_transform(day2_benign[feats].values),
        columns=feats,
    )

    # Load realigned Lab Benign
    df_idle = pd.read_csv("lab/captures/lab_idle_aligned.csv")
    df_busy = pd.read_csv("lab/captures/lab_busy_aligned.csv")
    df_lab = pd.concat([df_idle, df_busy], ignore_index=True)

    n_train = len(unscaled_train_benign)
    n_day2 = len(unscaled_day2_benign)
    n_lab = len(df_lab)
    n_idle = len(df_idle)
    n_busy = len(df_busy)

    results = {
        "sample_sizes": {
            "train_benign": n_train,
            "day2_benign": n_day2,
            "lab_benign_total": n_lab,
            "lab_idle": n_idle,
            "lab_busy": n_busy,
        },
        "features": {},
    }

    for f in feats:
        tr_v = unscaled_train_benign[f].to_numpy(dtype=float)
        d2_v = unscaled_day2_benign[f].to_numpy(dtype=float)
        lab_v = df_lab[f].to_numpy(dtype=float)

        results["features"][f] = compute_feature_metrics(lab_v, tr_v, d2_v)

    out_file = Path("results/lab_feature_comparison_strict.json")
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w") as fp:
        json.dump(results, fp, indent=2)

    print(f"Sample Sizes: Train Benign N={n_train:,} | Day 2 Benign N={n_day2:,} | Lab Benign N={n_lab:,} (Idle: {n_idle:,}, Busy: {n_busy:,})")
    print("\n" + "=" * 125)
    print("                 25-FEATURE STRICT AUDIT: RAW DISTRIBUTIONS, KS DISTANCE & CORE OVERLAP")
    print("=" * 125)
    hdr = (
        f"| {'Feature':<28} | {'Train [p5, p95]':<20} | {'Day2 [p5, p95]':<20} | {'Lab [p5, p95]':<20} | "
        f"{'Tr Ovl':<6} | {'D2 Ovl':<6} | {'KS Tr':<6} | {'KS D2':<6} | {'Bin Mis':<7} | {'Status':<10} |"
    )
    sep = f"|{'-'*30}|{'-'*22}|{'-'*22}|{'-'*22}|{'-'*8}|{'-'*8}|{'-'*8}|{'-'*8}|{'-'*9}|{'-'*12}|"
    print(hdr)
    print(sep)
    for f, m in results["features"].items():
        tr_str = f"[{m['train_p5']:.1f}, {m['train_p95']:.1f}]"
        d2_str = f"[{m['day2_p5']:.1f}, {m['day2_p95']:.1f}]"
        lab_str = f"[{m['lab_p5']:.1f}, {m['lab_p95']:.1f}]"
        tr_ovl = "YES" if m["tr_overlap"] else "NO"
        d2_ovl = "YES" if m["d2_overlap"] else "NO"
        bin_mis = "YES" if m["binary_mismatch"] else "NO"
        print(
            f"| {f:<28} | {tr_str:<20} | {d2_str:<20} | {lab_str:<20} | "
            f"{tr_ovl:<6} | {d2_ovl:<6} | {m['ks_train']:<6.3f} | {m['ks_day2']:<6.3f} | "
            f"{bin_mis:<7} | {m['status']:<10} |"
        )
    print(sep)


if __name__ == "__main__":
    main()
