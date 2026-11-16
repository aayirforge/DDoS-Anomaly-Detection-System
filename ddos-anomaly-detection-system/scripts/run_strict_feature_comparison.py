"""Stricter 25-feature comparison: p5-p95 overlap, KS distance vs Train and Day 2, and binary-vs-count mismatch check."""

from __future__ import annotations

import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
import scipy.stats

from ddos_ads.config import load_config
from ddos_ads.features import load_selected_features


def compute_strict_metrics(
    lab_vals: np.ndarray,
    train_vals: np.ndarray,
    day2_vals: np.ndarray,
) -> dict:
    # 1. Percentiles
    lab_p5, lab_p50, lab_p95 = float(np.percentile(lab_vals, 5)), float(np.percentile(lab_vals, 50)), float(np.percentile(lab_vals, 95))
    tr_p5, tr_p50, tr_p95 = float(np.percentile(train_vals, 5)), float(np.percentile(train_vals, 50)), float(np.percentile(train_vals, 95))
    d2_p5, d2_p50, d2_p95 = float(np.percentile(day2_vals, 5)), float(np.percentile(day2_vals, 50)), float(np.percentile(day2_vals, 95))

    # 2. Binary check
    tr_unique = np.unique(np.round(train_vals, 4))
    lab_unique = np.unique(np.round(lab_vals, 4))
    is_tr_binary = set(tr_unique).issubset({0.0, 1.0, -0.0})
    is_lab_binary = set(lab_unique).issubset({0.0, 1.0})
    binary_mismatch = (is_tr_binary != is_lab_binary)

    # 3. p5-p95 Overlap with Train
    tr_overlap_start = max(lab_p5, tr_p5)
    tr_overlap_end = min(lab_p95, tr_p95)
    tr_has_overlap = bool(tr_overlap_end >= tr_overlap_start)

    # 4. p5-p95 Overlap with Day 2
    d2_overlap_start = max(lab_p5, d2_p5)
    d2_overlap_end = min(lab_p95, d2_p95)
    d2_has_overlap = bool(d2_overlap_end >= d2_overlap_start)

    # 5. Two-sample KS distance
    # Subsample if large for fast accurate computation
    ks_tr = scipy.stats.ks_2samp(lab_vals, train_vals).statistic
    ks_d2 = scipy.stats.ks_2samp(lab_vals, day2_vals).statistic

    # 6. Overall status determination
    reasons = []
    if binary_mismatch:
        status = "MISMATCH"
        reasons.append(f"Binary mismatch (Train={is_tr_binary}, Lab={is_lab_binary})")
    elif not tr_has_overlap and not d2_has_overlap:
        status = "DISJOINT"
        reasons.append("No p5-p95 overlap with Train or Day 2")
    elif ks_tr >= 0.70 and ks_d2 >= 0.70:
        status = "HIGH_SHIFT"
        reasons.append(f"High KS distance (D_tr={ks_tr:.2f}, D_d2={ks_d2:.2f})")
    elif ks_tr >= 0.35 or ks_d2 >= 0.35:
        status = "MOD_SHIFT"
        reasons.append(f"Moderate shift (D_tr={ks_tr:.2f}, D_d2={ks_d2:.2f})")
    else:
        status = "ALIGNED"
        reasons.append("Core ranges overlap, low KS distance")

    return {
        "lab": {"p5": lab_p5, "p50": lab_p50, "p95": lab_p95, "is_binary": is_lab_binary},
        "train": {"p5": tr_p5, "p50": tr_p50, "p95": tr_p95, "is_binary": is_tr_binary},
        "day2": {"p5": d2_p5, "p50": d2_p50, "p95": d2_p95},
        "tr_overlap": tr_has_overlap,
        "d2_overlap": d2_has_overlap,
        "ks_tr": float(ks_tr),
        "ks_d2": float(ks_d2),
        "binary_mismatch": binary_mismatch,
        "status": status,
        "reasons": "; ".join(reasons),
    }


def main():
    config = load_config()
    feats = load_selected_features(config.get_path("models_dir") / "features.json")
    scaler = joblib.load(config.get_path("models_dir") / "scaler.joblib")

    # Load unscaled Day 1 Train Benign
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

    # Load realigned Lab Benign (idle + busy)
    df_idle = pd.read_csv("lab/captures/lab_idle_aligned.csv")
    df_busy = pd.read_csv("lab/captures/lab_busy_aligned.csv")
    df_lab_combined = pd.concat([df_idle, df_busy], ignore_index=True)

    results = {}
    rows = []

    for f in feats:
        lab_v = df_lab_combined[f].to_numpy(dtype=float)
        tr_v = unscaled_train_benign[f].to_numpy(dtype=float)
        d2_v = unscaled_day2_benign[f].to_numpy(dtype=float)

        m = compute_strict_metrics(lab_v, tr_v, d2_v)
        results[f] = m

        tr_range = f"[{m['train']['p5']:.1f}, {m['train']['p95']:.1f}]"
        lab_range = f"[{m['lab']['p5']:.1f}, {m['lab']['p95']:.1f}]"
        rows.append({
            "Feature": f,
            "Train [p5, p95]": tr_range,
            "Lab [p5, p95]": lab_range,
            "Overlap Tr": "YES" if m["tr_overlap"] else "NO",
            "Overlap D2": "YES" if m["d2_overlap"] else "NO",
            "KS Train": round(m["ks_tr"], 3),
            "KS Day2": round(m["ks_d2"], 3),
            "Bin Mismatch": "YES" if m["binary_mismatch"] else "NO",
            "Status": m["status"],
            "Notes": m["reasons"],
        })

    summary_df = pd.DataFrame(rows)

    out_file = Path("results/lab_strict_feature_comparison.json")
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w") as fp:
        json.dump(results, fp, indent=2)

    print("\n" + "=" * 145)
    print("                 STRICT 25-FEATURE DISTRIBUTION & OVERLAP AUDIT: LAB vs TRAIN & DAY 2 BENIGN")
    print("=" * 145)
    hdr = (
        f"| {'Feature':<28} | {'Train [p5, p95]':<20} | {'Lab [p5, p95]':<20} | "
        f"{'Tr Ovl':<6} | {'D2 Ovl':<6} | {'KS Tr':<6} | {'KS D2':<6} | {'Bin Mis':<7} | {'Status':<10} | {'Notes':<30} |"
    )
    sep = f"|{'-'*30}|{'-'*22}|{'-'*22}|{'-'*8}|{'-'*8}|{'-'*8}|{'-'*8}|{'-'*9}|{'-'*12}|{'-'*32}|"
    print(hdr)
    print(sep)
    for _, r in summary_df.iterrows():
        print(
            f"| {r['Feature']:<28} | {r['Train [p5, p95]']:<20} | {r['Lab [p5, p95]']:<20} | "
            f"{r['Overlap Tr']:<6} | {r['Overlap D2']:<6} | {r['KS Train']:<6.3f} | {r['KS Day2']:<6.3f} | "
            f"{r['Bin Mismatch']:<7} | {r['Status']:<10} | {r['Notes']:<30} |"
        )
    print(sep)


if __name__ == "__main__":
    main()
