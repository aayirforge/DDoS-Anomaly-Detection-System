"""Comprehensive feature distribution comparison between Lab Benign flows, Day 1 Train Benign, and Day 2 Benign."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List, Tuple
import joblib
import numpy as np
import pandas as pd

from ddos_ads.config import load_config
from ddos_ads.features import load_selected_features
from ddos_ads.pcap_to_flows import align_flow_dataframe, CICFLOWMETER_TO_CIC2019_MAP


BACKWARD_HEAVY_FEATURES = [
    "Bwd Packets/s",
    "Down/Up Ratio",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Max",
    "Init_Win_bytes_backward",
    "Total Length of Bwd Packets",
    "Bwd IAT Total",
    "Bwd IAT Min",
    "Bwd Header Length",
    "Bwd IAT Max",
    "Total Backward Packets",
    "Bwd IAT Mean",
    "Bwd Packet Length Min",
]


def compute_distribution_metrics(series: pd.Series) -> Dict[str, float]:
    clean = pd.to_numeric(series, errors="coerce").dropna()
    if clean.empty:
        return {"min": 0.0, "median": 0.0, "p95": 0.0, "max": 0.0, "zero_pct": 100.0}
    vals = clean.values
    return {
        "min": float(np.min(vals)),
        "median": float(np.median(vals)),
        "p95": float(np.percentile(vals, 95)),
        "max": float(np.max(vals)),
        "zero_pct": float(np.mean(vals == 0.0) * 100.0),
    }


def analyze_feature_distributions(
    lab_idle_df: pd.DataFrame,
    lab_busy_df: pd.DataFrame,
    train_benign_unscaled: pd.DataFrame,
    day2_benign_unscaled: pd.DataFrame,
    features: List[str],
    ratio_threshold: float = 100.0,
) -> Tuple[Dict, pd.DataFrame]:
    lab_combined = pd.concat([lab_idle_df, lab_busy_df], ignore_index=True)
    rows = []
    structured_results = {}

    for f in features:
        train_stats = compute_distribution_metrics(train_benign_unscaled[f])
        day2_stats = compute_distribution_metrics(day2_benign_unscaled[f])
        idle_stats = compute_distribution_metrics(lab_idle_df[f])
        busy_stats = compute_distribution_metrics(lab_busy_df[f])
        total_stats = compute_distribution_metrics(lab_combined[f])

        # Check for all-zeros
        is_all_zero = (total_stats["max"] == 0.0 and total_stats["min"] == 0.0)

        # Ratio checks (Lab Total vs Day 1 Train)
        flag_reasons = []
        is_flagged = False

        if is_all_zero:
            if train_stats["max"] > 0:
                is_flagged = True
                flag_reasons.append("ALL_ZERO_IN_LAB")
        else:
            # Check max ratio
            if train_stats["max"] > 0 and total_stats["max"] > 0:
                r_max = total_stats["max"] / train_stats["max"]
                if r_max > ratio_threshold or r_max < (1.0 / ratio_threshold):
                    is_flagged = True
                    ratio_str = f"{r_max:.1f}x" if r_max >= 1 else f"1/{1/r_max:.1f}x"
                    flag_reasons.append(f"max_ratio({ratio_str})")

            # Check median ratio if both are non-zero
            if train_stats["median"] > 0 and total_stats["median"] > 0:
                r_med = total_stats["median"] / train_stats["median"]
                if r_med > ratio_threshold or r_med < (1.0 / ratio_threshold):
                    is_flagged = True
                    ratio_str = f"{r_med:.1f}x" if r_med >= 1 else f"1/{1/r_med:.1f}x"
                    flag_reasons.append(f"median_ratio({ratio_str})")

        status = "FLAGGED" if is_flagged else "OK"

        feature_record = {
            "feature": f,
            "train_benign": train_stats,
            "day2_benign": day2_stats,
            "lab_idle": idle_stats,
            "lab_busy": busy_stats,
            "lab_combined": total_stats,
            "is_all_zero": is_all_zero,
            "status": status,
            "flag_reasons": flag_reasons,
            "is_backward_heavy": f in BACKWARD_HEAVY_FEATURES,
        }
        structured_results[f] = feature_record

        rows.append({
            "Feature": f,
            "Train_Med": train_stats["median"],
            "Train_Max": train_stats["max"],
            "Day2_Med": day2_stats["median"],
            "Day2_Max": day2_stats["max"],
            "Lab_Med": total_stats["median"],
            "Lab_P95": total_stats["p95"],
            "Lab_Max": total_stats["max"],
            "Status": status,
            "Notes": "; ".join(flag_reasons) if flag_reasons else ("All-zero expected" if is_all_zero else "OK"),
        })

    summary_df = pd.DataFrame(rows)
    return structured_results, summary_df
