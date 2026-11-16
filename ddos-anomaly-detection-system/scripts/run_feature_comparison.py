"""Run full feature scale comparison across Day 1 Train Benign, Day 2 Benign, Lab Idle, and Lab Busy."""

from __future__ import annotations

import json
from pathlib import Path
import joblib
import pandas as pd

from ddos_ads.config import load_config
from ddos_ads.features import load_selected_features
from scripts.compare_lab_features import analyze_feature_distributions, BACKWARD_HEAVY_FEATURES


def main():
    config = load_config()
    features_path = config.get_path("models_dir") / "features.json"
    scaler_path = config.get_path("models_dir") / "scaler.joblib"
    train_path = config.get_path("processed_data_dir") / "train.parquet"
    cross_path = config.get_path("processed_data_dir") / "test_cross_day.parquet"

    feats = load_selected_features(features_path)
    scaler = joblib.load(scaler_path)

    # 1. Load train benign (unscaled)
    df_train = pd.read_parquet(train_path)
    train_benign = df_train[df_train["Label_Binary"] == 0]
    unscaled_train_benign = pd.DataFrame(
        scaler.inverse_transform(train_benign[feats].values),
        columns=feats,
    )

    # 2. Load Day 2 cross-day benign (unscaled)
    df_cross = pd.read_parquet(cross_path)
    day2_benign = df_cross[df_cross["Label_Binary"] == 0]
    unscaled_day2_benign = pd.DataFrame(
        scaler.inverse_transform(day2_benign[feats].values),
        columns=feats,
    )

    # 3. Load aligned lab flows
    lab_idle_aligned = pd.read_csv("lab/captures/lab_idle_aligned.csv")
    lab_busy_aligned = pd.read_csv("lab/captures/lab_busy_aligned.csv")

    lab_idle_feats = lab_idle_aligned[feats]
    lab_busy_feats = lab_busy_aligned[feats]

    # 4. Analyze distributions
    structured_results, summary_df = analyze_feature_distributions(
        lab_idle_df=lab_idle_feats,
        lab_busy_df=lab_busy_feats,
        train_benign_unscaled=unscaled_train_benign,
        day2_benign_unscaled=unscaled_day2_benign,
        features=feats,
        ratio_threshold=100.0,
    )

    # 5. Directionality assessment
    lab_combined = pd.concat([lab_idle_aligned, lab_busy_aligned], ignore_index=True)
    fwd_pkts_sum = float(lab_combined["Total Fwd Packets"].sum())
    bwd_pkts_sum = float(lab_combined["Total Backward Packets"].sum())
    fwd_bytes_sum = float(lab_combined["Total Length of Fwd Packets"].sum())
    bwd_bytes_sum = float(lab_combined["Total Length of Bwd Packets"].sum())

    directionality_report = {
        "client_to_server_is_forward": True,
        "total_fwd_packets": fwd_pkts_sum,
        "total_bwd_packets": bwd_pkts_sum,
        "total_fwd_bytes": fwd_bytes_sum,
        "total_bwd_bytes": bwd_bytes_sum,
        "overall_down_up_ratio": bwd_pkts_sum / max(1.0, fwd_pkts_sum),
        "backward_heavy_features_populated": [
            f for f in BACKWARD_HEAVY_FEATURES if structured_results[f]["lab_combined"]["max"] > 0
        ],
        "backward_heavy_features_zero": [
            f for f in BACKWARD_HEAVY_FEATURES if structured_results[f]["lab_combined"]["max"] == 0
        ],
    }

    output_data = {
        "features_analyzed": len(feats),
        "lab_idle_flows": len(lab_idle_feats),
        "lab_busy_flows": len(lab_busy_feats),
        "lab_total_flows": len(lab_combined),
        "train_benign_flows": len(unscaled_train_benign),
        "day2_benign_flows": len(unscaled_day2_benign),
        "feature_distributions": structured_results,
        "directionality": directionality_report,
    }

    out_json = Path("results/lab_feature_comparison.json")
    out_json.parent.mkdir(parents=True, exist_ok=True)
    with open(out_json, "w") as f:
        json.dump(output_data, f, indent=2)

    print("\n" + "=" * 135)
    print("               LAB BENIGN vs DAY 1 TRAIN BENIGN vs DAY 2 BENIGN: FEATURE DISTRIBUTION COMPARISON")
    print("=" * 135)
    hdr = f"| {'Feature':<28} | {'Train Med':<10} | {'Train Max':<12} | {'Day2 Med':<10} | {'Lab Med':<10} | {'Lab P95':<10} | {'Lab Max':<12} | {'Status':<8} | {'Notes':<30} |"
    sep = f"|{'-'*30}|{'-'*12}|{'-'*14}|{'-'*12}|{'-'*12}|{'-'*12}|{'-'*14}|{'-'*10}|{'-'*32}|"
    print(hdr)
    print(sep)
    for _, r in summary_df.iterrows():
        print(
            f"| {r['Feature']:<28} | {r['Train_Med']:<10.2f} | {r['Train_Max']:<12.1f} | "
            f"{r['Day2_Med']:<10.2f} | {r['Lab_Med']:<10.2f} | {r['Lab_P95']:<10.2f} | "
            f"{r['Lab_Max']:<12.1f} | {r['Status']:<8} | {r['Notes']:<30} |"
        )
    print(sep)
    print(f"\nDirectionality Check:")
    print(f"Total Fwd Packets: {fwd_pkts_sum:,.0f} | Total Bwd Packets: {bwd_pkts_sum:,.0f} | Ratio: {directionality_report['overall_down_up_ratio']:.3f}")
    print(f"Total Fwd Bytes: {fwd_bytes_sum:,.0f} | Total Bwd Bytes: {bwd_bytes_sum:,.0f}")
    print(f"Backward-heavy features populated: {len(directionality_report['backward_heavy_features_populated'])}/{len(BACKWARD_HEAVY_FEATURES)}")
    if directionality_report['backward_heavy_features_zero']:
        print(f"Backward-heavy features all zero: {directionality_report['backward_heavy_features_zero']}")
    print("=" * 135 + "\n")


if __name__ == "__main__":
    main()
