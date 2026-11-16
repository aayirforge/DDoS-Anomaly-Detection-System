"""Comprehensive Evaluation of Lab Session 2 using Java CICFlowMeter.

Covers:
1. Java CICFlowMeter extraction and schema alignment with Direction Inversion Rule.
2. 25-feature distribution comparison against unscaled Train Benign (P(train=1) with n/N).
3. Payload vs Packet Length comparison for SYN floods (Python vs Java).
4. Rescoring at fixed Day 1 validation thresholds with step-size 5 windows.
5. Reconciliation of 5,672 vs 5,622 SYN flows.
"""

from __future__ import annotations

import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score
import scipy.stats
import torch

from ddos_ads.config import load_config
from ddos_ads.features import load_selected_features
from ddos_ads.pcap_to_flows import align_flow_dataframe
from ddos_ads.train_lstm import LSTMAnomalyClassifier


def make_windows(X: np.ndarray, win_size: int = 10, step_size: int = 5) -> np.ndarray:
    if len(X) < win_size:
        return np.empty((0, win_size, X.shape[1]), dtype=np.float32)
    return np.array([X[i : i + win_size] for i in range(0, len(X) - win_size + 1, step_size)], dtype=np.float32)


def get_window_stats(W: np.ndarray) -> np.ndarray:
    if len(W) == 0:
        return np.empty((0, 50), dtype=np.float32)
    return np.hstack([np.mean(W, axis=1), np.std(W, axis=1)])


def get_win_aggs(p: np.ndarray, win_size: int = 10, step_size: int = 5) -> tuple[np.ndarray, np.ndarray]:
    if len(p) < win_size:
        return np.array([]), np.array([])
    mx = np.array([np.max(p[i : i + win_size]) for i in range(0, len(p) - win_size + 1, step_size)])
    mn = np.array([np.mean(p[i : i + win_size]) for i in range(0, len(p) - win_size + 1, step_size)])
    return mx, mn


def main() -> None:
    config = load_config()
    feats = load_selected_features(config.get_path("models_dir") / "features.json")
    scaler = joblib.load(config.get_path("models_dir") / "scaler.joblib")
    rf = joblib.load(config.get_path("models_dir") / "rf.joblib")
    knn = joblib.load(config.get_path("models_dir") / "knn.joblib")

    # Load unscaled train data
    train_df = pd.read_parquet(config.get_path("processed_data_dir") / "train.parquet")
    train_b_scaled = train_df[train_df["Label_Binary"] == 0][feats]
    train_b = pd.DataFrame(scaler.inverse_transform(train_b_scaled.values), columns=feats)

    # Load Java raw CSVs
    raw_dir = Path("lab/captures/session2_java")
    df_idle_raw = pd.read_csv(raw_dir / "idle_classic.pcap_Flow.csv")
    df_busy_raw = pd.read_csv(raw_dir / "busy_classic.pcap_Flow.csv")
    df_syn_raw = pd.read_csv(raw_dir / "syn_classic.pcap_Flow.csv")

    # Align with direction rule
    feats_idle, meta_idle = align_flow_dataframe(df_idle_raw, feats, extractor="java", apply_direction_rule=True)
    feats_busy, meta_busy = align_flow_dataframe(df_busy_raw, feats, extractor="java", apply_direction_rule=True)
    feats_syn, meta_syn = align_flow_dataframe(df_syn_raw, feats, extractor="java", apply_direction_rule=True)

    # Save aligned CSVs
    aligned_dir = Path("lab/captures/session2_java_aligned")
    aligned_dir.mkdir(parents=True, exist_ok=True)
    pd.concat([meta_idle, feats_idle], axis=1).to_csv(aligned_dir / "lab_idle_aligned.csv", index=False)
    pd.concat([meta_busy, feats_busy], axis=1).to_csv(aligned_dir / "lab_busy_aligned.csv", index=False)
    pd.concat([meta_syn, feats_syn], axis=1).to_csv(aligned_dir / "lab_syn_flood_aligned.csv", index=False)

    # Attack flow filter: generator is 172.20.0.3
    is_syn_attack = (meta_syn["Source IP"] == "172.20.0.3")
    feats_syn_attack = feats_syn[is_syn_attack].reset_index(drop=True)
    meta_syn_attack = meta_syn[is_syn_attack].reset_index(drop=True)

    # Combined lab benign
    lab_b = pd.concat([feats_idle, feats_busy], ignore_index=True)

    # =========================================================================
    # PART 1: 25-Feature Comparison
    # =========================================================================
    binary_cols = {"ACK Flag Count", "URG Flag Count", "CWE Flag Count", "Fwd PSH Flags"}
    feat_comparison = []

    for f in feats:
        tr = train_b[f].to_numpy(dtype=float)
        lb = lab_b[f].to_numpy(dtype=float)
        ks_res = scipy.stats.ks_2samp(tr, lb)

        if f in binary_cols:
            n_tr_1 = int(np.sum(np.round(tr, 4) == 1.0))
            n_lb_1 = int(np.sum(np.round(lb, 4) == 1.0))
            p_tr = n_tr_1 / len(tr)
            p_lb = n_lb_1 / len(lb)
            feat_comparison.append({
                "feature": f,
                "is_binary": True,
                "train_p1_count": n_tr_1,
                "train_total": len(tr),
                "train_p1_ratio": round(p_tr, 4),
                "train_p1_str": f"{n_tr_1:,} / {len(tr):,} ({p_tr:.4f})",
                "lab_p1_count": n_lb_1,
                "lab_total": len(lb),
                "lab_p1_ratio": round(p_lb, 4),
                "lab_p1_str": f"{n_lb_1:,} / {len(lb):,} ({p_lb:.4f})",
                "ks_stat": round(float(ks_res.statistic), 4),
                "ks_pval": float(ks_res.pvalue),
            })
        else:
            tr_min, tr_p5, tr_med, tr_p95, tr_max = np.percentile(tr, [0, 5, 50, 95, 100])
            lb_min, lb_p5, lb_med, lb_p95, lb_max = np.percentile(lb, [0, 5, 50, 95, 100])
            overlap = bool(not (lb_p95 < tr_p5 or lb_p5 > tr_p95))
            feat_comparison.append({
                "feature": f,
                "is_binary": False,
                "train_min": round(float(tr_min), 2),
                "train_p5": round(float(tr_p5), 2),
                "train_med": round(float(tr_med), 2),
                "train_p95": round(float(tr_p95), 2),
                "train_max": round(float(tr_max), 2),
                "lab_min": round(float(lb_min), 2),
                "lab_p5": round(float(lb_p5), 2),
                "lab_med": round(float(lb_med), 2),
                "lab_p95": round(float(lb_p95), 2),
                "lab_max": round(float(lb_max), 2),
                "ks_stat": round(float(ks_res.statistic), 4),
                "ks_pval": float(ks_res.pvalue),
                "p5_p95_overlap": overlap,
            })

    # =========================================================================
    # PART 2: Python vs Java SYN Flood Packet Length Comparison
    # =========================================================================
    py_syn_aligned = pd.read_csv("lab/captures/session2/lab_syn_flood_aligned.csv")
    py_attack = py_syn_aligned[py_syn_aligned["Source IP"] == "172.20.0.3"]

    extractor_syn_comparison = {
        "python_extractor": {
            "n_attack_flows": len(py_attack),
            "totlen_fwd_pkts": {
                "min": float(py_attack["Total Length of Fwd Packets"].min()),
                "median": float(py_attack["Total Length of Fwd Packets"].median()),
                "max": float(py_attack["Total Length of Fwd Packets"].max()),
            },
            "fwd_pkt_len_max": {
                "min": float(py_attack["Fwd Packet Length Max"].min()),
                "median": float(py_attack["Fwd Packet Length Max"].median()),
                "max": float(py_attack["Fwd Packet Length Max"].max()),
            },
            "explanation": "Includes 20B IP header + 20B/34B TCP headers (measuring total frame/packet size).",
        },
        "java_extractor": {
            "n_attack_flows": len(feats_syn_attack),
            "totlen_fwd_pkts": {
                "min": float(feats_syn_attack["Total Length of Fwd Packets"].min()),
                "median": float(feats_syn_attack["Total Length of Fwd Packets"].median()),
                "max": float(feats_syn_attack["Total Length of Fwd Packets"].max()),
            },
            "fwd_pkt_len_max": {
                "min": float(feats_syn_attack["Fwd Packet Length Max"].min()),
                "median": float(feats_syn_attack["Fwd Packet Length Max"].median()),
                "max": float(feats_syn_attack["Fwd Packet Length Max"].max()),
            },
            "explanation": "Measures pure TCP payload length (0 bytes for SYN floods), exactly matching CIC-DDoS2019 dataset.",
        },
    }

    # =========================================================================
    # PART 3: Reconciliation of 5,672 vs 5,622 SYN Flows
    # =========================================================================
    raw_session2_py = pd.read_csv("lab/captures/session2/lab_syn_flood_aligned.csv")
    ip_counts = raw_session2_py["Source IP"].value_counts().to_dict()

    flow_reconciliation = {
        "total_extracted_flows_python": len(raw_session2_py),
        "attack_flows_hping3_172_20_0_3": int(ip_counts.get("172.20.0.3", 0)),
        "benign_concurrent_http_172_20_0_4": int(ip_counts.get("172.20.0.4", 0)),
        "docker_host_ssdp_172_20_0_1": int(ip_counts.get("172.20.0.1", 0)),
        "sum_verified": int(ip_counts.get("172.20.0.3", 0) + ip_counts.get("172.20.0.4", 0) + ip_counts.get("172.20.0.1", 0)),
        "explanation": "The 5,672 flows in lab_syn_flood.pcap contain 5,622 attack flows from 172.20.0.3, 49 background client HTTP flows from 172.20.0.4, and 1 SSDP multicast flow from 172.20.0.1.",
    }

    # =========================================================================
    # PART 4: Rescoring at Fixed Day 1 Validation Thresholds
    # =========================================================================
    X_idle = scaler.transform(feats_idle.values)
    X_busy = scaler.transform(feats_busy.values)
    X_benign = np.vstack([X_idle, X_busy])
    X_attack = scaler.transform(feats_syn_attack.values)

    W_idle = make_windows(X_idle, win_size=10, step_size=5)
    W_busy = make_windows(X_busy, win_size=10, step_size=5)
    W_benign = np.vstack([W_idle, W_busy])
    W_attack = make_windows(X_attack, win_size=10, step_size=5)

    # Train Window-Stats LR
    train_npz = np.load(config.get_path("processed_data_dir") / "lstm_train.npz")
    stats_scaler = StandardScaler()
    X_tr_stats = stats_scaler.fit_transform(get_window_stats(train_npz["X"]))
    lr = LogisticRegression(max_iter=1000, random_state=42)
    lr.fit(X_tr_stats, train_npz["y"].astype(int))

    # Load LSTM
    ckpt = torch.load(config.get_path("models_dir") / "lstm.pt", map_location="cpu")
    lstm = LSTMAnomalyClassifier(ckpt["input_dim"], ckpt["hidden_dim"], ckpt["num_layers"], 0.0)
    lstm.load_state_dict(ckpt["model_state_dict"])
    lstm.eval()

    def get_lstm_probs(W):
        if len(W) == 0:
            return np.array([])
        with torch.no_grad():
            logits = lstm(torch.from_numpy(W)).cpu().numpy().flatten()
            return 1.0 / (1.0 + np.exp(-logits))

    # Flow probabilities
    rf_p_benign = rf.predict_proba(X_benign)[:, 1]
    rf_p_attack = rf.predict_proba(X_attack)[:, 1]

    knn_p_benign = knn.predict_proba(X_benign)[:, 1]
    knn_p_attack = knn.predict_proba(X_attack)[:, 1]

    # Window aggregations
    rf_mx_i, rf_mn_i = get_win_aggs(rf.predict_proba(X_idle)[:, 1])
    rf_mx_b, rf_mn_b = get_win_aggs(rf.predict_proba(X_busy)[:, 1])
    rf_mx_benign = np.concatenate([rf_mx_i, rf_mx_b])
    rf_mn_benign = np.concatenate([rf_mn_i, rf_mn_b])
    rf_mx_attack, rf_mn_attack = get_win_aggs(rf_p_attack)

    knn_mx_i, knn_mn_i = get_win_aggs(knn.predict_proba(X_idle)[:, 1])
    knn_mx_b, knn_mn_b = get_win_aggs(knn.predict_proba(X_busy)[:, 1])
    knn_mx_benign = np.concatenate([knn_mx_i, knn_mx_b])
    knn_mn_benign = np.concatenate([knn_mn_i, knn_mn_b])
    knn_mx_attack, knn_mn_attack = get_win_aggs(knn_p_attack)

    lstm_p_benign = get_lstm_probs(W_benign)
    lstm_p_attack = get_lstm_probs(W_attack)

    lr_p_benign = lr.predict_proba(stats_scaler.transform(get_window_stats(W_benign)))[:, 1]
    lr_p_attack = lr.predict_proba(stats_scaler.transform(get_window_stats(W_attack)))[:, 1]

    models_to_score = [
        ("Random Forest (Flow)", rf_p_benign, rf_p_attack, 0.1288, len(X_benign), len(X_attack)),
        ("KNN (Flow)", knn_p_benign, knn_p_attack, 0.1268, len(X_benign), len(X_attack)),
        ("RF Window-Max", rf_mx_benign, rf_mx_attack, 0.9094, len(W_benign), len(W_attack)),
        ("RF Window-Mean", rf_mn_benign, rf_mn_attack, 0.7563, len(W_benign), len(W_attack)),
        ("KNN Window-Max", knn_mx_benign, knn_mx_attack, 1.0, len(W_benign), len(W_attack)),
        ("KNN Window-Mean", knn_mn_benign, knn_mn_attack, 0.6482, len(W_benign), len(W_attack)),
        ("LSTM (Window)", lstm_p_benign, lstm_p_attack, 0.9919, len(W_benign), len(W_attack)),
        ("Window-Stats LR", lr_p_benign, lr_p_attack, 0.6206, len(W_benign), len(W_attack)),
    ]

    rescoring_results = []
    for name, p_neg, p_pos, thresh, n_neg, n_pos in models_to_score:
        fp = int(np.sum(p_neg >= thresh))
        tn = int(len(p_neg) - fp)
        tp = int(np.sum(p_pos >= thresh))
        fn = int(len(p_pos) - tp)
        fpr = fp / len(p_neg) if len(p_neg) > 0 else 0.0
        rec = tp / len(p_pos) if len(p_pos) > 0 else 0.0

        y_true = np.concatenate([np.zeros(len(p_neg)), np.ones(len(p_pos))])
        y_scores = np.concatenate([p_neg, p_pos])
        auc = float(roc_auc_score(y_true, y_scores)) if len(np.unique(y_scores)) > 1 else 0.5

        rescoring_results.append({
            "model": name,
            "threshold": thresh,
            "benign_count": n_neg,
            "attack_count": n_pos,
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "fpr": round(fpr, 4),
            "syn_recall": round(rec, 4),
            "roc_auc": round(auc, 4),
        })

    # Save full evaluation payload
    out_payload = {
        "metadata": {
            "extractor": "Java CICFlowMeter (offline CLI)",
            "step_size": 5,
            "direction_rule_applied": True,
            "sample_sizes": {
                "train_benign_flows": len(train_b),
                "lab_idle_flows": len(feats_idle),
                "lab_busy_flows": len(feats_busy),
                "lab_benign_flows_total": len(lab_b),
                "lab_idle_windows": len(W_idle),
                "lab_busy_windows": len(W_busy),
                "lab_benign_windows_total": len(W_benign),
                "lab_syn_attack_flows": len(feats_syn_attack),
                "lab_syn_attack_windows": len(W_attack),
            },
        },
        "flow_reconciliation_5672_vs_5622": flow_reconciliation,
        "extractor_packet_length_comparison": extractor_syn_comparison,
        "feature_comparison_25": feat_comparison,
        "rescoring_at_fixed_thresholds": rescoring_results,
    }

    out_file = Path("results/lab_session2_java_eval.json")
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(out_payload, f, indent=2)

    print(f"Results successfully saved to {out_file}")


if __name__ == "__main__":
    main()
