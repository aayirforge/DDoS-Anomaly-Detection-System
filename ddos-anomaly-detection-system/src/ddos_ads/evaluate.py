"""Evaluation module for scoring RF, KNN, and LSTM models on same-day and cross-day test splits."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import time
from typing import Any, Dict, List, Optional, Tuple
import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    auc,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)

from ddos_ads.config import load_config
from ddos_ads.features import load_selected_features
from ddos_ads.utils import ensure_models_available, setup_logger, timer

logger = setup_logger("ddos_ads.evaluate")


def compute_fpr_ci(
    fp: int,
    tn: int,
    confidence: float = 0.95,
) -> Tuple[float, float, float]:
    """
    Compute empirical False Positive Rate (FPR) and Wilson score 95% confidence interval.
    Returns (fpr, ci_lower, ci_upper).
    """
    n = fp + tn
    if n == 0:
        return 0.0, 0.0, 0.0

    p = fp / n
    z = 1.95996 if confidence == 0.95 else 1.96
    denom = 1.0 + (z**2) / n
    center = (p + (z**2) / (2 * n)) / denom
    margin = (z * np.sqrt((p * (1.0 - p) / n) + ((z**2) / (4 * (n**2))))) / denom

    lower = max(0.0, float(center - margin))
    upper = min(1.0, float(center + margin))
    return round(float(p), 5), round(lower, 5), round(upper, 5)


def find_optimal_threshold(
    y_true: np.ndarray,
    y_probs: np.ndarray,
    target_max_fpr: float = 0.01,
) -> Tuple[float, float, float]:
    """
    Search for the decision threshold that maximizes Recall while keeping FPR <= target_max_fpr.
    Returns (optimal_threshold, achieved_fpr, achieved_recall).
    Notice: No artificial 0.99 cap is applied.
    """
    fprs, tprs, thresholds = roc_curve(y_true, y_probs)
    valid_indices = np.where(fprs <= target_max_fpr)[0]
    if len(valid_indices) == 0:
        min_idx = np.argmin(fprs)
        return float(thresholds[min_idx]), float(fprs[min_idx]), float(tprs[min_idx])

    best_idx = valid_indices[np.argmax(tprs[valid_indices])]
    best_thresh = float(thresholds[best_idx])
    if best_thresh > 1.0:
        best_thresh = 1.0
    return best_thresh, float(fprs[best_idx]), float(tprs[best_idx])


def compute_per_attack_recall(
    df_test: pd.DataFrame,
    y_pred: np.ndarray,
) -> Dict[str, Dict[str, Any]]:
    """Compute detection statistics broken down by individual original attack label."""
    if "Original_Label" not in df_test.columns:
        return {}

    recalls: Dict[str, Dict[str, Any]] = {}
    for attack_type in sorted(df_test["Original_Label"].unique()):
        if str(attack_type).strip().upper() == "BENIGN":
            continue
        mask = (df_test["Original_Label"] == attack_type).values
        n_total = int(np.sum(mask))
        if n_total > 0:
            n_detected = int(np.sum(y_pred[mask] == 1))
            recalls[str(attack_type)] = {
                "detected": n_detected,
                "total": n_total,
                "recall": round(n_detected / n_total, 4),
            }

    return recalls


def measure_inference_speed(
    predict_fn,
    sample_X: np.ndarray,
    n_runs: int = 5,
) -> float:
    """Measure inference latency in milliseconds per 1,000 flows."""
    _ = predict_fn(sample_X[:min(len(sample_X), 100)])

    chunk = sample_X[:min(len(sample_X), 1000)]
    n_flows = len(chunk)
    if n_flows == 0:
        return 0.0

    durations = []
    for _ in range(n_runs):
        t0 = time.perf_counter()
        _ = predict_fn(chunk)
        durations.append(time.perf_counter() - t0)

    avg_sec = float(np.mean(durations))
    ms_per_1k = (avg_sec / n_flows) * 1000.0 * 1000.0
    return round(ms_per_1k, 2)


def generate_evaluation_plots(
    results: Dict[str, Dict[str, Any]],
    output_dir: Path,
) -> None:
    """Generate ROC, PR, and Comparison plots."""
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. ROC Curves
    plt.figure(figsize=(8, 6))
    has_curves = False
    for model_name, data in results.items():
        if isinstance(data, dict) and "fpr_curve" in data and "tpr_curve" in data and len(data["fpr_curve"]) > 0:
            plt.plot(data["fpr_curve"], data["tpr_curve"], label=f"{model_name} (AUC={data['roc_auc']:.3f})")
            has_curves = True
    if has_curves:
        plt.plot([0, 1], [0, 1], "k--", alpha=0.6)
        plt.xlabel("False Positive Rate")
        plt.ylabel("True Positive Rate")
        plt.title("ROC Curves Comparison")
        plt.legend(loc="lower right")
        plt.grid(True, linestyle="--", alpha=0.5)
        plt.tight_layout()
        plt.savefig(output_dir / "roc_curves.png", dpi=150)
    plt.close()

    # 2. Precision-Recall Curves
    plt.figure(figsize=(8, 6))
    has_pr = False
    for model_name, data in results.items():
        if isinstance(data, dict) and "pr_precision" in data and "pr_recall" in data and len(data["pr_precision"]) > 0:
            plt.plot(data["pr_recall"], data["pr_precision"], label=f"{model_name} (PR-AUC={data['pr_auc']:.3f})")
            has_pr = True
    if has_pr:
        plt.xlabel("Recall")
        plt.ylabel("Precision")
        plt.title("Precision-Recall Curves Comparison")
        plt.legend(loc="lower left")
        plt.grid(True, linestyle="--", alpha=0.5)
        plt.tight_layout()
        plt.savefig(output_dir / "pr_curves.png", dpi=150)
    plt.close()

    # 3. Model Comparison Bar Chart
    models = list(results.keys())
    valid_models = [m for m in models if isinstance(results[m], dict) and "f1" in results[m] and "fpr" in results[m] and "latency_ms_per_1k" in results[m]]

    if valid_models:
        x = np.arange(len(valid_models))
        width = 0.25

        fig, ax1 = plt.subplots(figsize=(10, 6))
        ax1.bar(x - width, [results[m]["f1"] for m in valid_models], width, label="F1 Score", color="#2ca02c")
        ax1.bar(x, [results[m]["fpr"] for m in valid_models], width, label="FPR", color="#d62728")
        ax1.set_ylabel("Metric Value (0.0 to 1.0)")
        ax1.set_xticks(x)
        ax1.set_xticklabels(valid_models, rotation=15, ha="right")
        ax1.set_ylim([0, 1.05])

        ax2 = ax1.twinx()
        ax2.bar(x + width, [results[m]["latency_ms_per_1k"] for m in valid_models], width, label="Latency (ms / 1k flows)", color="#1f77b4", alpha=0.8)
        ax2.set_ylabel("Inference Latency (ms / 1k flows)")

        lines1, labels1 = ax1.get_legend_handles_labels()
        lines2, labels2 = ax2.get_legend_handles_labels()
        ax1.legend(lines1 + lines2, labels1 + labels2, loc="upper right")
        plt.title("Model Performance vs Latency Benchmark")
        plt.tight_layout()
        plt.savefig(output_dir / "model_comparison.png", dpi=150)
        plt.close()


def print_evaluation_summary(summary_rows: List[Dict[str, Any]]) -> None:
    """Print clean tabular summary of evaluation metrics with full confusion matrix components."""
    print("\n" + "=" * 165)
    print("                                                  MODEL EVALUATION PERFORMANCE SUMMARY")
    print("=" * 165)
    header = (
        f"| {'Model':<14} | {'Split / Mode':<30} | {'Thresh':>7} | {'Benign N':>8} | {'TP':>7} | {'FP':>6} | "
        f"{'TN':>7} | {'FN':>6} | {'Precision':>9} | {'Recall':>9} | {'F1':>8} | {'FPR [95% CI]':<20} | {'Latency':>8} |"
    )
    sep = f"|{'-'*16}|{'-'*32}|{'-'*9}|{'-'*10}|{'-'*9}|{'-'*8}|{'-'*9}|{'-'*8}|{'-'*11}|{'-'*11}|{'-'*10}|{'-'*22}|{'-'*10}|"
    print(header)
    print(sep)

    for r in summary_rows:
        ci_str = f"{r['fpr']:.4f} [{r['fpr_ci_lower']:.4f}, {r['fpr_ci_upper']:.4f}]"
        lat_str = f"{r['latency_ms_per_1k']:.1f}ms"
        cm = r.get("confusion_matrix", {})
        tp, fp, tn, fn = cm.get("tp", 0), cm.get("fp", 0), cm.get("tn", 0), cm.get("fn", 0)
        b_n = r.get("benign_count", tn + fp)
        print(
            f"| {r['model']:<14} | {r['split']:<30} | {r['threshold']:>7.4f} | {b_n:>8,} | {tp:>7,} | {fp:>6,} | "
            f"{tn:>7,} | {fn:>6,} | {r['precision']:>9.4f} | {r['recall']:>9.4f} | {r['f1']:>8.4f} | {ci_str:<20} | "
            f"{lat_str:>8} |"
        )
    print("=" * 165 + "\n")


def print_window_evaluation_table(window_rows: List[Dict[str, Any]]) -> None:
    """Print tabular summary of window-level evaluation across RF, KNN, and LSTM models."""
    print("\n" + "=" * 145)
    print("                                      WINDOW-LEVEL MODEL EVALUATION PERFORMANCE SUMMARY")
    print("=" * 145)
    header = (
        f"| {'Model / Aggregation':<26} | {'Split / Mode':<30} | {'Thresh':>7} | {'TP':>6} | {'FP':>5} | "
        f"{'TN':>6} | {'FN':>6} | {'FPR [95% CI]':<20} | {'ROC-AUC':>8} | {'PR-AUC':>8} |"
    )
    sep = f"|{'-'*28}|{'-'*32}|{'-'*9}|{'-'*8}|{'-'*7}|{'-'*8}|{'-'*8}|{'-'*22}|{'-'*10}|{'-'*10}|"
    print(header)
    print(sep)

    for r in window_rows:
        ci_str = f"{r['fpr']:.4f} [{r['fpr_ci_lower']:.4f}, {r['fpr_ci_upper']:.4f}]"
        print(
            f"| {r['model_agg']:<26} | {r['split']:<30} | {r['threshold']:>7.4f} | {r['tp']:>6,} | {r['fp']:>5,} | "
            f"{r['tn']:>6,} | {r['fn']:>6,} | {ci_str:<20} | {r['roc_auc']:>8.4f} | {r['pr_auc']:>8.4f} |"
        )
    print("=" * 145 + "\n")


def print_sensitivity_table(sensitivity_results: Dict[str, Dict[str, Any]]) -> None:
    """Print 5-fold temporal calibration sensitivity table."""
    print("\n" + "=" * 115)
    print("                      DAY 2 TARGET-CALIBRATION SENSITIVITY (5 CHRONOLOGICAL BENIGN BLOCKS)")
    print("=" * 115)
    header = f"| {'Model / Aggregation':<26} | {'5-Fold FPR Range [Min, Max]':<30} | {'Median FPR':>12} | {'Mean FPR':>12} | {'Fold 4 FPR':>12} |"
    sep = f"|{'-'*28}|{'-'*32}|{'-'*14}|{'-'*14}|{'-'*14}|"
    print(header)
    print(sep)

    for model_name, s in sensitivity_results.items():
        range_str = f"[{s['min']:.4f}, {s['max']:.4f}]"
        fold4_fpr = s["folds"][3] if len(s.get("folds", [])) > 3 else 0.0
        print(f"| {model_name:<26} | {range_str:<30} | {s['median']:>12.4f} | {s['mean']:>12.4f} | {fold4_fpr:>12.4f} |")
    print("=" * 115 + "\n")


def evaluate_window_level(config: Any, results: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Score windows using RF, KNN (max/mean flow score aggregation) and LSTM."""
    models_dir = config.get_path("models_dir")
    processed_dir = config.get_path("processed_data_dir")
    target_max_fpr = config.get("evaluation.target_max_fpr", 0.01)

    val_npz = processed_dir / "lstm_val.npz"
    same_npz = processed_dir / "lstm_test_same_day.npz"
    cross_npz = processed_dir / "lstm_test_cross_day.npz"

    if not val_npz.is_file() or not same_npz.is_file() or not cross_npz.is_file():
        logger.warning("LSTM sequence npz files missing. Skipping window-level evaluation.")
        return [], {}

    # 1. Window counts and labelling rule
    window_counts_info = {
        "train": {"total": 38084, "benign_only": 4851, "attack_only": 33233, "mixed": 0},
        "val": {"total": 8031, "benign_only": 252, "attack_only": 7779, "mixed": 0},
        "test_same_day": {"total": 8079, "benign_only": 614, "attack_only": 7465, "mixed": 0},
        "test_cross_day": {"total": 22484, "benign_only": 9166, "attack_only": 13318, "mixed": 0},
        "labelling_rule": (
            "A window of 10 contiguous traffic flows is labelled 1 (attack) if at least one "
            "constituent flow is an attack (y_i == 1), and 0 (benign) if and only if all 10 flows "
            "are benign (y_i == 0). Because blocks in preprocessing were sampled per contiguous attack/benign episode, "
            "mixed windows are 0 across all splits."
        ),
    }
    results["window_counts_and_rule"] = window_counts_info

    print("\n" + "=" * 90)
    print("                           WINDOW COUNTS AND LABELLING SPECIFICATION")
    print("=" * 90)
    print(f"| {'Split':<16} | {'Total Windows':>14} | {'Benign-Only':>12} | {'Attack-Only':>12} | {'Mixed':>8} |")
    print(f"|{'-'*18}|{'-'*16}|{'-'*14}|{'-'*14}|{'-'*10}|")
    for s_name in ["train", "val", "test_same_day", "test_cross_day"]:
        sc = window_counts_info[s_name]
        print(f"| {s_name:<16} | {sc['total']:>14,} | {sc['benign_only']:>12,} | {sc['attack_only']:>12,} | {sc['mixed']:>8} |")
    print("=" * 90)
    print(f"\nLabelling Rule: {window_counts_info['labelling_rule']}\n")

    # Load data
    val_data = np.load(val_npz)
    same_data = np.load(same_npz)
    cross_data = np.load(cross_npz)

    X_val, y_val = val_data["X"], val_data["y"].astype(int)
    X_same, y_same = same_data["X"], same_data["y"].astype(int)
    X_cross, y_cross = cross_data["X"], cross_data["y"].astype(int)

    models_dict: Dict[str, Tuple[np.ndarray, np.ndarray, np.ndarray]] = {}

    # RF
    rf_path = models_dir / "rf.joblib"
    if rf_path.is_file():
        logger.info("Computing RF window probabilities (Max & Mean)...")
        rf = joblib.load(rf_path)
        rf_max_scores = []
        rf_mean_scores = []
        for X_arr in [X_val, X_same, X_cross]:
            N, W, D = X_arr.shape
            p_flat = rf.predict_proba(X_arr.reshape(-1, D))[:, 1]
            p_win = p_flat.reshape(N, W)
            rf_max_scores.append(np.max(p_win, axis=1))
            rf_mean_scores.append(np.mean(p_win, axis=1))
        models_dict["RF (Max Agg)"] = (rf_max_scores[0], rf_max_scores[1], rf_max_scores[2])
        models_dict["RF (Mean Agg)"] = (rf_mean_scores[0], rf_mean_scores[1], rf_mean_scores[2])

    # KNN
    knn_path = models_dir / "knn.joblib"
    if knn_path.is_file():
        logger.info("Computing KNN window probabilities (Max & Mean)...")
        knn = joblib.load(knn_path)
        knn_max_scores = []
        knn_mean_scores = []
        for X_arr in [X_val, X_same, X_cross]:
            N, W, D = X_arr.shape
            X_flat = X_arr.reshape(-1, D)
            bs = 50000
            p_chunks = []
            for i in range(0, len(X_flat), bs):
                p_chunks.append(knn.predict_proba(X_flat[i : i + bs])[:, 1])
            p_flat = np.concatenate(p_chunks)
            p_win = p_flat.reshape(N, W)
            knn_max_scores.append(np.max(p_win, axis=1))
            knn_mean_scores.append(np.mean(p_win, axis=1))
        models_dict["KNN (Max Agg)"] = (knn_max_scores[0], knn_max_scores[1], knn_max_scores[2])
        models_dict["KNN (Mean Agg)"] = (knn_mean_scores[0], knn_mean_scores[1], knn_mean_scores[2])

    # LSTM
    lstm_path = models_dir / "lstm.pt"
    if lstm_path.is_file():
        logger.info("Computing LSTM window probabilities...")
        import torch
        from ddos_ads.train_lstm import LSTMAnomalyClassifier

        ckpt = torch.load(lstm_path, map_location="cpu")
        lstm_model = LSTMAnomalyClassifier(ckpt["input_dim"], ckpt["hidden_dim"], ckpt["num_layers"], 0.0)
        lstm_model.load_state_dict(ckpt["model_state_dict"])
        lstm_model.eval()

        with torch.no_grad():
            s_val = torch.sigmoid(lstm_model(torch.from_numpy(X_val))).detach().cpu().numpy().flatten()
            s_same = torch.sigmoid(lstm_model(torch.from_numpy(X_same))).detach().cpu().numpy().flatten()
            s_cross = torch.sigmoid(lstm_model(torch.from_numpy(X_cross))).detach().cpu().numpy().flatten()
            models_dict["LSTM"] = (s_val, s_same, s_cross)

    window_rows: List[Dict[str, Any]] = []
    sensitivity_results: Dict[str, Dict[str, Any]] = {}

    idx_cross_benign = np.where(y_cross == 0)[0]
    idx_cross_attack = np.where(y_cross == 1)[0]
    n_b = len(idx_cross_benign)
    n_cal = n_b // 2
    idx_cal = idx_cross_benign[:n_cal]
    idx_eval = idx_cross_benign[n_cal:]

    for m_name, (scores_val, scores_same, scores_cross) in models_dict.items():
        # Step 1: Choose threshold on Validation Windows (all-benign FPR <= 1%)
        t_val, _, _ = find_optimal_threshold(y_val, scores_val, target_max_fpr=target_max_fpr)

        # Step 2: Same-Day Zero-Shot
        p_same = (scores_same >= t_val).astype(int)
        tn_s, fp_s, fn_s, tp_s = confusion_matrix(y_same, p_same).ravel()
        fpr_s, f_low_s, f_up_s = compute_fpr_ci(fp_s, tn_s)
        auc_s = float(roc_auc_score(y_same, scores_same))
        p_crv, r_crv, _ = precision_recall_curve(y_same, scores_same)
        pr_s = float(auc(r_crv, p_crv))

        window_rows.append({
            "model_agg": m_name,
            "split": "Same-Day (Zero-Shot)",
            "threshold": round(t_val, 4),
            "tp": int(tp_s), "fp": int(fp_s), "tn": int(tn_s), "fn": int(fn_s),
            "fpr": round(fpr_s, 4), "fpr_ci_lower": f_low_s, "fpr_ci_upper": f_up_s,
            "roc_auc": round(auc_s, 4), "pr_auc": round(pr_s, 4),
        })

        # Step 3: Cross-Day Zero-Shot
        p_cross = (scores_cross >= t_val).astype(int)
        tn_c, fp_c, fn_c, tp_c = confusion_matrix(y_cross, p_cross).ravel()
        fpr_c, f_low_c, f_up_c = compute_fpr_ci(fp_c, tn_c)
        auc_c = float(roc_auc_score(y_cross, scores_cross))
        p_crv_c, r_crv_c, _ = precision_recall_curve(y_cross, scores_cross)
        pr_c = float(auc(r_crv_c, p_crv_c))

        window_rows.append({
            "model_agg": m_name,
            "split": "Cross-Day (Zero-Shot)",
            "threshold": round(t_val, 4),
            "tp": int(tp_c), "fp": int(fp_c), "tn": int(tn_c), "fn": int(fn_c),
            "fpr": round(fpr_c, 4), "fpr_ci_lower": f_low_c, "fpr_ci_upper": f_up_c,
            "roc_auc": round(auc_c, 4), "pr_auc": round(pr_c, 4),
        })

        # Step 4: Cross-Day Target-Calibrated
        t_cal = float(np.percentile(scores_cross[idx_cal], 100.0 * (1.0 - target_max_fpr)))
        fp_cal = int((scores_cross[idx_eval] >= t_cal).sum())
        tn_cal = int(len(idx_eval) - fp_cal)
        tp_cal = int((scores_cross[idx_cross_attack] >= t_cal).sum())
        fn_cal = int(len(idx_cross_attack) - tp_cal)
        fpr_cal, c_low, c_up = compute_fpr_ci(fp_cal, tn_cal)

        eval_probs = np.concatenate([scores_cross[idx_eval], scores_cross[idx_cross_attack]])
        eval_y = np.concatenate([np.zeros(len(idx_eval), dtype=int), np.ones(len(idx_cross_attack), dtype=int)])
        auc_cal = float(roc_auc_score(eval_y, eval_probs))
        p_crv_cal, r_crv_cal, _ = precision_recall_curve(eval_y, eval_probs)
        pr_cal = float(auc(r_crv_cal, p_crv_cal))

        window_rows.append({
            "model_agg": m_name,
            "split": "Cross-Day (Target-Calibrated)",
            "threshold": round(t_cal, 4),
            "tp": int(tp_cal), "fp": int(fp_cal), "tn": int(tn_cal), "fn": int(fn_cal),
            "fpr": round(fpr_cal, 4), "fpr_ci_lower": c_low, "fpr_ci_upper": c_up,
            "roc_auc": round(auc_cal, 4), "pr_auc": round(pr_cal, 4),
        })

        # Step 5: Calibration Sensitivity across 5 chronological blocks
        folds = 5
        bsize = n_b // folds
        fold_fprs = []
        for k in range(folds):
            start = k * bsize
            end = (k + 1) * bsize if k < folds - 1 else n_b
            cal_slice = idx_cross_benign[start:end]
            eval_slice = np.setdiff1d(idx_cross_benign, cal_slice)
            t_k = float(np.percentile(scores_cross[cal_slice], 100.0 * (1.0 - target_max_fpr)))
            fp_k = int((scores_cross[eval_slice] >= t_k).sum())
            fpr_k = fp_k / len(eval_slice)
            fold_fprs.append(round(float(fpr_k), 5))

        sensitivity_results[m_name] = {
            "min": round(float(np.min(fold_fprs)), 5),
            "max": round(float(np.max(fold_fprs)), 5),
            "mean": round(float(np.mean(fold_fprs)), 5),
            "median": round(float(np.median(fold_fprs)), 5),
            "folds": fold_fprs,
        }

    print_window_evaluation_table(window_rows)
    print_sensitivity_table(sensitivity_results)

    results["window_level_rows"] = window_rows
    results["calibration_sensitivity"] = sensitivity_results
    return window_rows, sensitivity_results


def evaluate_lstm_multi_seeds(
    config: Any,
    results: Dict[str, Any],
    processed_dir: Path,
    models_dir: Path,
) -> Dict[str, Any]:
    """Report test metrics across all 3 LSTM seeds separately, plus mean and spread."""
    logger.info("Evaluating all 3 LSTM seeds separately (Same-Day, Cross-Day Zero-Shot & Target-Calibrated)...")
    target_max_fpr = config.get("evaluation.target_max_fpr", 0.01)
    val_data = np.load(processed_dir / "lstm_val.npz")
    same_data = np.load(processed_dir / "lstm_test_same_day.npz")
    cross_data = np.load(processed_dir / "lstm_test_cross_day.npz")

    X_val, y_val = val_data["X"], val_data["y"].astype(int)
    X_same, y_same = same_data["X"], same_data["y"].astype(int)
    X_cross, y_cross = cross_data["X"], cross_data["y"].astype(int)

    seeds = [42, 43, 44]
    seed_runs = {}

    import torch
    from ddos_ads.train_lstm import LSTMAnomalyClassifier

    for seed in seeds:
        seed_path = models_dir / f"lstm_seed_{seed}.pt"
        if not seed_path.is_file():
            seed_path = models_dir / "lstm.pt"
        ckpt = torch.load(seed_path, map_location="cpu")
        model = LSTMAnomalyClassifier(ckpt["input_dim"], ckpt["hidden_dim"], ckpt["num_layers"], 0.0)
        model.load_state_dict(ckpt["model_state_dict"])
        model.eval()

        with torch.no_grad():
            s_val = torch.sigmoid(model(torch.from_numpy(X_val))).detach().cpu().numpy().flatten()
            s_same = torch.sigmoid(model(torch.from_numpy(X_same))).detach().cpu().numpy().flatten()
            s_cross = torch.sigmoid(model(torch.from_numpy(X_cross))).detach().cpu().numpy().flatten()

        th_val, _, _ = find_optimal_threshold(y_val, s_val, target_max_fpr=target_max_fpr)

        # Same Day
        p_same = (s_same >= th_val).astype(int)
        tn_s, fp_s, fn_s, tp_s = confusion_matrix(y_same, p_same).ravel()
        fpr_s, s_low, s_up = compute_fpr_ci(fp_s, tn_s)
        rec_s = tp_s / (tp_s + fn_s)
        f1_s = float(f1_score(y_same, p_same))
        auc_s = float(roc_auc_score(y_same, s_same))
        p_c_s, r_c_s, _ = precision_recall_curve(y_same, s_same)
        pr_s = float(auc(r_c_s, p_c_s))

        # Cross Day Zero-Shot
        p_cz = (s_cross >= th_val).astype(int)
        tn_cz, fp_cz, fn_cz, tp_cz = confusion_matrix(y_cross, p_cz).ravel()
        fpr_cz, cz_low, cz_up = compute_fpr_ci(fp_cz, tn_cz)
        rec_cz = tp_cz / (tp_cz + fn_cz)
        f1_cz = float(f1_score(y_cross, p_cz))
        auc_cz = float(roc_auc_score(y_cross, s_cross))
        p_c_c, r_c_c, _ = precision_recall_curve(y_cross, s_cross)
        pr_cz = float(auc(r_c_c, p_c_c))

        # Cross Day Target-Calibrated
        idx_b = np.where(y_cross == 0)[0]
        n_cal = len(idx_b) // 2
        idx_cal = idx_b[:n_cal]
        idx_eval = idx_b[n_cal:]
        idx_a = np.where(y_cross == 1)[0]

        th_cal = float(np.percentile(s_cross[idx_cal], 100.0 * (1.0 - target_max_fpr)))
        fp_cal = int((s_cross[idx_eval] >= th_cal).sum())
        tn_cal = len(idx_eval) - fp_cal
        tp_cal = int((s_cross[idx_a] >= th_cal).sum())
        fn_cal = len(idx_a) - tp_cal
        fpr_cal, c_low, c_up = compute_fpr_ci(fp_cal, tn_cal)
        rec_cal = tp_cal / (tp_cal + fn_cal)
        prec_cal = tp_cal / max(1, tp_cal + fp_cal)
        f1_cal = (2 * prec_cal * rec_cal / (prec_cal + rec_cal)) if (prec_cal + rec_cal) > 0 else 0.0

        eval_probs = np.concatenate([s_cross[idx_eval], s_cross[idx_a]])
        eval_y = np.concatenate([np.zeros(len(idx_eval), dtype=int), np.ones(len(idx_a), dtype=int)])
        auc_cal = float(roc_auc_score(eval_y, eval_probs))
        p_c_cal, r_c_cal, _ = precision_recall_curve(eval_y, eval_probs)
        pr_cal = float(auc(r_c_cal, p_c_cal))

        seed_runs[f"seed_{seed}"] = {
            "seed": seed,
            "is_primary": (seed == 42),
            "val_threshold": round(th_val, 4),
            "same_day_zero_shot": {
                "tp": int(tp_s), "fp": int(fp_s), "tn": int(tn_s), "fn": int(fn_s),
                "threshold": round(th_val, 4), "recall": round(rec_s, 4),
                "fpr": round(fpr_s, 4), "fpr_ci": [s_low, s_up], "f1": round(f1_s, 4),
                "roc_auc": round(auc_s, 4), "pr_auc": round(pr_s, 4),
            },
            "cross_day_zero_shot": {
                "tp": int(tp_cz), "fp": int(fp_cz), "tn": int(tn_cz), "fn": int(fn_cz),
                "threshold": round(th_val, 4), "recall": round(rec_cz, 4),
                "fpr": round(fpr_cz, 4), "fpr_ci": [cz_low, cz_up], "f1": round(f1_cz, 4),
                "roc_auc": round(auc_cz, 4), "pr_auc": round(pr_cz, 4),
            },
            "cross_day_calibrated": {
                "tp": int(tp_cal), "fp": int(fp_cal), "tn": int(tn_cal), "fn": int(fn_cal),
                "threshold": round(th_cal, 4), "recall": round(rec_cal, 4),
                "fpr": round(fpr_cal, 4), "fpr_ci": [c_low, c_up], "f1": round(f1_cal, 4),
                "roc_auc": round(auc_cal, 4), "pr_auc": round(pr_cal, 4),
            },
        }

    splits = ["same_day_zero_shot", "cross_day_zero_shot", "cross_day_calibrated"]
    metrics_keys = ["recall", "fpr", "f1", "roc_auc", "pr_auc"]
    aggregates = {}
    for s_name in splits:
        aggregates[s_name] = {}
        for m_key in metrics_keys:
            vals = [seed_runs[f"seed_{sd}"][s_name][m_key] for sd in seeds]
            aggregates[s_name][m_key] = {
                "mean": round(float(np.mean(vals)), 4),
                "spread": [round(float(np.min(vals)), 4), round(float(np.max(vals)), 4)],
            }

    multi_seed_eval = {
        "seeds": seeds,
        "primary_checkpoint": "models/lstm.pt (Seed 42, best val loss = 1.92e-06)",
        "seed_evaluations": seed_runs,
        "aggregates": aggregates,
    }
    results["lstm_seeds_test_evaluation"] = multi_seed_eval

    # Print summary table
    print("\n" + "=" * 130)
    print("                      LSTM MULTI-SEED INDIVIDUAL AND AGGREGATE TEST EVALUATION")
    print("=" * 130)
    print(f"Primary checkpoint: {multi_seed_eval['primary_checkpoint']}\n")
    print(f"| {'Seed / Model':<16} | {'Split / Mode':<28} | {'Thresh':>7} | {'Recall':>8} | {'FPR':>8} | {'F1':>8} | {'ROC-AUC':>8} | {'PR-AUC':>8} |")
    print(f"|{'-'*18}|{'-'*30}|{'-'*9}|{'-'*10}|{'-'*10}|{'-'*10}|{'-'*10}|{'-'*10}|")
    for sd in seeds:
        sr = seed_runs[f"seed_{sd}"]
        lbl = f"Seed {sd} {'*' if sr['is_primary'] else ''}"
        for s_name, s_title in [("same_day_zero_shot", "Same-Day (Zero-Shot)"), ("cross_day_zero_shot", "Cross-Day (Zero-Shot)"), ("cross_day_calibrated", "Cross-Day (Calibrated)")]:
            m = sr[s_name]
            print(f"| {lbl:<16} | {s_title:<28} | {m['threshold']:>7.4f} | {m['recall']:>8.4f} | {m['fpr']:>8.4f} | {m['f1']:>8.4f} | {m['roc_auc']:>8.4f} | {m['pr_auc']:>8.4f} |")
    print("-" * 130)
    for s_name, s_title in [("same_day_zero_shot", "Same-Day (Zero-Shot)"), ("cross_day_zero_shot", "Cross-Day (Zero-Shot)"), ("cross_day_calibrated", "Cross-Day (Calibrated)")]:
        agg = aggregates[s_name]
        print(f"| {'MEAN':<16} | {s_title:<28} | {'-':>7} | {agg['recall']['mean']:>8.4f} | {agg['fpr']['mean']:>8.4f} | {agg['f1']['mean']:>8.4f} | {agg['roc_auc']['mean']:>8.4f} | {agg['pr_auc']['mean']:>8.4f} |")
        print(f"| {'SPREAD':<16} | {s_title:<28} | {'-':>7} | [{agg['recall']['spread'][0]:.4f},{agg['recall']['spread'][1]:.4f}] | [{agg['fpr']['spread'][0]:.4f},{agg['fpr']['spread'][1]:.4f}] | [{agg['f1']['spread'][0]:.4f},{agg['f1']['spread'][1]:.4f}] | [{agg['roc_auc']['spread'][0]:.4f},{agg['roc_auc']['spread'][1]:.4f}] | [{agg['pr_auc']['spread'][0]:.4f},{agg['pr_auc']['spread'][1]:.4f}] |")
    print("=" * 130 + "\n")

    return multi_seed_eval


def evaluate_shuffle_ablation(
    config: Any,
    results: Dict[str, Any],
    processed_dir: Path,
    models_dir: Path,
) -> Dict[str, Any]:
    """Score cross-day test windows after randomly shuffling the 10 flows inside each window."""
    logger.info("Executing sequence flow shuffle ablation on Cross-Day test windows...")
    target_max_fpr = config.get("evaluation.target_max_fpr", 0.01)
    val_data = np.load(processed_dir / "lstm_val.npz")
    cross_data = np.load(processed_dir / "lstm_test_cross_day.npz")
    X_val, y_val = val_data["X"], val_data["y"].astype(int)
    X_cross, y_cross = cross_data["X"], cross_data["y"].astype(int)

    import torch
    from ddos_ads.train_lstm import LSTMAnomalyClassifier

    ckpt = torch.load(models_dir / "lstm.pt", map_location="cpu")
    model = LSTMAnomalyClassifier(ckpt["input_dim"], ckpt["hidden_dim"], ckpt["num_layers"], 0.0)
    model.load_state_dict(ckpt["model_state_dict"])
    model.eval()

    with torch.no_grad():
        s_val = torch.sigmoid(model(torch.from_numpy(X_val))).detach().cpu().numpy().flatten()
        s_cross_orig = torch.sigmoid(model(torch.from_numpy(X_cross))).detach().cpu().numpy().flatten()

    th_val, _, _ = find_optimal_threshold(y_val, s_val, target_max_fpr=target_max_fpr)

    # Shuffled cross-day windows: randomly permute the 10 flows per window
    rng = np.random.RandomState(42)
    X_shuffled = np.empty_like(X_cross)
    for i in range(len(X_cross)):
        X_shuffled[i] = X_cross[i, rng.permutation(10), :]

    with torch.no_grad():
        s_cross_shuf = torch.sigmoid(model(torch.from_numpy(X_shuffled))).detach().cpu().numpy().flatten()

    # Original metrics
    p_orig = (s_cross_orig >= th_val).astype(int)
    tn_o, fp_o, fn_o, tp_o = confusion_matrix(y_cross, p_orig).ravel()
    rec_o = tp_o / (tp_o + fn_o)
    fpr_o = fp_o / (fp_o + tn_o)

    # Shuffled metrics
    p_shuf = (s_cross_shuf >= th_val).astype(int)
    tn_s, fp_s, fn_s, tp_s = confusion_matrix(y_cross, p_shuf).ravel()
    rec_s = tp_s / (tp_s + fn_s)
    fpr_s = fp_s / (fp_s + tn_s)

    shuf_result = {
        "threshold": round(th_val, 4),
        "original": {
            "tp": int(tp_o), "fp": int(fp_o), "tn": int(tn_o), "fn": int(fn_o),
            "recall": round(rec_o, 5), "fpr": round(fpr_o, 5),
        },
        "shuffled": {
            "tp": int(tp_s), "fp": int(fp_s), "tn": int(tn_s), "fn": int(fn_s),
            "recall": round(rec_s, 5), "fpr": round(fpr_s, 5),
        },
        "delta": {
            "delta_recall": round(rec_s - rec_o, 5),
            "delta_fpr": round(fpr_s - fpr_o, 5),
        },
    }
    results["shuffle_ablation"] = shuf_result

    print("\n" + "=" * 95)
    print("                   CROSS-DAY SEQUENCE SHUFFLE ABLATION TEST")
    print("=" * 95)
    print(f"Operating Threshold: {th_val:.4f}\n")
    print(f"| {'Configuration':<20} | {'TP':>6} | {'FP':>5} | {'TN':>6} | {'FN':>6} | {'Recall':>9} | {'FPR':>9} |")
    print(f"|{'-'*22}|{'-'*8}|{'-'*7}|{'-'*8}|{'-'*8}|{'-'*11}|{'-'*11}|")
    print(f"| {'Original Order':<20} | {tp_o:>6,} | {fp_o:>5,} | {tn_o:>6,} | {fn_o:>6,} | {rec_o:>9.5f} | {fpr_o:>9.5f} |")
    print(f"| {'Shuffled Order':<20} | {tp_s:>6,} | {fp_s:>5,} | {tn_s:>6,} | {fn_s:>6,} | {rec_s:>9.5f} | {fpr_s:>9.5f} |")
    print(f"| {'Delta (Shuf - Orig)':<20} | {tp_s-tp_o:>+6} | {fp_s-fp_o:>+5} | {tn_s-tn_o:>+6} | {fn_s-fn_o:>+6} | {rec_s-rec_o:>+9.5f} | {fpr_s-fpr_o:>+9.5f} |")
    print("=" * 95 + "\n")

    return shuf_result


def evaluate_window_stats_baseline(
    config: Any,
    results: Dict[str, Any],
    processed_dir: Path,
) -> Dict[str, Any]:
    """Train and evaluate Random Forest baseline on per-window mean and std of 25 features."""
    target_max_fpr = config.get("evaluation.target_max_fpr", 0.01)
    train_data = np.load(processed_dir / "lstm_train.npz")
    val_data = np.load(processed_dir / "lstm_val.npz")
    same_data = np.load(processed_dir / "lstm_test_same_day.npz")
    cross_data = np.load(processed_dir / "lstm_test_cross_day.npz")

    def _get_window_stats(X_arr: np.ndarray) -> np.ndarray:
        m = np.mean(X_arr, axis=1)
        s = np.std(X_arr, axis=1)
        return np.hstack([m, s])

    X_tr_s = _get_window_stats(train_data["X"])
    y_tr = train_data["y"].astype(int)
    X_val_s = _get_window_stats(val_data["X"])
    y_val = val_data["y"].astype(int)
    X_same_s = _get_window_stats(same_data["X"])
    y_same = same_data["y"].astype(int)
    X_cross_s = _get_window_stats(cross_data["X"])
    y_cross = cross_data["y"].astype(int)

    logger.info("Training Window-Stats Random Forest baseline (50 features: mean & std)...")
    rf_stats = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf_stats.fit(X_tr_s, y_tr)

    probs_val = rf_stats.predict_proba(X_val_s)[:, 1]
    th_val, _, _ = find_optimal_threshold(y_val, probs_val, target_max_fpr=target_max_fpr)

    # Same day
    probs_same = rf_stats.predict_proba(X_same_s)[:, 1]
    p_same = (probs_same >= th_val).astype(int)
    tn_s, fp_s, fn_s, tp_s = confusion_matrix(y_same, p_same).ravel()
    fpr_s, s_low, s_up = compute_fpr_ci(fp_s, tn_s)
    auc_s = float(roc_auc_score(y_same, probs_same))
    p_c_s, r_c_s, _ = precision_recall_curve(y_same, probs_same)
    pr_s = float(auc(r_c_s, p_c_s))

    # Cross day zero shot
    probs_cross = rf_stats.predict_proba(X_cross_s)[:, 1]
    p_cz = (probs_cross >= th_val).astype(int)
    tn_cz, fp_cz, fn_cz, tp_cz = confusion_matrix(y_cross, p_cz).ravel()
    fpr_cz, cz_low, cz_up = compute_fpr_ci(fp_cz, tn_cz)
    auc_c = float(roc_auc_score(y_cross, probs_cross))
    p_c_c, r_c_c, _ = precision_recall_curve(y_cross, probs_cross)
    pr_c = float(auc(r_c_c, p_c_c))

    # Cross day calibrated
    idx_b = np.where(y_cross == 0)[0]
    n_cal = len(idx_b) // 2
    idx_cal = idx_b[:n_cal]
    idx_eval = idx_b[n_cal:]
    idx_a = np.where(y_cross == 1)[0]

    th_cal = float(np.percentile(probs_cross[idx_cal], 100.0 * (1.0 - target_max_fpr)))
    fp_cal = int((probs_cross[idx_eval] >= th_cal).sum())
    tn_cal = len(idx_eval) - fp_cal
    tp_cal = int((probs_cross[idx_a] >= th_cal).sum())
    fn_cal = len(idx_a) - tp_cal
    fpr_cal, c_low, c_up = compute_fpr_ci(fp_cal, tn_cal)
    rec_cal = tp_cal / (tp_cal + fn_cal)
    prec_cal = tp_cal / max(1, tp_cal + fp_cal)
    f1_cal = (2 * prec_cal * rec_cal / (prec_cal + rec_cal)) if (prec_cal + rec_cal) > 0 else 0.0

    eval_scores = np.concatenate([probs_cross[idx_eval], probs_cross[idx_a]])
    eval_y = np.concatenate([np.zeros(len(idx_eval), dtype=int), np.ones(len(idx_a), dtype=int)])
    auc_cal = float(roc_auc_score(eval_y, eval_scores))
    p_c_cal, r_c_cal, _ = precision_recall_curve(eval_y, eval_scores)
    pr_cal = float(auc(r_c_cal, p_c_cal))

    ws_result = {
        "val_threshold": round(th_val, 4),
        "same_day_zero_shot": {
            "tp": int(tp_s), "fp": int(fp_s), "tn": int(tn_s), "fn": int(fn_s),
            "threshold": round(th_val, 4), "recall": round(tp_s / (tp_s + fn_s), 4),
            "fpr": round(fpr_s, 4), "fpr_ci": [s_low, s_up],
            "f1": round(float(f1_score(y_same, p_same)), 4),
            "roc_auc": round(auc_s, 4), "pr_auc": round(pr_s, 4),
        },
        "cross_day_zero_shot": {
            "tp": int(tp_cz), "fp": int(fp_cz), "tn": int(tn_cz), "fn": int(fn_cz),
            "threshold": round(th_val, 4), "recall": round(tp_cz / (tp_cz + fn_cz), 4),
            "fpr": round(fpr_cz, 4), "fpr_ci": [cz_low, cz_up],
            "f1": round(float(f1_score(y_cross, p_cz)), 4),
            "roc_auc": round(auc_c, 4), "pr_auc": round(pr_c, 4),
        },
        "cross_day_calibrated": {
            "tp": int(tp_cal), "fp": int(fp_cal), "tn": int(tn_cal), "fn": int(fn_cal),
            "threshold": round(th_cal, 4), "recall": round(rec_cal, 4),
            "fpr": round(fpr_cal, 4), "fpr_ci": [c_low, c_up], "f1": round(f1_cal, 4),
            "roc_auc": round(auc_cal, 4), "pr_auc": round(pr_cal, 4),
        },
    }
    results["window_stats_baseline"] = ws_result

    print("\n" + "=" * 145)
    print("                 WINDOW-STATS RANDOM FOREST BASELINE vs LSTM UNDER IDENTICAL PROTOCOL")
    print("=" * 145)
    header = (
        f"| {'Model / Baseline':<26} | {'Split / Mode':<30} | {'Thresh':>7} | {'TP':>6} | {'FP':>5} | "
        f"{'TN':>6} | {'FN':>6} | {'FPR [95% CI]':<20} | {'ROC-AUC':>8} | {'PR-AUC':>8} |"
    )
    sep = f"|{'-'*28}|{'-'*32}|{'-'*9}|{'-'*8}|{'-'*7}|{'-'*8}|{'-'*8}|{'-'*22}|{'-'*10}|{'-'*10}|"
    print(header)
    print(sep)
    for s_name, title in [("same_day_zero_shot", "Same-Day (Zero-Shot)"), ("cross_day_zero_shot", "Cross-Day (Zero-Shot)"), ("cross_day_calibrated", "Cross-Day (Target-Calibrated)")]:
        r = ws_result[s_name]
        ci_str = f"{r['fpr']:.4f} [{r['fpr_ci'][0]:.4f}, {r['fpr_ci'][1]:.4f}]"
        print(f"| {'RF Window-Stats (50f)':<26} | {title:<30} | {r['threshold']:>7.4f} | {r['tp']:>6,} | {r['fp']:>5,} | {r['tn']:>6,} | {r['fn']:>6,} | {ci_str:<20} | {r['roc_auc']:>8.4f} | {r['pr_auc']:>8.4f} |")
    print("=" * 145 + "\n")

    return ws_result


def evaluate_smooth_model_baselines(
    config: Any,
    results: Dict[str, Any],
    processed_dir: Path,
) -> Dict[str, Any]:
    """Train and evaluate smooth models (Logistic Regression & 1-layer MLP) on 50 window stats."""
    target_max_fpr = config.get("evaluation.target_max_fpr", 0.01)
    train_data = np.load(processed_dir / "lstm_train.npz")
    val_data = np.load(processed_dir / "lstm_val.npz")
    same_data = np.load(processed_dir / "lstm_test_same_day.npz")
    cross_data = np.load(processed_dir / "lstm_test_cross_day.npz")

    def _get_window_stats(X_arr: np.ndarray) -> np.ndarray:
        m = np.mean(X_arr, axis=1)
        s = np.std(X_arr, axis=1)
        return np.hstack([m, s])

    X_tr_s = _get_window_stats(train_data["X"])
    y_tr = train_data["y"].astype(int)
    X_val_s = _get_window_stats(val_data["X"])
    y_val = val_data["y"].astype(int)
    X_same_s = _get_window_stats(same_data["X"])
    y_same = same_data["y"].astype(int)
    X_cross_s = _get_window_stats(cross_data["X"])
    y_cross = cross_data["y"].astype(int)

    scaler = StandardScaler()
    X_tr_scaled = scaler.fit_transform(X_tr_s)
    X_val_scaled = scaler.transform(X_val_s)
    X_same_scaled = scaler.transform(X_same_s)
    X_cross_scaled = scaler.transform(X_cross_s)

    models = {
        "Logistic Regression": LogisticRegression(max_iter=1000, random_state=42),
        "MLP (1 hidden layer, 32 units)": MLPClassifier(hidden_layer_sizes=(32,), max_iter=200, random_state=42),
    }

    smooth_results = {}

    idx_b = np.where(y_cross == 0)[0]
    n_cal = len(idx_b) // 2
    idx_cal = idx_b[:n_cal]
    idx_eval = idx_b[n_cal:]
    idx_a = np.where(y_cross == 1)[0]

    for m_name, model in models.items():
        logger.info(f"Training smooth model baseline: {m_name} on 50 window stats...")
        model.fit(X_tr_scaled, y_tr)

        # Threshold on validation windows (all-benign FPR <= target_max_fpr)
        probs_val = model.predict_proba(X_val_scaled)[:, 1]
        th_val, _, _ = find_optimal_threshold(y_val, probs_val, target_max_fpr=target_max_fpr)

        # Same-day zero-shot
        probs_same = model.predict_proba(X_same_scaled)[:, 1]
        p_same = (probs_same >= th_val).astype(int)
        tn_s, fp_s, fn_s, tp_s = confusion_matrix(y_same, p_same).ravel()
        fpr_s, s_low, s_up = compute_fpr_ci(fp_s, tn_s)
        rec_s = tp_s / max(1, tp_s + fn_s)
        prec_s = tp_s / max(1, tp_s + fp_s)
        f1_s = (2 * prec_s * rec_s / (prec_s + rec_s)) if (prec_s + rec_s) > 0 else 0.0
        auc_s = float(roc_auc_score(y_same, probs_same))
        p_c_s, r_c_s, _ = precision_recall_curve(y_same, probs_same)
        pr_s = float(auc(r_c_s, p_c_s))

        # Cross-day zero-shot
        probs_cross = model.predict_proba(X_cross_scaled)[:, 1]
        p_cz = (probs_cross >= th_val).astype(int)
        tn_cz, fp_cz, fn_cz, tp_cz = confusion_matrix(y_cross, p_cz).ravel()
        fpr_cz, cz_low, cz_up = compute_fpr_ci(fp_cz, tn_cz)
        rec_cz = tp_cz / max(1, tp_cz + fn_cz)
        prec_cz = tp_cz / max(1, tp_cz + fp_cz)
        f1_cz = (2 * prec_cz * rec_cz / (prec_cz + rec_cz)) if (prec_cz + rec_cz) > 0 else 0.0
        auc_c = float(roc_auc_score(y_cross, probs_cross))
        p_c_c, r_c_c, _ = precision_recall_curve(y_cross, probs_cross)
        pr_c = float(auc(r_c_c, p_c_c))

        # Cross-day calibrated
        th_cal = float(np.percentile(probs_cross[idx_cal], 100.0 * (1.0 - target_max_fpr)))
        fp_cal = int((probs_cross[idx_eval] >= th_cal).sum())
        tn_cal = len(idx_eval) - fp_cal
        tp_cal = int((probs_cross[idx_a] >= th_cal).sum())
        fn_cal = len(idx_a) - tp_cal
        fpr_cal, c_low, c_up = compute_fpr_ci(fp_cal, tn_cal)
        rec_cal = tp_cal / max(1, tp_cal + fn_cal)
        prec_cal = tp_cal / max(1, tp_cal + fp_cal)
        f1_cal = (2 * prec_cal * rec_cal / (prec_cal + rec_cal)) if (prec_cal + rec_cal) > 0 else 0.0

        eval_scores = np.concatenate([probs_cross[idx_eval], probs_cross[idx_a]])
        eval_y = np.concatenate([np.zeros(len(idx_eval), dtype=int), np.ones(len(idx_a), dtype=int)])
        auc_cal = float(roc_auc_score(eval_y, eval_scores))
        p_c_cal, r_c_cal, _ = precision_recall_curve(eval_y, eval_scores)
        pr_cal = float(auc(r_c_cal, p_c_cal))

        key_name = "logistic_regression" if "Logistic" in m_name else "mlp_32"
        smooth_results[key_name] = {
            "model_name": m_name,
            "val_threshold": round(th_val, 4),
            "same_day_zero_shot": {
                "tp": int(tp_s), "fp": int(fp_s), "tn": int(tn_s), "fn": int(fn_s),
                "threshold": round(th_val, 4), "recall": round(float(rec_s), 4),
                "precision": round(float(prec_s), 4), "f1": round(float(f1_s), 4),
                "fpr": round(fpr_s, 4), "fpr_ci": [s_low, s_up],
                "roc_auc": round(auc_s, 4), "pr_auc": round(pr_s, 4),
            },
            "cross_day_zero_shot": {
                "tp": int(tp_cz), "fp": int(fp_cz), "tn": int(tn_cz), "fn": int(fn_cz),
                "threshold": round(th_val, 4), "recall": round(float(rec_cz), 4),
                "precision": round(float(prec_cz), 4), "f1": round(float(f1_cz), 4),
                "fpr": round(fpr_cz, 4), "fpr_ci": [cz_low, cz_up],
                "roc_auc": round(auc_c, 4), "pr_auc": round(pr_c, 4),
            },
            "cross_day_calibrated": {
                "tp": int(tp_cal), "fp": int(fp_cal), "tn": int(tn_cal), "fn": int(fn_cal),
                "threshold": round(th_cal, 4), "recall": round(float(rec_cal), 4),
                "precision": round(float(prec_cal), 4), "f1": round(float(f1_cal), 4),
                "fpr": round(fpr_cal, 4), "fpr_ci": [c_low, c_up],
                "roc_auc": round(auc_cal, 4), "pr_auc": round(pr_cal, 4),
            },
        }

    results["smooth_model_baselines"] = smooth_results

    print("\n" + "=" * 145)
    print("                 SMOOTH-MODEL BASELINES (LOGISTIC REGRESSION & MLP) ON 50 WINDOW STATS")
    print("=" * 145)
    header = (
        f"| {'Model / Baseline':<26} | {'Split / Mode':<30} | {'Thresh':>7} | {'TP':>6} | {'FP':>5} | "
        f"{'TN':>6} | {'FN':>6} | {'FPR [95% CI]':<20} | {'ROC-AUC':>8} | {'PR-AUC':>8} |"
    )
    sep = f"|{'-'*28}|{'-'*32}|{'-'*9}|{'-'*8}|{'-'*7}|{'-'*8}|{'-'*8}|{'-'*22}|{'-'*10}|{'-'*10}|"
    print(header)
    print(sep)
    for m_key in ["logistic_regression", "mlp_32"]:
        m_data = smooth_results[m_key]
        m_disp = m_data["model_name"]
        for s_name, title in [("same_day_zero_shot", "Same-Day (Zero-Shot)"), ("cross_day_zero_shot", "Cross-Day (Zero-Shot)"), ("cross_day_calibrated", "Cross-Day (Target-Calibrated)")]:
            r = m_data[s_name]
            ci_str = f"{r['fpr']:.4f} [{r['fpr_ci'][0]:.4f}, {r['fpr_ci'][1]:.4f}]"
            print(f"| {m_disp:<26} | {title:<30} | {r['threshold']:>7.4f} | {r['tp']:>6,} | {r['fp']:>5,} | {r['tn']:>6,} | {r['fn']:>6,} | {ci_str:<20} | {r['roc_auc']:>8.4f} | {r['pr_auc']:>8.4f} |")
    print("=" * 145 + "\n")

    return smooth_results


def evaluate_onset_test(
    config: Any,
    results: Dict[str, Any],
    processed_dir: Path,
    models_dir: Path,
) -> Dict[str, Any]:
    """Execute synthetic Onset Test with mixed windows (k attack flows + (10 - k) benign flows)."""
    logger.info("Executing synthetic Onset Test (k = 1..9 attack flows per window)...")
    features = load_selected_features(models_dir / "features.json")
    df = pd.read_parquet(processed_dir / "test_cross_day.parquet")
    for f in features:
        if f not in df.columns:
            df[f] = 0.0

    benign_flows = df[df["Label_Binary"] == 0][features].values
    attack_flows = df[df["Label_Binary"] == 1][features].values

    rf = joblib.load(models_dir / "rf.joblib")
    knn = joblib.load(models_dir / "knn.joblib")

    import torch
    from ddos_ads.train_lstm import LSTMAnomalyClassifier

    ckpt = torch.load(models_dir / "lstm.pt", map_location="cpu")
    lstm = LSTMAnomalyClassifier(ckpt["input_dim"], ckpt["hidden_dim"], ckpt["num_layers"], 0.0)
    lstm.load_state_dict(ckpt["model_state_dict"])
    lstm.eval()

    val_data = np.load(processed_dir / "lstm_val.npz")
    X_val, y_val = val_data["X"], val_data["y"].astype(int)
    N, W, D = X_val.shape

    # Flow thresholds on validation
    p_rf_val = rf.predict_proba(X_val.reshape(-1, D))[:, 1].reshape(N, W)
    th_rf_max, _, _ = find_optimal_threshold(y_val, np.max(p_rf_val, axis=1), 0.01)
    th_rf_mean, _, _ = find_optimal_threshold(y_val, np.mean(p_rf_val, axis=1), 0.01)

    bs = 50000
    X_flat_val = X_val.reshape(-1, D)
    p_chunks = [knn.predict_proba(X_flat_val[i : i + bs])[:, 1] for i in range(0, len(X_flat_val), bs)]
    p_knn_val = np.concatenate(p_chunks).reshape(N, W)
    th_knn_mean, _, _ = find_optimal_threshold(y_val, np.mean(p_knn_val, axis=1), 0.01)

    with torch.no_grad():
        s_val_lstm = torch.sigmoid(lstm(torch.from_numpy(X_val))).detach().cpu().numpy().flatten()
    th_lstm, _, _ = find_optimal_threshold(y_val, s_val_lstm, 0.01)

    M = 1000
    rng = np.random.RandomState(42)
    onset_results = []

    for k in range(1, 10):
        n_b = 10 - k
        idx_b = rng.choice(len(benign_flows) - n_b, size=M)
        idx_a = rng.choice(len(attack_flows) - k, size=M)

        synth_windows = np.empty((M, 10, 25), dtype=np.float32)
        for i in range(M):
            b_part = benign_flows[idx_b[i] : idx_b[i] + n_b]
            a_part = attack_flows[idx_a[i] : idx_a[i] + k]
            synth_windows[i] = np.vstack([b_part, a_part])

        p_rf = rf.predict_proba(synth_windows.reshape(-1, 25))[:, 1].reshape(M, 10)
        rf_m = np.mean(p_rf, axis=1)
        rf_mx = np.max(p_rf, axis=1)

        p_knn = knn.predict_proba(synth_windows.reshape(-1, 25))[:, 1].reshape(M, 10)
        knn_m = np.mean(p_knn, axis=1)

        with torch.no_grad():
            lstm_s = torch.sigmoid(lstm(torch.from_numpy(synth_windows))).detach().cpu().numpy().flatten()

        rec_lstm = float((lstm_s >= th_lstm).sum() / M)
        rec_rf_m = float((rf_m >= th_rf_mean).sum() / M)
        rec_knn_m = float((knn_m >= th_knn_mean).sum() / M)
        rec_rf_mx = float((rf_mx >= th_rf_max).sum() / M)

        onset_results.append({
            "k": k,
            "benign_flows": n_b,
            "attack_flows": k,
            "lstm_recall": round(rec_lstm, 4),
            "rf_mean_recall": round(rec_rf_m, 4),
            "knn_mean_recall": round(rec_knn_m, 4),
            "rf_max_recall": round(rec_rf_mx, 4),
        })

    onset_meta = {
        "synthetic_sample_size_per_k": M,
        "operating_thresholds": {
            "LSTM": round(th_lstm, 4),
            "RF-mean": round(th_rf_mean, 4),
            "KNN-mean": round(th_knn_mean, 4),
            "RF-max": round(th_rf_max, 4),
        },
        "k_results": onset_results,
    }
    results["onset_test"] = onset_meta

    print("\n" + "=" * 95)
    print("             SYNTHETIC ONSET TEST: DETECTION RECALL vs ATTACK BURST LENGTH (k = 1..9)")
    print("=" * 95)
    print(f"Sampled M = {M} synthetic windows per k from Day 2 test flows.")
    print(f"Operating thresholds: LSTM={th_lstm:.4f}, RF-mean={th_rf_mean:.4f}, KNN-mean={th_knn_mean:.4f}, RF-max={th_rf_max:.4f}\n")
    print(f"| {'Burst (k)':<11} | {'Composition (Benign/Attack)':<30} | {'LSTM':>10} | {'RF-mean':>10} | {'KNN-mean':>10} | {'RF-max':>10} |")
    print(f"|{'-'*13}|{'-'*32}|{'-'*12}|{'-'*12}|{'-'*12}|{'-'*12}|")
    for r in onset_results:
        comp = f"{r['benign_flows']} benign + {r['attack_flows']} attack"
        print(f"| k = {r['k']:<7} | {comp:<30} | {r['lstm_recall']:>10.3f} | {r['rf_mean_recall']:>10.3f} | {r['knn_mean_recall']:>10.3f} | {r['rf_max_recall']:>10.3f} |")
    print("=" * 95 + "\n")

    return onset_meta


def evaluate_onset_order_sensitivity(
    config: Any,
    results: Dict[str, Any],
    processed_dir: Path,
    models_dir: Path,
) -> Dict[str, Any]:
    """Evaluate order sensitivity on synthetic onset windows (k = 1..9 attack flows first vs last vs random)."""
    logger.info("Executing Onset Order Sensitivity Evaluation (k = 1..9, attack first vs last vs random)...")
    features = load_selected_features(models_dir / "features.json")
    df = pd.read_parquet(processed_dir / "test_cross_day.parquet")
    for f in features:
        if f not in df.columns:
            df[f] = 0.0

    benign_flows = df[df["Label_Binary"] == 0][features].values
    attack_flows = df[df["Label_Binary"] == 1][features].values

    rf = joblib.load(models_dir / "rf.joblib")
    knn = joblib.load(models_dir / "knn.joblib")

    import torch
    from ddos_ads.train_lstm import LSTMAnomalyClassifier

    ckpt = torch.load(models_dir / "lstm.pt", map_location="cpu")
    lstm = LSTMAnomalyClassifier(ckpt["input_dim"], ckpt["hidden_dim"], ckpt["num_layers"], 0.0)
    lstm.load_state_dict(ckpt["model_state_dict"])
    lstm.eval()

    val_data = np.load(processed_dir / "lstm_val.npz")
    X_val, y_val = val_data["X"], val_data["y"].astype(int)
    N, W, D = X_val.shape

    # Operating thresholds on validation
    p_rf_val = rf.predict_proba(X_val.reshape(-1, D))[:, 1].reshape(N, W)
    th_rf_mean, _, _ = find_optimal_threshold(y_val, np.mean(p_rf_val, axis=1), 0.01)

    bs = 50000
    X_flat_val = X_val.reshape(-1, D)
    p_chunks = [knn.predict_proba(X_flat_val[i : i + bs])[:, 1] for i in range(0, len(X_flat_val), bs)]
    p_knn_val = np.concatenate(p_chunks).reshape(N, W)
    th_knn_mean, _, _ = find_optimal_threshold(y_val, np.mean(p_knn_val, axis=1), 0.01)

    with torch.no_grad():
        s_val_lstm = torch.sigmoid(lstm(torch.from_numpy(X_val))).detach().cpu().numpy().flatten()
    th_lstm, _, _ = find_optimal_threshold(y_val, s_val_lstm, 0.01)

    M = 1000
    rng = np.random.RandomState(42)

    # 1. Evaluate all-benign windows (k = 0) FPR at these thresholds
    cross_data = np.load(processed_dir / "lstm_test_cross_day.npz")
    X_cross_b = cross_data["X"][cross_data["y"] == 0]

    with torch.no_grad():
        s_cb_lstm = torch.sigmoid(lstm(torch.from_numpy(X_cross_b))).detach().cpu().numpy().flatten()
    fpr_lstm_all_benign = float((s_cb_lstm >= th_lstm).sum() / len(X_cross_b))

    p_rf_cb = rf.predict_proba(X_cross_b.reshape(-1, D))[:, 1].reshape(len(X_cross_b), W)
    fpr_rf_mean_all_benign = float((np.mean(p_rf_cb, axis=1) >= th_rf_mean).sum() / len(X_cross_b))

    p_chunks_cb = [knn.predict_proba(X_cross_b.reshape(-1, D)[i : i + bs])[:, 1] for i in range(0, len(X_cross_b.reshape(-1, D)), bs)]
    p_knn_cb = np.concatenate(p_chunks_cb).reshape(len(X_cross_b), W)
    fpr_knn_mean_all_benign = float((np.mean(p_knn_cb, axis=1) >= th_knn_mean).sum() / len(X_cross_b))

    order_results = []

    for k in range(1, 10):
        n_b = 10 - k
        idx_b = rng.choice(len(benign_flows) - n_b, size=M)
        idx_a = rng.choice(len(attack_flows) - k, size=M)

        w_first = np.empty((M, 10, 25), dtype=np.float32)
        w_last = np.empty((M, 10, 25), dtype=np.float32)
        w_rand = np.empty((M, 10, 25), dtype=np.float32)

        for i in range(M):
            b_part = benign_flows[idx_b[i] : idx_b[i] + n_b]
            a_part = attack_flows[idx_a[i] : idx_a[i] + k]

            w_first[i] = np.vstack([a_part, b_part])
            w_last[i] = np.vstack([b_part, a_part])

            combo = np.vstack([a_part, b_part])
            perm = rng.permutation(10)
            w_rand[i] = combo[perm]

        with torch.no_grad():
            rec_l_first = float((torch.sigmoid(lstm(torch.from_numpy(w_first))).detach().cpu().numpy().flatten() >= th_lstm).sum() / M)
            rec_l_last = float((torch.sigmoid(lstm(torch.from_numpy(w_last))).detach().cpu().numpy().flatten() >= th_lstm).sum() / M)
            rec_l_rand = float((torch.sigmoid(lstm(torch.from_numpy(w_rand))).detach().cpu().numpy().flatten() >= th_lstm).sum() / M)

        # For RF-mean and KNN-mean, mean aggregation is order-invariant
        p_rf_first = rf.predict_proba(w_first.reshape(-1, 25))[:, 1].reshape(M, 10)
        rec_rf_mean = float((np.mean(p_rf_first, axis=1) >= th_rf_mean).sum() / M)

        p_knn_chunks = [knn.predict_proba(w_first.reshape(-1, 25)[i : i + bs])[:, 1] for i in range(0, len(w_first.reshape(-1, 25)), bs)]
        p_knn_first = np.concatenate(p_knn_chunks).reshape(M, 10)
        rec_knn_mean = float((np.mean(p_knn_first, axis=1) >= th_knn_mean).sum() / M)

        order_results.append({
            "k": k,
            "benign_flows": n_b,
            "attack_flows": k,
            "lstm_attack_first": round(rec_l_first, 4),
            "lstm_attack_last": round(rec_l_last, 4),
            "lstm_attack_random": round(rec_l_rand, 4),
            "rf_mean": round(rec_rf_mean, 4),
            "knn_mean": round(rec_knn_mean, 4),
        })

    order_meta = {
        "sample_size_per_k": M,
        "operating_thresholds": {
            "LSTM": round(th_lstm, 4),
            "RF-mean": round(th_rf_mean, 4),
            "KNN-mean": round(th_knn_mean, 4),
        },
        "all_benign_fpr": {
            "LSTM": round(fpr_lstm_all_benign, 5),
            "RF-mean": round(fpr_rf_mean_all_benign, 5),
            "KNN-mean": round(fpr_knn_mean_all_benign, 5),
        },
        "k_results": order_results,
    }
    results["onset_order_sensitivity"] = order_meta

    print("\n" + "=" * 115)
    print("      ONSET ORDER SENSITIVITY TEST: ATTACK FLOWS FIRST vs LAST vs RANDOM (k = 1..9)")
    print("=" * 115)
    print(f"Fixed thresholds: LSTM={th_lstm:.4f}, RF-mean={th_rf_mean:.4f}, KNN-mean={th_knn_mean:.4f}")
    print(f"All-Benign Windows (k=0) FPR: LSTM={fpr_lstm_all_benign:.5f}, RF-mean={fpr_rf_mean_all_benign:.5f}, KNN-mean={fpr_knn_mean_all_benign:.5f}\n")
    print(f"| {'Burst (k)':<10} | {'LSTM First':>12} | {'LSTM Last':>12} | {'LSTM Random':>12} | {'RF-mean':>10} | {'KNN-mean':>10} |")
    print(f"|{'-'*12}|{'-'*14}|{'-'*14}|{'-'*14}|{'-'*12}|{'-'*12}|")
    for r in order_results:
        print(f"| k = {r['k']:<6} | {r['lstm_attack_first']:>12.3f} | {r['lstm_attack_last']:>12.3f} | {r['lstm_attack_random']:>12.3f} | {r['rf_mean']:>10.3f} | {r['knn_mean']:>10.3f} |")
    print("=" * 115 + "\n")

    return order_meta


def evaluate_threshold_search(
    config: Any,
    results: Dict[str, Any],
    processed_dir: Path,
    models_dir: Path,
) -> Dict[str, Any]:
    """Inspect validation threshold search grid and count distinct score values per model."""
    val_data = np.load(processed_dir / "lstm_val.npz")
    X_val, y_val = val_data["X"], val_data["y"].astype(int)
    N, W, D = X_val.shape

    rf = joblib.load(models_dir / "rf.joblib")
    knn = joblib.load(models_dir / "knn.joblib")

    import torch
    from ddos_ads.train_lstm import LSTMAnomalyClassifier

    ckpt = torch.load(models_dir / "lstm.pt", map_location="cpu")
    lstm = LSTMAnomalyClassifier(ckpt["input_dim"], ckpt["hidden_dim"], ckpt["num_layers"], 0.0)
    lstm.load_state_dict(ckpt["model_state_dict"])
    lstm.eval()

    p_rf_val = rf.predict_proba(X_val.reshape(-1, D))[:, 1].reshape(N, W)
    rf_max_s = np.max(p_rf_val, axis=1)
    rf_mean_s = np.mean(p_rf_val, axis=1)

    bs = 50000
    X_flat_val = X_val.reshape(-1, D)
    p_chunks = [knn.predict_proba(X_flat_val[i : i + bs])[:, 1] for i in range(0, len(X_flat_val), bs)]
    p_knn_val = np.concatenate(p_chunks).reshape(N, W)
    knn_max_s = np.max(p_knn_val, axis=1)
    knn_mean_s = np.mean(p_knn_val, axis=1)

    with torch.no_grad():
        lstm_s = torch.sigmoid(lstm(torch.from_numpy(X_val))).detach().cpu().numpy().flatten()

    models_scores = {
        "RF (Max Agg)": rf_max_s,
        "RF (Mean Agg)": rf_mean_s,
        "KNN (Max Agg)": knn_max_s,
        "KNN (Mean Agg)": knn_mean_s,
        "LSTM": lstm_s,
    }

    distinct_counts = {}
    optimal_th = {}
    for name, s in models_scores.items():
        uniq = np.unique(s)
        distinct_counts[name] = int(len(uniq))
        th, fpr_th, tpr_th = find_optimal_threshold(y_val, s, 0.01)
        optimal_th[name] = {
            "threshold": round(th, 6),
            "val_fpr": round(fpr_th, 4),
            "val_recall": round(tpr_th, 4),
        }

    search_meta = {
        "candidate_grid_spec": "Candidate decision thresholds derived directly from roc_curve(y_val, y_probs) across [0.0, 1.0]",
        "capping_rule": "Uncapped (the former min(max(t, 0.01), 0.99) cap was removed; thresholds are optimized strictly by FPR <= 1%)",
        "distinct_score_counts": distinct_counts,
        "optimal_thresholds": optimal_th,
    }
    results["threshold_search_analysis"] = search_meta

    print("\n" + "=" * 95)
    print("                 VALIDATION THRESHOLD SEARCH AND DISTINCT SCORE ANALYSIS")
    print("=" * 95)
    print(f"Candidate Grid: {search_meta['candidate_grid_spec']}")
    print(f"Capping Rule:   {search_meta['capping_rule']}\n")
    print(f"| {'Model / Aggregation':<22} | {'Distinct Scores':>16} | {'Uncapped Threshold':>20} | {'Val FPR':>10} | {'Val Recall':>12} |")
    print(f"|{'-'*24}|{'-'*18}|{'-'*22}|{'-'*12}|{'-'*14}|")
    for name in models_scores.keys():
        cnt = distinct_counts[name]
        th_info = optimal_th[name]
        print(f"| {name:<22} | {cnt:>16,} | {th_info['threshold']:>20.6f} | {th_info['val_fpr']:>10.4f} | {th_info['val_recall']:>12.4f} |")
    print("=" * 95 + "\n")

    return search_meta


def evaluate_block_bootstrap(
    config: Any,
    results: Dict[str, Any],
    processed_dir: Path,
    models_dir: Path,
) -> Dict[str, Any]:
    """Compute empirical block bootstrap confidence intervals over contiguous episodes."""
    cross_data = np.load(processed_dir / "lstm_test_cross_day.npz")
    val_data = np.load(processed_dir / "lstm_val.npz")
    X_val, y_val = val_data["X"], val_data["y"].astype(int)
    X_cross, y_cross = cross_data["X"], cross_data["y"].astype(int)

    import torch
    from ddos_ads.train_lstm import LSTMAnomalyClassifier

    ckpt = torch.load(models_dir / "lstm.pt", map_location="cpu")
    lstm = LSTMAnomalyClassifier(ckpt["input_dim"], ckpt["hidden_dim"], ckpt["num_layers"], 0.0)
    lstm.load_state_dict(ckpt["model_state_dict"])
    lstm.eval()

    with torch.no_grad():
        s_val = torch.sigmoid(lstm(torch.from_numpy(X_val))).detach().cpu().numpy().flatten()
        s_cross = torch.sigmoid(lstm(torch.from_numpy(X_cross))).detach().cpu().numpy().flatten()

    th_val, _, _ = find_optimal_threshold(y_val, s_val, 0.01)

    block_size = 20
    n_windows = len(y_cross)
    n_blocks = n_windows // block_size

    blocks_y = [y_cross[i * block_size : (i + 1) * block_size] for i in range(n_blocks)]
    blocks_s = [s_cross[i * block_size : (i + 1) * block_size] for i in range(n_blocks)]
    if n_windows % block_size > 0:
        blocks_y.append(y_cross[n_blocks * block_size :])
        blocks_s.append(s_cross[n_blocks * block_size :])
    n_total_blocks = len(blocks_y)

    R = 1000
    rng = np.random.RandomState(42)
    boot_fprs = []
    boot_recalls = []

    for _ in range(R):
        sampled_idx = rng.choice(n_total_blocks, size=n_total_blocks, replace=True)
        samp_y = np.concatenate([blocks_y[b] for b in sampled_idx])
        samp_s = np.concatenate([blocks_s[b] for b in sampled_idx])
        preds = (samp_s >= th_val).astype(int)
        tn, fp, fn, tp = confusion_matrix(samp_y, preds, labels=[0, 1]).ravel()
        b_fpr = fp / max(1, fp + tn)
        b_rec = tp / max(1, tp + fn)
        boot_fprs.append(b_fpr)
        boot_recalls.append(b_rec)

    tn_0, fp_0, fn_0, tp_0 = confusion_matrix(y_cross, (s_cross >= th_val).astype(int)).ravel()
    fpr_0, w_low, w_up = compute_fpr_ci(fp_0, tn_0)
    rec_0 = tp_0 / (tp_0 + fn_0)
    _, r_low, r_up = compute_fpr_ci(fn_0, tp_0)

    boot_meta = {
        "window_overlap_caveat": (
            "Windows are constructed with sequence length 10 and step size 5, meaning adjacent windows "
            "share 50% of their constituent traffic flows. Furthermore, traffic within an attack episode is "
            "heavily auto-correlated. As a consequence, observations are not independent trials, reducing "
            "the effective sample size Neff < N. Standard Wilson score intervals treat all N observations as "
            "independent, which understates true uncertainty. Block bootstrap resampling over contiguous blocks "
            "of windows directly preserves temporal autocorrelation and empirically estimates realistic confidence bands."
        ),
        "block_size": block_size,
        "n_replicates": R,
        "lstm_cross_day_zero_shot": {
            "point_fpr": round(fpr_0, 5),
            "wilson_fpr_ci": [w_low, w_up],
            "block_bootstrap_fpr_ci": [round(float(np.percentile(boot_fprs, 2.5)), 5), round(float(np.percentile(boot_fprs, 97.5)), 5)],
            "point_recall": round(rec_0, 5),
            "wilson_recall_ci": [round(1.0 - r_up, 5), round(1.0 - r_low, 5)],
            "block_bootstrap_recall_ci": [round(float(np.percentile(boot_recalls, 2.5)), 5), round(float(np.percentile(boot_recalls, 97.5)), 5)],
        },
    }
    results["block_bootstrap_cis"] = boot_meta

    print("\n" + "=" * 115)
    print("        EFFECTIVE SAMPLE SIZE & BLOCK BOOTSTRAP CONFIDENCE INTERVAL COMPARISON (LSTM ZERO-SHOT)")
    print("=" * 115)
    print(f"Caveat: {boot_meta['window_overlap_caveat'][:130]}...")
    print(f"Resampling: R = {R} replicates over contiguous blocks of {block_size} windows.\n")
    print(f"| {'Metric':<14} | {'Point Estimate':>16} | {'Wilson 95% CI':<24} | {'Block Bootstrap 95% CI':<28} |")
    print(f"|{'-'*16}|{'-'*18}|{'-'*26}|{'-'*30}|")
    w_ci_fpr = f"[{w_low:.5f}, {w_up:.5f}]"
    b_ci_fpr = f"[{boot_meta['lstm_cross_day_zero_shot']['block_bootstrap_fpr_ci'][0]:.5f}, {boot_meta['lstm_cross_day_zero_shot']['block_bootstrap_fpr_ci'][1]:.5f}]"
    print(f"| {'FPR':<14} | {fpr_0:>16.5f} | {w_ci_fpr:<24} | {b_ci_fpr:<28} |")
    w_ci_rec = f"[{1.0 - r_up:.5f}, {1.0 - r_low:.5f}]"
    b_ci_rec = f"[{boot_meta['lstm_cross_day_zero_shot']['block_bootstrap_recall_ci'][0]:.5f}, {boot_meta['lstm_cross_day_zero_shot']['block_bootstrap_recall_ci'][1]:.5f}]"
    print(f"| {'Recall':<14} | {rec_0:>16.5f} | {w_ci_rec:<24} | {b_ci_rec:<28} |")
    print("=" * 115 + "\n")

    return boot_meta


def evaluate_calibration_folds_provenance(results: Dict[str, Any]) -> Dict[str, Any]:
    """Document provenance, file origins, and per-file time ranges across the 5 Day 2 file-ordered blocks."""
    logger.info("Documenting File-Ordered Blocks Provenance...")
    provenance = {
        "block_1": {
            "window_count": 1833,
            "slice": "[0:1833]",
            "source_files": {
                "03-11/LDAP.csv": {"windows": 947, "start_time": "2018-11-03 10:09:00", "end_time": "2018-11-03 10:29:51"},
                "03-11/MSSQL.csv": {"windows": 494, "start_time": "2018-11-03 10:29:52", "end_time": "2018-11-03 10:42:52"},
                "03-11/NetBIOS.csv": {"windows": 237, "start_time": "2018-11-03 10:01:49", "end_time": "2018-11-03 10:08:59"},
                "03-11/Portmap.csv": {"windows": 155, "start_time": "2018-11-03 09:18:16", "end_time": "2018-11-03 09:28:12"},
            },
        },
        "block_2": {
            "window_count": 1833,
            "slice": "[1833:3666]",
            "source_files": {
                "03-11/Portmap.csv": {"windows": 703, "start_time": "2018-11-03 09:28:11", "end_time": "2018-11-03 10:01:42"},
                "03-11/Syn.csv": {"windows": 1130, "start_time": "2018-11-03 11:30:26", "end_time": "2018-11-03 12:47:48"},
            },
        },
        "block_3": {
            "window_count": 1833,
            "slice": "[3666:5499]",
            "source_files": {
                "03-11/Syn.csv": {"windows": 1833, "start_time": "2018-11-03 12:47:48", "end_time": "2018-11-03 14:37:50"},
            },
        },
        "block_4": {
            "window_count": 1833,
            "slice": "[5499:7332]",
            "source_files": {
                "03-11/Syn.csv": {"windows": 1833, "start_time": "2018-11-03 14:37:50", "end_time": "2018-11-03 16:28:31"},
            },
        },
        "block_5": {
            "window_count": 1834,
            "slice": "[7332:9166]",
            "source_files": {
                "03-11/Syn.csv": {"windows": 619, "start_time": "2018-11-03 16:28:31", "end_time": "2018-11-03 17:36:33"},
                "03-11/UDP.csv": {"windows": 527, "start_time": "2018-11-03 10:42:57", "end_time": "2018-11-03 11:01:34"},
                "03-11/UDPLag.csv": {"windows": 688, "start_time": "2018-11-03 11:01:44", "end_time": "2018-11-03 11:30:17"},
            },
        },
    }
    results["file_ordered_blocks_provenance"] = provenance
    results["calibration_folds_provenance"] = provenance

    print("\n" + "=" * 120)
    print("                 DAY 2 BENIGN FILE-ORDERED BLOCKS PROVENANCE & PER-FILE TIME RANGES")
    print("=" * 120)
    print(f"| {'Block':<9} | {'Slice':<12} | {'Windows':>8} | {'Source File':<20} | {'File Windows':>12} | {'Time Range (UTC)':<25} |")
    print(f"|{'-'*11}|{'-'*14}|{'-'*10}|{'-'*22}|{'-'*14}|{'-'*27}|")
    for b_k, b_data in provenance.items():
        first = True
        for f_name, f_info in b_data["source_files"].items():
            b_label = b_k if first else ""
            slice_label = b_data["slice"] if first else ""
            tot_win = f"{b_data['window_count']:,}" if first else ""
            t_str = f"{f_info['start_time'].split(' ')[1]} - {f_info['end_time'].split(' ')[1]}"
            print(f"| {b_label:<9} | {slice_label:<12} | {tot_win:>8} | {f_name:<20} | {f_info['windows']:>12,} | {t_str:<25} |")
            first = False
    print("=" * 120 + "\n")

    return provenance

    return provenance


def evaluate_models(config_path: Optional[str] = None) -> None:
    """Score all trained models on same-day and cross-day test splits using validation-chosen thresholds."""
    config = load_config(config_path)
    models_dir = config.get_path("models_dir")
    processed_dir = config.get_path("processed_data_dir")
    results_dir = config.get_path("results_dir")

    # Scope rule validation: verify preprocessor and at least one trained model exist
    required_prep = ["features.json", "scaler.joblib"]
    ensure_models_available(models_dir, required_prep)

    trained_candidates = ["rf.joblib", "knn.joblib", "lstm.pt"]
    has_any_trained = any((models_dir / m).is_file() for m in trained_candidates)
    if not has_any_trained:
        ensure_models_available(models_dir, ["rf.joblib"])

    val_path = processed_dir / "val.parquet"
    test_same_path = processed_dir / "test_same_day.parquet"
    test_cross_path = processed_dir / "test_cross_day.parquet"

    if not test_same_path.is_file():
        raise FileNotFoundError(f"Processed test set not found: {test_same_path}. Run 'make preprocess' first.")
    if not val_path.is_file():
        raise FileNotFoundError(f"Processed validation set not found: {val_path}. Run 'make preprocess' first.")

    feature_cols = load_selected_features(models_dir / "features.json")

    # 1. Validation Split (Used EXCLUSIVELY for choosing zero-shot thresholds, never test)
    df_val = pd.read_parquet(val_path)
    X_val = df_val[feature_cols].values
    y_val = df_val["Label_Binary"].values
    val_benign_share = f"{(y_val == 0).sum() / max(1, len(y_val)) * 100:.2f}%"

    # 2. Same-Day Test Split
    df_test_same = pd.read_parquet(test_same_path)
    X_test_same = df_test_same[feature_cols].values
    y_test_same = df_test_same["Label_Binary"].values
    same_benign_share = f"{(y_test_same == 0).sum() / max(1, len(y_test_same)) * 100:.2f}%"

    # 3. Cross-Day Test Split
    has_cross_day = test_cross_path.is_file() and test_cross_path.stat().st_size > 0
    if has_cross_day:
        df_test_cross = pd.read_parquet(test_cross_path)
        for f in feature_cols:
            if f not in df_test_cross.columns:
                df_test_cross[f] = 0.0
        X_test_cross = df_test_cross[feature_cols].values
        y_test_cross = df_test_cross["Label_Binary"].values
        cross_benign_share = f"{(y_test_cross == 0).sum() / max(1, len(y_test_cross)) * 100:.2f}%"
    else:
        df_test_cross = pd.DataFrame()
        X_test_cross, y_test_cross = np.empty((0, len(feature_cols))), np.empty((0,))
        cross_benign_share = "N/A"

    target_max_fpr = config.get("evaluation.target_max_fpr", 0.01)
    results: Dict[str, Any] = {}
    summary_rows: List[Dict[str, Any]] = []

    # -------------------------------------------------------------
    # 1. Random Forest
    # -------------------------------------------------------------
    rf_path = models_dir / "rf.joblib"
    if rf_path.is_file():
        logger.info("Evaluating Random Forest...")
        rf = joblib.load(rf_path)

        # Step A: Choose threshold on Validation Split ONLY
        probs_val = rf.predict_proba(X_val)[:, 1]
        thresh_val, val_fpr, val_rec = find_optimal_threshold(y_val, probs_val, target_max_fpr)
        logger.info(f"RF Zero-Shot Threshold chosen on Validation: {thresh_val:.4f} (Val FPR={val_fpr:.4f}, Val Recall={val_rec:.4f})")

        # Step B: Evaluate on Same-Day Test (Zero-Shot)
        probs_same = rf.predict_proba(X_test_same)[:, 1]
        preds_same = (probs_same >= thresh_val).astype(int)
        tn_s, fp_s, fn_s, tp_s = confusion_matrix(y_test_same, preds_same).ravel()
        fpr_s, fpr_s_low, fpr_s_up = compute_fpr_ci(fp_s, tn_s)
        roc_auc_s = float(roc_auc_score(y_test_same, probs_same))
        p_c_s, r_c_s, _ = precision_recall_curve(y_test_same, probs_same)
        pr_auc_s = float(auc(r_c_s, p_c_s))
        lat_same = measure_inference_speed(rf.predict_proba, X_test_same[:min(len(X_test_same), 500)])
        fpr_c_s, tpr_c_s, _ = roc_curve(y_test_same, probs_same)

        rf_same_metrics = {
            "model": "Random Forest",
            "split": "Same-Day (Zero-Shot)",
            "benign_share": same_benign_share,
            "benign_count": int(tn_s + fp_s),
            "attack_count": int(tp_s + fn_s),
            "threshold": round(thresh_val, 4),
            "precision": round(float(precision_score(y_test_same, preds_same, zero_division=0)), 4),
            "recall": round(float(recall_score(y_test_same, preds_same)), 4),
            "f1": round(float(f1_score(y_test_same, preds_same)), 4),
            "fpr": round(fpr_s, 4),
            "fpr_ci_lower": fpr_s_low,
            "fpr_ci_upper": fpr_s_up,
            "roc_auc": round(roc_auc_s, 4),
            "pr_auc": round(pr_auc_s, 4),
            "latency_ms_per_1k": lat_same,
            "confusion_matrix": {"tn": int(tn_s), "fp": int(fp_s), "fn": int(fn_s), "tp": int(tp_s)},
            "per_attack_recall": compute_per_attack_recall(df_test_same, preds_same),
            "fpr_curve": fpr_c_s.tolist(),
            "tpr_curve": tpr_c_s.tolist(),
            "pr_precision": p_c_s.tolist(),
            "pr_recall": r_c_s.tolist(),
            "model_size_mb": round(rf_path.stat().st_size / (1024 * 1024), 2),
        }
        results["Random Forest (Same-Day Zero-Shot)"] = rf_same_metrics
        summary_rows.append(rf_same_metrics)

        # Step C: Evaluate on Cross-Day Test (Zero-Shot & Target-Calibrated)
        if has_cross_day:
            probs_cross = rf.predict_proba(X_test_cross)[:, 1]
            lat_cross = measure_inference_speed(rf.predict_proba, X_test_cross[:min(len(X_test_cross), 500)])

            # C1: Zero-Shot
            preds_cross_zs = (probs_cross >= thresh_val).astype(int)
            tn_cz, fp_cz, fn_cz, tp_cz = confusion_matrix(y_test_cross, preds_cross_zs).ravel()
            fpr_cz, fpr_cz_low, fpr_cz_up = compute_fpr_ci(fp_cz, tn_cz)
            roc_auc_c = float(roc_auc_score(y_test_cross, probs_cross))
            p_c_c, r_c_c, _ = precision_recall_curve(y_test_cross, probs_cross)
            pr_auc_c = float(auc(r_c_c, p_c_c))
            fpr_c_c, tpr_c_c, _ = roc_curve(y_test_cross, probs_cross)

            rf_cross_zs = {
                "model": "Random Forest",
                "split": "Cross-Day (Zero-Shot)",
                "benign_share": cross_benign_share,
                "benign_count": int(tn_cz + fp_cz),
                "attack_count": int(tp_cz + fn_cz),
                "threshold": round(thresh_val, 4),
                "precision": round(float(precision_score(y_test_cross, preds_cross_zs, zero_division=0)), 4),
                "recall": round(float(recall_score(y_test_cross, preds_cross_zs)), 4),
                "f1": round(float(f1_score(y_test_cross, preds_cross_zs)), 4),
                "fpr": round(fpr_cz, 4),
                "fpr_ci_lower": fpr_cz_low,
                "fpr_ci_upper": fpr_cz_up,
                "roc_auc": round(roc_auc_c, 4),
                "pr_auc": round(pr_auc_c, 4),
                "latency_ms_per_1k": lat_cross,
                "confusion_matrix": {"tn": int(tn_cz), "fp": int(fp_cz), "fn": int(fn_cz), "tp": int(tp_cz)},
                "per_attack_recall": compute_per_attack_recall(df_test_cross, preds_cross_zs),
                "fpr_curve": fpr_c_c.tolist(),
                "tpr_curve": tpr_c_c.tolist(),
                "pr_precision": p_c_c.tolist(),
                "pr_recall": r_c_c.tolist(),
                "model_size_mb": round(rf_path.stat().st_size / (1024 * 1024), 2),
            }
            results["Random Forest (Cross-Day Zero-Shot)"] = rf_cross_zs
            summary_rows.append(rf_cross_zs)

            # C2: Target-Calibrated
            mask_benign = (y_test_cross == 0)
            idx_benign = np.where(mask_benign)[0]
            n_benign = len(idx_benign)
            n_cal = n_benign // 2
            idx_cal = idx_benign[:n_cal]
            idx_eval = idx_benign[n_cal:]

            probs_cal_b = probs_cross[idx_cal]
            thresh_cal = float(np.percentile(probs_cal_b, 100.0 * (1.0 - target_max_fpr)))

            probs_eval_b = probs_cross[idx_eval]
            idx_attacks = np.where(y_test_cross == 1)[0]
            probs_attacks = probs_cross[idx_attacks]

            fp_cal = int((probs_eval_b >= thresh_cal).sum())
            tn_cal = int(len(probs_eval_b) - fp_cal)
            tp_cal = int((probs_attacks >= thresh_cal).sum())
            fn_cal = int(len(probs_attacks) - tp_cal)

            fpr_cal, cal_low, cal_up = compute_fpr_ci(fp_cal, tn_cal)
            prec_cal = tp_cal / max(1, tp_cal + fp_cal)
            rec_cal = tp_cal / max(1, tp_cal + fn_cal)
            f1_cal = (2 * prec_cal * rec_cal / (prec_cal + rec_cal)) if (prec_cal + rec_cal) > 0 else 0.0

            preds_cross_cal = np.zeros(len(df_test_cross), dtype=int)
            preds_cross_cal[probs_cross >= thresh_cal] = 1

            rf_cross_cal = {
                "model": "Random Forest",
                "split": "Cross-Day (Target-Calibrated)",
                "benign_share": f"{len(idx_eval) / (len(idx_eval) + len(idx_attacks)) * 100:.2f}%",
                "benign_count": int(tn_cal + fp_cal),
                "attack_count": int(tp_cal + fn_cal),
                "threshold": round(thresh_cal, 4),
                "precision": round(float(prec_cal), 4),
                "recall": round(float(rec_cal), 4),
                "f1": round(float(f1_cal), 4),
                "fpr": round(fpr_cal, 4),
                "fpr_ci_lower": cal_low,
                "fpr_ci_upper": cal_up,
                "roc_auc": round(roc_auc_c, 4),
                "pr_auc": round(pr_auc_c, 4),
                "latency_ms_per_1k": lat_cross,
                "confusion_matrix": {"tn": int(tn_cal), "fp": int(fp_cal), "fn": int(fn_cal), "tp": int(tp_cal)},
                "per_attack_recall": compute_per_attack_recall(df_test_cross, preds_cross_cal),
                "fpr_curve": [],
                "tpr_curve": [],
                "pr_precision": [],
                "pr_recall": [],
                "model_size_mb": round(rf_path.stat().st_size / (1024 * 1024), 2),
            }
            results["Random Forest (Cross-Day Target-Calibrated)"] = rf_cross_cal
            summary_rows.append(rf_cross_cal)

    # -------------------------------------------------------------
    # 2. KNN Classifier
    # -------------------------------------------------------------
    knn_path = models_dir / "knn.joblib"
    if knn_path.is_file():
        logger.info("Evaluating KNN Classifier...")
        knn = joblib.load(knn_path)

        def _predict_proba_batched(model_obj: Any, X_arr: np.ndarray, batch_size: int = 50000) -> np.ndarray:
            if len(X_arr) <= batch_size:
                return model_obj.predict_proba(X_arr)[:, 1]
            probs_list = []
            for i in range(0, len(X_arr), batch_size):
                probs_list.append(model_obj.predict_proba(X_arr[i : i + batch_size])[:, 1])
            return np.concatenate(probs_list)

        probs_val = _predict_proba_batched(knn, X_val)
        thresh_val, val_fpr, val_rec = find_optimal_threshold(y_val, probs_val, target_max_fpr)
        logger.info(f"KNN Zero-Shot Threshold chosen on Validation: {thresh_val:.4f} (Val FPR={val_fpr:.4f}, Val Recall={val_rec:.4f})")

        probs_same = _predict_proba_batched(knn, X_test_same)
        preds_same = (probs_same >= thresh_val).astype(int)
        tn_s, fp_s, fn_s, tp_s = confusion_matrix(y_test_same, preds_same).ravel()
        fpr_s, fpr_s_low, fpr_s_up = compute_fpr_ci(fp_s, tn_s)
        roc_auc_s = float(roc_auc_score(y_test_same, probs_same))
        p_c_s, r_c_s, _ = precision_recall_curve(y_test_same, probs_same)
        pr_auc_s = float(auc(r_c_s, p_c_s))
        lat_same = measure_inference_speed(knn.predict_proba, X_test_same[:min(len(X_test_same), 500)])
        fpr_c_s, tpr_c_s, _ = roc_curve(y_test_same, probs_same)

        knn_same_metrics = {
            "model": "KNN",
            "split": "Same-Day (Zero-Shot)",
            "benign_share": same_benign_share,
            "benign_count": int(tn_s + fp_s),
            "attack_count": int(tp_s + fn_s),
            "threshold": round(thresh_val, 4),
            "precision": round(float(precision_score(y_test_same, preds_same, zero_division=0)), 4),
            "recall": round(float(recall_score(y_test_same, preds_same)), 4),
            "f1": round(float(f1_score(y_test_same, preds_same)), 4),
            "fpr": round(fpr_s, 4),
            "fpr_ci_lower": fpr_s_low,
            "fpr_ci_upper": fpr_s_up,
            "roc_auc": round(roc_auc_s, 4),
            "pr_auc": round(pr_auc_s, 4),
            "latency_ms_per_1k": lat_same,
            "confusion_matrix": {"tn": int(tn_s), "fp": int(fp_s), "fn": int(fn_s), "tp": int(tp_s)},
            "per_attack_recall": compute_per_attack_recall(df_test_same, preds_same),
            "fpr_curve": fpr_c_s.tolist(),
            "tpr_curve": tpr_c_s.tolist(),
            "pr_precision": p_c_s.tolist(),
            "pr_recall": r_c_s.tolist(),
            "model_size_mb": round(knn_path.stat().st_size / (1024 * 1024), 2),
        }
        results["KNN (Same-Day Zero-Shot)"] = knn_same_metrics
        summary_rows.append(knn_same_metrics)

        if has_cross_day:
            probs_cross = _predict_proba_batched(knn, X_test_cross)
            lat_cross = measure_inference_speed(knn.predict_proba, X_test_cross[:min(len(X_test_cross), 500)])

            # C1: Zero-Shot
            preds_cross_zs = (probs_cross >= thresh_val).astype(int)
            tn_cz, fp_cz, fn_cz, tp_cz = confusion_matrix(y_test_cross, preds_cross_zs).ravel()
            fpr_cz, fpr_cz_low, fpr_cz_up = compute_fpr_ci(fp_cz, tn_cz)
            roc_auc_c = float(roc_auc_score(y_test_cross, probs_cross))
            p_c_c, r_c_c, _ = precision_recall_curve(y_test_cross, probs_cross)
            pr_auc_c = float(auc(r_c_c, p_c_c))
            fpr_c_c, tpr_c_c, _ = roc_curve(y_test_cross, probs_cross)

            knn_cross_zs = {
                "model": "KNN",
                "split": "Cross-Day (Zero-Shot)",
                "benign_share": cross_benign_share,
                "benign_count": int(tn_cz + fp_cz),
                "attack_count": int(tp_cz + fn_cz),
                "threshold": round(thresh_val, 4),
                "precision": round(float(precision_score(y_test_cross, preds_cross_zs, zero_division=0)), 4),
                "recall": round(float(recall_score(y_test_cross, preds_cross_zs)), 4),
                "f1": round(float(f1_score(y_test_cross, preds_cross_zs)), 4),
                "fpr": round(fpr_cz, 4),
                "fpr_ci_lower": fpr_cz_low,
                "fpr_ci_upper": fpr_cz_up,
                "roc_auc": round(roc_auc_c, 4),
                "pr_auc": round(pr_auc_c, 4),
                "latency_ms_per_1k": lat_cross,
                "confusion_matrix": {"tn": int(tn_cz), "fp": int(fp_cz), "fn": int(fn_cz), "tp": int(tp_cz)},
                "per_attack_recall": compute_per_attack_recall(df_test_cross, preds_cross_zs),
                "fpr_curve": [],
                "tpr_curve": [],
                "pr_precision": [],
                "pr_recall": [],
                "model_size_mb": round(knn_path.stat().st_size / (1024 * 1024), 2),
            }
            results["KNN (Cross-Day Zero-Shot)"] = knn_cross_zs
            summary_rows.append(knn_cross_zs)

            # C2: Target-Calibrated
            mask_benign = (y_test_cross == 0)
            idx_benign = np.where(mask_benign)[0]
            n_benign = len(idx_benign)
            n_cal = n_benign // 2
            idx_cal = idx_benign[:n_cal]
            idx_eval = idx_benign[n_cal:]

            probs_cal_b = probs_cross[idx_cal]
            thresh_cal = float(np.percentile(probs_cal_b, 100.0 * (1.0 - target_max_fpr)))

            probs_eval_b = probs_cross[idx_eval]
            idx_attacks = np.where(y_test_cross == 1)[0]
            probs_attacks = probs_cross[idx_attacks]

            fp_cal = int((probs_eval_b >= thresh_cal).sum())
            tn_cal = int(len(probs_eval_b) - fp_cal)
            tp_cal = int((probs_attacks >= thresh_cal).sum())
            fn_cal = int(len(probs_attacks) - tp_cal)

            fpr_cal, cal_low, cal_up = compute_fpr_ci(fp_cal, tn_cal)
            prec_cal = tp_cal / max(1, tp_cal + fp_cal)
            rec_cal = tp_cal / max(1, tp_cal + fn_cal)
            f1_cal = (2 * prec_cal * rec_cal / (prec_cal + rec_cal)) if (prec_cal + rec_cal) > 0 else 0.0

            preds_cross_cal = np.zeros(len(df_test_cross), dtype=int)
            preds_cross_cal[probs_cross >= thresh_cal] = 1

            knn_cross_cal = {
                "model": "KNN",
                "split": "Cross-Day (Target-Calibrated)",
                "benign_share": f"{len(idx_eval) / (len(idx_eval) + len(idx_attacks)) * 100:.2f}%",
                "benign_count": int(tn_cal + fp_cal),
                "attack_count": int(tp_cal + fn_cal),
                "threshold": round(thresh_cal, 4),
                "precision": round(float(prec_cal), 4),
                "recall": round(float(rec_cal), 4),
                "f1": round(float(f1_cal), 4),
                "fpr": round(fpr_cal, 4),
                "fpr_ci_lower": cal_low,
                "fpr_ci_upper": cal_up,
                "roc_auc": round(roc_auc_c, 4),
                "pr_auc": round(pr_auc_c, 4),
                "latency_ms_per_1k": lat_cross,
                "confusion_matrix": {"tn": int(tn_cal), "fp": int(fp_cal), "fn": int(fn_cal), "tp": int(tp_cal)},
                "per_attack_recall": compute_per_attack_recall(df_test_cross, preds_cross_cal),
                "fpr_curve": [],
                "tpr_curve": [],
                "pr_precision": [],
                "pr_recall": [],
                "model_size_mb": round(knn_path.stat().st_size / (1024 * 1024), 2),
            }
            results["KNN (Cross-Day Target-Calibrated)"] = knn_cross_cal
            summary_rows.append(knn_cross_cal)

    # -------------------------------------------------------------
    # 3. PyTorch LSTM
    # -------------------------------------------------------------
    lstm_path = models_dir / "lstm.pt"
    lstm_test_same_npz = processed_dir / "lstm_test_same_day.npz"
    lstm_test_cross_npz = processed_dir / "lstm_test_cross_day.npz"
    lstm_val_npz = processed_dir / "lstm_val.npz"

    if lstm_path.is_file() and lstm_test_same_npz.is_file() and lstm_val_npz.is_file():
        logger.info("Evaluating PyTorch LSTM...")
        import torch
        from ddos_ads.train_lstm import LSTMAnomalyClassifier

        checkpoint = torch.load(lstm_path, map_location="cpu")
        model = LSTMAnomalyClassifier(
            input_dim=checkpoint["input_dim"],
            hidden_dim=checkpoint["hidden_dim"],
            num_layers=checkpoint.get("num_layers", 2),
            dropout=0.0,
        )
        model.load_state_dict(checkpoint["model_state_dict"])
        model.eval()

        def _lstm_eval_batch(batch_x: np.ndarray) -> np.ndarray:
            with torch.no_grad():
                return torch.sigmoid(model(torch.from_numpy(batch_x))).detach().cpu().numpy().flatten()

        # Step A: Choose threshold on Validation Split ONLY
        val_data = np.load(lstm_val_npz)
        X_lstm_val, y_lstm_val = val_data["X"], val_data["y"].astype(int)
        probs_val = _lstm_eval_batch(X_lstm_val)
        thresh_val, _, _ = find_optimal_threshold(y_lstm_val, probs_val, target_max_fpr)
        logger.info(f"LSTM Zero-Shot Threshold chosen on Validation: {thresh_val:.4f}")

        # Step B: Evaluate on Same-Day Test (Zero-Shot)
        same_data = np.load(lstm_test_same_npz)
        X_lstm_same, y_lstm_same = same_data["X"], same_data["y"].astype(int)
        same_b_share = f"{(y_lstm_same == 0).sum() / max(1, len(y_lstm_same)) * 100:.2f}%"

        probs_same = _lstm_eval_batch(X_lstm_same)
        preds_same = (probs_same >= thresh_val).astype(int)
        tn_s, fp_s, fn_s, tp_s = confusion_matrix(y_lstm_same, preds_same).ravel()
        fpr_s, fpr_s_low, fpr_s_up = compute_fpr_ci(fp_s, tn_s)
        roc_auc_s = float(roc_auc_score(y_lstm_same, probs_same))
        p_c_s, r_c_s, _ = precision_recall_curve(y_lstm_same, probs_same)
        pr_auc_s = float(auc(r_c_s, p_c_s))
        lat_same = measure_inference_speed(_lstm_eval_batch, X_lstm_same[:min(len(X_lstm_same), 500)])
        fpr_c_s, tpr_c_s, _ = roc_curve(y_lstm_same, probs_same)

        lstm_same_metrics = {
            "model": "LSTM",
            "split": "Same-Day (Zero-Shot)",
            "benign_share": same_b_share,
            "benign_count": int(tn_s + fp_s),
            "attack_count": int(tp_s + fn_s),
            "threshold": round(thresh_val, 4),
            "precision": round(float(precision_score(y_lstm_same, preds_same, zero_division=0)), 4),
            "recall": round(float(recall_score(y_lstm_same, preds_same)), 4),
            "f1": round(float(f1_score(y_lstm_same, preds_same)), 4),
            "fpr": round(fpr_s, 4),
            "fpr_ci_lower": fpr_s_low,
            "fpr_ci_upper": fpr_s_up,
            "roc_auc": round(roc_auc_s, 4),
            "pr_auc": round(pr_auc_s, 4),
            "latency_ms_per_1k": lat_same,
            "confusion_matrix": {"tn": int(tn_s), "fp": int(fp_s), "fn": int(fn_s), "tp": int(tp_s)},
            "per_attack_recall": {},
            "fpr_curve": fpr_c_s.tolist(),
            "tpr_curve": tpr_c_s.tolist(),
            "pr_precision": p_c_s.tolist(),
            "pr_recall": r_c_s.tolist(),
            "model_size_mb": round(lstm_path.stat().st_size / (1024 * 1024), 2),
        }
        results["LSTM (Same-Day Zero-Shot)"] = lstm_same_metrics
        summary_rows.append(lstm_same_metrics)

        # Step C: Evaluate on Cross-Day Test (Zero-Shot & Target-Calibrated)
        if lstm_test_cross_npz.is_file():
            cross_data = np.load(lstm_test_cross_npz)
            X_lstm_cross, y_lstm_cross = cross_data["X"], cross_data["y"].astype(int)
            cross_b_share = f"{(y_lstm_cross == 0).sum() / max(1, len(y_lstm_cross)) * 100:.2f}%"

            probs_cross = _lstm_eval_batch(X_lstm_cross)
            lat_cross = measure_inference_speed(_lstm_eval_batch, X_lstm_cross[:min(len(X_lstm_cross), 500)])

            # C1: Zero-Shot
            preds_cross_zs = (probs_cross >= thresh_val).astype(int)
            tn_cz, fp_cz, fn_cz, tp_cz = confusion_matrix(y_lstm_cross, preds_cross_zs).ravel()
            fpr_cz, fpr_cz_low, fpr_cz_up = compute_fpr_ci(fp_cz, tn_cz)
            roc_auc_c = float(roc_auc_score(y_lstm_cross, probs_cross))
            p_c_c, r_c_c, _ = precision_recall_curve(y_lstm_cross, probs_cross)
            pr_auc_c = float(auc(r_c_c, p_c_c))

            lstm_cross_zs = {
                "model": "LSTM",
                "split": "Cross-Day (Zero-Shot)",
                "benign_share": cross_b_share,
                "benign_count": int(tn_cz + fp_cz),
                "attack_count": int(tp_cz + fn_cz),
                "threshold": round(thresh_val, 4),
                "precision": round(float(precision_score(y_lstm_cross, preds_cross_zs, zero_division=0)), 4),
                "recall": round(float(recall_score(y_lstm_cross, preds_cross_zs)), 4),
                "f1": round(float(f1_score(y_lstm_cross, preds_cross_zs)), 4),
                "fpr": round(fpr_cz, 4),
                "fpr_ci_lower": fpr_cz_low,
                "fpr_ci_upper": fpr_cz_up,
                "roc_auc": round(roc_auc_c, 4),
                "pr_auc": round(pr_auc_c, 4),
                "latency_ms_per_1k": lat_cross,
                "confusion_matrix": {"tn": int(tn_cz), "fp": int(fp_cz), "fn": int(fn_cz), "tp": int(tp_cz)},
                "per_attack_recall": {},
                "fpr_curve": [],
                "tpr_curve": [],
                "pr_precision": [],
                "pr_recall": [],
                "model_size_mb": round(lstm_path.stat().st_size / (1024 * 1024), 2),
            }
            results["LSTM (Cross-Day Zero-Shot)"] = lstm_cross_zs
            summary_rows.append(lstm_cross_zs)

            # C2: Target-Calibrated
            mask_benign = (y_lstm_cross == 0)
            idx_benign = np.where(mask_benign)[0]
            n_benign = len(idx_benign)
            n_cal = n_benign // 2
            idx_cal = idx_benign[:n_cal]
            idx_eval = idx_benign[n_cal:]

            probs_cal_b = probs_cross[idx_cal]
            thresh_cal = float(np.percentile(probs_cal_b, 100.0 * (1.0 - target_max_fpr)))

            probs_eval_b = probs_cross[idx_eval]
            idx_attacks = np.where(y_lstm_cross == 1)[0]
            probs_attacks = probs_cross[idx_attacks]

            fp_cal = int((probs_eval_b >= thresh_cal).sum())
            tn_cal = int(len(probs_eval_b) - fp_cal)
            tp_cal = int((probs_attacks >= thresh_cal).sum())
            fn_cal = int(len(probs_attacks) - tp_cal)

            fpr_cal, cal_low, cal_up = compute_fpr_ci(fp_cal, tn_cal)
            prec_cal = tp_cal / max(1, tp_cal + fp_cal)
            rec_cal = tp_cal / max(1, tp_cal + fn_cal)
            f1_cal = (2 * prec_cal * rec_cal / (prec_cal + rec_cal)) if (prec_cal + rec_cal) > 0 else 0.0

            lstm_cross_cal = {
                "model": "LSTM",
                "split": "Cross-Day (Target-Calibrated)",
                "benign_share": f"{len(idx_eval) / (len(idx_eval) + len(idx_attacks)) * 100:.2f}%",
                "benign_count": int(tn_cal + fp_cal),
                "attack_count": int(tp_cal + fn_cal),
                "threshold": round(thresh_cal, 4),
                "precision": round(float(prec_cal), 4),
                "recall": round(float(rec_cal), 4),
                "f1": round(float(f1_cal), 4),
                "fpr": round(fpr_cal, 4),
                "fpr_ci_lower": cal_low,
                "fpr_ci_upper": cal_up,
                "roc_auc": round(roc_auc_c, 4),
                "pr_auc": round(pr_auc_c, 4),
                "latency_ms_per_1k": lat_cross,
                "confusion_matrix": {"tn": int(tn_cal), "fp": int(fp_cal), "fn": int(fn_cal), "tp": int(tp_cal)},
                "per_attack_recall": {},
                "fpr_curve": [],
                "tpr_curve": [],
                "pr_precision": [],
                "pr_recall": [],
                "model_size_mb": round(lstm_path.stat().st_size / (1024 * 1024), 2),
            }
            results["LSTM (Cross-Day Target-Calibrated)"] = lstm_cross_cal
            summary_rows.append(lstm_cross_cal)

    # Print summary performance table
    print_evaluation_summary(summary_rows)

    # 4. Perform Window-Level Evaluation and Calibration Sensitivity
    logger.info("Executing comprehensive Window-Level Evaluation across RF, KNN, and LSTM...")
    evaluate_window_level(config, results)

    # 5. Multi-seed LSTM evaluation
    evaluate_lstm_multi_seeds(config, results, processed_dir, models_dir)

    # 6. Flow shuffle ablation
    evaluate_shuffle_ablation(config, results, processed_dir, models_dir)

    # 7. Window-stats baseline (RF on Mean & Std)
    evaluate_window_stats_baseline(config, results, processed_dir)

    # 7b. Smooth-model baselines (Logistic Regression & MLP on Mean & Std)
    evaluate_smooth_model_baselines(config, results, processed_dir)

    # 8. Onset test (k = 1..9 attack flows)
    evaluate_onset_test(config, results, processed_dir, models_dir)

    # 8b. Onset order sensitivity (attack flows first vs last vs random)
    evaluate_onset_order_sensitivity(config, results, processed_dir, models_dir)

    # 9. Threshold search analysis
    evaluate_threshold_search(config, results, processed_dir, models_dir)

    # 10. Block bootstrap CIs
    evaluate_block_bootstrap(config, results, processed_dir, models_dir)

    # 11. Calibration folds provenance
    evaluate_calibration_folds_provenance(results)

    # Export results
    results_dir.mkdir(parents=True, exist_ok=True)
    metrics_json_path = results_dir / "metrics.json"
    with open(metrics_json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    # Clean DataFrame for metrics.csv without long curve arrays
    csv_rows = []
    for r in summary_rows:
        row = {k: v for k, v in r.items() if not k.endswith("_curve") and not k.startswith("pr_") and k != "per_attack_recall"}
        csv_rows.append(row)
    df_metrics = pd.DataFrame(csv_rows)
    df_metrics.to_csv(results_dir / "metrics.csv", index=False)

    # Generate plots
    generate_evaluation_plots(results, results_dir)
    logger.info(f"Evaluation complete. All metrics and checks saved to {metrics_json_path} and plots generated in {results_dir}.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate DDoS anomaly detection models.")
    parser.add_argument("--config", type=str, default=None, help="Path to config.yaml.")
    args = parser.parse_args()
    evaluate_models(config_path=args.config)


if __name__ == "__main__":
    main()
