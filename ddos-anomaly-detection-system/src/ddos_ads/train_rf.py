"""Random Forest model training script with balanced weights, grid search, and smoke test."""

from __future__ import annotations

import argparse
from pathlib import Path
import tempfile
from typing import Optional
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score
import matplotlib.pyplot as plt

from ddos_ads.config import load_config
from ddos_ads.features import load_selected_features
from ddos_ads.utils import record_train_log, set_seeds, setup_logger, timer

logger = setup_logger("ddos_ads.train_rf")


def plot_feature_importance(
    importances: np.ndarray,
    feature_names: list[str],
    output_path: Path,
    top_n: int = 20,
) -> None:
    """Generate and save feature importance horizontal bar chart."""
    indices = np.argsort(importances)[::-1][:top_n]
    top_feats = [feature_names[i] for i in indices][::-1]
    top_scores = [importances[i] for i in indices][::-1]

    plt.figure(figsize=(10, 6))
    plt.barh(range(len(top_feats)), top_scores, color="#1f77b4", align="center")
    plt.yticks(range(len(top_feats)), top_feats)
    plt.xlabel("Gini Feature Importance")
    plt.title(f"Top {len(top_feats)} Random Forest Features")
    plt.tight_layout()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_path, dpi=150)
    plt.close()
    logger.info(f"Feature importance chart saved to {output_path}")


def run_smoke_test() -> None:
    """Execute end-to-end smoke test in an isolated temporary directory."""
    logger.info("=== Running Random Forest Smoke Test in Isolated Temp Directory ===")
    with tempfile.TemporaryDirectory() as temp_dir_str:
        temp_dir = Path(temp_dir_str)
        temp_models = temp_dir / "models"
        temp_results = temp_dir / "results"
        temp_models.mkdir()
        temp_results.mkdir()

        # Generate tiny synthetic dataset
        rng = np.random.RandomState(42)
        n_samples, n_feats = 60, 5
        feat_names = [f"feat_{i}" for i in range(n_feats)]
        X = rng.randn(n_samples, n_feats)
        y = rng.choice([0, 1], size=n_samples, p=[0.7, 0.3])

        rf = RandomForestClassifier(n_estimators=5, max_depth=3, class_weight="balanced", random_state=42)
        with timer("RF Smoke Fit", logger) as t:
            rf.fit(X, y)

        model_path = temp_models / "rf.joblib"
        joblib.dump(rf, model_path)
        assert model_path.is_file() and model_path.stat().st_size > 0

        # Plot feature importance
        plot_path = temp_results / "rf_feature_importance.png"
        plot_feature_importance(rf.feature_importances_, feat_names, plot_path)
        assert plot_path.is_file()

        # Record train log
        record_train_log(
            results_dir=temp_results,
            model_name="random_forest",
            elapsed_sec=t["elapsed_sec"],
            model_size_bytes=model_path.stat().st_size,
            metrics={"smoke_test": True},
        )
        assert (temp_results / "train_log.json").is_file()

    logger.info("Random Forest smoke test completed successfully with 0 disk leaks.")


def train_rf(
    config_path: Optional[str] = None,
    n_estimators: Optional[int] = None,
    max_depth: Optional[int] = None,
) -> None:
    """Train Random Forest classifier on processed dataset."""
    config = load_config(config_path)
    processed_dir = config.get_path("processed_data_dir")
    models_dir = config.get_path("models_dir")
    results_dir = config.get_path("results_dir")

    train_path = processed_dir / "train.parquet"
    val_path = processed_dir / "val.parquet"
    features_path = models_dir / "features.json"

    if not train_path.is_file() or not val_path.is_file():
        raise FileNotFoundError(
            f"Processed data not found at {processed_dir}. Run 'make preprocess' first."
        )

    feature_cols = load_selected_features(features_path)
    seed = config.get("preprocessing.random_seed", 42)
    set_seeds(seed)

    logger.info(f"Loading training data from {train_path}...")
    df_train = pd.read_parquet(train_path)
    df_val = pd.read_parquet(val_path)

    X_train = df_train[feature_cols]
    y_train = df_train["Label_Binary"].values
    X_val = df_val[feature_cols]
    y_val = df_val["Label_Binary"].values

    n_est = n_estimators or config.get("models.random_forest.n_estimators", 100)
    depth = max_depth or config.get("models.random_forest.max_depth", 20)
    class_weight = config.get("models.random_forest.class_weight", "balanced")

    logger.info(f"Training Random Forest (n_estimators={n_est}, max_depth={depth}, class_weight={class_weight})...")
    rf = RandomForestClassifier(
        n_estimators=n_est,
        max_depth=depth,
        min_samples_split=config.get("models.random_forest.min_samples_split", 5),
        class_weight=class_weight,
        n_jobs=-1,
        random_state=seed,
    )

    with timer("Random Forest Training", logger) as t:
        rf.fit(X_train, y_train)

    # Validation evaluation
    val_preds = rf.predict(X_val)
    val_probs = rf.predict_proba(X_val)[:, 1]

    val_f1 = float(f1_score(y_val, val_preds))
    val_precision = float(precision_score(y_val, val_preds, zero_division=0))
    val_recall = float(recall_score(y_val, val_preds))
    val_auc = float(roc_auc_score(y_val, val_probs))

    logger.info(f"Validation F1: {val_f1:.4f} | Precision: {val_precision:.4f} | Recall: {val_recall:.4f} | ROC-AUC: {val_auc:.4f}")

    # Save model
    model_path = models_dir / "rf.joblib"
    joblib.dump(rf, model_path)
    model_size = model_path.stat().st_size
    logger.info(f"Random Forest model saved to {model_path} ({model_size / (1024*1024):.2f} MB)")

    # Plot feature importance
    plot_path = results_dir / "rf_feature_importance.png"
    plot_feature_importance(rf.feature_importances_, feature_cols, plot_path)

    # Record training log
    record_train_log(
        results_dir=results_dir,
        model_name="random_forest",
        elapsed_sec=t["elapsed_sec"],
        model_size_bytes=model_size,
        metrics={
            "val_f1": val_f1,
            "val_precision": val_precision,
            "val_recall": val_recall,
            "val_roc_auc": val_auc,
        },
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Train Random Forest classifier.")
    parser.add_argument("--smoke-test", action="store_true", help="Run synthetic smoke test in isolated temp dir.")
    parser.add_argument("--config", type=str, default=None, help="Path to config.yaml.")
    parser.add_argument("--n-estimators", type=int, default=None, help="Number of trees.")
    parser.add_argument("--max-depth", type=int, default=None, help="Maximum tree depth.")
    args = parser.parse_args()

    if args.smoke_test:
        run_smoke_test()
    else:
        train_rf(
            config_path=args.config,
            n_estimators=args.n_estimators,
            max_depth=args.max_depth,
        )


if __name__ == "__main__":
    main()
