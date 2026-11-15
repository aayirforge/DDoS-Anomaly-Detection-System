"""K-Nearest Neighbors model training with hyperparameter tuning on validation split and smoke test."""

from __future__ import annotations

import argparse
from pathlib import Path
import tempfile
from typing import List, Optional
import joblib
import numpy as np
import pandas as pd
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score

from ddos_ads.config import load_config
from ddos_ads.features import load_selected_features
from ddos_ads.utils import record_train_log, set_seeds, setup_logger, timer

logger = setup_logger("ddos_ads.train_knn")


def run_smoke_test() -> None:
    """Execute isolated KNN smoke test without writing to real directories."""
    logger.info("=== Running KNN Smoke Test in Isolated Temp Directory ===")
    with tempfile.TemporaryDirectory() as temp_dir_str:
        temp_dir = Path(temp_dir_str)
        temp_models = temp_dir / "models"
        temp_results = temp_dir / "results"
        temp_models.mkdir()
        temp_results.mkdir()

        # Generate tiny synthetic dataset
        rng = np.random.RandomState(42)
        n_samples, n_feats = 50, 4
        X_train = rng.randn(n_samples, n_feats)
        y_train = rng.choice([0, 1], size=n_samples, p=[0.7, 0.3])
        X_val = rng.randn(20, n_feats)
        y_val = rng.choice([0, 1], size=20, p=[0.7, 0.3])

        knn = KNeighborsClassifier(n_neighbors=3, weights="distance")
        with timer("KNN Smoke Fit", logger) as t:
            knn.fit(X_train, y_train)

        preds = knn.predict(X_val)
        assert len(preds) == 20

        model_path = temp_models / "knn.joblib"
        joblib.dump(knn, model_path)
        assert model_path.is_file() and model_path.stat().st_size > 0

        record_train_log(
            results_dir=temp_results,
            model_name="knn",
            elapsed_sec=t["elapsed_sec"],
            model_size_bytes=model_path.stat().st_size,
            metrics={"smoke_test": True},
        )
        assert (temp_results / "train_log.json").is_file()

    logger.info("KNN smoke test completed successfully with 0 disk leaks.")


def train_knn(
    config_path: Optional[str] = None,
    k: Optional[int] = None,
    weights: Optional[str] = None,
    subsample_size: Optional[int] = None,
) -> None:
    """Train and tune KNN classifier on processed dataset."""
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

    logger.info(f"Loading data from {train_path} and {val_path}...")
    df_train = pd.read_parquet(train_path)
    df_val = pd.read_parquet(val_path)

    # Subsample training data to prevent excessive memory and inference latency
    sub_size = subsample_size or config.get("models.knn.subsample_train_size", 25000)
    if len(df_train) > sub_size:
        logger.info(f"Subsampling training set from {len(df_train)} to {sub_size} flows for KNN...")
        # Preserve benign flows balance
        benign = df_train[df_train["Label_Binary"] == 0]
        attack = df_train[df_train["Label_Binary"] == 1]
        half = sub_size // 2
        sub_benign = benign.sample(n=min(len(benign), half), random_state=seed)
        sub_attack = attack.sample(n=min(len(attack), sub_size - len(sub_benign)), random_state=seed)
        df_train_sub = pd.concat([sub_benign, sub_attack], ignore_index=True)
    else:
        df_train_sub = df_train

    X_train = df_train_sub[feature_cols].values
    y_train = df_train_sub["Label_Binary"].values

    # Subsample validation set for evaluation if large
    val_eval_size = min(len(df_val), 10000)
    df_val_sub = df_val.sample(n=val_eval_size, random_state=seed) if len(df_val) > val_eval_size else df_val
    X_val = df_val_sub[feature_cols].values
    y_val = df_val_sub["Label_Binary"].values

    candidate_ks = [k] if k is not None else config.get("models.knn.candidate_k", [3, 5, 7])
    candidate_weights = [weights] if weights is not None else config.get("models.knn.candidate_weights", ["uniform", "distance"])

    best_score = -1.0
    best_model: Optional[KNeighborsClassifier] = None
    best_params = {}

    logger.info(f"Tuning KNN on validation set across k={candidate_ks}, weights={candidate_weights}...")
    with timer("KNN Model Selection", logger) as t:
        for cand_k in candidate_ks:
            for cand_w in candidate_weights:
                model = KNeighborsClassifier(n_neighbors=cand_k, weights=cand_w, n_jobs=-1)
                model.fit(X_train, y_train)

                val_preds = model.predict(X_val)
                score = float(f1_score(y_val, val_preds, zero_division=0))
                logger.info(f"Candidate k={cand_k}, weights={cand_w} -> Val F1: {score:.4f}")

                if score > best_score:
                    best_score = score
                    best_model = model
                    best_params = {"k": cand_k, "weights": cand_w}

    if best_model is None:
        raise RuntimeError("KNN tuning failed to find a valid model.")

    logger.info(f"Optimal KNN parameters: {best_params} (Val F1: {best_score:.4f})")

    # Evaluate best model
    val_preds = best_model.predict(X_val)
    val_probs = best_model.predict_proba(X_val)[:, 1]
    val_f1 = float(f1_score(y_val, val_preds))
    val_prec = float(precision_score(y_val, val_preds, zero_division=0))
    val_rec = float(recall_score(y_val, val_preds))
    val_auc = float(roc_auc_score(y_val, val_probs))

    # Save model
    model_path = models_dir / "knn.joblib"
    joblib.dump(best_model, model_path)
    model_size = model_path.stat().st_size
    logger.info(f"KNN model saved to {model_path} ({model_size / (1024*1024):.2f} MB)")

    record_train_log(
        results_dir=results_dir,
        model_name="knn",
        elapsed_sec=t["elapsed_sec"],
        model_size_bytes=model_size,
        metrics={
            "best_params": best_params,
            "val_f1": val_f1,
            "val_precision": val_prec,
            "val_recall": val_rec,
            "val_roc_auc": val_auc,
        },
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Train K-Nearest Neighbors classifier.")
    parser.add_argument("--smoke-test", action="store_true", help="Run synthetic smoke test in isolated temp dir.")
    parser.add_argument("--config", type=str, default=None, help="Path to config.yaml.")
    parser.add_argument("--k", type=int, default=None, help="Specific number of neighbors k.")
    parser.add_argument("--weights", choices=["uniform", "distance"], default=None, help="Weight function.")
    parser.add_argument("--subsample-size", type=int, default=None, help="Training subsample size.")
    args = parser.parse_args()

    if args.smoke_test:
        run_smoke_test()
    else:
        train_knn(
            config_path=args.config,
            k=args.k,
            weights=args.weights,
            subsample_size=args.subsample_size,
        )


if __name__ == "__main__":
    main()
