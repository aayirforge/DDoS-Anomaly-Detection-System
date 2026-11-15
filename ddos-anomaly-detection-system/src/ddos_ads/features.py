"""Feature engineering, correlation pruning, feature ranking, and sequence window generation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Tuple
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from ddos_ads.utils import setup_logger

logger = setup_logger("ddos_ads.features")


def remove_collinear_features(
    df: pd.DataFrame,
    feature_cols: List[str],
    threshold: float = 0.95,
) -> List[str]:
    """
    Remove collinear features whose absolute Pearson correlation exceeds the threshold.
    Returns the retained subset of feature column names.
    """
    if len(feature_cols) <= 1:
        return feature_cols

    corr_matrix = df[feature_cols].corr().abs()
    upper = corr_matrix.where(np.triu(np.ones(corr_matrix.shape), k=1).astype(bool))

    to_drop = [col for col in upper.columns if any(upper[col] > threshold)]
    retained = [col for col in feature_cols if col not in to_drop]

    logger.info(
        f"Correlation filter (threshold > {threshold}): dropped {len(to_drop)} features, "
        f"retained {len(retained)} out of {len(feature_cols)}."
    )
    return retained


def rank_and_select_features(
    X: pd.DataFrame,
    y: pd.Series,
    feature_cols: List[str],
    top_k: int = 25,
    random_seed: int = 42,
) -> List[str]:
    """
    Rank features using a fast RandomForestClassifier and return the top K feature names.
    """
    if len(feature_cols) <= top_k:
        logger.info(f"Available features ({len(feature_cols)}) <= top_k ({top_k}). Retaining all.")
        return feature_cols

    logger.info(f"Ranking {len(feature_cols)} candidate features using RandomForest...")
    rf = RandomForestClassifier(
        n_estimators=30,
        max_depth=10,
        n_jobs=-1,
        random_state=random_seed,
    )
    rf.fit(X[feature_cols], y)

    importances = rf.feature_importances_
    ranked_indices = np.argsort(importances)[::-1]
    selected = [feature_cols[i] for i in ranked_indices[:top_k]]

    logger.info(f"Selected top {len(selected)} features:")
    for rank, feat in enumerate(selected[:10], 1):
        idx = feature_cols.index(feat)
        logger.info(f"  {rank}. {feat} (importance: {importances[idx]:.4f})")

    return selected


def save_selected_features(
    features: List[str],
    output_path: Path | str,
    metadata: Optional[dict[str, Any]] = None,
) -> None:
    """Save selected feature column names and optional metadata (dropped columns, parameters) to JSON."""
    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {
        "selected_features": features,
        "feature_count": len(features),
    }
    if metadata:
        payload.update(metadata)

    with open(p, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    logger.info(f"Saved {len(features)} feature names and metadata to {p}")


def load_selected_features(features_path: Path | str) -> List[str]:
    """Load selected feature column names from JSON (supports both list and dictionary schemas)."""
    p = Path(features_path)
    if not p.is_file():
        raise FileNotFoundError(f"Selected features file not found: {p}")
    with open(p, "r", encoding="utf-8") as f:
        data = json.load(f)
        if isinstance(data, dict) and "selected_features" in data:
            return data["selected_features"]
        if isinstance(data, list):
            return data
        raise ValueError(f"Unexpected features format in {p}")


def build_lstm_windows(
    X: np.ndarray,
    y: np.ndarray,
    window_size: int = 10,
    step_size: int = 5,
) -> Tuple[np.ndarray, np.ndarray]:
    """
    Create sliding windows for LSTM time-series modeling.
    Crucial guard: Windows are constructed strictly within a single continuous dataset/split
    and must NEVER cross split boundaries.
    """
    n_samples = len(X)
    if n_samples < window_size:
        return (
            np.empty((0, window_size, X.shape[1]), dtype=np.float32),
            np.empty((0,), dtype=np.float32),
        )

    windows_X = []
    windows_y = []

    for start_idx in range(0, n_samples - window_size + 1, step_size):
        end_idx = start_idx + window_size
        win_X = X[start_idx:end_idx]
        win_y = y[start_idx:end_idx]

        # Window is labeled 1 if any flow is an attack, 0 if all are benign
        win_label = 1.0 if np.any(win_y == 1) else 0.0

        windows_X.append(win_X)
        windows_y.append(win_label)

    return (
        np.array(windows_X, dtype=np.float32),
        np.array(windows_y, dtype=np.float32),
    )


def build_lstm_windows_from_blocks(
    df: pd.DataFrame,
    feature_cols: List[str],
    window_size: int = 10,
    step_size: int = 5,
    block_col: str = "Block_ID",
) -> Tuple[np.ndarray, np.ndarray]:
    """
    Construct LSTM sliding windows strictly within contiguous blocks of flows.
    Windows NEVER cross block boundaries or discontinuous sample gaps.
    """
    if df.empty or block_col not in df.columns:
        X_mat = df[feature_cols].to_numpy(dtype=np.float32) if not df.empty else np.empty((0, len(feature_cols)))
        y_arr = df["Label_Binary"].to_numpy(dtype=np.float32) if not df.empty else np.empty((0,))
        return build_lstm_windows(X_mat, y_arr, window_size=window_size, step_size=step_size)

    all_X_windows = []
    all_y_windows = []

    for _, block_df in df.groupby(block_col, sort=False):
        if len(block_df) >= window_size:
            X_block = block_df[feature_cols].to_numpy(dtype=np.float32)
            y_block = block_df["Label_Binary"].to_numpy(dtype=np.float32)
            wX, wy = build_lstm_windows(X_block, y_block, window_size=window_size, step_size=step_size)
            if len(wX) > 0:
                all_X_windows.append(wX)
                all_y_windows.append(wy)

    if not all_X_windows:
        return (
            np.empty((0, window_size, len(feature_cols)), dtype=np.float32),
            np.empty((0,), dtype=np.float32),
        )

    return (
        np.concatenate(all_X_windows, axis=0),
        np.concatenate(all_y_windows, axis=0),
    )

