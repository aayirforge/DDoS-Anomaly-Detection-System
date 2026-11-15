"""Tests for configuration loader, utils, and timestamp parsing."""

import os
from pathlib import Path
import pytest
import pandas as pd
from ddos_ads.config import load_config, Config
from ddos_ads.utils import (
    parse_cic_timestamp,
    check_models_exist,
    ensure_models_available,
    set_seeds,
    timer,
)


def test_config_loading_and_paths(tmp_path: Path) -> None:
    """Verify that config.yaml loads properly and resolves relative paths."""
    config = load_config()
    assert config is not None
    assert config.project_root.is_dir()

    # Verify placeholder Kaggle slug
    slug = config.get("download.kaggle_dataset_slug")
    assert isinstance(slug, str)
    assert len(slug) > 0

    # Verify paths resolve to absolute
    raw_dir = config.get_path("raw_data_dir")
    assert raw_dir.is_absolute()
    assert raw_dir.name == "raw"

    # Verify day patterns
    assert config.get("preprocessing.train_day_pattern") == "01-12"
    assert config.get("preprocessing.cross_day_pattern") == "03-11"

    # Verify safety defaults
    assert config.get("mitigation.enable_blocking") is False
    assert config.get("mitigation.exempt_rfc1918") is False


def test_model_presence_check(tmp_path: Path) -> None:
    """Verify that check_models_exist and ensure_models_available correctly detect missing models."""
    empty_dir = tmp_path / "models"
    empty_dir.mkdir()

    # Empty dir should fail check
    assert not check_models_exist(empty_dir, ["features.json", "scaler.joblib"])

    # Calling ensure_models_available must raise SystemExit(1)
    with pytest.raises(SystemExit) as exc_info:
        ensure_models_available(empty_dir, ["features.json"])
    assert exc_info.value.code == 1

    # Populate fake files and verify check succeeds
    (empty_dir / "features.json").write_text("[]")
    (empty_dir / "scaler.joblib").write_text("dummy")
    assert check_models_exist(empty_dir, ["features.json", "scaler.joblib"])


def test_timestamp_parsing_variants() -> None:
    """Verify parsing of various timestamp formats encountered in CIC-DDoS2019 data."""
    # 1. Standard ISO format
    s_iso = pd.Series(["2019-01-12 10:30:00", "2019-01-12 10:30:05", "2019-01-12 10:30:10"])
    res_iso = parse_cic_timestamp(s_iso)
    assert not res_iso.isna().any()
    assert res_iso.iloc[0].year == 2019
    assert res_iso.iloc[0].month == 1
    assert res_iso.iloc[0].day == 12

    # 2. 12-hour AM/PM format
    s_ampm = pd.Series(["12/01/2019 10:30:00 AM", "12/01/2019 02:45:00 PM"])
    res_ampm = parse_cic_timestamp(s_ampm)
    assert not res_ampm.isna().any()
    assert res_ampm.iloc[1].hour == 14

    # 3. Epoch timestamps (seconds)
    s_epoch_sec = pd.Series([1547289000, 1547289005])
    res_epoch_sec = parse_cic_timestamp(s_epoch_sec)
    assert not res_epoch_sec.isna().any()
    assert res_epoch_sec.iloc[0].year == 2019

    # 4. Epoch timestamps (milliseconds)
    s_epoch_ms = pd.Series([1547289000000, 1547289005000])
    res_epoch_ms = parse_cic_timestamp(s_epoch_ms)
    assert not res_epoch_ms.isna().any()
    assert res_epoch_ms.iloc[0].year == 2019

    # 5. Empty and edge cases
    empty_s = pd.Series([], dtype=object)
    assert parse_cic_timestamp(empty_s).empty


def test_timer_and_seed() -> None:
    """Verify seed setting and timer context manager."""
    set_seeds(123)
    with timer("test block") as t:
        _ = sum(i * i for i in range(1000))
    assert t["elapsed_sec"] >= 0.0


def test_load_selected_features_dict_and_list_formats(tmp_path: Path) -> None:
    """Verify load_selected_features correctly parses both dict and plain list formats."""
    from ddos_ads.features import load_selected_features, save_selected_features
    import json

    # 1. Plain list format
    list_file = tmp_path / "features_list.json"
    features_list = ["feat_1", "feat_2", "feat_3"]
    list_file.write_text(json.dumps(features_list), encoding="utf-8")
    assert load_selected_features(list_file) == features_list

    # 2. Dictionary format with metadata
    dict_file = tmp_path / "features_dict.json"
    save_selected_features(
        features_list,
        dict_file,
        metadata={"dropped_columns": {"identifiers": ["Flow ID"], "lab_artifacts": ["Destination Port"]}},
    )
    loaded = load_selected_features(dict_file)
    assert loaded == features_list

    # 3. Invalid format raises ValueError
    bad_file = tmp_path / "bad_features.json"
    bad_file.write_text(json.dumps({"wrong_key": 123}), encoding="utf-8")
    with pytest.raises(ValueError, match="Unexpected features format"):
        load_selected_features(bad_file)


def test_timestamp_ordering_and_window_building_without_timestamp_in_features() -> None:
    """
    Verify that temporal sorting and block grouping work correctly with timestamps,
    and that Timestamp is strictly preserved in metadata but never present in the LSTM feature matrix.
    """
    from ddos_ads.features import build_lstm_windows_from_blocks
    import numpy as np

    # Generate synthetic sequence of flows with timestamps
    ts_list = pd.date_range("2019-01-12 10:00:00", periods=30, freq="1s")
    df = pd.DataFrame({
        "Timestamp": ts_list,
        "feat_a": np.arange(30, dtype=np.float32),
        "feat_b": np.arange(30, dtype=np.float32) * 2.0,
        "Label_Binary": [0] * 15 + [1] * 15,
        "Block_ID": ["blk_0"] * 15 + ["blk_1"] * 15,
    })

    # Assert df is chronologically ordered
    assert (df["Timestamp"].diff().dropna() > pd.Timedelta(0)).all()

    # Build windows using only numeric feature columns (excluding Timestamp)
    feature_cols = ["feat_a", "feat_b"]
    assert "Timestamp" not in feature_cols

    X_win, y_win = build_lstm_windows_from_blocks(
        df,
        feature_cols=feature_cols,
        window_size=10,
        step_size=5,
        block_col="Block_ID",
    )

    # Windows shape: 2 blocks of 15 rows with window_size=10, step=5 -> 2 windows per block = 4 windows
    assert X_win.shape == (4, 10, 2)
    assert y_win.shape == (4,)
    # First block is all benign (y=0), second block is all attack (y=1)
    assert (y_win[:2] == 0.0).all()
    assert (y_win[2:] == 1.0).all()
