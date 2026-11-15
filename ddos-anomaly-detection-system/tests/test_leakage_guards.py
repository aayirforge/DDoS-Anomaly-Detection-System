"""Tests for per-file data leakage guards and temporal consistency."""

from pathlib import Path
import pytest
import numpy as np
import pandas as pd
from ddos_ads.preprocess import assert_per_file_leakage_guards


def test_leakage_guards_pass_on_valid_per_file_splits() -> None:
    """Verify assertion passes when splits are strictly chronological per file."""
    t0 = pd.Timestamp("2019-01-12 10:00:00")
    t1 = pd.Timestamp("2019-01-12 11:00:00")
    t2 = pd.Timestamp("2019-01-12 12:00:00")

    df_train = pd.DataFrame({
        "Timestamp": [t0],
        "Source_File": ["01-12/Syn.csv"],
        "feat_a": [1.0],
        "Label_Binary": [0],
    })
    df_val = pd.DataFrame({
        "Timestamp": [t1],
        "Source_File": ["01-12/Syn.csv"],
        "feat_a": [2.0],
        "Label_Binary": [1],
    })
    df_test_same = pd.DataFrame({
        "Timestamp": [t2],
        "Source_File": ["01-12/Syn.csv"],
        "feat_a": [3.0],
        "Label_Binary": [1],
    })

    assert_per_file_leakage_guards(
        df_train=df_train,
        df_val=df_val,
        df_test_same=df_test_same,
        feature_cols=["feat_a"],
        drop_identifiers=["Source IP", "Flow ID"],
    )


def test_leakage_guard_catches_identifier_or_source_file_in_features() -> None:
    """Verify guard raises AssertionError when metadata leaks into feature list."""
    df_train = pd.DataFrame({
        "Timestamp": [pd.Timestamp("2019-01-12 10:00:00")],
        "Source_File": ["01-12/Syn.csv"],
        "feat_a": [1.0],
    })
    df_val = pd.DataFrame({
        "Timestamp": [pd.Timestamp("2019-01-12 11:00:00")],
        "Source_File": ["01-12/Syn.csv"],
        "feat_a": [2.0],
    })
    df_test = pd.DataFrame({
        "Timestamp": [pd.Timestamp("2019-01-12 12:00:00")],
        "Source_File": ["01-12/Syn.csv"],
        "feat_a": [3.0],
    })

    with pytest.raises(AssertionError, match="Metadata/identifier columns in features"):
        assert_per_file_leakage_guards(
            df_train=df_train,
            df_val=df_val,
            df_test_same=df_test,
            feature_cols=["feat_a", "Source_File"],
            drop_identifiers=["Source IP"],
        )


def test_leakage_guard_catches_per_file_temporal_crossover() -> None:
    """Verify guard raises AssertionError if train timestamps exceed val timestamps within the same source file."""
    df_train = pd.DataFrame({
        "Timestamp": [pd.Timestamp("2019-01-12 11:30:00")],
        "Source_File": ["01-12/Syn.csv"],
        "feat_a": [1.0],
    })
    df_val = pd.DataFrame({
        "Timestamp": [pd.Timestamp("2019-01-12 11:00:00")],
        "Source_File": ["01-12/Syn.csv"],
        "feat_a": [2.0],
    })
    df_test = pd.DataFrame({
        "Timestamp": [pd.Timestamp("2019-01-12 12:00:00")],
        "Source_File": ["01-12/Syn.csv"],
        "feat_a": [3.0],
    })

    with pytest.raises(AssertionError, match="TEMPORAL LEAKAGE in source"):
        assert_per_file_leakage_guards(
            df_train=df_train,
            df_val=df_val,
            df_test_same=df_test,
            feature_cols=["feat_a"],
            drop_identifiers=["Flow ID"],
        )
