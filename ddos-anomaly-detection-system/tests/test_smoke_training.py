"""Unit tests for model training smoke tests in isolated temporary directories."""

from pathlib import Path
import pytest
from ddos_ads.config import load_config
from ddos_ads.train_rf import run_smoke_test as run_rf_smoke
from ddos_ads.train_knn import run_smoke_test as run_knn_smoke


def test_rf_smoke_test_isolation() -> None:
    """Verify that Random Forest smoke test executes and leaves 0 disk leaks in real project directories."""
    config = load_config()
    models_dir = config.get_path("models_dir")
    results_dir = config.get_path("results_dir")

    # Capture files before smoke test
    before_models = set(models_dir.glob("*"))
    before_results = set(results_dir.glob("*"))

    # Execute smoke test
    run_rf_smoke()

    # Capture files after smoke test
    after_models = set(models_dir.glob("*"))
    after_results = set(results_dir.glob("*"))

    # Assert no leaks
    assert before_models == after_models, f"Leak detected in models dir: {after_models - before_models}"
    assert before_results == after_results, f"Leak detected in results dir: {after_results - before_results}"


def test_knn_smoke_test_isolation() -> None:
    """Verify that KNN smoke test executes and leaves 0 disk leaks in real project directories."""
    config = load_config()
    models_dir = config.get_path("models_dir")
    results_dir = config.get_path("results_dir")

    before_models = set(models_dir.glob("*"))
    before_results = set(results_dir.glob("*"))

    run_knn_smoke()

    after_models = set(models_dir.glob("*"))
    after_results = set(results_dir.glob("*"))

    assert before_models == after_models, f"Leak detected in models dir: {after_models - before_models}"
    assert before_results == after_results, f"Leak detected in results dir: {after_results - before_results}"


def test_lstm_smoke_test_isolation() -> None:
    """Verify that LSTM smoke test executes and leaves 0 disk leaks in real project directories."""
    try:
        import torch
        from ddos_ads.train_lstm import run_smoke_test as run_lstm_smoke
    except ImportError:
        pytest.skip("PyTorch not yet installed in current test environment.")

    config = load_config()
    models_dir = config.get_path("models_dir")
    results_dir = config.get_path("results_dir")

    before_models = set(models_dir.glob("*"))
    before_results = set(results_dir.glob("*"))

    run_lstm_smoke()

    after_models = set(models_dir.glob("*"))
    after_results = set(results_dir.glob("*"))

    assert before_models == after_models, f"Leak detected in models dir: {after_models - before_models}"
    assert before_results == after_results, f"Leak detected in results dir: {after_results - before_results}"
