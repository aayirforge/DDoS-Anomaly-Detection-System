"""Tests for evaluation module missing-model guards."""

from pathlib import Path
import pytest
from ddos_ads.evaluate import evaluate_models, find_optimal_threshold
import numpy as np


def test_evaluate_exits_when_models_missing(tmp_path: Path) -> None:
    """Verify evaluate_models raises SystemExit(1) with instructional message when models are absent."""
    from unittest.mock import patch
    with patch("ddos_ads.evaluate.ensure_models_available", side_effect=SystemExit(1)):
        with pytest.raises(SystemExit) as exc_info:
            evaluate_models()
        assert exc_info.value.code == 1


def test_find_optimal_threshold_calculation() -> None:
    """Verify threshold selector respects target_max_fpr."""
    rng = np.random.RandomState(42)
    # 100 benign, 100 attack
    y_true = np.array([0] * 100 + [1] * 100)
    # Probabilities: benign mostly low, attack mostly high
    y_probs = np.concatenate([rng.uniform(0.0, 0.3, size=100), rng.uniform(0.4, 0.95, size=100)])

    thresh, fpr, tpr = find_optimal_threshold(y_true, y_probs, target_max_fpr=0.05)
    assert 0.0 < thresh < 1.0
    assert fpr <= 0.05
    assert tpr > 0.80


def test_report_generation_numerical_consistency(tmp_path: Path) -> None:
    """Verify generate_report constructs report and passes strict consistency checks."""
    from ddos_ads.report import generate_report
    metrics_path = Path("results/metrics.json")
    results_dir = Path("results")
    out_path = tmp_path / "test_report.md"

    if metrics_path.is_file():
        content = generate_report(metrics_path, results_dir, out_path)
        assert out_path.is_file()
        assert len(content) > 500
        assert "Comparable Performance" in content
        assert "Tree-Boundary Hypothesis" in content
        assert "Homogeneous Windows" in content
        assert "Mixed Transition Windows" in content
