"""Tests for sequence window generation for LSTM."""

import numpy as np
import pytest
from ddos_ads.features import build_lstm_windows


def test_build_lstm_windows_shape_and_labeling() -> None:
    """Verify LSTM sliding window shapes, step size, and OR-labeling logic."""
    # 20 samples, 4 features
    N, F = 20, 4
    X = np.arange(N * F, dtype=np.float32).reshape(N, F)
    # Binary flow labels: first 9 are benign (0), 10th is attack (1), remainder benign
    y = np.zeros(N, dtype=np.float32)
    y[9] = 1.0

    window_size = 5
    step_size = 2
    X_win, y_win = build_lstm_windows(X, y, window_size=window_size, step_size=step_size)

    # Number of windows: (20 - 5) // 2 + 1 = 8 windows
    assert X_win.shape == (8, window_size, F)
    assert y_win.shape == (8,)

    # Windows spanning index 9:
    # win 0: [0:5] -> max index 4 -> label 0
    # win 1: [2:7] -> max index 6 -> label 0
    # win 2: [4:9] -> max index 8 -> label 0
    # win 3: [6:11] -> includes index 9 -> label 1
    # win 4: [8:13] -> includes index 9 -> label 1
    # win 5: [10:15] -> index 9 not included -> label 0
    assert y_win[0] == 0.0
    assert y_win[1] == 0.0
    assert y_win[2] == 0.0
    assert y_win[3] == 1.0
    assert y_win[4] == 1.0
    assert y_win[5] == 0.0


def test_build_lstm_windows_too_short() -> None:
    """Verify empty windows when input length is less than window_size."""
    X = np.ones((4, 3), dtype=np.float32)
    y = np.zeros(4, dtype=np.float32)
    X_win, y_win = build_lstm_windows(X, y, window_size=10, step_size=5)

    assert X_win.shape == (0, 10, 3)
    assert y_win.shape == (0,)
