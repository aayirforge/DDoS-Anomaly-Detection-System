"""Utility functions for logging, reproducibility, timing, timestamp parsing, and model validation."""

from __future__ import annotations

from contextlib import contextmanager
import logging
import os
from pathlib import Path
import random
import sys
import time
from typing import Any, Callable, Generator, Iterable, List, Optional
import numpy as np
import pandas as pd


def setup_logger(
    name: str = "ddos_ads",
    level: int = logging.INFO,
    log_file: Optional[Path | str] = None,
) -> logging.Logger:
    """Create or configure a standard structured logger."""
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Avoid duplicate handlers on re-initialization
    if not logger.handlers:
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)

        if log_file:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(str(log_path), encoding="utf-8")
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

    return logger


def set_seeds(seed: int = 42) -> None:
    """Set random seeds across Python, NumPy, and PyTorch for reproducible runs."""
    random.seed(seed)
    os.environ["PYTHONHASHSEED"] = str(seed)
    np.random.seed(seed)

    try:
        import torch
        torch.manual_seed(seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(seed)
            torch.backends.cudnn.deterministic = True
            torch.backends.cudnn.benchmark = False
    except ImportError:
        pass


@contextmanager
def timer(description: str = "Operation", logger: Optional[logging.Logger] = None) -> Generator[dict[str, float], None, None]:
    """Context manager measuring execution time."""
    start_time = time.perf_counter()
    metrics: dict[str, float] = {"elapsed_sec": 0.0}
    try:
        yield metrics
    finally:
        elapsed = time.perf_counter() - start_time
        metrics["elapsed_sec"] = elapsed
        msg = f"{description} completed in {elapsed:.4f}s"
        if logger:
            logger.info(msg)
        else:
            print(f"[TIMER] {msg}")


def check_models_exist(models_dir: Path | str, required_files: Optional[Iterable[str]] = None) -> bool:
    """Check if trained models exist in the specified directory."""
    m_dir = Path(models_dir)
    if not m_dir.is_dir():
        return False

    targets = list(required_files) if required_files is not None else ["features.json", "scaler.joblib"]
    for fname in targets:
        if not (m_dir / fname).is_file():
            return False
    return True


def ensure_models_available(models_dir: Path | str, required_files: Optional[Iterable[str]] = None) -> None:
    """Validate that required models exist. If missing, exit with a clean instructional message."""
    if not check_models_exist(models_dir, required_files):
        sep = "=" * 60
        err_msg = f"\n{sep}\nModels not found. Run: make train\n{sep}\n"
        sys.stderr.write(err_msg)
        sys.stderr.flush()
        raise SystemExit(1)


def record_train_log(
    results_dir: Path | str,
    model_name: str,
    elapsed_sec: float,
    model_size_bytes: int,
    metrics: Optional[dict[str, Any]] = None,
) -> None:
    """Record training metrics, duration, and model size into results/train_log.json."""
    import json
    log_file = Path(results_dir) / "train_log.json"
    log_file.parent.mkdir(parents=True, exist_ok=True)

    current_data = {}
    if log_file.is_file():
        try:
            with open(log_file, "r", encoding="utf-8") as f:
                current_data = json.load(f)
        except Exception:
            current_data = {}

    current_data[model_name] = {
        "train_time_sec": round(elapsed_sec, 4),
        "model_size_bytes": model_size_bytes,
        "model_size_mb": round(model_size_bytes / (1024 * 1024), 2),
        "timestamp": pd.Timestamp.now().isoformat(),
        "metrics": metrics or {},
    }

    with open(log_file, "w", encoding="utf-8") as f:
        json.dump(current_data, f, indent=2)


def parse_cic_timestamp(series: pd.Series) -> pd.Series:

    """
    Parse timestamp series from CIC-DDoS2019 / CICFlowMeter CSVs into pd.Timestamp.
    Supports formats:
      - '2019-01-12 10:30:00'
      - '12/01/2019 10:30:00 AM'
      - Epoch timestamps (seconds or milliseconds)
    """
    if series.empty:
        return pd.Series(dtype="datetime64[ns]")

    # Check if numeric (epoch)
    sample = series.dropna().iloc[0] if not series.dropna().empty else None
    if sample is None:
        return pd.to_datetime(series, errors="coerce")

    if isinstance(sample, (int, float, np.integer, np.floating)):
        # Determine whether seconds or milliseconds
        if float(sample) > 1e11:  # Milliseconds
            return pd.to_datetime(series, unit="ms", errors="coerce")
        return pd.to_datetime(series, unit="s", errors="coerce")

    # If string with numbers only
    if isinstance(sample, str) and sample.strip().replace(".", "", 1).isdigit():
        num_val = float(sample.strip())
        if num_val > 1e11:
            return pd.to_datetime(series.astype(float), unit="ms", errors="coerce")
        return pd.to_datetime(series.astype(float), unit="s", errors="coerce")

    # Parse datetime string with fallback
    try:
        # Standard format
        return pd.to_datetime(series, format="%Y-%m-%d %H:%M:%S", errors="raise")
    except Exception:
        pass

    try:
        # 12-hour AM/PM format
        return pd.to_datetime(series, format="%d/%m/%Y %I:%M:%S %p", errors="raise")
    except Exception:
        pass

    # Generic parser
    return pd.to_datetime(series, errors="coerce")
