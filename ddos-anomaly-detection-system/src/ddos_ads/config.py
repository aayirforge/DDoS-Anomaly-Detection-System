"""Configuration loader and path resolver for DDoS Anomaly Detection System."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml


class Config:
    """Manages system configuration loaded from config.yaml."""

    def __init__(self, config_dict: Dict[str, Any], project_root: Path) -> None:
        self._raw_config: Dict[str, Any] = config_dict
        self._project_root: Path = project_root.resolve()

    @property
    def project_root(self) -> Path:
        return self._project_root

    @property
    def raw(self) -> Dict[str, Any]:
        return self._raw_config

    def get(self, key_path: str, default: Any = None) -> Any:
        """Retrieve a nested config value using dot-notation, e.g., 'models.rf.n_estimators'."""
        keys = key_path.split(".")
        val: Any = self._raw_config
        for k in keys:
            if isinstance(val, dict) and k in val:
                val = val[k]
            else:
                return default
        return val

    def get_path(self, path_key: str) -> Path:
        """Resolve a relative path defined under 'paths' section to an absolute Path."""
        rel_path = self.get(f"paths.{path_key}")
        if rel_path is None:
            raise KeyError(f"Path key '{path_key}' not found under 'paths' in configuration.")
        p = Path(rel_path)
        if not p.is_absolute():
            p = (self._project_root / p).resolve()
        return p

    def ensure_directories(self) -> None:
        """Ensure all standard project directories exist."""
        paths_section = self._raw_config.get("paths", {})
        for key in paths_section:
            p = self.get_path(key)
            p.mkdir(parents=True, exist_ok=True)


def find_project_root(start_dir: Optional[Path] = None) -> Path:
    """Traverse upwards to find the project root containing config.yaml."""
    curr = (start_dir or Path.cwd()).resolve()
    for parent in [curr] + list(curr.parents):
        if (parent / "config.yaml").is_file():
            return parent
    # Default to current directory if not found
    return curr


def load_config(config_path: Optional[str | Path] = None) -> Config:
    """Load configuration from config.yaml or specified path."""
    if config_path is not None:
        p = Path(config_path).resolve()
        if not p.is_file():
            raise FileNotFoundError(f"Configuration file not found: {p}")
        project_root = p.parent
        with open(p, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return Config(data, project_root)

    root = find_project_root()
    default_config_path = root / "config.yaml"
    if not default_config_path.is_file():
        raise FileNotFoundError(
            f"config.yaml not found at expected project root: {root}. "
            "Please ensure you are running from inside the project directory or pass --config."
        )

    with open(default_config_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    return Config(data, root)
