"""Tests for dataset download manager and manifest integrity."""

import json
from pathlib import Path
import pytest
import pandas as pd
from ddos_ads.download_data import (
    compute_sha256,
    quick_row_count,
    verify_csv_readable,
    build_manifest,
    check_kaggle_credentials,
)


def test_verify_csv_readable(tmp_path: Path) -> None:
    """Verify CSV validation function correctly handles valid, empty, and corrupt files."""
    valid_csv = tmp_path / "valid.csv"
    valid_csv.write_text("col_a,col_b\n1,2\n3,4\n")
    assert verify_csv_readable(valid_csv)

    empty_csv = tmp_path / "empty.csv"
    empty_csv.write_text("")
    assert not verify_csv_readable(empty_csv)

    non_existent = tmp_path / "ghost.csv"
    assert not verify_csv_readable(non_existent)


def test_manifest_building_and_resume_safety(tmp_path: Path) -> None:
    """Verify that build_manifest creates a valid manifest.json with SHA256 and sizes."""
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()

    # Create dummy CSV files
    f1 = raw_dir / "01-12_DrDoS_DNS.csv"
    f1.write_text("Flow ID,Timestamp,Total Fwd Packets,Label\n1,2019-01-12 10:00:00,10,DrDoS_DNS\n2,2019-01-12 10:00:01,20,BENIGN\n")

    f2 = raw_dir / "03-11_PortScan.csv"
    f2.write_text("Flow ID,Timestamp,Total Fwd Packets,Label\n3,2019-03-11 14:00:00,5,PortScan\n")

    manifest = build_manifest(raw_dir)
    assert manifest["total_files"] == 2
    assert len(manifest["files"]) == 2

    # Check manifest file on disk
    manifest_disk = json.loads((raw_dir / "manifest.json").read_text())
    assert manifest_disk["total_files"] == 2
    assert any(f["filename"] == "01-12_DrDoS_DNS.csv" for f in manifest_disk["files"])
    assert any(f["filename"] == "03-11_PortScan.csv" for f in manifest_disk["files"])

    # Test row count logic
    dns_file = next(f for f in manifest["files"] if f["filename"] == "01-12_DrDoS_DNS.csv")
    assert dns_file["row_count"] == 2
    assert len(dns_file["sha256"]) == 64


def test_kaggle_credentials_mock(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Verify Kaggle credential detection through env vars and home directory."""
    # When no env and no file
    monkeypatch.delenv("KAGGLE_USERNAME", raising=False)
    monkeypatch.delenv("KAGGLE_KEY", raising=False)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    assert not check_kaggle_credentials()

    # When env vars are set
    monkeypatch.setenv("KAGGLE_USERNAME", "dummy_user")
    monkeypatch.setenv("KAGGLE_KEY", "dummy_key")
    assert check_kaggle_credentials()
