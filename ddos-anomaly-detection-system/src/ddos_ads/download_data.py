"""Data acquisition and manifest indexing module with direct zip streaming support."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import time
from typing import Any, Dict, List, Optional
import zipfile
import pandas as pd
from tqdm import tqdm

from ddos_ads.config import load_config
from ddos_ads.utils import setup_logger

logger = setup_logger("ddos_ads.download")


def compute_sha256(filepath: Path, block_size: int = 65536) -> str:
    """Compute SHA256 checksum of a file."""
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(block_size), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def quick_row_count(filepath: Path) -> int:
    """Quickly estimate or count rows in a CSV file."""
    try:
        count = 0
        with open(filepath, "rb") as f:
            for _ in f:
                count += 1
        return max(0, count - 1)  # Subtract header
    except Exception:
        return -1


def verify_csv_readable(filepath: Path) -> bool:
    """Verify that a CSV file exists, is non-empty, and can be read by pandas."""
    if not filepath.is_file() or filepath.stat().st_size == 0:
        return False
    try:
        _ = pd.read_csv(filepath, nrows=5)
        return True
    except Exception as e:
        logger.warning(f"File {filepath.name} failed CSV validation: {e}")
        return False


def build_manifest(raw_dir: Path) -> Dict[str, Any]:
    """
    Scan raw directory and generate manifest.json.
    Supports both extracted CSV files and direct zip archives (CSV-01-12.zip, CSV-03-11.zip).
    """
    manifest_records: List[Dict[str, Any]] = []
    zip_records: List[Dict[str, Any]] = []

    # 1. Scan standalone CSVs
    csv_files = sorted([
        f for f in raw_dir.rglob("*.csv")
        if f.is_file() and not f.name.startswith("~") and not f.name.startswith(".")
    ])

    if csv_files:
        logger.info(f"Auditing {len(csv_files)} standalone CSV files in {raw_dir}...")
        for f in tqdm(csv_files, desc="Indexing CSV files"):
            size_bytes = f.stat().st_size
            sha = compute_sha256(f)
            rows = quick_row_count(f)
            manifest_records.append({
                "filename": str(f.relative_to(raw_dir)),
                "size_bytes": size_bytes,
                "size_mb": round(size_bytes / (1024 * 1024), 2),
                "sha256": sha,
                "row_count": rows,
                "is_valid_csv": verify_csv_readable(f),
                "source_type": "extracted_csv",
            })

    # 2. Scan zip archives
    zip_files = sorted([f for f in raw_dir.glob("*.zip") if f.is_file()])
    for zf in zip_files:
        logger.info(f"Auditing zip archive: {zf.name}...")
        z_sha = compute_sha256(zf)
        z_size = zf.stat().st_size

        members_info = []
        try:
            with zipfile.ZipFile(zf, "r") as z:
                for info in z.infolist():
                    if info.filename.endswith(".csv") and not info.filename.startswith("~") and not Path(info.filename).name.startswith("."):
                        # Verify readable header
                        readable = False
                        try:
                            with z.open(info.filename) as member_f:
                                _ = pd.read_csv(member_f, nrows=3)
                                readable = True
                        except Exception:
                            readable = False

                        members_info.append({
                            "member_name": info.filename,
                            "uncompressed_bytes": info.file_size,
                            "uncompressed_mb": round(info.file_size / (1024 * 1024), 2),
                            "crc32": hex(info.CRC),
                            "is_readable_csv": readable,
                        })
        except Exception as e:
            logger.error(f"Error inspecting zip file {zf.name}: {e}")

        zip_records.append({
            "archive_filename": zf.name,
            "archive_size_bytes": z_size,
            "archive_size_mb": round(z_size / (1024 * 1024), 2),
            "sha256": z_sha,
            "contained_csv_count": len(members_info),
            "members": members_info,
        })

    manifest = {
        "dataset": "CIC-DDoS2019",
        "generated_at": pd.Timestamp.now().isoformat(),
        "total_files": len(manifest_records) + len(zip_records),
        "total_standalone_csvs": len(manifest_records),
        "total_zip_archives": len(zip_records),
        "files": manifest_records,
        "standalone_csv_files": manifest_records,
        "zip_archives": zip_records,
    }

    manifest_path = raw_dir / "manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as out:
        json.dump(manifest, out, indent=2)

    logger.info(f"Manifest written to {manifest_path}")
    return manifest


def count_raw_dataset_labels(
    raw_dir: Path,
    config_path: Optional[str] = None,
    max_rows_per_file: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Inspect raw CSV files (or zip streams) and compute exact label distributions
    along with normalized labels.
    """
    config = load_config(config_path)
    label_map = config.get("preprocessing.label_normalization_map", {})
    planned_files_cfg = config.get("download.planned_files", {})
    all_planned = []
    for day_list in planned_files_cfg.values():
        all_planned.extend(day_list)

    raw_label_counts: Counter[str] = Counter()
    normalized_label_counts: Counter[str] = Counter()
    per_file_counts: Dict[str, Dict[str, int]] = {}

    # Check zip files first
    zip_files = list(raw_dir.glob("*.zip"))
    csv_files = [f for f in raw_dir.rglob("*.csv") if not f.name.startswith("~") and not f.name.startswith(".")]

    logger.info("Scanning dataset to compute label distributions...")

    if zip_files:
        for zf in zip_files:
            logger.info(f"Streaming and counting labels from zip: {zf.name}...")
            with zipfile.ZipFile(zf, "r") as z:
                members = [
                    m for m in z.namelist()
                    if m.endswith(".csv") and not m.startswith("~") and not Path(m).name.startswith(".")
                ]
                # Filter to planned files if configured
                if all_planned:
                    members = [m for m in members if any(p in m for p in all_planned)]

                for m in members:
                    m_counts: Counter[str] = Counter()
                    try:
                        with z.open(m) as f:
                            rows_read = 0
                            for chunk in pd.read_csv(
                                f,
                                usecols=lambda c: "label" in c.lower(),
                                chunksize=100000,
                                low_memory=False,
                            ):
                                col = chunk.columns[0]
                                labels = chunk[col].astype(str).str.strip().tolist()
                                m_counts.update(labels)
                                rows_read += len(labels)
                                if max_rows_per_file and rows_read >= max_rows_per_file:
                                    break
                    except Exception as e:
                        logger.warning(f"Error reading {m} from {zf.name}: {e}")

                    per_file_counts[m] = dict(m_counts)
                    raw_label_counts.update(m_counts)

    elif csv_files:
        for f in csv_files:
            m_counts = Counter()
            try:
                rows_read = 0
                for chunk in pd.read_csv(
                    f,
                    usecols=lambda c: "label" in c.lower(),
                    chunksize=100000,
                    low_memory=False,
                ):
                    col = chunk.columns[0]
                    labels = chunk[col].astype(str).str.strip().tolist()
                    m_counts.update(labels)
                    rows_read += len(labels)
                    if max_rows_per_file and rows_read >= max_rows_per_file:
                        break
            except Exception as e:
                logger.warning(f"Error reading {f.name}: {e}")

            per_file_counts[f.name] = dict(m_counts)
            raw_label_counts.update(m_counts)

    # Compute normalized counts
    for raw_label, count in raw_label_counts.items():
        norm_label = label_map.get(raw_label)
        if not norm_label:
            # Fallback heuristic: strip DrDoS_ prefix
            norm_label = raw_label.replace("DrDoS_", "")
        normalized_label_counts[norm_label] += count

    return {
        "raw_label_counts": dict(raw_label_counts),
        "normalized_label_counts": dict(normalized_label_counts),
        "per_file_counts": per_file_counts,
    }


def check_kaggle_credentials() -> bool:
    """Check if Kaggle credentials exist in environment variables or ~/.kaggle/kaggle.json."""
    if os.environ.get("KAGGLE_USERNAME") and os.environ.get("KAGGLE_KEY"):
        return True
    kaggle_json = Path.home() / ".kaggle" / "kaggle.json"
    return kaggle_json.is_file()


def print_manual_instructions(unb_url: str, raw_dir: Path) -> None:
    """Display manual download instructions for the CIC-DDoS2019 dataset."""
    msg = f"""
================================================================================
                CIC-DDoS2019 DATASET ACQUISITION
================================================================================
Official UNB Portal: {unb_url}
Raw Directory: {raw_dir.resolve()}

Zip archives or extracted CSVs can be processed directly without manual extraction.
================================================================================
"""
    print(msg, file=sys.stdout)


def run_download(
    source: str = "manual",
    days: Optional[List[str]] = None,
    max_files: Optional[int] = None,
    config_path: Optional[str] = None,
) -> None:
    """Main orchestrator for dataset download, manifest generation, and label counting."""
    config = load_config(config_path)
    raw_dir = config.get_path("raw_data_dir")
    raw_dir.mkdir(parents=True, exist_ok=True)

    unb_url = config.get("download.cic_info_url", "https://www.unb.ca/cic/datasets/ddos-2019.html")

    print(
        f"\n[DDoS-ADS Data Manager] Source: {source} | Target Directory: {raw_dir}\n"
    )

    if source.lower() == "kaggle":
        slug = config.get("download.kaggle_dataset_slug", "placeholder/slug")
        target_days = days or config.get("download.days", ["01-12", "03-11"])
        try:
            from ddos_ads.download_data import download_from_kaggle
            download_from_kaggle(slug, raw_dir, days=target_days, max_files=max_files)
        except Exception as e:
            logger.error(f"Kaggle download failed: {e}")
            print_manual_instructions(unb_url, raw_dir)
    else:
        print_manual_instructions(unb_url, raw_dir)

    # Build manifest
    manifest = build_manifest(raw_dir)

    print("\n" + "=" * 80)
    print("                     DATASET MANIFEST SUMMARY")
    print("=" * 80)
    print(f"Total Standalone CSVs Indexed: {manifest['total_standalone_csvs']}")
    print(f"Total Zip Archives Indexed:    {manifest['total_zip_archives']}")

    for z in manifest.get("zip_archives", []):
        print(f"\nArchive: {z['archive_filename']} ({z['archive_size_mb']:.1f} MB, {z['contained_csv_count']} CSV members)")
        for m in z.get("members", [])[:6]:
            print(f"  • {m['member_name']} ({m['uncompressed_mb']:.1f} MB, Valid CSV: {m['is_readable_csv']})")
        if len(z.get("members", [])) > 6:
            print(f"  ... and {len(z['members']) - 6} more CSV members")

    # Count raw labels across files
    print("\n" + "=" * 80)
    print("                 COUNTING RAW & NORMALIZED LABELS")
    print("=" * 80)
    label_info = count_raw_dataset_labels(raw_dir, config_path)

    print("\n--- Raw Label Distribution across dataset ---")
    for lbl, count in sorted(label_info["raw_label_counts"].items(), key=lambda x: -x[1]):
        print(f"  {lbl:<20}: {count:>12,}")

    print("\n--- Normalized Label Distribution (Mapped across Days) ---")
    for norm_lbl, count in sorted(label_info["normalized_label_counts"].items(), key=lambda x: -x[1]):
        print(f"  {norm_lbl:<20}: {count:>12,}")
    print("=" * 80 + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Download and validate CIC-DDoS2019 dataset.")
    parser.add_argument("--source", choices=["kaggle", "manual"], default="manual", help="Data source.")
    parser.add_argument("--days", nargs="+", default=None, help="Filter target days (e.g. 01-12 03-11).")
    parser.add_argument("--max-files", type=int, default=None, help="Maximum number of files to process.")
    parser.add_argument("--config", type=str, default=None, help="Path to config.yaml.")
    args = parser.parse_args()

    run_download(
        source=args.source,
        days=args.days,
        max_files=args.max_files,
        config_path=args.config,
    )


if __name__ == "__main__":
    main()
