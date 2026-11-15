"""Data preprocessing with per-file chronological splitting, global duplicate removal, caching, and contiguous block windowing."""

from __future__ import annotations

import argparse
import gc
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Set, Tuple
import zipfile
import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from tqdm import tqdm

from ddos_ads.config import Config, load_config
from ddos_ads.features import (
    build_lstm_windows_from_blocks,
    rank_and_select_features,
    remove_collinear_features,
    save_selected_features,
)
from ddos_ads.utils import parse_cic_timestamp, set_seeds, setup_logger, timer

logger = setup_logger("ddos_ads.preprocess")

CACHE_VERSION = "v3_named_drops_no_dstport"


def check_and_prepare_cache_dir(cache_dir: Path) -> None:
    """
    Ensure the parquet cache matches the current preprocessing version.
    If stale or missing, purges all cached parquet files to prevent corrupt/incompatible data.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    version_file = cache_dir / "cache_version.txt"
    if version_file.is_file():
        current_ver = version_file.read_text(encoding="utf-8").strip()
        if current_ver == CACHE_VERSION:
            return

    logger.info(f"Cache version missing or mismatched (expected {CACHE_VERSION}). Purging stale cache...")
    for item in cache_dir.glob("*.parquet"):
        try:
            item.unlink()
        except Exception:
            pass
    version_file.write_text(CACHE_VERSION, encoding="utf-8")


def clean_chunk(
    df: pd.DataFrame,
    drop_identifiers: List[str],
    label_map: Dict[str, str],
    source_name: str,
    drop_destination_port: bool = False,
) -> Tuple[pd.DataFrame, int]:
    """
    Clean a DataFrame chunk:
      - Strips whitespace from column names.
      - Handles Label column by name -> Normalized_Label, Original_Label, Label_Binary.
      - Handles Timestamp column by name -> parse_cic_timestamp.
      - Drops identifier & metadata columns explicitly by name (Flow ID, Source IP, Destination IP,
        Source Port, SimillarHTTP, Inbound, Unnamed: 0, etc.) and optionally Destination Port.
      - Converts feature candidate columns to numeric, replacing bad/inf with NaN.
      - Drops rows with bad/NaN values and counts them (never fills with 0).
      - Downcasts remaining numeric columns to float32.
    Returns (cleaned_df, count_of_dropped_corrupted_rows).
    """
    df.columns = [c.strip() for c in df.columns]

    label_col = None
    for candidate in ["Label", "label", " Label"]:
        if candidate in df.columns:
            label_col = candidate
            break

    if label_col is None:
        raise ValueError("No 'Label' column found in dataset chunk.")

    df["Original_Label"] = df[label_col].astype(str).str.strip()
    df["Normalized_Label"] = df["Original_Label"].map(label_map)
    # Fallback: strip DrDoS_ prefix if not in explicit mapping
    mask_unmapped = df["Normalized_Label"].isna()
    if mask_unmapped.any():
        df.loc[mask_unmapped, "Normalized_Label"] = (
            df.loc[mask_unmapped, "Original_Label"].str.replace("DrDoS_", "", regex=False)
        )

    df["Label_Binary"] = (df["Normalized_Label"].str.upper() != "BENIGN").astype(np.int8)
    df["Source_File"] = source_name

    # Parse timestamp by name
    ts_col = None
    for candidate in ["Timestamp", "timestamp", " Timestamp"]:
        if candidate in df.columns:
            ts_col = candidate
            break

    if ts_col:
        df["Timestamp"] = parse_cic_timestamp(df[ts_col])
    else:
        df["Timestamp"] = pd.date_range("2019-01-01", periods=len(df), freq="100ms")

    # Drop identifier & metadata columns explicitly by name
    cols_to_remove = set(drop_identifiers)
    cols_to_remove.add(label_col)
    if drop_destination_port:
        cols_to_remove.update(["Destination Port", "destination_port", "Dst Port"])

    existing_to_drop = [c for c in cols_to_remove if c in df.columns]
    df = df.drop(columns=existing_to_drop)

    # Columns preserved for metadata/windowing/analysis
    preserved_meta = {"Timestamp", "Original_Label", "Normalized_Label", "Source_File", "Block_ID", "Label_Binary"}

    # Numerical feature columns: coerce to numeric, invalid string/bad entries become NaN
    feature_cols = [c for c in df.columns if c not in preserved_meta]
    for col in feature_cols:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    # Replace inf and -inf with NaN
    df[feature_cols] = df[feature_cols].replace([np.inf, -np.inf], np.nan)

    # Count rows with corrupted, invalid, or infinite values and drop them (NEVER fill with 0)
    n_before = len(df)
    df = df.dropna()
    dropped_bad_rows = n_before - len(df)

    # Downcast float columns to float32 to save RAM and disk
    for c in feature_cols:
        df[c] = df[c].astype(np.float32)

    return df, dropped_bad_rows


def sample_contiguous_blocks(
    df: pd.DataFrame,
    target_count: int,
    block_size: int = 50,
    random_seed: int = 42,
    block_prefix: str = "blk",
) -> pd.DataFrame:
    """
    Sample rows as contiguous blocks of consecutive flows rather than scattered individual rows.
    Guarantees temporal continuity for sequence/LSTM modeling.
    """
    n_rows = len(df)
    if n_rows == 0:
        return df
    if n_rows <= target_count:
        df_out = df.copy()
        df_out["Block_ID"] = f"{block_prefix}_0"
        return df_out

    n_blocks_needed = max(1, target_count // block_size)
    total_blocks = max(1, n_rows // block_size)

    rng = np.random.RandomState(random_seed)
    if total_blocks <= n_blocks_needed:
        selected_block_indices = list(range(total_blocks))
    else:
        selected_block_indices = sorted(rng.choice(total_blocks, size=n_blocks_needed, replace=False))

    sampled_dfs = []
    for i, b_idx in enumerate(selected_block_indices):
        start = b_idx * block_size
        end = min(n_rows, start + block_size)
        blk = df.iloc[start:end].copy()
        blk["Block_ID"] = f"{block_prefix}_{i}"
        sampled_dfs.append(blk)

    return pd.concat(sampled_dfs, ignore_axis=True)


def iter_source_files(
    raw_dir: Path,
    read_from_zip: bool = True,
    planned_files: Optional[Dict[str, List[str]]] = None,
) -> Generator[Tuple[str, str, Any], None, None]:
    """
    Yields (day_tag, file_identifier, file_opener) for reading raw data chunks
    either directly from zip archives or from extracted CSV files on disk.
    """
    zip_files = sorted(list(raw_dir.glob("*.zip")))

    if read_from_zip and zip_files:
        logger.info(f"Streaming data directly from {len(zip_files)} zip archive(s)...")
        for zf in zip_files:
            z = zipfile.ZipFile(zf, "r")
            members = [
                m for m in z.namelist()
                if m.endswith(".csv") and not m.startswith("~") and not Path(m).name.startswith(".")
            ]
            for m in sorted(members):
                day_tag = "01-12" if "01-12" in m or "01-12" in zf.name else "03-11"
                if planned_files:
                    allowed = planned_files.get(day_tag, [])
                    if allowed and not any(p in m for p in allowed):
                        continue

                def opener(member=m, z_obj=z):
                    return z_obj.open(member)

                yield day_tag, m, opener

    else:
        logger.info("Reading extracted CSV files from disk...")
        csv_files = sorted([
            f for f in raw_dir.rglob("*.csv")
            if not f.name.startswith("~") and not f.name.startswith(".")
        ])
        for f in csv_files:
            day_tag = "01-12" if "01-12" in str(f) else "03-11"
            if planned_files:
                allowed = planned_files.get(day_tag, [])
                if allowed and not any(p in str(f) for p in allowed):
                    continue

            def opener(path=f):
                return open(path, "r", encoding="utf-8", errors="replace")

            yield day_tag, str(f.relative_to(raw_dir)), opener


def load_or_cache_source_file(
    day_tag: str,
    file_id: str,
    file_opener,
    cache_dir: Path,
    config: Config,
    global_seen_hashes: Optional[Set[int]] = None,
) -> Tuple[Path, int, int]:
    """
    Load cleaned source file using local parquet cache for resume safety,
    deduplicating against global_seen_hashes before writing to parquet.
    Returns (cached_path, total_rows_seen, dropped_duplicates).
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    sanitized_name = file_id.replace("/", "_").replace("\\", "_").replace(".csv", ".parquet")
    cached_path = cache_dir / sanitized_name

    if cached_path.is_file() and cached_path.stat().st_size > 0:
        logger.info(f"Using cached file: {sanitized_name} ({cached_path.stat().st_size / (1024*1024):.1f} MB)")
        return cached_path, 0, 0

    drop_identifiers = config.get("preprocessing.drop_identifier_columns", [])
    drop_dst_port = config.get("preprocessing.drop_destination_port", False)
    label_map = config.get("preprocessing.label_normalization_map", {})
    chunk_size = config.get("preprocessing.chunk_size", 100000)

    logger.info(f"Streaming and caching raw stream: {file_id} (Day: {day_tag})...")
    chunks: List[pd.DataFrame] = []
    total_seen = 0
    total_dropped = 0
    total_corrupted = 0

    with file_opener() as f:
        for chunk in pd.read_csv(f, chunksize=chunk_size, low_memory=False):
            cleaned, n_bad = clean_chunk(
                chunk,
                drop_identifiers=drop_identifiers,
                label_map=label_map,
                source_name=file_id,
                drop_destination_port=drop_dst_port,
            )
            total_corrupted += n_bad
            if cleaned.empty:
                continue

            n_chunk = len(cleaned)
            total_seen += n_chunk

            if global_seen_hashes is not None:
                dedup_cols = [
                    c for c in cleaned.columns
                    if c not in ["Source_File", "Block_ID", "Timestamp", "Original_Label", "Normalized_Label"]
                ]
                hashes = pd.util.hash_pandas_object(cleaned[dedup_cols], index=False)
                mask_unique = ~hashes.isin(global_seen_hashes)
                n_dup = int((~mask_unique).sum())
                total_dropped += n_dup

                # Update global seen hashes with the new unique rows
                global_seen_hashes.update(hashes[mask_unique].tolist())
                cleaned = cleaned[mask_unique]

            if not cleaned.empty:
                chunks.append(cleaned)

    if total_corrupted > 0:
        logger.info(f"Source {file_id}: Dropped {total_corrupted:,} rows containing corrupted/NaN/infinite values.")

    if not chunks:
        empty_df = pd.DataFrame()
        empty_df.to_parquet(cached_path, index=False)
        return cached_path, total_seen, total_dropped

    df_cleaned = pd.concat(chunks, ignore_axis=True)
    df_cleaned = df_cleaned.sort_values(by="Timestamp").reset_index(drop=True)
    df_cleaned.to_parquet(cached_path, index=False)
    logger.info(f"Cached {len(df_cleaned):,} rows to {cached_path.name}")
    del df_cleaned, chunks
    gc.collect()

    return cached_path, total_seen, total_dropped


def find_strict_split_index(df: pd.DataFrame, target_idx: int) -> int:
    """Adjust target split index so the timestamp strictly advances at the split boundary."""
    n = len(df)
    if target_idx <= 0 or target_idx >= n:
        return target_idx

    target_ts = df["Timestamp"].iloc[target_idx - 1]
    idx = target_idx
    while idx < n and df["Timestamp"].iloc[idx] == target_ts:
        idx += 1
    if idx < n:
        return idx

    idx = target_idx - 1
    while idx > 0 and df["Timestamp"].iloc[idx] == target_ts:
        idx -= 1
    return max(1, idx)


def print_and_enforce_split_table(
    splits: Dict[str, pd.DataFrame],
    min_benign_per_split: int = 500,
) -> None:
    """
    Display comprehensive tabular breakdown of Benign and canonical Attack types
    across all splits, and enforce min_benign_per_split threshold.
    """
    split_names = ["Train", "Validation", "Same-Day Test", "Cross-Day Test"]
    all_categories: set[str] = set()

    for s_df in splits.values():
        if not s_df.empty:
            all_categories.update(s_df["Normalized_Label"].unique())

    # Sort categories with BENIGN first, then alphabetical
    attack_cats = sorted([c for c in all_categories if c.upper() != "BENIGN"])
    categories_ordered = ["BENIGN"] + attack_cats

    # Build matrix
    table_data: Dict[str, Dict[str, int]] = {cat: {s: 0 for s in split_names} for cat in categories_ordered}

    for s_name in split_names:
        df_s = splits.get(s_name, pd.DataFrame())
        if not df_s.empty:
            counts = df_s["Normalized_Label"].value_counts()
            for cat, cnt in counts.items():
                if cat in table_data:
                    table_data[cat][s_name] = int(cnt)

    # Print markdown table
    print("\n" + "=" * 95)
    print("                     PER-SPLIT BENIGN & CANONICAL ATTACK TABLE")
    print("=" * 95)
    header = f"| {'Category':<16} | {'Train':>12} | {'Validation':>12} | {'Same-Day Test':>14} | {'Cross-Day Test':>14} | {'Total':>14} |"
    sep = f"|{'-'*18}|{'-'*14}|{'-'*14}|{'-'*16}|{'-'*16}|{'-'*16}|"
    print(header)
    print(sep)

    total_per_split = {s: 0 for s in split_names}
    for cat in categories_ordered:
        row_tot = sum(table_data[cat][s] for s in split_names)
        for s in split_names:
            total_per_split[s] += table_data[cat][s]
        print(
            f"| {cat:<16} | {table_data[cat]['Train']:>12,} | {table_data[cat]['Validation']:>12,} | "
            f"{table_data[cat]['Same-Day Test']:>14,} | {table_data[cat]['Cross-Day Test']:>14,} | {row_tot:>14,} |"
        )

    print(sep)
    grand_tot = sum(total_per_split.values())
    print(
        f"| {'TOTAL':<16} | {total_per_split['Train']:>12,} | {total_per_split['Validation']:>12,} | "
        f"{total_per_split['Same-Day Test']:>14,} | {total_per_split['Cross-Day Test']:>14,} | {grand_tot:>14,} |"
    )

    benign_row = table_data.get("BENIGN", {})
    benign_pct_row = [
        f"{benign_row.get(s, 0) / max(1, total_per_split[s]) * 100:.2f}%" for s in split_names
    ]
    print(
        f"| {'% Benign':<16} | {benign_pct_row[0]:>12} | {benign_pct_row[1]:>12} | "
        f"{benign_pct_row[2]:>14} | {benign_pct_row[3]:>14} | "
        f"{sum(benign_row.values()) / max(1, grand_tot) * 100:.2f}% |"
    )
    print("=" * 95 + "\n")

    # Strict enforcement of min_benign_per_split on every split
    for s_name in split_names:
        b_cnt = benign_row.get(s_name, 0)
        logger.info(f"Split '{s_name}' Benign Count: {b_cnt:,} (Threshold: {min_benign_per_split:,})")
        if b_cnt < min_benign_per_split:
            err_msg = (
                f"\nCRITICAL ENFORCEMENT ERROR: Split '{s_name}' contains only {b_cnt:,} benign flows, "
                f"which is less than the required minimum ({min_benign_per_split:,}). Aborting before writing parquet."
            )
            logger.error(err_msg)
            raise ValueError(err_msg)


def assert_per_file_leakage_guards(
    df_train: pd.DataFrame,
    df_val: pd.DataFrame,
    df_test_same: pd.DataFrame,
    feature_cols: List[str],
    drop_identifiers: List[str],
    drop_destination_port: bool = False,
) -> None:
    """
    Enforce per-file chronological leakage assertions:
      1. Zero metadata or identifier columns in feature set.
      2. For each source file: train max time < val min time <= val max time < same-day test min time.
    """
    forbidden = set(drop_identifiers) | {
        "Timestamp", "Original_Label", "Normalized_Label", "Label_Binary", "Label", "Source_File", "Block_ID"
    }
    if drop_destination_port:
        forbidden.update(["Destination Port", "destination_port", "Dst Port"])

    violating_features = forbidden.intersection(set(feature_cols))
    if violating_features:
        raise AssertionError(f"LEAKAGE DETECTED: Metadata/identifier columns in features: {violating_features}")

    source_files = df_train["Source_File"].unique() if "Source_File" in df_train.columns else []
    for src in source_files:
        tr_sub = df_train[df_train["Source_File"] == src]
        val_sub = df_val[df_val["Source_File"] == src]
        ts_sub = df_test_same[df_test_same["Source_File"] == src]

        if not tr_sub.empty and not val_sub.empty:
            max_tr = tr_sub["Timestamp"].max()
            min_val = val_sub["Timestamp"].min()
            if max_tr >= min_val:
                raise AssertionError(
                    f"TEMPORAL LEAKAGE in source '{src}': Train max timestamp ({max_tr}) >= "
                    f"Validation min timestamp ({min_val})."
                )

        if not val_sub.empty and not ts_sub.empty:
            max_val = val_sub["Timestamp"].max()
            min_ts = ts_sub["Timestamp"].min()
            if max_val >= min_ts:
                raise AssertionError(
                    f"TEMPORAL LEAKAGE in source '{src}': Validation max timestamp ({max_val}) >= "
                    f"Same-day Test min timestamp ({min_ts})."
                )

    logger.info("Per-file leakage guards passed: All temporal sequence boundaries validated.")


def run_preprocessing(
    config_path: Optional[str] = None,
    read_from_zip: Optional[bool] = None,
) -> None:
    """Execute complete end-to-end preprocessing with per-file chronological splits, global dedup, and block sampling."""
    config = load_config(config_path)
    raw_dir = config.get_path("raw_data_dir")
    processed_dir = config.get_path("processed_data_dir")
    models_dir = config.get_path("models_dir")
    cache_dir = processed_dir / ".cache"

    processed_dir.mkdir(parents=True, exist_ok=True)
    models_dir.mkdir(parents=True, exist_ok=True)
    check_and_prepare_cache_dir(cache_dir)

    seed = config.get("preprocessing.random_seed", 42)
    set_seeds(seed)

    target_sample_size = config.get("preprocessing.sample_size", 300000)
    train_ratio = config.get("preprocessing.train_ratio", 0.70)
    val_ratio = config.get("preprocessing.val_ratio", 0.15)
    planned_files = config.get("download.planned_files", None)
    min_benign = config.get("preprocessing.min_benign_per_split", 500)
    use_zip = read_from_zip if read_from_zip is not None else config.get("download.read_from_zip", True)
    drop_dst_port = config.get("preprocessing.drop_destination_port", True)
    drop_identifiers = config.get("preprocessing.drop_identifier_columns", [])

    # 1. Ingest/cache all files with global duplicate detection
    source_items = list(iter_source_files(raw_dir, read_from_zip=use_zip, planned_files=planned_files))
    print(f"\n[DDoS Preprocessing] Processing {len(source_items)} planned stream files...")

    global_seen_hashes: Set[int] = set()
    cached_sources: List[Tuple[str, str, Path]] = []
    total_seen_flows = 0
    total_dropped_duplicates = 0

    for day_tag, file_id, opener in tqdm(source_items, desc="Ingesting/Caching & Deduplicating streams"):
        cached_p, seen_cnt, drop_cnt = load_or_cache_source_file(
            day_tag, file_id, opener, cache_dir, config, global_seen_hashes=global_seen_hashes
        )
        total_seen_flows += seen_cnt
        total_dropped_duplicates += drop_cnt
        cached_sources.append((day_tag, file_id, cached_p))

    if total_dropped_duplicates > 0:
        logger.info(
            f"Global duplicate removal complete: Dropped {total_dropped_duplicates:,} duplicate flows out of {total_seen_flows:,}."
        )

    # 2. Split chronologically per file FIRST, then sample contiguous blocks within each split
    train_pieces: List[pd.DataFrame] = []
    val_pieces: List[pd.DataFrame] = []
    test_same_pieces: List[pd.DataFrame] = []
    test_cross_pieces: List[pd.DataFrame] = []

    day1_files = [f for d, f, _ in cached_sources if d == "01-12"]
    day2_files = [f for d, f, _ in cached_sources if d == "03-11"]

    per_file_day1_quota = max(1000, target_sample_size // max(1, len(day1_files)))
    per_file_day2_quota = max(1000, (target_sample_size // 2) // max(1, len(day2_files)))

    print("\n[DDoS Preprocessing] Performing per-file chronological splitting & contiguous block sampling...")
    for day_tag, file_id, cached_p in tqdm(cached_sources, desc="Splitting & Sampling per file"):
        if not cached_p.is_file() or cached_p.stat().st_size == 0:
            continue

        df_file = pd.read_parquet(cached_p)
        if df_file.empty:
            continue

        df_file = df_file.sort_values(by="Timestamp").reset_index(drop=True)
        n_file = len(df_file)

        if day_tag == "01-12":
            # STEP 1: SPLIT CHRONOLOGICALLY PER FILE FIRST!
            tr_idx = int(n_file * train_ratio)
            v_idx = int(n_file * (train_ratio + val_ratio))

            tr_end = find_strict_split_index(df_file, tr_idx)
            v_end = find_strict_split_index(df_file, v_idx)

            raw_split_train = df_file.iloc[:tr_end].copy().reset_index(drop=True)
            raw_split_val = df_file.iloc[tr_end:v_end].copy().reset_index(drop=True)
            raw_split_test = df_file.iloc[v_end:].copy().reset_index(drop=True)

            # STEP 2: SAMPLE CONTIGUOUS BLOCKS WITHIN EACH SPLIT (NEVER SAMPLE BEFORE SPLITTING)
            quota_tr = int(per_file_day1_quota * train_ratio)
            quota_v = int(per_file_day1_quota * val_ratio)
            quota_ts = int(per_file_day1_quota * (1.0 - train_ratio - val_ratio))

            def sample_blocks_within_split(df_s: pd.DataFrame, target_n: int, prefix: str) -> pd.DataFrame:
                benign = df_s[df_s["Label_Binary"] == 0].copy()
                attack = df_s[df_s["Label_Binary"] == 1].copy()

                # Preserve all benign, assigning block IDs for sequence modeling
                sampled_benign = sample_contiguous_blocks(
                    benign,
                    target_count=len(benign),
                    block_size=50,
                    random_seed=seed,
                    block_prefix=f"{prefix}_benign",
                )

                rem_attack = max(1, target_n - len(benign))
                sampled_attack = sample_contiguous_blocks(
                    attack,
                    target_count=rem_attack,
                    block_size=50,
                    random_seed=seed,
                    block_prefix=f"{prefix}_attack",
                )
                combined = pd.concat([sampled_benign, sampled_attack], ignore_axis=True)
                return combined.sort_values(by="Timestamp").reset_index(drop=True)

            prefix_base = file_id.replace("/", "_").replace(".csv", "")
            train_pieces.append(sample_blocks_within_split(raw_split_train, quota_tr, f"{prefix_base}_tr"))
            val_pieces.append(sample_blocks_within_split(raw_split_val, quota_v, f"{prefix_base}_val"))
            test_same_pieces.append(sample_blocks_within_split(raw_split_test, quota_ts, f"{prefix_base}_ts"))

        else:
            # Day 2: Cross-day test pool
            prefix_base = file_id.replace("/", "_").replace(".csv", "")
            benign = df_file[df_file["Label_Binary"] == 0].copy()
            attack = df_file[df_file["Label_Binary"] == 1].copy()

            sampled_benign = sample_contiguous_blocks(
                benign,
                target_count=len(benign),
                block_size=50,
                random_seed=seed,
                block_prefix=f"{prefix_base}_cross_benign",
            )

            rem_attack = max(1, per_file_day2_quota - len(benign))
            sampled_attack = sample_contiguous_blocks(
                attack,
                target_count=rem_attack,
                block_size=50,
                random_seed=seed,
                block_prefix=f"{prefix_base}_cross_attack",
            )
            combined = pd.concat([sampled_benign, sampled_attack], ignore_axis=True)
            test_cross_pieces.append(combined.sort_values(by="Timestamp").reset_index(drop=True))

        del df_file
        gc.collect()

    df_train = pd.concat(train_pieces, ignore_axis=True).reset_index(drop=True)
    df_val = pd.concat(val_pieces, ignore_axis=True).reset_index(drop=True)
    df_test_same = pd.concat(test_same_pieces, ignore_axis=True).reset_index(drop=True)
    df_test_cross = pd.concat(test_cross_pieces, ignore_axis=True).reset_index(drop=True)

    # 3. Print and strictly enforce min_benign_per_split BEFORE writing any parquet!
    splits_dict = {
        "Train": df_train,
        "Validation": df_val,
        "Same-Day Test": df_test_same,
        "Cross-Day Test": df_test_cross,
    }
    print_and_enforce_split_table(splits_dict, min_benign_per_split=min_benign)

    # 4. Feature selection: correlation pruning + RF ranking
    metadata_cols = {"Timestamp", "Original_Label", "Normalized_Label", "Label_Binary", "Source_File", "Block_ID"}
    candidate_features = [
        c for c in df_train.select_dtypes(include=[np.number]).columns
        if c not in metadata_cols and df_train[c].std() > 1e-6
    ]

    corr_thresh = config.get("preprocessing.correlation_threshold", 0.95)
    top_k = config.get("preprocessing.top_k_features", 25)

    uncorrelated = remove_collinear_features(df_train, candidate_features, threshold=corr_thresh)
    collinear_dropped = [c for c in candidate_features if c not in uncorrelated]

    final_features = rank_and_select_features(
        X=df_train,
        y=df_train["Label_Binary"],
        feature_cols=uncorrelated,
        top_k=top_k,
        random_seed=seed,
    )

    # Record dropped columns and metadata explicitly in features.json
    named_dropped = list(drop_identifiers) + ["Label", "Timestamp"]
    if drop_dst_port:
        named_dropped.append("Destination Port")

    features_metadata = {
        "dropped_columns": {
            "identifiers_and_metadata_dropped_by_name": sorted(named_dropped),
            "lab_artifacts_dropped": ["Destination Port"] if drop_dst_port else [],
            "collinear_features_dropped": collinear_dropped,
        },
        "correlation_threshold": corr_thresh,
        "top_k_requested": top_k,
    }

    features_json_path = models_dir / "features.json"
    save_selected_features(final_features, features_json_path, metadata=features_metadata)

    # 5. Assert per-file leakage guards
    assert_per_file_leakage_guards(
        df_train=df_train,
        df_val=df_val,
        df_test_same=df_test_same,
        feature_cols=final_features,
        drop_identifiers=drop_identifiers,
        drop_destination_port=drop_dst_port,
    )

    # 6. Fit StandardScaler on TRAIN ONLY
    logger.info("Fitting StandardScaler on TRAIN split only...")
    scaler = StandardScaler()
    df_train[final_features] = scaler.fit_transform(df_train[final_features])
    df_val[final_features] = scaler.transform(df_val[final_features])
    df_test_same[final_features] = scaler.transform(df_test_same[final_features])

    scaler_path = models_dir / "scaler.joblib"
    joblib.dump(scaler, scaler_path)
    logger.info(f"StandardScaler saved to {scaler_path}")

    if not df_test_cross.empty:
        for f in final_features:
            if f not in df_test_cross.columns:
                df_test_cross[f] = 0.0
        df_test_cross[final_features] = scaler.transform(df_test_cross[final_features])

    # 7. Save Parquet splits
    splits_to_save = {
        "train.parquet": df_train,
        "val.parquet": df_val,
        "test_same_day.parquet": df_test_same,
        "test_cross_day.parquet": df_test_cross,
    }

    for fname, split_df in splits_to_save.items():
        if not split_df.empty:
            out_file = processed_dir / fname
            split_df.to_parquet(out_file, index=False)
            logger.info(f"Wrote {fname}: {len(split_df):,} rows")

    # 8. Build LSTM windows strictly from contiguous blocks
    win_size = config.get("windowing.window_size", 10)
    step_size = config.get("windowing.step_size", 5)

    lstm_splits = [
        ("lstm_train.npz", df_train),
        ("lstm_val.npz", df_val),
        ("lstm_test_same_day.npz", df_test_same),
        ("lstm_test_cross_day.npz", df_test_cross),
    ]

    for fname, split_df in lstm_splits:
        if not split_df.empty and len(split_df) >= win_size:
            X_win, y_win = build_lstm_windows_from_blocks(
                split_df,
                feature_cols=final_features,
                window_size=win_size,
                step_size=step_size,
                block_col="Block_ID",
            )
            np.savez_compressed(processed_dir / fname, X=X_win, y=y_win)
            logger.info(f"Wrote {fname}: {len(X_win):,} contiguous windows of shape ({win_size}, {len(final_features)})")

    logger.info("Preprocessing pipeline completed successfully.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Preprocess CIC-DDoS2019 dataset.")
    parser.add_argument("--config", type=str, default=None, help="Path to config.yaml.")
    parser.add_argument("--read-from-zip", action="store_true", default=None, help="Read directly from raw zip archives.")
    args = parser.parse_args()
    run_preprocessing(config_path=args.config, read_from_zip=args.read_from_zip)


if __name__ == "__main__":
    main()
