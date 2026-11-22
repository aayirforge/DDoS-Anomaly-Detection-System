"""Packet capture (tshark), flow extraction (cicflowmeter), and schema alignment."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from typing import Dict, List, Optional, Tuple
import pandas as pd

from ddos_ads.config import load_config
from ddos_ads.features import load_selected_features
from ddos_ads.utils import parse_cic_timestamp, setup_logger

logger = setup_logger("ddos_ads.pcap_to_flows")

# Explicit canonical mapping from cicflowmeter snake_case names and Java CICFlowMeter names to CIC-DDoS2019 title-case names
CICFLOWMETER_TO_CIC2019_MAP: Dict[str, str] = {
    # Timestamps & 5-tuple
    "timestamp": "Timestamp",
    "src_ip": "Source IP",
    "dst_ip": "Destination IP",
    "src_port": "Source Port",
    "dst_port": "Destination Port",
    "protocol": "Protocol",
    "flow_id": "Flow ID",
    # Java CICFlowMeter variations
    "src ip": "Source IP",
    "dst ip": "Destination IP",
    "src port": "Source Port",
    "dst port": "Destination Port",
    "total fwd packet": "Total Fwd Packets",
    "total bwd packets": "Total Backward Packets",
    "total length of fwd packet": "Total Length of Fwd Packets",
    "total length of bwd packet": "Total Length of Bwd Packets",
    "fwd segment size avg": "Avg Fwd Segment Size",
    "bwd segment size avg": "Avg Bwd Segment Size",
    "fwd init win bytes": "Init_Win_bytes_forward",
    "bwd init win bytes": "Init_Win_bytes_backward",
    "fwd act data pkts": "act_data_pkt_fwd",
    "fwd seg size min": "min_seg_size_forward",
    "cwr flag count": "CWE Flag Count",
    # Basic flow statistics
    "flow_duration": "Flow Duration",
    "tot_fwd_pkts": "Total Fwd Packets",
    "tot_bwd_pkts": "Total Backward Packets",
    "totlen_fwd_pkts": "Total Length of Fwd Packets",
    "totlen_bwd_pkts": "Total Length of Bwd Packets",
    "fwd_pkt_len_max": "Fwd Packet Length Max",
    "fwd_pkt_len_min": "Fwd Packet Length Min",
    "fwd_pkt_len_mean": "Fwd Packet Length Mean",
    "fwd_pkt_len_std": "Fwd Packet Length Std",
    "bwd_pkt_len_max": "Bwd Packet Length Max",
    "bwd_pkt_len_min": "Bwd Packet Length Min",
    "bwd_pkt_len_mean": "Bwd Packet Length Mean",
    "bwd_pkt_len_std": "Bwd Packet Length Std",
    "flow_byts_s": "Flow Bytes/s",
    "flow_pkts_s": "Flow Packets/s",
    "flow_iat_mean": "Flow IAT Mean",
    "flow_iat_std": "Flow IAT Std",
    "flow_iat_max": "Flow IAT Max",
    "flow_iat_min": "Flow IAT Min",
    "fwd_iat_tot": "Fwd IAT Total",
    "fwd_iat_mean": "Fwd IAT Mean",
    "fwd_iat_std": "Fwd IAT Std",
    "fwd_iat_max": "Fwd IAT Max",
    "fwd_iat_min": "Fwd IAT Min",
    "bwd_iat_tot": "Bwd IAT Total",
    "bwd_iat_mean": "Bwd IAT Mean",
    "bwd_iat_std": "Bwd IAT Std",
    "bwd_iat_max": "Bwd IAT Max",
    "bwd_iat_min": "Bwd IAT Min",
    # Header & Flag statistics
    "fwd_psh_flags": "Fwd PSH Flags",
    "bwd_psh_flags": "Bwd PSH Flags",
    "fwd_urg_flags": "Fwd URG Flags",
    "bwd_urg_flags": "Bwd URG Flags",
    "fwd_header_len": "Fwd Header Length",
    "bwd_header_len": "Bwd Header Length",
    "fwd_pkts_s": "Fwd Packets/s",
    "bwd_pkts_s": "Bwd Packets/s",
    "pkt_len_min": "Min Packet Length",
    "pkt_len_max": "Max Packet Length",
    "pkt_len_mean": "Packet Length Mean",
    "pkt_len_std": "Packet Length Std",
    "pkt_len_var": "Packet Length Variance",
    "fin_flag_cnt": "FIN Flag Count",
    "syn_flag_cnt": "SYN Flag Count",
    "rst_flag_cnt": "RST Flag Count",
    "psh_flag_cnt": "PSH Flag Count",
    "ack_flag_cnt": "ACK Flag Count",
    "urg_flag_cnt": "URG Flag Count",
    "cwe_flag_count": "CWE Flag Count",
    "cwr_flag_count": "CWE Flag Count",
    "ece_flag_cnt": "ECE Flag Count",
    "down_up_ratio": "Down/Up Ratio",
    "pkt_size_avg": "Average Packet Size",
    "subflow_fwd_pkts": "Subflow Fwd Packets",
    "subflow_fwd_byts": "Subflow Fwd Bytes",
    "subflow_bwd_pkts": "Subflow Bwd Packets",
    "subflow_bwd_byts": "Subflow Bwd Bytes",
    "init_fwd_win_byts": "Init_Win_bytes_forward",
    "init_bwd_win_byts": "Init_Win_bytes_backward",
    "fwd_act_data_pkts": "act_data_pkt_fwd",
    "fwd_seg_size_min": "min_seg_size_forward",
    "active_mean": "Active Mean",
    "active_std": "Active Std",
    "active_max": "Active Max",
    "active_min": "Active Min",
    "idle_mean": "Idle Mean",
    "idle_std": "Idle Std",
    "idle_max": "Idle Max",
    "idle_min": "Idle Min",
}


# Features requiring unit scaling (seconds -> microseconds) and binarization (counts -> {0, 1})
BWD_IAT_FEATURES = {"Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Min", "Bwd IAT Max"}
BINARY_FLAG_FEATURES = {"ACK Flag Count", "URG Flag Count", "CWE Flag Count", "Fwd PSH Flags"}

# Bidirectional feature pairs swapped when flow starts server-to-client
DIRECTION_SWAP_PAIRS = [
    ("Source IP", "Destination IP"),
    ("Source Port", "Destination Port"),
    ("Total Fwd Packets", "Total Backward Packets"),
    ("Total Length of Fwd Packets", "Total Length of Bwd Packets"),
    ("Fwd Packet Length Max", "Bwd Packet Length Max"),
    ("Fwd Packet Length Min", "Bwd Packet Length Min"),
    ("Fwd Packet Length Mean", "Bwd Packet Length Mean"),
    ("Fwd Packet Length Std", "Bwd Packet Length Std"),
    ("Fwd IAT Total", "Bwd IAT Total"),
    ("Fwd IAT Mean", "Bwd IAT Mean"),
    ("Fwd IAT Std", "Bwd IAT Std"),
    ("Fwd IAT Max", "Bwd IAT Max"),
    ("Fwd IAT Min", "Bwd IAT Min"),
    ("Fwd PSH Flags", "Bwd PSH Flags"),
    ("Fwd URG Flags", "Bwd URG Flags"),
    ("Fwd Header Length", "Bwd Header Length"),
    ("Fwd Packets/s", "Bwd Packets/s"),
    ("Init_Win_bytes_forward", "Init_Win_bytes_backward"),
    ("Avg Fwd Segment Size", "Avg Bwd Segment Size"),
    ("Subflow Fwd Packets", "Subflow Bwd Packets"),
    ("Subflow Fwd Bytes", "Subflow Bwd Bytes"),
]


def normalize_column_name(col: str) -> str:
    """Normalize string for fuzzy matching (lowercase, alphanumeric only)."""
    return re.sub(r"[^a-z0-9]", "", col.lower())


def align_flow_dataframe(
    raw_df: pd.DataFrame,
    target_features: List[str],
    label: Optional[str] = None,
    extractor: str = "auto",
    apply_direction_rule: bool = False,
    server_ip: str = "172.20.0.2",
    server_ports: Tuple[int, ...] = (80, 443),
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Align raw flow DataFrame from cicflowmeter (Java or Python) to the exact CIC-DDoS2019 feature representation.

    Parameters:
        raw_df: Raw flow dataframe from Java or Python cicflowmeter.
        target_features: List of ordered feature names matching models/features.json.
        label: Optional string label (e.g. "BENIGN" or "Syn").
        extractor: "auto", "java", or "python". Auto-detects based on raw columns.
        apply_direction_rule: If True, flows initiated server-to-client (Source IP == server_ip
                              or Source Port in server_ports) will have their forward and backward
                              features inverted to maintain client-initiated perspective.
        server_ip: IP address of lab web server.
        server_ports: Ports of lab web server.

    Returns:
        (features_df, metadata_df):
          - features_df: DataFrame ordered exactly according to target_features.
          - metadata_df: DataFrame containing 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol, timestamp).
    """
    import numpy as np
    df = raw_df.copy()
    # Strip whitespace from column names
    df.columns = [str(c).strip() for c in df.columns]

    # Detect extractor if auto
    if extractor == "auto":
        raw_cols_lower = {str(c).strip().lower() for c in raw_df.columns}
        if "bwd_iat_tot" in raw_cols_lower or "tot_fwd_pkts" in raw_cols_lower:
            is_java = False
        else:
            is_java = True
    else:
        is_java = (extractor.lower() == "java")

    # Map columns using explicit dictionary
    rename_dict = {}
    for col in df.columns:
        clean_col = col.lower()
        if clean_col in CICFLOWMETER_TO_CIC2019_MAP:
            rename_dict[col] = CICFLOWMETER_TO_CIC2019_MAP[clean_col]

    df = df.rename(columns=rename_dict)

    # Secondary fuzzy mapping fallback for unmatched columns
    normalized_existing = {normalize_column_name(c): c for c in df.columns}
    for target in target_features:
        if target not in df.columns:
            norm_target = normalize_column_name(target)
            if norm_target in normalized_existing:
                df = df.rename(columns={normalized_existing[norm_target]: target})

    # Apply direction rule if requested: server-initiated flows have forward and backward features swapped
    if apply_direction_rule:
        src_ip_col = df["Source IP"] if "Source IP" in df.columns else pd.Series([""] * len(df), index=df.index)
        src_port_col = pd.to_numeric(df["Source Port"], errors="coerce").fillna(0) if "Source Port" in df.columns else pd.Series([0] * len(df), index=df.index)
        is_server = (src_ip_col.astype(str) == str(server_ip)) | (src_port_col.isin(server_ports))
        n_server = int(is_server.sum())
        if n_server > 0:
            logger.info(f"Direction rule: inverting forward/backward features for {n_server} server-to-client flows.")
            for fwd_col, bwd_col in DIRECTION_SWAP_PAIRS:
                if fwd_col in df.columns and bwd_col in df.columns:
                    tmp = df.loc[is_server, fwd_col].copy()
                    df.loc[is_server, fwd_col] = df.loc[is_server, bwd_col]
                    df.loc[is_server, bwd_col] = tmp
            if "Down/Up Ratio" in df.columns:
                r_vals = pd.to_numeric(df.loc[is_server, "Down/Up Ratio"], errors="coerce").fillna(0.0)
                df.loc[is_server, "Down/Up Ratio"] = np.where(r_vals > 0, 1.0 / r_vals, 0.0)

    # Extract metadata columns (5-tuple + Timestamp)
    meta_cols = ["Timestamp", "Source IP", "Destination IP", "Source Port", "Destination Port", "Protocol"]
    metadata_df = pd.DataFrame(index=df.index)

    for m in meta_cols:
        if m in df.columns:
            metadata_df[m] = df[m]
        else:
            metadata_df[m] = "Unknown"

    if "Timestamp" in metadata_df.columns and metadata_df["Timestamp"].iloc[0] != "Unknown":
        metadata_df["Timestamp"] = parse_cic_timestamp(metadata_df["Timestamp"])
    else:
        metadata_df["Timestamp"] = pd.Timestamp.now()

    # Fill and align model features
    missing_features = []
    features_df = pd.DataFrame(index=df.index)

    for target in target_features:
        if target in df.columns:
            val_series = pd.to_numeric(df[target], errors="coerce").fillna(0.0)
            if target in BWD_IAT_FEATURES:
                # Java CICFlowMeter outputs microseconds natively; Python outputs seconds
                if not is_java:
                    val_series = val_series * 1e6
            elif target in BINARY_FLAG_FEATURES:
                # Both Java and Python outputs flag counts; train.parquet is binary {0, 1}
                val_series = (val_series > 0).astype(float)
            features_df[target] = val_series
        else:
            features_df[target] = 0.0
            missing_features.append(target)

    if missing_features:
        logger.warning(
            f"SCHEMA ALIGNMENT WARNING: {len(missing_features)} features were missing from flow capture "
            f"and filled with 0.0: {missing_features[:10]}{'...' if len(missing_features) > 10 else ''}"
        )

    # Optional label injection for lab validation
    if label is not None:
        metadata_df["Label"] = label
        metadata_df["Label_Binary"] = 0 if label.upper() == "BENIGN" else 1

    return features_df, metadata_df


def check_feature_scales(
    lab_flow_df: pd.DataFrame,
    train_benign_df: pd.DataFrame,
    feature_cols: List[str],
    ratio_threshold: float = 100.0,
) -> Tuple[pd.DataFrame, List[str]]:
    """
    Compare min, median, and max of each feature for a lab PCAP's benign flows
    against train benign flows, flagging any feature differing by more than ratio_threshold.
    """
    rows = []
    flagged = []

    for f in feature_cols:
        if f not in train_benign_df.columns or f not in lab_flow_df.columns:
            continue

        tr_series = pd.to_numeric(train_benign_df[f], errors="coerce").dropna()
        lab_series = pd.to_numeric(lab_flow_df[f], errors="coerce").dropna()

        if tr_series.empty or lab_series.empty:
            continue

        tr_min, tr_med, tr_max = float(tr_series.min()), float(tr_series.median()), float(tr_series.max())
        lab_min, lab_med, lab_max = float(lab_series.min()), float(lab_series.median()), float(lab_series.max())

        ratio_med = "N/A"
        ratio_max = "N/A"
        is_flagged = False
        reasons = []

        if tr_med > 0 and lab_med > 0:
            r = lab_med / tr_med
            ratio_med = f"{r:.2f}x" if r >= 1 else f"1/{1/r:.1f}x"
            if r > ratio_threshold or r < (1.0 / ratio_threshold):
                is_flagged = True
                reasons.append(f"median({ratio_med})")

        if tr_max > 0 and lab_max > 0:
            r_m = lab_max / tr_max
            ratio_max = f"{r_m:.2f}x" if r_m >= 1 else f"1/{1/r_m:.1f}x"
            if r_m > ratio_threshold or r_m < (1.0 / ratio_threshold):
                is_flagged = True
                reasons.append(f"max({ratio_max})")

        status = "FLAGGED" if is_flagged else "OK"
        if is_flagged:
            flagged.append(f)

        rows.append({
            "Feature": f,
            "Train_Min": tr_min,
            "Train_Med": tr_med,
            "Train_Max": tr_max,
            "Lab_Min": lab_min,
            "Lab_Med": lab_med,
            "Lab_Max": lab_max,
            "Med_Ratio": ratio_med,
            "Max_Ratio": ratio_max,
            "Status": status,
            "Reason": ", ".join(reasons) if reasons else "None",
        })

    df_summary = pd.DataFrame(rows)

    print("\n" + "=" * 120)
    print("                 FEATURE SCALE VALIDATION: LAB PCAP FLOWS vs TRAIN BENIGN FLOWS")
    print("=" * 120)
    header = (
        f"| {'Feature':<28} | {'Train [Min, Med, Max]':<28} | {'Lab [Min, Med, Max]':<28} | "
        f"{'Med Ratio':<10} | {'Max Ratio':<10} | {'Status':<8} |"
    )
    sep = f"|{'-'*30}|{'-'*30}|{'-'*30}|{'-'*12}|{'-'*12}|{'-'*10}|"
    print(header)
    print(sep)

    for _, r in df_summary.iterrows():
        tr_str = f"[{r['Train_Min']:.1f}, {r['Train_Med']:.1f}, {r['Train_Max']:.1f}]"
        lab_str = f"[{r['Lab_Min']:.1f}, {r['Lab_Med']:.1f}, {r['Lab_Max']:.1f}]"
        print(
            f"| {r['Feature']:<28} | {tr_str:<28} | {lab_str:<28} | "
            f"{r['Med_Ratio']:<10} | {r['Max_Ratio']:<10} | {r['Status']:<8} |"
        )
    print(sep)
    print(f"Total Features Analyzed: {len(df_summary)} | Flagged (> {ratio_threshold}x): {len(flagged)}")
    if flagged:
        print(f"Flagged features to inspect for unit mismatches: {flagged}")
    print("=" * 120 + "\n")

    return df_summary, flagged


def capture_pcap(
    interface: str,
    duration_sec: int,
    output_pcap: Path,
    bpf_filter: Optional[str] = None,
    tshark_path: str = "/usr/bin/tshark",
) -> Path:
    """Capture network traffic using tshark."""
    output_pcap.parent.mkdir(parents=True, exist_ok=True)
    tshark_bin = shutil.which(tshark_path) or shutil.which("tshark")
    if not tshark_bin:
        raise RuntimeError("tshark binary not found. Install wireshark / tshark package.")

    cmd = [
        tshark_bin,
        "-i", interface,
        "-a", f"duration:{duration_sec}",
        "-w", str(output_pcap),
    ]
    if bpf_filter:
        cmd.extend(["-f", bpf_filter])

    logger.info(f"Executing packet capture on '{interface}' for {duration_sec}s -> {output_pcap}...")
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0 and not output_pcap.is_file():
        raise RuntimeError(f"tshark capture failed (exit {result.returncode}): {result.stderr}")

    logger.info(f"Capture complete. Output size: {output_pcap.stat().st_size if output_pcap.is_file() else 0} bytes.")
    return output_pcap


def extract_flows_java(
    pcap_path: Path,
    output_dir: Path,
) -> List[Path]:
    """
    Extract network flows from PCAP using the official Java CICFlowMeter (offline mode).
    Handles automatic pcapng->pcap conversion, native JNI lib paths, and dependency classpath.
    """
    import os
    output_dir.mkdir(parents=True, exist_ok=True)
    pcap_path = Path(pcap_path).resolve()

    base_dir = Path(__file__).resolve().parents[2]  # ddos-anomaly-detection-system root
    jar_env = os.environ.get("FLOWMETER_JAR")
    jar_path = Path(jar_env) if jar_env else (base_dir / "tools" / "cicflowmeter-java" / "target" / "SimpleFlowMeterV4-0.0.4-SNAPSHOT.jar")
    if not jar_path.exists():
        fallback_jar = base_dir / "tools" / "SimpleFlowMeterV4-0.0.4-SNAPSHOT.jar"
        if fallback_jar.exists():
            jar_path = fallback_jar
    jnetpcap_dir = base_dir / "tools" / "cicflowmeter-java" / "jnetpcap" / "linux" / "jnetpcap-1.4.r1425"
    lib_dir = base_dir / "tools" / "lib"
    lib_dir.mkdir(parents=True, exist_ok=True)

    # Ensure libpcap.so exists in tools/lib
    libpcap_so = lib_dir / "libpcap.so"
    if not libpcap_so.exists():
        for cand in ["/usr/lib/x86_64-linux-gnu/libpcap.so.0.8", "/usr/lib/x86_64-linux-gnu/libpcap.so.1.11.0", "/usr/lib/libpcap.so"]:
            if Path(cand).exists():
                try:
                    libpcap_so.symlink_to(cand)
                except Exception:
                    pass
                break

    # Build classpath from maven repository
    m2_env = os.environ.get("M2_REPO")
    m2 = Path(m2_env) if m2_env else (Path.home() / ".m2/repository")
    jars = [str(j) for j in m2.glob("**/*.jar")] if m2.exists() else []
    jars.append(str(base_dir / "tools" / "cicflowmeter-java" / "target" / "classes"))
    jars.append(str(jar_path))
    cp_str = ":".join(jars)

    # Classic pcap conversion if pcapng (SwingUtils requires classic pcap)
    tmp_classic = Path(f"/tmp/{pcap_path.stem}_{int(time.time()*1000)}_classic.pcap")
    target_pcap = pcap_path
    editcap_bin = shutil.which("editcap")
    if editcap_bin:
        cmd_edit = [editcap_bin, "-F", "pcap", str(pcap_path), str(tmp_classic)]
        res_edit = subprocess.run(cmd_edit, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if res_edit.returncode == 0 and tmp_classic.is_file():
            target_pcap = tmp_classic

    env = os.environ.copy()
    env["LD_LIBRARY_PATH"] = f"{jnetpcap_dir}:{lib_dir}:/tmp/lib:" + env.get("LD_LIBRARY_PATH", "")

    cmd = [
        "java",
        f"-Djava.library.path={jnetpcap_dir}:{lib_dir}:/tmp/lib",
        "-cp", cp_str,
        "cic.cs.unb.ca.ifm.Cmd",
        str(target_pcap),
        str(output_dir),
    ]

    logger.info(f"Extracting flows using Java CICFlowMeter from {target_pcap} -> {output_dir}...")
    res = subprocess.run(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if res.returncode != 0:
        logger.error(f"Java CICFlowMeter failed with code {res.returncode}:\n{res.stderr}")

    if tmp_classic.exists() and tmp_classic != pcap_path:
        try:
            tmp_classic.unlink()
        except Exception:
            pass

    # Find created CSV(s)
    csvs = list(output_dir.glob(f"*{pcap_path.stem}*.csv")) or list(output_dir.glob("*_Flow.csv")) or list(output_dir.glob("*.csv"))
    logger.info(f"Java CICFlowMeter extraction finished. {len(csvs)} CSV files present in {output_dir}.")
    return csvs


def convert_pcap_to_flows(
    pcap_path: Path,
    output_dir: Path,
    extractor: str = "java",
    cicflowmeter_bin: str = "cicflowmeter",
) -> List[Path]:
    """Convert PCAP file into CSV flows using Java CICFlowMeter (primary) or Python port."""
    output_dir.mkdir(parents=True, exist_ok=True)

    if extractor.lower() == "java":
        return extract_flows_java(pcap_path, output_dir)

    # Fallback / legacy python port behind explicit flag
    logger.warning("Python extractor is non-authoritative due to known wire-vs-payload length differences. Java CICFlowMeter is the primary verified extractor.")
    csv_out = output_dir / f"{pcap_path.stem}_flows.csv"
    try:
        from cicflowmeter.sniffer import create_sniffer
        logger.info(f"Extracting flows using cicflowmeter Python module from {pcap_path}...")
        sniffer, session = create_sniffer(
            input_file=str(pcap_path),
            input_interface=None,
            output_mode="csv",
            output=str(csv_out),
            fields=None,
            verbose=False,
        )
        sniffer.start()
        sniffer.join()
        if hasattr(session, "_gc_stop"):
            session._gc_stop.set()
        session.flush_flows()
        if csv_out.is_file() and csv_out.stat().st_size > 0:
            logger.info(f"Flow conversion finished: {csv_out.name} ({csv_out.stat().st_size} bytes).")
            return [csv_out]
    except Exception as exc:
        logger.warning(f"Direct Python cicflowmeter extraction encountered: {exc}. Trying CLI fallback...")

    bin_path = shutil.which(cicflowmeter_bin) or shutil.which("cicflowmeter")
    if bin_path:
        cmd = [bin_path, "-f", str(pcap_path), "-c", str(csv_out)]
        logger.info(f"Running cicflowmeter CLI: {' '.join(cmd)}")
        _ = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    csvs = list(output_dir.glob("*.csv"))
    logger.info(f"Flow conversion finished. {len(csvs)} CSV files present in {output_dir}.")
    return csvs


def main() -> None:
    parser = argparse.ArgumentParser(description="PCAP capture, flow conversion, and schema alignment.")
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # Capture
    p_cap = subparsers.add_parser("capture", help="Capture live traffic to PCAP using tshark.")
    p_cap.add_argument("--interface", "-i", type=str, default="any", help="Network interface.")
    p_cap.add_argument("--duration", "-d", type=int, default=5, help="Capture duration in seconds.")
    p_cap.add_argument("--filter", "-f", type=str, default="ip or ip6", help="BPF capture filter.")
    p_cap.add_argument("--out", "-o", type=str, default=None, help="Output PCAP path.")

    # Convert
    p_conv = subparsers.add_parser("convert", help="Convert PCAP to CSV flows via Java or Python CICFlowMeter.")
    p_conv.add_argument("--pcap", "-p", type=str, required=True, help="Input PCAP path.")
    p_conv.add_argument("--out-dir", "-o", type=str, default=None, help="Output directory for flows.")
    p_conv.add_argument("--extractor", "-e", type=str, default="java", choices=["java", "python"], help="Extractor backend (default: java).")

    # Align
    p_align = subparsers.add_parser("align", help="Align flow CSV to CIC-DDoS2019 features.")
    p_align.add_argument("--flow-csv", "-c", type=str, required=True, help="Input cicflowmeter CSV.")
    p_align.add_argument("--out-csv", "-o", type=str, required=True, help="Output aligned CSV path.")
    p_align.add_argument("--label", "-l", type=str, default=None, help="Optional label to inject.")
    p_align.add_argument("--extractor", "-e", type=str, default="auto", choices=["auto", "java", "python"], help="Extractor used.")
    p_align.add_argument("--direction-rule", action="store_true", help="Apply direction inversion for server-to-client flows.")
    p_align.add_argument("--server-ip", type=str, default="172.20.0.2", help="Lab server IP.")

    # All
    p_all = subparsers.add_parser("all", help="Capture, convert, and align end-to-end.")
    p_all.add_argument("--interface", "-i", type=str, default="any", help="Network interface.")
    p_all.add_argument("--duration", "-d", type=int, default=5, help="Capture duration.")
    p_all.add_argument("--filter", "-f", type=str, default="ip or ip6", help="BPF filter.")
    p_all.add_argument("--extractor", "-e", type=str, default="java", choices=["java", "python"], help="Extractor backend.")

    # Check Scales
    p_check = subparsers.add_parser("check-scales", help="Validate feature scales between lab flows and train benign.")
    p_check.add_argument("--flow-csv", "-c", type=str, required=True, help="Input lab flow CSV.")
    p_check.add_argument("--threshold", "-t", type=float, default=100.0, help="Discrepancy ratio threshold (default: 100.0).")

    args = parser.parse_args()
    config = load_config()

    if args.subcommand == "capture":
        out = Path(args.out) if args.out else config.get_path("capture_dir") / f"capture_{int(time.time())}.pcap"
        capture_pcap(args.interface, args.duration, out, bpf_filter=args.filter)

    elif args.subcommand == "convert":
        pcap_in = Path(args.pcap)
        out_dir = Path(args.out_dir) if args.out_dir else config.get_path("flows_dir")
        convert_pcap_to_flows(pcap_in, out_dir, extractor=args.extractor)

    elif args.subcommand == "align":
        features_path = config.get_path("models_dir") / "features.json"
        if not features_path.is_file():
            logger.error(f"Models not found. Run: make train")
            sys.exit(1)
        feats = load_selected_features(features_path)
        raw_df = pd.read_csv(args.flow_csv)
        feat_df, meta_df = align_flow_dataframe(
            raw_df,
            feats,
            label=args.label,
            extractor=args.extractor,
            apply_direction_rule=args.direction_rule,
            server_ip=args.server_ip,
        )
        combined = pd.concat([meta_df, feat_df], axis=1)
        combined.to_csv(args.out_csv, index=False)
        logger.info(f"Aligned flows written to {args.out_csv}")

    elif args.subcommand == "check-scales":
        import joblib
        features_path = config.get_path("models_dir") / "features.json"
        scaler_path = config.get_path("models_dir") / "scaler.joblib"
        train_path = config.get_path("processed_data_dir") / "train.parquet"

        if not features_path.is_file() or not scaler_path.is_file() or not train_path.is_file():
            logger.error("Required model/dataset files not found. Run: make preprocess")
            sys.exit(1)

        feats = load_selected_features(features_path)
        scaler = joblib.load(scaler_path)
        df_train = pd.read_parquet(train_path)

        train_benign = df_train[df_train["Label_Binary"] == 0]
        raw_train_b = pd.DataFrame(scaler.inverse_transform(train_benign[feats].values), columns=feats)

        lab_raw = pd.read_csv(args.flow_csv)
        if any(f not in lab_raw.columns for f in feats):
            lab_feat, _ = align_flow_dataframe(lab_raw, feats)
        else:
            lab_feat = lab_raw[feats]

        check_feature_scales(lab_feat, raw_train_b, feats, ratio_threshold=args.threshold)


if __name__ == "__main__":
    main()
