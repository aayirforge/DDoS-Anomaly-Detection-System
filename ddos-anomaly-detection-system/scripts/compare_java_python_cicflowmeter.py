"""Compare Java CICFlowMeter vs Python cicflowmeter port on the same PCAP."""

from __future__ import annotations

import json
from pathlib import Path
import numpy as np
import pandas as pd
import scipy.stats

from ddos_ads.config import load_config
from ddos_ads.features import load_selected_features
from ddos_ads.pcap_to_flows import align_flow_dataframe
from ddos_ads.utils import parse_cic_timestamp


def main():
    config = load_config()
    feats = load_selected_features(config.get_path("models_dir") / "features.json")

    # Load raw CSVs
    df_java_raw = pd.read_csv("/tmp/java_flows_test/lab_idle_classic.pcap_Flow.csv")
    df_py_raw = pd.read_csv("/tmp/python_flows_test/lab_idle_classic_flows.csv")

    # Align columns to standard CIC-DDoS2019 names
    # Java column headers have slight variations like 'Src IP', 'Total Fwd Packet', etc.
    java_col_map = {
        "Src IP": "src_ip",
        "Dst IP": "dst_ip",
        "Src Port": "src_port",
        "Dst Port": "dst_port",
        "Protocol": "protocol",
        "Timestamp": "timestamp",
        "Flow Duration": "flow_duration",
        "Total Fwd Packet": "tot_fwd_pkts",
        "Total Bwd packets": "tot_bwd_pkts",
        "Total Length of Fwd Packet": "totlen_fwd_pkts",
        "Total Length of Bwd Packet": "totlen_bwd_pkts",
        "Fwd Packet Length Max": "fwd_pkt_len_max",
        "Fwd Packet Length Min": "fwd_pkt_len_min",
        "Fwd Packet Length Mean": "fwd_pkt_len_mean",
        "Fwd Packet Length Std": "fwd_pkt_len_std",
        "Bwd Packet Length Max": "bwd_pkt_len_max",
        "Bwd Packet Length Min": "bwd_pkt_len_min",
        "Bwd Packet Length Mean": "bwd_pkt_len_mean",
        "Bwd Packet Length Std": "bwd_pkt_len_std",
        "Flow Bytes/s": "flow_byts_s",
        "Flow Packets/s": "flow_pkts_s",
        "Flow IAT Mean": "flow_iat_mean",
        "Flow IAT Std": "flow_iat_std",
        "Flow IAT Max": "flow_iat_max",
        "Flow IAT Min": "flow_iat_min",
        "Fwd IAT Total": "fwd_iat_tot",
        "Fwd IAT Mean": "fwd_iat_mean",
        "Fwd IAT Std": "fwd_iat_std",
        "Fwd IAT Max": "fwd_iat_max",
        "Fwd IAT Min": "fwd_iat_min",
        "Bwd IAT Total": "bwd_iat_tot",
        "Bwd IAT Mean": "bwd_iat_mean",
        "Bwd IAT Std": "bwd_iat_std",
        "Bwd IAT Max": "bwd_iat_max",
        "Bwd IAT Min": "bwd_iat_min",
        "Fwd PSH Flags": "fwd_psh_flags",
        "Bwd PSH Flags": "bwd_psh_flags",
        "Fwd URG Flags": "fwd_urg_flags",
        "Bwd URG Flags": "bwd_urg_flags",
        "Fwd Header Length": "fwd_header_len",
        "Bwd Header Length": "bwd_header_len",
        "Fwd Packets/s": "fwd_pkts_s",
        "Bwd Packets/s": "bwd_pkts_s",
        "Packet Length Min": "pkt_len_min",
        "Packet Length Max": "pkt_len_max",
        "Packet Length Mean": "pkt_len_mean",
        "Packet Length Std": "pkt_len_std",
        "Packet Length Variance": "pkt_len_var",
        "FIN Flag Count": "fin_flag_cnt",
        "SYN Flag Count": "syn_flag_cnt",
        "RST Flag Count": "rst_flag_cnt",
        "PSH Flag Count": "psh_flag_cnt",
        "ACK Flag Count": "ack_flag_cnt",
        "URG Flag Count": "urg_flag_cnt",
        "CWR Flag Count": "cwr_flag_count",
        "ECE Flag Count": "ece_flag_cnt",
        "Down/Up Ratio": "down_up_ratio",
        "Average Packet Size": "pkt_size_avg",
        "Fwd Segment Size Avg": "fwd_seg_size_avg",
        "Bwd Segment Size Avg": "bwd_seg_size_avg",
        "Subflow Fwd Packets": "subflow_fwd_pkts",
        "Subflow Fwd Bytes": "subflow_fwd_byts",
        "Subflow Bwd Packets": "subflow_bwd_pkts",
        "Subflow Bwd Bytes": "subflow_bwd_byts",
        "FWD Init Win Bytes": "init_fwd_win_byts",
        "Bwd Init Win Bytes": "init_bwd_win_byts",
        "Fwd Act Data Pkts": "fwd_act_data_pkts",
        "Fwd Seg Size Min": "fwd_seg_size_min",
        "Active Mean": "active_mean",
        "Active Std": "active_std",
        "Active Max": "active_max",
        "Active Min": "active_min",
        "Idle Mean": "idle_mean",
        "Idle Std": "idle_std",
        "Idle Max": "idle_max",
        "Idle Min": "idle_min",
    }

    df_java_renamed = df_java_raw.rename(columns={k: v for k, v in java_col_map.items() if k in df_java_raw.columns})

    # Note: Java CICFlowMeter writes Bwd IAT in microseconds natively.
    # Python cicflowmeter writes seconds. Our align_flow_dataframe multiplies Python by 1e6.
    # For Java, Bwd IAT is already in microseconds, so we don't multiply it by 1e6 twice.
    feats_java_aligned, meta_java = align_flow_dataframe(df_java_renamed, feats)
    # Re-normalize Java Bwd IAT because Java was already microseconds!
    for bwd_feat in ["Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Min", "Bwd IAT Max"]:
        # In align_flow_dataframe it was multiplied by 1e6; undo for Java to keep raw microseconds
        feats_java_aligned[bwd_feat] = feats_java_aligned[bwd_feat] / 1e6

    feats_py_aligned, meta_py = align_flow_dataframe(df_py_raw, feats)

    meta_java["idx"] = meta_java.index
    meta_py["idx"] = meta_py.index

    # Parse timestamps to seconds epoch for comparison
    meta_java["ts_sec"] = parse_cic_timestamp(meta_java["Timestamp"]).astype(np.int64) // 10**9
    meta_py["ts_sec"] = parse_cic_timestamp(meta_py["Timestamp"]).astype(np.int64) // 10**9

    # Match flows by 5-tuple
    # Notice: In biflows, forward direction could be inverted between implementations.
    # We check canonical 5-tuple: min(src, dst), max(src, dst), min(sport, dport), max(sport, dport), proto
    def get_canon_key(row):
        ip1, ip2 = sorted([str(row["Source IP"]), str(row["Destination IP"])])
        p1, p2 = sorted([int(row["Source Port"]), int(row["Destination Port"])])
        proto = int(row["Protocol"])
        return (ip1, ip2, p1, p2, proto)

    meta_java["canon_5tuple"] = meta_java.apply(get_canon_key, axis=1)
    meta_py["canon_5tuple"] = meta_py.apply(get_canon_key, axis=1)

    matched_pairs = []
    used_java = set()

    for py_idx, py_row in meta_py.iterrows():
        key = py_row["canon_5tuple"]
        py_ts = py_row["ts_sec"]
        
        # Candidates in Java
        cands = meta_java[(meta_java["canon_5tuple"] == key) & (~meta_java["idx"].isin(used_java))]
        if not cands.empty:
            # Pick closest in time
            time_diffs = (cands["ts_sec"] - py_ts).abs()
            best_j_idx = cands.loc[time_diffs.idxmin()]["idx"]
            matched_pairs.append((best_j_idx, py_idx))
            used_java.add(best_j_idx)

    print(f"Matched {len(matched_pairs)} flows between Java (total {len(meta_java)}) and Python (total {len(meta_py)}).")

    # Compute agreement for each feature
    agreement_records = []
    java_matched_feats = feats_java_aligned.iloc[[p[0] for p in matched_pairs]].reset_index(drop=True)
    py_matched_feats = feats_py_aligned.iloc[[p[1] for p in matched_pairs]].reset_index(drop=True)

    for f in feats:
        v_j = java_matched_feats[f].to_numpy(dtype=float)
        v_p = py_matched_feats[f].to_numpy(dtype=float)

        diff = np.abs(v_j - v_p)
        mae = float(np.mean(diff))
        max_diff = float(np.max(diff))

        # Check exact matches (with 1e-4 tolerance)
        exact_matches = int((diff <= 1e-4).sum())
        exact_pct = float(exact_matches / len(diff) * 100) if len(diff) > 0 else 0.0

        # Pearson correlation
        if np.std(v_j) > 1e-6 and np.std(v_p) > 1e-6:
            r = float(scipy.stats.pearsonr(v_j, v_p)[0])
        elif np.allclose(v_j, v_p, atol=1e-4):
            r = 1.0
        else:
            r = 0.0

        agreement_records.append({
            "feature": f,
            "java_mean": round(float(np.mean(v_j)), 4),
            "python_mean": round(float(np.mean(v_p)), 4),
            "mae": round(mae, 4),
            "max_abs_diff": round(max_diff, 4),
            "exact_match_pct": round(exact_pct, 1),
            "pearson_r": round(r, 4),
        })

    out_file = Path("results/cicflowmeter_java_vs_python_agreement.json")
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w") as fp:
        json.dump({
            "sample_sizes": {
                "pcap": "lab_idle.pcap (Session 2)",
                "java_flows": len(df_java_raw),
                "python_flows": len(df_py_raw),
                "matched_flows": len(matched_pairs),
            },
            "per_feature_agreement": agreement_records,
        }, fp, indent=2)

    print(f"Agreement analysis saved to {out_file}.")


if __name__ == "__main__":
    main()
