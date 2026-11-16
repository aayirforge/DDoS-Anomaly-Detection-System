"""Tests for network flow column alignment and zero-fill schema mapping."""

import pandas as pd
import pytest
from ddos_ads.pcap_to_flows import align_flow_dataframe, normalize_column_name


def test_normalize_column_name() -> None:
    """Verify column normalization removes spaces and punctuation."""
    assert normalize_column_name("Total Fwd Packets") == "totalfwdpackets"
    assert normalize_column_name("tot_fwd_pkts") == "totfwdpkts"
    assert normalize_column_name("Flow Bytes/s") == "flowbytess"


def test_align_flow_dataframe_mapping_and_zero_fill() -> None:
    """Verify explicit mapping of cicflowmeter snake_case columns and zero-fill of missing features."""
    raw_flows = pd.DataFrame({
        "src_ip": ["192.168.1.100"],
        "dst_ip": ["10.0.0.1"],
        "src_port": [54321],
        "dst_port": [80],
        "protocol": [6],
        "timestamp": ["2019-01-12 10:00:00"],
        "tot_fwd_pkts": [15],
        "flow_duration": [120000],
        "flow_byts_s": [450.5],
    })

    target_features = [
        "Total Fwd Packets",
        "Flow Duration",
        "Flow Bytes/s",
        "Non_Existent_Feature_X",  # This feature should be zero-filled
    ]

    feat_df, meta_df = align_flow_dataframe(raw_flows, target_features, label="BENIGN")

    # Feature DataFrame checks
    assert list(feat_df.columns) == target_features
    assert feat_df["Total Fwd Packets"].iloc[0] == 15.0
    assert feat_df["Flow Duration"].iloc[0] == 120000.0
    assert feat_df["Flow Bytes/s"].iloc[0] == 450.5
    assert feat_df["Non_Existent_Feature_X"].iloc[0] == 0.0

    # Metadata DataFrame checks
    assert meta_df["Source IP"].iloc[0] == "192.168.1.100"
    assert meta_df["Destination IP"].iloc[0] == "10.0.0.1"
    assert meta_df["Source Port"].iloc[0] == 54321
    assert meta_df["Destination Port"].iloc[0] == 80
    assert meta_df["Label"].iloc[0] == "BENIGN"
    assert meta_df["Label_Binary"].iloc[0] == 0


def test_align_flow_dataframe_bwd_iat_scaling_and_flag_binarization() -> None:
    """Verify four Bwd IAT features are multiplied by 1e6 and flags are strictly binarized to {0.0, 1.0}."""
    raw_flows = pd.DataFrame({
        "src_ip": ["172.20.0.3", "172.20.0.3"],
        "dst_ip": ["172.20.0.2", "172.20.0.2"],
        "src_port": [50000, 50001],
        "dst_port": [80, 80],
        "protocol": [6, 6],
        "timestamp": ["2026-11-15 17:00:00", "2026-11-15 17:00:01"],
        # Bwd IAT in seconds (as produced by python cicflowmeter)
        "bwd_iat_tot": [0.0015, 0.0],
        "bwd_iat_mean": [0.0005, 0.0],
        "bwd_iat_min": [0.0001, 0.0],
        "bwd_iat_max": [0.0009, 0.0],
        # Flag counts (as produced by python cicflowmeter)
        "ack_flag_cnt": [11, 0],
        "urg_flag_cnt": [2, 0],
        "cwr_flag_count": [5, 0],  # maps to CWE Flag Count
        "fwd_psh_flags": [3, 0],
    })

    target_features = [
        "Bwd IAT Total",
        "Bwd IAT Mean",
        "Bwd IAT Min",
        "Bwd IAT Max",
        "ACK Flag Count",
        "URG Flag Count",
        "CWE Flag Count",
        "Fwd PSH Flags",
    ]

    feat_df, _ = align_flow_dataframe(raw_flows, target_features)

    # 1. Bwd IAT scaling by 1e6 (seconds -> microseconds)
    assert feat_df["Bwd IAT Total"].iloc[0] == pytest.approx(1500.0)
    assert feat_df["Bwd IAT Total"].iloc[1] == 0.0
    assert feat_df["Bwd IAT Mean"].iloc[0] == pytest.approx(500.0)
    assert feat_df["Bwd IAT Mean"].iloc[1] == 0.0
    assert feat_df["Bwd IAT Min"].iloc[0] == pytest.approx(100.0)
    assert feat_df["Bwd IAT Min"].iloc[1] == 0.0
    assert feat_df["Bwd IAT Max"].iloc[0] == pytest.approx(900.0)
    assert feat_df["Bwd IAT Max"].iloc[1] == 0.0

    # 2. Flag counts binarized to {0.0, 1.0}
    for flag_col in ["ACK Flag Count", "URG Flag Count", "CWE Flag Count", "Fwd PSH Flags"]:
        assert feat_df[flag_col].iloc[0] == 1.0, f"{flag_col} row 0 should be binarized to 1.0"
        assert feat_df[flag_col].iloc[1] == 0.0, f"{flag_col} row 1 should be binarized to 0.0"
        assert set(feat_df[flag_col].unique()).issubset({0.0, 1.0})


def test_align_flow_dataframe_java_and_direction_rule() -> None:
    """Verify Java CICFlowMeter features: Bwd IAT is NOT scaled by 1e6, flags binarized, and direction rule swaps."""
    raw_java_flows = pd.DataFrame({
        "Src IP": ["172.20.0.4", "172.20.0.2"],
        "Dst IP": ["172.20.0.2", "172.20.0.4"],
        "Src Port": [40000, 80],
        "Dst Port": [80, 40000],
        "Protocol": [6, 6],
        "Timestamp": ["15/11/2026 09:10:44 pm", "15/11/2026 09:10:45 pm"],
        "Total Fwd Packet": [10, 50],
        "Total Bwd packets": [20, 5],
        "Total Length of Fwd Packet": [500.0, 2500.0],
        "Total Length of Bwd Packet": [1000.0, 250.0],
        "Bwd IAT Total": [12345.0, 67890.0],
        "Bwd IAT Mean": [2345.0, 6789.0],
        "ACK Flag Count": [7, 0],
        "URG Flag Count": [3, 0],
        "CWR Flag Count": [1, 0],
        "Fwd PSH Flags": [4, 0],
        "Down/Up Ratio": [2.0, 0.1],
    })

    target_features = [
        "Total Fwd Packets",
        "Total Backward Packets",
        "Total Length of Fwd Packets",
        "Total Length of Bwd Packets",
        "Bwd IAT Total",
        "Bwd IAT Mean",
        "ACK Flag Count",
        "URG Flag Count",
        "CWE Flag Count",
        "Fwd PSH Flags",
        "Down/Up Ratio",
    ]

    feat_df, meta_df = align_flow_dataframe(
        raw_java_flows,
        target_features,
        extractor="java",
        apply_direction_rule=True,
        server_ip="172.20.0.2",
    )

    # 1. Bwd IAT should remain unscaled (Java outputs microseconds natively)
    assert feat_df["Bwd IAT Total"].iloc[0] == 12345.0
    assert feat_df["Bwd IAT Mean"].iloc[0] == 2345.0

    # 2. Flag counts should be strictly binarized
    assert feat_df["ACK Flag Count"].iloc[0] == 1.0
    assert feat_df["URG Flag Count"].iloc[0] == 1.0
    assert feat_df["CWE Flag Count"].iloc[0] == 1.0
    assert feat_df["Fwd PSH Flags"].iloc[0] == 1.0

    assert feat_df["ACK Flag Count"].iloc[1] == 0.0
    assert feat_df["URG Flag Count"].iloc[1] == 0.0

    # 3. Direction rule check:
    # Row 0 was client->server: Total Fwd Packets = 10, Total Backward Packets = 20
    assert feat_df["Total Fwd Packets"].iloc[0] == 10.0
    assert feat_df["Total Backward Packets"].iloc[0] == 20.0

    # Row 1 was server->client: originally Fwd=50, Bwd=5 -> swapped to Fwd=5, Bwd=50!
    assert feat_df["Total Fwd Packets"].iloc[1] == 5.0
    assert feat_df["Total Backward Packets"].iloc[1] == 50.0
    assert feat_df["Total Length of Fwd Packets"].iloc[1] == 250.0
    assert feat_df["Total Length of Bwd Packets"].iloc[1] == 2500.0
    assert feat_df["Down/Up Ratio"].iloc[1] == pytest.approx(10.0)  # 1 / 0.1

