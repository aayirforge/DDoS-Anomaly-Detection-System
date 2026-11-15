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
