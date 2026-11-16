#!/usr/bin/env python3
"""Item 1: Flood-flow verification against tshark and reconciliation of packet/flow counts."""

import json
import subprocess
from pathlib import Path
import pandas as pd


def get_tshark_flow_fields(pcap_path: Path, src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> dict:
    # Forward packets
    cmd_fwd = [
        "tshark", "-r", str(pcap_path),
        "-Y", f"ip.src == {src_ip} && ip.dst == {dst_ip} && tcp.srcport == {src_port} && tcp.dstport == {dst_port}",
        "-T", "fields",
        "-e", "tcp.len",
        "-e", "tcp.flags.syn",
        "-e", "tcp.flags.ack",
        "-e", "tcp.window_size_value"
    ]
    out_fwd = subprocess.check_output(cmd_fwd).decode().strip().split("\n")
    out_fwd = [line.split("\t") for line in out_fwd if line.strip()]

    # Backward packets
    cmd_bwd = [
        "tshark", "-r", str(pcap_path),
        "-Y", f"ip.src == {dst_ip} && ip.dst == {src_ip} && tcp.srcport == {dst_port} && tcp.dstport == {src_port}",
        "-T", "fields",
        "-e", "tcp.len",
        "-e", "tcp.flags.syn",
        "-e", "tcp.flags.ack",
        "-e", "tcp.window_size_value"
    ]
    out_bwd = subprocess.check_output(cmd_bwd).decode().strip().split("\n")
    out_bwd = [line.split("\t") for line in out_bwd if line.strip()]

    fwd_pkts = len(out_fwd)
    bwd_pkts = len(out_bwd)
    sum_tcp_len_fwd = sum(int(p[0]) for p in out_fwd) if out_fwd else 0
    syn_fwd = sum(1 for p in out_fwd if p[1] in ("1", "True"))
    ack_fwd = sum(1 for p in out_fwd if p[2] in ("1", "True"))
    syn_bwd = sum(1 for p in out_bwd if p[1] in ("1", "True"))
    ack_bwd = sum(1 for p in out_bwd if p[2] in ("1", "True"))

    init_win_fwd = int(out_fwd[0][3]) if out_fwd else 0
    init_win_bwd = int(out_bwd[0][3]) if out_bwd else 0

    return {
        "fwd_pkts": fwd_pkts,
        "bwd_pkts": bwd_pkts,
        "sum_tcp_len_fwd": sum_tcp_len_fwd,
        "syn_count_fwd": syn_fwd,
        "ack_count_fwd": ack_fwd,
        "syn_count_bwd": syn_bwd,
        "ack_count_bwd": ack_bwd,
        "init_win_bytes_fwd": init_win_fwd,
        "init_win_bytes_bwd": init_win_bwd,
    }


def main():
    root = Path(__file__).resolve().parent.parent
    pcap_path = root / "lab/captures/session2/lab_syn_flood.pcap"
    java_csv_path = root / "lab/captures/session2_java/syn_classic.pcap_Flow.csv"
    py_csv_path = root / "lab/captures/session2/lab_syn_flood_flows.csv"

    java_df = pd.read_csv(java_csv_path)
    java_df.columns = [c.strip() for c in java_df.columns]
    java_flood = java_df[java_df["Src IP"] == "172.20.0.3"].copy()

    # Select 5 flows with backward response and 5 without backward response
    flows_with_bwd = java_flood[java_flood["Bwd Init Win Bytes"] > 0].head(5)
    flows_without_bwd = java_flood[java_flood["Bwd Init Win Bytes"] == 0].head(5)
    sample_df = pd.concat([flows_with_bwd, flows_without_bwd], ignore_index=True)

    py_df = pd.read_csv(py_csv_path)
    py_flood = py_df[py_df["src_ip"] == "172.20.0.3"].copy()

    flow_verifications = []
    for _, j_row in sample_df.iterrows():
        src_port = int(j_row["Src Port"])
        dst_port = int(j_row["Dst Port"])
        src_ip = "172.20.0.3"
        dst_ip = "172.20.0.2"

        tshark_res = get_tshark_flow_fields(pcap_path, src_ip, dst_ip, src_port, dst_port)

        # Match Python row
        p_row_match = py_flood[py_flood["src_port"] == src_port]
        if not p_row_match.empty:
            p_row = p_row_match.iloc[0]
            py_res = {
                "fwd_pkts": int(p_row["tot_fwd_pkts"]),
                "bwd_pkts": int(p_row["tot_bwd_pkts"]),
                "totlen_fwd_pkts": float(p_row["totlen_fwd_pkts"]),
                "fwd_pkt_len_max": float(p_row["fwd_pkt_len_max"]),
                "syn_flag_cnt": int(p_row.get("syn_flag_cnt", 0)),
                "ack_flag_cnt": int(p_row.get("ack_flag_cnt", 0)),
                "init_fwd_win_byts": int(p_row["init_fwd_win_byts"]),
                "init_bwd_win_byts": int(p_row["init_bwd_win_byts"]),
            }
        else:
            py_res = None

        java_res = {
            "fwd_pkts": int(j_row["Total Fwd Packet"]),
            "bwd_pkts": int(j_row["Total Bwd packets"]),
            "totlen_fwd_pkts": float(j_row["Total Length of Fwd Packet"]),
            "fwd_pkt_len_max": float(j_row["Fwd Packet Length Max"]),
            "syn_flag_cnt": int(j_row.get("SYN Flag Count", 0)),
            "ack_flag_cnt": int(j_row.get("ACK Flag Count", 0)),
            "init_fwd_win_byts": int(j_row["FWD Init Win Bytes"]),
            "init_bwd_win_byts": int(j_row["Bwd Init Win Bytes"]),
        }

        flow_verifications.append({
            "flow_5tuple": f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} (TCP)",
            "src_port": src_port,
            "has_server_response": bool(tshark_res["bwd_pkts"] > 0),
            "tshark_ground_truth": tshark_res,
            "java_cicflowmeter": java_res,
            "python_cicflowmeter": py_res,
        })

    reconciliation = {
        "pcap_total_frames": 6554,
        "pcap_ip_conversations": {
            "172.20.0.3 <-> 172.20.0.2 (SYN flood attack)": {
                "fwd_frames_from_attacker": 5913,
                "bwd_frames_from_server": 28,
                "total_frames": 5941,
                "unique_src_ports": 5622,
                "packet_count_distribution_per_src_port": {
                    "1_packet": 5346,
                    "2_packets": 262,
                    "3_packets": 13,
                    "4_packets": 1
                },
                "total_packets_sum_check": "5346*1 + 262*2 + 13*3 + 1*4 = 5913 packets"
            },
            "172.20.0.4 <-> 172.20.0.2 (Benign background client)": {
                "fwd_frames": 311,
                "bwd_frames": 289,
                "total_frames": 600
            },
            "172.20.0.1 <-> 239.255.255.250 (Docker host SSDP)": {
                "frames": 4
            },
            "other_broadcast_or_arp": {
                "frames": 9
            }
        },
        "reconciliation_findings": {
            "mathematical_impossibility_explained": (
                "5,622 flows each having >= 2 physical packets would require at least 11,244 packets, "
                "which is impossible in a 6,554-packet pcap. In reality, 5,346 of the 5,622 attack flows "
                "contain exactly 1 physical packet in the pcap (single SYN without retransmission)."
            ),
            "python_port_bug": (
                "In cicflowmeter/flow_session.py, a new flow is instantiated via Flow(pkt), which adds pkt "
                "to self.packets in Flow.__init__. Immediately following this block, execution falls through to "
                "flow.add_packet(pkt), appending the very same packet a second time. Consequently, every single-packet "
                "flow is assigned tot_fwd_pkts = 2, and every 2-packet retransmission is assigned tot_fwd_pkts = 3. "
                "Furthermore, the Python port extracts packet length as wire/IP packet length (54 bytes) rather than "
                "TCP payload length, giving 54 * 2 = 108 bytes."
            ),
            "java_cicflowmeter_behavior": (
                "Java CICFlowMeter requires bidirectional activity or >= 2 packets to output a flow, completely "
                "discarding all 5,346 single-packet flows. It outputs exactly 277 flows (276 flows with >= 2 physical "
                "SYN packets due to retransmissions, plus 1 single-packet flow that received a SYN-ACK reply). "
                "Java measures Total Length of Fwd Packets strictly as TCP payload length, which is 0 for pure SYNs."
            )
        }
    }

    out_data = {
        "verified_flows_count": len(flow_verifications),
        "flows": flow_verifications,
        "reconciliation": reconciliation
    }

    out_file = root / "results/flood_flows_tshark_verification.json"
    with open(out_file, "w") as f:
        json.dump(out_data, f, indent=2)
    print(f"Wrote verification and reconciliation to {out_file}")


if __name__ == "__main__":
    main()
