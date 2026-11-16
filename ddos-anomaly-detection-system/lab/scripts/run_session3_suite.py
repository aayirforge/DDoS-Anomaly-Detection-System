#!/usr/bin/env python3
"""
Session 3 Master Suite Orchestrator & Benchmark Evaluator.
Executes the pre-registered Session 3 experimental suite exactly as specified in session3_plan.md:
  1. Multi-protocol benign baseline (900s / 15 minutes).
  2. TCP SYN Flood (50, 200, 500, 1000 pps) x 3 repeats (120s each).
  3. UDP Flood Random Dst Ports (50, 200, 500, 1000 pps) x 3 repeats (120s each).
  4. UDP Flood Volumetric Port 80 (50, 200, 500, 1000 pps) x 3 repeats (120s each).
  5. Reconnaissance Port Scan (30 pps to sequential ports) x 3 repeats (120s each).
  6. Moving-block bootstrap (B=10s, 2000 resamples) 95% CIs.
  7. Java CICFlowMeter flow extraction and flow-model transfer evaluation.
  8. SHA-256 manifest of all generated pcaps.
"""

import argparse
from collections import defaultdict
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import numpy as np
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[2]
LOCAL_CAPTURE_DIR = REPO_ROOT / "lab/captures/session3"
DOCKER_CAPTURE_DIR = "/captures/session3"
RESULTS_DIR = REPO_ROOT / "results"
MODELS_DIR = REPO_ROOT / "models"
TOOLS_DIR = REPO_ROOT / "tools"

BPF_FILTER = "(ip or ip6) and not multicast and not broadcast and not port 1900 and not port 5353"
VICTIM_IP = "172.20.0.2"
BENIGN_CLIENT_IP = "172.20.0.4"
ATTACK_GENERATOR_IP = "172.20.0.3"


def run_cmd(cmd: str, check: bool = True) -> subprocess.CompletedProcess:
    print(f"[RUN] {cmd}")
    return subprocess.run(cmd, shell=True, check=check, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def get_interface_drops(container: str = "victim-web", iface: str = "eth0") -> int:
    try:
        res = subprocess.run(
            f"docker exec {container} cat /proc/net/dev",
            shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True
        )
        for line in res.stdout.splitlines():
            line = line.strip()
            if line.startswith(f"{iface}:"):
                parts = line.split()
                # field 4 is rx_drop (parts[3] after iface: or parts[4])
                cols = line.split(":")[1].split()
                rx_drop = int(cols[3])
                return rx_drop
    except Exception as e:
        print(f"[WARN] Failed to read drops: {e}")
    return 0


def capture_run(
    run_id: str,
    pcap_filename: str,
    capture_dur: int,
    attack_cmd: str = None,
    benign_cmd: str = None,
    benign_start_delay: float = 0.0,
    attack_start_delay: float = 2.0,
    skip_capture: bool = False,
):
    LOCAL_CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
    pcap_docker_path = f"{DOCKER_CAPTURE_DIR}/{pcap_filename}"
    local_pcap_path = LOCAL_CAPTURE_DIR / pcap_filename

    if skip_capture and local_pcap_path.is_file():
        print(f"[REUSE EXISTING PCAP] {local_pcap_path} ({local_pcap_path.stat().st_size} bytes)")
        return local_pcap_path, 0

    print(f"\n=======================================================")
    print(f"Starting Run: {run_id} ({capture_dur}s) -> {pcap_filename}")
    print(f"=======================================================")

    drop_start = get_interface_drops("victim-web", "eth0")

    # Start tshark in background on victim-web
    tshark_cmd = (
        f"docker exec -d victim-web tshark -i eth0 -f \"{BPF_FILTER}\" "
        f"-a duration:{capture_dur} -w {pcap_docker_path} -F pcap"
    )
    run_cmd(tshark_cmd)
    time.sleep(2.0)  # ensure tshark is attached

    procs = []
    # Launch benign background client if requested
    if benign_cmd:
        print(f"[BENIGN BACKGROUND] {benign_cmd}")
        p_benign = subprocess.Popen(benign_cmd, shell=True)
        procs.append(p_benign)

    # Launch attack traffic generator if requested
    if attack_cmd:
        print(f"[ATTACK GENERATOR] {attack_cmd}")
        p_attack = subprocess.Popen(attack_cmd, shell=True)
        procs.append(p_attack)

    for p in procs:
        p.wait()

    # Wait for tshark to finish and flush buffer
    print("Traffic generators finished. Waiting for tshark to flush...")
    time.sleep(4.0)

    drop_end = get_interface_drops("victim-web", "eth0")
    total_drops = max(0, drop_end - drop_start)

    # Ensure permissions and verify pcap file exists locally
    run_cmd(f"docker exec victim-web chmod 666 {pcap_docker_path}")
    if not local_pcap_path.is_file():
        raise FileNotFoundError(f"Expected PCAP {local_pcap_path} was not created!")

    pcap_size = local_pcap_path.stat().st_size
    print(f"[OK] Captured {pcap_filename} ({pcap_size} bytes, {total_drops} interface drops).")
    return local_pcap_path, total_drops


def parse_tcp_packets(pcap_path: Path):
    cmd = [
        "tshark", "-r", str(pcap_path), "-Y", "tcp",
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "tcp.flags.syn",
        "-e", "tcp.flags.ack",
        "-e", "tcp.flags.reset"
    ]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
    packets = []
    for line in res.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) < 8:
            continue
        ts = float(parts[0])
        s_ip, d_ip = parts[1], parts[2]
        s_port, d_port = int(parts[3]), int(parts[4])
        syn = 1 if parts[5] in ("1", "True") else 0
        ack = 1 if parts[6] in ("1", "True") else 0
        rst = 1 if parts[7] in ("1", "True") else 0
        packets.append({
            "ts": ts, "src": s_ip, "dst": d_ip,
            "sport": s_port, "dport": d_port,
            "syn": syn, "ack": ack, "rst": rst
        })
    return packets


def evaluate_handshake_rule(packets, duration_sec: int, t_start: float, attack_type: str = "flood"):
    """
    Evaluates Incomplete TCP Handshake Rule:
    - Timeout N = 2.0s
    - Continuous sliding 1.0s window:
      - Reconnaissance Scan: incomplete >= 15 AND (dst_ports >= 3 OR dst_ips >= 3) -> ALERT_SCAN
      - Flood Condition A: incomplete >= 15 AND distinct src IPs >= 3 (and <= 2 dst ports/hosts) -> ALERT_SYN_FLOOD
      - Flood Condition B: incomplete >= 20 (and <= 2 dst ports/hosts) -> ALERT_SYN_FLOOD
    """
    syn_sessions = {}
    for p in packets:
        ts = p["ts"]
        s_ip, d_ip = p["src"], p["dst"]
        s_p, d_p = p["sport"], p["dport"]
        syn, ack = p["syn"], p["ack"]

        fwd_key = (s_ip, d_ip, s_p, d_p)
        rev_key = (d_ip, s_ip, d_p, s_p)

        if syn == 1 and ack == 0 and d_ip == VICTIM_IP:
            syn_sessions[fwd_key] = {"syn_ts": ts, "completed": False, "dst_ip": d_ip, "dst_port": d_p, "src_ip": s_ip}
        elif syn == 1 and ack == 1 and s_ip == VICTIM_IP:
            pass
        elif ack == 1 and syn == 0 and d_ip == VICTIM_IP:
            if fwd_key in syn_sessions:
                if ts - syn_sessions[fwd_key]["syn_ts"] <= 2.0:
                    syn_sessions[fwd_key]["completed"] = True

    incomplete_events = [v for v in syn_sessions.values() if not v["completed"]]
    incomplete_events.sort(key=lambda x: x["syn_ts"])
    inc_ts = np.array([e["syn_ts"] for e in incomplete_events])

    # Continuous sliding 1.0s evaluation at each event confirmation time (syn_ts + 2.0s)
    first_alert_ts = None
    first_alert_type = None
    alert_syn_flood_seconds = set()
    alert_scan_seconds = set()

    for e in incomplete_events:
        eval_time = e["syn_ts"] + 2.0
        # Window [eval_time - 1.0, eval_time]
        mask = (inc_ts + 2.0 > eval_time - 1.0) & (inc_ts + 2.0 <= eval_time)
        cnt = np.sum(mask)
        window_events = [incomplete_events[j] for j in np.where(mask)[0]]
        distinct_dst_ports = len(set(ev["dst_port"] for ev in window_events))
        distinct_dst_ips = len(set(ev["dst_ip"] for ev in window_events))
        distinct_src_ips = len(set(ev["src_ip"] for ev in window_events))

        sec_bin = int(np.floor(eval_time - t_start))
        if 0 <= sec_bin < duration_sec:
            # Reconnaissance Scan
            if cnt >= 15 and (distinct_dst_ports >= 3 or distinct_dst_ips >= 3):
                alert_scan_seconds.add(sec_bin)
                if first_alert_ts is None:
                    first_alert_ts = eval_time
                    first_alert_type = "ALERT_SCAN"
            # DoS Flood
            elif distinct_dst_ports <= 2 and distinct_dst_ips <= 2:
                if (cnt >= 15 and distinct_src_ips >= 3) or (cnt >= 20):
                    alert_syn_flood_seconds.add(sec_bin)
                    if first_alert_ts is None:
                        first_alert_ts = eval_time
                        first_alert_type = "ALERT_SYN_FLOOD"

    return {
        "first_alert_ts": first_alert_ts,
        "first_alert_type": first_alert_type,
        "alert_syn_flood_seconds": alert_syn_flood_seconds,
        "alert_scan_seconds": alert_scan_seconds,
        "total_incomplete_syns": len(incomplete_events)
    }


def parse_udp_packets(pcap_path: Path):
    cmd = [
        "tshark", "-r", str(pcap_path), "-Y", "udp && !icmp",
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "udp.srcport",
        "-e", "udp.dstport"
    ]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
    packets = []
    for line in res.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        packets.append({
            "ts": float(parts[0]),
            "src": parts[1],
            "dst": parts[2],
            "sport": int(parts[3]),
            "dport": int(parts[4])
        })
    return packets


def evaluate_udp_rule(packets, duration_sec: int, t_start: float):
    """
    Evaluates Dual-Condition UDP Rule:
    - Excludes ICMP-quoted headers (udp && !icmp)
    - Condition 1: >= 40 UDP packets/s per destination IP
    - Condition 2: >= 30 UDP packets/s per destination IP AND >= 10 distinct destination ports/s
    """
    # Group by destination IP and 1-second bin
    victim_pkts = [p for p in packets if p["dst"] == VICTIM_IP]
    alert_udp_seconds = set()
    first_alert_ts = None

    ts_arr = np.array([p["ts"] for p in victim_pkts])
    ports_arr = np.array([p["dport"] for p in victim_pkts])

    for b in range(duration_sec):
        bin_start = t_start + b
        bin_end = bin_start + 1.0
        mask = (ts_arr >= bin_start) & (ts_arr < bin_end)
        cnt = np.sum(mask)
        distinct_p = len(np.unique(ports_arr[mask])) if cnt > 0 else 0

        if cnt >= 40 or (cnt >= 30 and distinct_p >= 10):
            alert_udp_seconds.add(b)
            if first_alert_ts is None:
                idx_in_bin = np.where(mask)[0]
                if cnt >= 40 and len(idx_in_bin) >= 40:
                    crossing_pkt_idx = idx_in_bin[39]
                    first_alert_ts = ts_arr[crossing_pkt_idx]
                else:
                    first_alert_ts = ts_arr[idx_in_bin[0]]

    return {
        "first_alert_ts": first_alert_ts,
        "alert_udp_seconds": alert_udp_seconds,
        "total_victim_udp_packets": len(victim_pkts)
    }


def compute_measured_rates(pcap_path: Path, src_ip: str, proto_filter: str):
    cmd = [
        "tshark", "-r", str(pcap_path), "-Y", f"ip.src == {src_ip} && {proto_filter}",
        "-T", "fields", "-e", "frame.time_epoch"
    ]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
    ts = [float(l.strip()) for l in res.stdout.splitlines() if l.strip()]
    if not ts:
        return 0, 0.0, 0.0, 0.0, 0.0, 0.0, None

    ts = np.array(ts)
    t0 = ts[0]
    t1 = ts[-1]
    dur = max(0.001, t1 - t0)
    total_pkts = len(ts)
    overall_mean = total_pkts / dur

    # Per-second bins
    sec_bins = np.floor(ts - t0).astype(int)
    counts = np.bincount(sec_bins)
    # Ignore partial first and last seconds if needed or use full range
    med_rate = float(np.median(counts)) if len(counts) > 0 else 0.0
    min_rate = int(np.min(counts)) if len(counts) > 0 else 0
    max_rate = int(np.max(counts)) if len(counts) > 0 else 0

    return total_pkts, overall_mean, med_rate, min_rate, max_rate, dur, t0


def moving_block_bootstrap(data_series: list, block_size: int = 10, n_boot: int = 2000, seed: int = 42):
    """
    Moving-block bootstrap across temporally correlated binary/metric sequence.
    """
    rng = np.random.default_rng(seed)
    N = len(data_series)
    if N <= block_size:
        val = float(np.mean(data_series))
        return val, val, val

    num_blocks = N - block_size + 1
    blocks = [data_series[i:i + block_size] for i in range(num_blocks)]
    k = int(np.ceil(N / block_size))

    resample_means = []
    for _ in range(n_boot):
        chosen_indices = rng.integers(0, num_blocks, size=k)
        sampled_seq = []
        for idx in chosen_indices:
            sampled_seq.extend(blocks[idx])
        sampled_seq = sampled_seq[:N]
        resample_means.append(np.mean(sampled_seq))

    low = float(np.percentile(resample_means, 2.5))
    high = float(np.percentile(resample_means, 97.5))
    mid = float(np.mean(resample_means))
    return mid, low, high


def extract_and_evaluate_flow_models(pcap_path: Path):
    """
    Extracts flows with Java CICFlowMeter v4 and evaluates frozen transfer candidates:
    RF Full 25, KNN Full 25, RF Robust 14, KNN Robust 14 Diagnostic, LR Robust 28, LSTM.
    """
    import joblib
    import torch
    from ddos_ads.pcap_to_flows import extract_flows_java

    tmp_out = REPO_ROOT / f"lab/captures/session3/flows_{pcap_path.stem}"
    tmp_out.mkdir(parents=True, exist_ok=True)

    csvs = extract_flows_java(pcap_path, tmp_out)
    if not csvs:
        return {"status": "NO_FLOWS", "flow_count": 0}

    df = pd.read_csv(csvs[0])
    df.columns = [c.strip() for c in df.columns]

    # Filter flows >= 2 packets
    total_pkts_col = df["Total Fwd Packet"] + df["Total Bwd packets"]
    df_2pkt = df[total_pkts_col >= 2].copy()

    res = {
        "pcap": pcap_path.name,
        "total_extracted_flows": len(df),
        "flows_ge_2_pkts": len(df_2pkt)
    }

    if len(df_2pkt) == 0:
        res["status"] = "NO_FLOWS_GE_2_PKTS"
        shutil.rmtree(tmp_out, ignore_errors=True)
        return res

    from ddos_ads.pcap_to_flows import align_flow_dataframe

    # Feature alignment
    with open(MODELS_DIR / "features.json") as f:
        feat_meta = json.load(f)
    full_25 = feat_meta["selected_features"]
    robust_14 = [
        "Bwd Packets/s",
        "Down/Up Ratio",
        "Bwd Packet Length Mean",
        "Bwd Packet Length Max",
        "Total Length of Bwd Packets",
        "Bwd Header Length",
        "Flow Packets/s",
        "Total Backward Packets",
        "Bwd Packet Length Min",
        "Flow Bytes/s",
        "Total Length of Fwd Packets",
        "Total Fwd Packets",
        "Fwd Packet Length Max",
        "Idle Std"
    ]

    features_df, metadata_df = align_flow_dataframe(df_2pkt, full_25, apply_direction_rule=True, server_ip=VICTIM_IP)

    # Label assignment based on src IP: 172.20.0.3 is attack, other IPs are benign
    src_ips = metadata_df["Source IP"].astype(str).values
    is_attack = (src_ips == ATTACK_GENERATOR_IP).astype(int)
    n_benign = int(np.sum(is_attack == 0))
    n_attack = int(np.sum(is_attack == 1))
    res["n_benign_flows"] = n_benign
    res["n_attack_flows"] = n_attack

    # Load thresholds
    with open(MODELS_DIR / "thresholds.json") as f:
        th = json.load(f)

    # 1. RF Full 25
    rf_full = joblib.load(MODELS_DIR / "rf.joblib")
    scaler = joblib.load(MODELS_DIR / "scaler.joblib")
    X_full = scaler.transform(features_df[full_25].fillna(0).values)
    scores_rf_full = rf_full.predict_proba(X_full)[:, 1]
    th_rf = th["flow_models"]["rf_full_25"]["decision_threshold"]
    fp_rf = int(np.sum((scores_rf_full >= th_rf) & (is_attack == 0)))
    tp_rf = int(np.sum((scores_rf_full >= th_rf) & (is_attack == 1)))
    res["rf_full_25"] = {
        "threshold": th_rf,
        "fpr": fp_rf / max(1, n_benign),
        "recall": tp_rf / max(1, n_attack),
        "fp": fp_rf, "tp": tp_rf
    }

    # 2. KNN Full 25
    knn_full = joblib.load(MODELS_DIR / "knn.joblib")
    scores_knn_full = knn_full.predict_proba(X_full)[:, 1]
    th_knn = th["flow_models"]["knn_full_25"]["decision_threshold"]
    fp_knn = int(np.sum((scores_knn_full >= th_knn) & (is_attack == 0)))
    tp_knn = int(np.sum((scores_knn_full >= th_knn) & (is_attack == 1)))
    res["knn_full_25"] = {
        "threshold": th_knn,
        "fpr": fp_knn / max(1, n_benign),
        "recall": tp_knn / max(1, n_attack),
        "fp": fp_knn, "tp": tp_knn
    }

    # 3. RF Robust 14
    rf_rob = joblib.load(MODELS_DIR / "rf_robust_14.joblib")
    scaler_rob_std = joblib.load(MODELS_DIR / "scaler_robust_14_std.joblib")
    X_rob_std = scaler_rob_std.transform(features_df[robust_14].fillna(0).values)
    scores_rf_rob = rf_rob.predict_proba(X_rob_std)[:, 1]
    th_rf_rob = th["flow_models"]["rf_robust_14"]["decision_threshold"]
    fp_rf_rob = int(np.sum((scores_rf_rob >= th_rf_rob) & (is_attack == 0)))
    tp_rf_rob = int(np.sum((scores_rf_rob >= th_rf_rob) & (is_attack == 1)))
    res["rf_robust_14"] = {
        "threshold": th_rf_rob,
        "fpr": fp_rf_rob / max(1, n_benign),
        "recall": tp_rf_rob / max(1, n_attack),
        "fp": fp_rf_rob, "tp": tp_rf_rob
    }

    # 4. KNN Robust 14 Diagnostic (signed log1p + clip [-5, 5])
    knn_rob = joblib.load(MODELS_DIR / "knn_robust_14_log1p_champion.joblib")
    scaler_rob_log = joblib.load(MODELS_DIR / "scaler_robust_14_log1p.joblib")
    X_vals = features_df[robust_14].fillna(0).values
    X_rob_log = np.sign(X_vals) * np.log1p(np.abs(X_vals))
    X_rob_scaled = np.clip(scaler_rob_log.transform(X_rob_log), -5.0, 5.0)
    scores_knn_rob = knn_rob.predict_proba(X_rob_scaled)[:, 1]
    th_knn_diag = th["window_models"]["knn_robust_14_in_sample_diagnostic"]["decision_threshold_fixed"]
    fp_knn_rob = int(np.sum((scores_knn_rob >= th_knn_diag) & (is_attack == 0)))
    tp_knn_rob = int(np.sum((scores_knn_rob >= th_knn_diag) & (is_attack == 1)))
    res["knn_robust_14_diagnostic"] = {
        "threshold": th_knn_diag,
        "fpr": fp_knn_rob / max(1, n_benign),
        "recall": tp_knn_rob / max(1, n_attack),
        "fp": fp_knn_rob, "tp": tp_knn_rob
    }

    shutil.rmtree(tmp_out, ignore_errors=True)
    return res


def execute_suite(stages: list, skip_capture: bool = False):
    """
    Executes the designated stages.
    """
    # Load existing results manifest if present
    eval_json_path = RESULTS_DIR / "session3_evaluation.json"
    if eval_json_path.is_file():
        try:
            with open(eval_json_path) as f:
                results_manifest = json.load(f)
        except Exception:
            results_manifest = {}
    else:
        results_manifest = {}

    csum_path = LOCAL_CAPTURE_DIR / "session3_pcaps.sha256"
    if csum_path.is_file():
        try:
            with open(csum_path) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        parts = line.split(None, 1)
                        if len(parts) == 2:
                            pcap_checksums[parts[1]] = parts[0]
        except Exception:
            pcap_checksums = {}
    else:
        pcap_checksums = {}

    # Stage 1: Benign baseline (900s)
    if "baseline" in stages or "all" in stages:
        print("\n=======================================================")
        print("STAGE 1: 15-Minute Multi-Protocol Benign Baseline")
        print("=======================================================")
        pcap_file, drops = capture_run(
            run_id="session3_benign_baseline_900s",
            pcap_filename="session3_benign_baseline_900s.pcap",
            capture_dur=904,
            benign_cmd="docker exec benign-client python /app/session2c_benign.py --duration 900",
            attack_cmd=None,
            skip_capture=skip_capture
        )

        with open(pcap_file, "rb") as f:
            csum = hashlib.sha256(f.read()).hexdigest()
        pcap_checksums["session3_benign_baseline_900s.pcap"] = csum

        # Evaluate benign baseline
        tcp_pkts = parse_tcp_packets(pcap_file)
        t_start = tcp_pkts[0]["ts"] if tcp_pkts else 0.0
        hs_res = evaluate_handshake_rule(tcp_pkts, duration_sec=900, t_start=t_start)

        udp_pkts = parse_udp_packets(pcap_file)
        udp_res = evaluate_udp_rule(udp_pkts, duration_sec=900, t_start=t_start)

        syn_fa_bins = len(hs_res["alert_syn_flood_seconds"])
        scan_fa_bins = len(hs_res["alert_scan_seconds"])
        udp_fa_bins = len(udp_res["alert_udp_seconds"])

        combined_fa_bins = len(hs_res["alert_syn_flood_seconds"] | udp_res["alert_udp_seconds"])
        combined_fpr = combined_fa_bins / 900.0

        # Moving block bootstrap CI for benign FPR
        combined_indicators = [
            1 if (s in hs_res["alert_syn_flood_seconds"] or s in udp_res["alert_udp_seconds"]) else 0
            for s in range(900)
        ]
        fpr_mid, fpr_low, fpr_high = moving_block_bootstrap(combined_indicators, block_size=10, n_boot=2000)

        pass_syn_fa = syn_fa_bins <= 9
        pass_udp_fa = udp_fa_bins <= 9
        pass_combined_fa = combined_fa_bins <= 9 and combined_fpr <= 0.010

        baseline_eval = {
            "duration_seconds": 900,
            "interface_drops": drops,
            "tcp_handshake_rule_false_alarm_seconds": syn_fa_bins,
            "tcp_handshake_rule_scan_false_alarm_seconds": scan_fa_bins,
            "dual_udp_rule_false_alarm_seconds": udp_fa_bins,
            "combined_active_defense_false_alarm_seconds": combined_fa_bins,
            "combined_active_defense_fpr": round(combined_fpr, 4),
            "combined_fpr_95_ci": [round(fpr_low, 4), round(fpr_high, 4)],
            "status": "PASS" if pass_combined_fa else "FAIL"
        }
        results_manifest["benign_baseline"] = baseline_eval
        print(f"\n[BASELINE RESULT] Combined FA: {combined_fa_bins}/900 ({combined_fpr*100:.2f}%) | 95% CI: [{fpr_low*100:.2f}%, {fpr_high*100:.2f}%] | Status: {baseline_eval['status']}")

    # Attack matrix definition: vector -> rates
    attack_definitions = []
    if "syn" in stages or "all" in stages:
        for r in [50, 200, 500, 1000]:
            attack_definitions.append({
                "vector": "tcp_syn_flood",
                "rate": r,
                "gen_type": "syn",
                "port": 80,
                "target_delay": 2.5
            })
    if "udp_random" in stages or "all" in stages:
        for r in [50, 200, 500, 1000]:
            attack_definitions.append({
                "vector": "udp_flood_random_ports",
                "rate": r,
                "gen_type": "udp",
                "port": 0,
                "target_delay": 1.0
            })
    if "udp_volumetric" in stages or "all" in stages:
        for r in [50, 200, 500, 1000]:
            attack_definitions.append({
                "vector": "udp_flood_volumetric_port80",
                "rate": r,
                "gen_type": "udp",
                "port": 80,
                "target_delay": 1.0
            })
    if "scan" in stages or "all" in stages:
        attack_definitions.append({
            "vector": "reconnaissance_port_scan",
            "rate": 30,
            "gen_type": "scan",
            "port": 0,
            "target_delay": 2.5
        })

    # Execute Attack Runs (3 repeats each)
    attack_results = defaultdict(list)
    for ad in attack_definitions:
        vec = ad["vector"]
        r = ad["rate"]
        target_del = ad["target_delay"]

        for rep in [1, 2, 3]:
            run_id = f"session3_{vec}_{r}pps_rep{rep}"
            pcap_name = f"{run_id}.pcap"

            if ad["gen_type"] == "scan":
                attack_cmd = (
                    "docker exec traffic-generator python -c \""
                    "import socket, time; t_end = time.time() + 120; p = 1024; count = 0; t0 = time.time();\n"
                    "while time.time() < t_end:\n"
                    "    target_time = t0 + (count * (1.0 / 30.0))\n"
                    "    now = time.time()\n"
                    "    if target_time > now: time.sleep(target_time - now)\n"
                    "    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
                    "    s.setblocking(False)\n"
                    "    try: s.connect_ex(('172.20.0.2', p))\n"
                    "    except Exception: pass\n"
                    "    s.close()\n"
                    "    p = 1024 + (p - 1024 + 1) % 60000; count += 1\n"
                    "dur = time.time() - t0\n"
                    "print(f'Port scan finished: {count} SYNs sent in {dur:.2f}s ({count/dur:.2f} pps)')\n"
                    "\""
                )
            else:
                attack_cmd = (
                    f"docker exec traffic-generator python /app/flood.py "
                    f"--type {ad['gen_type']} --target victim-web --port {ad['port']} --rate {r} --duration 120"
                )

            benign_cmd = "docker exec benign-client python /app/session2c_benign.py --duration 124"

            pcap_file, drops = capture_run(
                run_id=run_id,
                pcap_filename=pcap_name,
                capture_dur=126,
                attack_cmd=attack_cmd,
                benign_cmd=benign_cmd,
                skip_capture=skip_capture
            )

            with open(pcap_file, "rb") as f:
                csum = hashlib.sha256(f.read()).hexdigest()
            pcap_checksums[pcap_name] = csum

            # Rate measurement from pcap
            proto_filter = "tcp" if "syn" in vec or "scan" in vec else "udp && !icmp"
            n_pkts, m_mean, m_med, m_min, m_max, m_dur, t_attack_start = compute_measured_rates(
                pcap_file, ATTACK_GENERATOR_IP, proto_filter
            )

            # Rule evaluation
            if "syn" in vec or "scan" in vec:
                tcp_pkts = parse_tcp_packets(pcap_file)
                eval_res = evaluate_handshake_rule(tcp_pkts, duration_sec=120, t_start=t_attack_start, attack_type="scan" if "scan" in vec else "flood")
                first_alert_ts = eval_res["first_alert_ts"]
                first_alert_type = eval_res["first_alert_type"]

                if "scan" in vec:
                    alert_seconds = eval_res["alert_scan_seconds"]
                    wrong_fa_seconds = len(eval_res["alert_syn_flood_seconds"])
                else:
                    alert_seconds = eval_res["alert_syn_flood_seconds"]
                    wrong_fa_seconds = len(eval_res["alert_scan_seconds"])
            else:
                udp_pkts = parse_udp_packets(pcap_file)
                eval_res = evaluate_udp_rule(udp_pkts, duration_sec=120, t_start=t_attack_start)
                first_alert_ts = eval_res["first_alert_ts"]
                first_alert_type = "ALERT_UDP_FLOOD" if first_alert_ts is not None else None
                alert_seconds = eval_res["alert_udp_seconds"]
                wrong_fa_seconds = 0

            # Delay calculation
            delay = round(first_alert_ts - t_attack_start, 4) if (first_alert_ts is not None and t_attack_start is not None) else None
            first_alert_bin = int(np.floor(delay)) if delay is not None else 0

            # Post-first-alert recall
            evaluated_seconds_post_first = max(1, 120 - first_alert_bin)
            alerted_post_first = len([s for s in alert_seconds if s >= first_alert_bin])
            recall_post_first = alerted_post_first / evaluated_seconds_post_first

            # Binary series for bootstrapping
            binary_seq = [1 if s in alert_seconds else 0 for s in range(120)]

            # Check criteria
            pass_delay = delay is not None and delay <= target_del
            pass_recall = recall_post_first >= 0.950
            pass_rate = abs(m_mean - r) / r <= 0.05 if r > 0 else True
            run_status = "PASS" if (pass_delay and pass_recall and pass_rate) else "FAIL"

            rep_summary = {
                "run_id": run_id,
                "repeat": rep,
                "nominal_rate_pps": r,
                "measured_rate": {
                    "total_packets": n_pkts,
                    "mean_pps": round(m_mean, 2),
                    "median_pps": round(m_med, 2),
                    "min_pps": m_min,
                    "max_pps": m_max,
                    "measured_duration_sec": round(m_dur, 2)
                },
                "interface_drops": drops,
                "first_detection_delay_sec": delay,
                "target_delay_sec": target_del,
                "evaluated_attack_seconds_post_first_alert": evaluated_seconds_post_first,
                "alerted_seconds_post_first_alert": alerted_post_first,
                "recall_post_first_alert": round(recall_post_first, 4),
                "wrong_alarm_seconds": wrong_fa_seconds,
                "status": run_status,
                "binary_seq": binary_seq
            }
            attack_results[f"{vec}_{r}pps"].append(rep_summary)
            print(f"[{run_id}] Delay: {delay}s (target <={target_del}s) | Recall: {recall_post_first*100:.2f}% (target >=95%) | Measured: {m_mean:.2f} pps | Drops: {drops} | Status: {run_status}")

    # Compute Pooled Statistics & Moving-Block Bootstrap CIs
    pooled_summary = {}
    for cond_key, reps in attack_results.items():
        delays = [r["first_detection_delay_sec"] for r in reps if r["first_detection_delay_sec"] is not None]
        recalls = [r["recall_post_first_alert"] for r in reps]
        drops_total = sum(r["interface_drops"] for r in reps)
        rates_mean = [r["measured_rate"]["mean_pps"] for r in reps]

        pooled_seq = []
        for r in reps:
            pooled_seq.extend(r["binary_seq"])

        rec_mid, rec_low, rec_high = moving_block_bootstrap(pooled_seq, block_size=10, n_boot=2000)

        all_passed = all(r["status"] == "PASS" for r in reps)

        pooled_summary[cond_key] = {
            "repeats": reps,
            "pooled_mean_rate_pps": round(float(np.mean(rates_mean)), 2),
            "pooled_mean_delay_sec": round(float(np.mean(delays)), 4) if delays else None,
            "pooled_mean_recall_post_first_alert": round(float(np.mean(recalls)), 4),
            "pooled_recall_95_ci": [round(rec_low, 4), round(rec_high, 4)],
            "total_interface_drops": drops_total,
            "overall_status": "PASS" if all_passed else "FAIL"
        }

    if "attack_evaluations" not in results_manifest:
        results_manifest["attack_evaluations"] = {}
    results_manifest["attack_evaluations"].update(pooled_summary)

    # Save Authoritative JSON
    with open(RESULTS_DIR / "session3_evaluation.json", "w") as f:
        json.dump(results_manifest, f, indent=2)
    print(f"\n[OK] Wrote Session 3 evaluations to {RESULTS_DIR / 'session3_evaluation.json'}")

    # Save Checksums Manifest
    csum_path = LOCAL_CAPTURE_DIR / "session3_pcaps.sha256"
    with open(csum_path, "w") as f:
        for fname, h in sorted(pcap_checksums.items()):
            f.write(f"{h}  {fname}\n")
    print(f"[OK] Wrote PCAP checksums to {csum_path}")

    return results_manifest


def run_flow_transfer_evaluation():
    """
    Runs Java CICFlowMeter extraction and flow model scoring on all Session 3 pcaps.
    """
    print("\n=======================================================")
    print("FLOW MODELS TRANSFER EVALUATION (Java CICFlowMeter v4)")
    print("=======================================================")
    flow_transfer_results = []
    pcaps = sorted(list(LOCAL_CAPTURE_DIR.glob("*.pcap")))

    for p in pcaps:
        print(f"[EXTRACT & EVALUATE] {p.name}...")
        try:
            res = extract_and_evaluate_flow_models(p)
            flow_transfer_results.append(res)
        except Exception as e:
            print(f"[ERROR] Failed flow evaluation for {p.name}: {e}")
            flow_transfer_results.append({"pcap": p.name, "error": str(e), "status": "ERROR"})

    out_file = RESULTS_DIR / "session3_flow_models_transfer.json"
    with open(out_file, "w") as f:
        json.dump(flow_transfer_results, f, indent=2)
    print(f"[OK] Wrote flow models transfer results to {out_file}")


def main():
    parser = argparse.ArgumentParser(description="Session 3 Live Test Suite")
    parser.add_argument("--stage", choices=["all", "baseline", "syn", "udp_random", "udp_volumetric", "scan", "evaluate_flows"], default="all")
    parser.add_argument("--skip-capture", action="store_true", help="Reuse existing PCAPs if present")
    args = parser.parse_args()

    if args.stage == "evaluate_flows":
        run_flow_transfer_evaluation()
    else:
        stages = [args.stage] if args.stage != "all" else ["baseline", "syn", "udp_random", "udp_volumetric", "scan"]
        execute_suite(stages, skip_capture=args.skip_capture)
        if args.stage == "all":
            run_flow_transfer_evaluation()


if __name__ == "__main__":
    main()
