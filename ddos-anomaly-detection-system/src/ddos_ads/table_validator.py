"""Cell-by-cell validator mapping markdown table cells to exact named JSON keys."""

import json
from pathlib import Path
import re
from typing import Dict, Any, List

def parse_markdown_table_rows(table_path: Path) -> List[List[str]]:
    """Parse markdown table into list of row cells."""
    rows = []
    for line in table_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.split("|")[1:-1]]
        if not cells or all(c.startswith(":") or c.startswith("-") for c in cells if c):
            continue
        rows.append(cells)
    return rows

def validate_table_a_baseline(table_path: Path, eval_data: Dict[str, Any]) -> None:
    b = eval_data["benign_baseline"]
    rows = parse_markdown_table_rows(table_path)
    assert len(rows) >= 2, "Table S3-A must have a header and at least 1 data row"
    data_row = rows[1]
    
    # Columns:
    # 0: Traffic Scenario
    # 1: Capture File
    # 2: Evaluated Duration
    # 3: Interface Drops
    # 4: SYN Flood False Alarms
    # 5: Port Scan False Alarms
    # 6: Dual-UDP False Alarms
    # 7: Combined Active Defense Alarms
    # 8: FPR
    # 9: Upper Bound
    # 10: Target Max FPR
    # 11: Final Status
    
    expected_cells = {
        "Evaluated Duration": f"{b['duration_seconds']} s (15 min)",
        "Interface Drops": f"{b['interface_drops']}",
        "SYN Flood False Alarms": f"{b['tcp_handshake_rule_false_alarm_seconds']} s",
        "Port Scan False Alarms": f"{b['tcp_handshake_rule_scan_false_alarm_seconds']} s (0 in 900 s; PASS)",
        "Dual-UDP False Alarms": f"{b['dual_udp_rule_false_alarm_seconds']} s",
        "Combined Active Defense Alarms": f"{b['combined_active_defense_false_alarm_seconds']} s",
        "False Positive Rate (FPR)": f"**{b['combined_active_defense_fpr']*100:.2f}%**",
        "Final Status": f"**{b['status']}**"
    }
    
    cell_indices = {
        "Evaluated Duration": 2,
        "Interface Drops": 3,
        "SYN Flood False Alarms": 4,
        "Port Scan False Alarms": 5,
        "Dual-UDP False Alarms": 6,
        "Combined Active Defense Alarms": 7,
        "False Positive Rate (FPR)": 8,
        "Final Status": 11
    }
    
    for key, idx in cell_indices.items():
        exp = expected_cells[key]
        act = data_row[idx]
        if act != exp:
            raise AssertionError(f"Table S3-A cell mismatch for key '{key}': expected '{exp}', got '{act}'")

def validate_table_b_per_repeat(table_path: Path, eval_data: Dict[str, Any]) -> None:
    rows = parse_markdown_table_rows(table_path)
    header = rows[0]
    data_rows = rows[1:]
    
    # Map by run_id (column index 1: `run_id`)
    row_by_run_id = {}
    for r in data_rows:
        rid = r[1].replace("`", "")
        row_by_run_id[rid] = r

    for scen_name, scen_data in eval_data["attack_evaluations"].items():
        for rep in scen_data["repeats"]:
            rid = rep["run_id"]
            if rid not in row_by_run_id:
                raise AssertionError(f"Run ID '{rid}' from JSON not found in Table S3-B")
            r = row_by_run_id[rid]
            
            # Key checks:
            # col 2: Nominal Rate
            # col 3: Measured Rate
            # col 4: Total Packets
            # col 5: Duration
            # col 6: Drops
            # col 7: Real Delay
            # col 10: Post-Alert Recall
            # col 11: Alerted / Evaluated Sec
            # col 12: Wrong Alarms
            # col 13: Overall Run Status
            
            checks = {
                "nominal_rate_pps": (r[2], f"{rep['nominal_rate_pps']} pps"),
                "measured_rate.mean_pps": (r[3], f"{rep['measured_rate']['mean_pps']:.2f} pps"),
                "measured_rate.total_packets": (r[4], f"{rep['measured_rate']['total_packets']:,}"),
                "measured_rate.measured_duration_sec": (r[5], f"{rep['measured_rate']['measured_duration_sec']:.2f} s"),
                "interface_drops": (r[6], f"{rep['interface_drops']}"),
                "first_detection_delay_sec": (r[7], f"{rep['first_detection_delay_sec']:.3f} s"),
                "recall_post_first_alert": (r[10], f"{rep['recall_post_first_alert']*100:.2f}%"),
                "seconds_ratio": (r[11], f"{rep['alerted_seconds_post_first_alert']}/{rep['evaluated_attack_seconds_post_first_alert']} s"),
                "wrong_alarm_seconds": (r[12], f"{rep['wrong_alarm_seconds']} s"),
                "status": (r[13], f"**{rep['status']}**")
            }
            
            for key_name, (act, exp) in checks.items():
                if act != exp:
                    raise AssertionError(
                        f"Table S3-B cell mismatch for run '{rid}' on JSON key '{key_name}': "
                        f"expected '{exp}', got '{act}'"
                    )

def validate_table_c_pooled_summary(table_path: Path, eval_data: Dict[str, Any]) -> None:
    rows = parse_markdown_table_rows(table_path)
    data_rows = rows[1:]
    
    # Map by scenario pretty name (col 0)
    row_by_scen = {}
    for r in data_rows:
        sc_name = r[0].replace("**", "").replace(" ", "_").lower()
        row_by_scen[sc_name] = r
        
    for scen_name, sc in eval_data["attack_evaluations"].items():
        if scen_name not in row_by_scen:
            raise AssertionError(f"Scenario '{scen_name}' from JSON not found in Table S3-C")
        r = row_by_scen[scen_name]
        
        checks = {
            "pooled_mean_rate_pps": (r[3], f"**{sc['pooled_mean_rate_pps']:.2f} pps**"),
            "pooled_mean_delay_sec": (r[4], f"**{sc['pooled_mean_delay_sec']:.3f} s**"),
            "pooled_mean_recall_post_first_alert": (r[7], f"**{sc['pooled_mean_recall_post_first_alert']*100:.2f}%**"),
            "total_interface_drops": (r[9], f"{sc['total_interface_drops']}"),
            "overall_status": (r[10], f"**{sc['overall_status']}**")
        }
        for key_name, (act, exp) in checks.items():
            if act != exp:
                raise AssertionError(
                    f"Table S3-C cell mismatch for scenario '{scen_name}' on JSON key '{key_name}': "
                    f"expected '{exp}', got '{act}'"
                )

def validate_table_d_flow_transfer(table_path: Path, flow_data: List[Dict[str, Any]]) -> None:
    rows = parse_markdown_table_rows(table_path)
    data_rows = rows[1:]
    
    # Check baseline row (row index 0 in data_rows)
    baseline_entry = next((e for e in flow_data if "baseline" in e["pcap"]), None)
    if baseline_entry:
        b_row = data_rows[0]
        rf = baseline_entry["rf_full_25"]
        knn = baseline_entry["knn_full_25"]
        rf_rob = baseline_entry["rf_robust_14"]
        knn_rob = baseline_entry["knn_robust_14_diagnostic"]
        
        checks = {
            "flows_ge_2_pkts": (b_row[1], f"{baseline_entry['flows_ge_2_pkts']:,}"),
            "n_benign_flows": (b_row[2], f"{baseline_entry['n_benign_flows']:,}"),
            "n_attack_flows": (b_row[3], f"{baseline_entry['n_attack_flows']:,}"),
            "rf_full_25.fpr": (b_row[5], f"FPR: **{rf['fpr']*100:.2f}%** ({rf['fp']}/{baseline_entry['flows_ge_2_pkts']})"),
            "knn_full_25.fpr": (b_row[6], f"FPR: **{knn['fpr']*100:.2f}%** ({knn['fp']}/{baseline_entry['flows_ge_2_pkts']})"),
            "rf_robust_14.fpr": (b_row[7], f"FPR: **{rf_rob['fpr']*100:.2f}%** ({rf_rob['fp']}/{baseline_entry['flows_ge_2_pkts']})"),
            "knn_robust_14_diagnostic.fpr": (b_row[8], f"FPR: **{knn_rob['fpr']*100:.2f}%** ({knn_rob['fp']}/{baseline_entry['flows_ge_2_pkts']})"),
        }
        for key_name, (act, exp) in checks.items():
            if act != exp:
                raise AssertionError(
                    f"Table S3-D cell mismatch for Benign Baseline on JSON key '{key_name}': "
                    f"expected '{exp}', got '{act}'"
                )

def validate_all_tables_against_json(results_dir: Path) -> None:
    eval_json = results_dir / "session3_evaluation.json"
    if not eval_json.exists():
        raise FileNotFoundError(f"{eval_json} not found")
    eval_data = json.loads(eval_json.read_text(encoding="utf-8"))
    
    tables_dir = results_dir / "tables"
    t_a = tables_dir / "table_s3_a_baseline.md"
    t_b = tables_dir / "table_s3_b_per_repeat.md"
    t_c = tables_dir / "table_s3_c_pooled_summary.md"
    t_d = tables_dir / "table_s3_d_flow_transfer.md"
    
    if t_a.exists():
        validate_table_a_baseline(t_a, eval_data)
    if t_b.exists():
        validate_table_b_per_repeat(t_b, eval_data)
    if t_c.exists():
        validate_table_c_pooled_summary(t_c, eval_data)

    flow_json = results_dir / "session3_flow_models_transfer.json"
    if flow_json.exists() and t_d.exists():
        flow_data = json.loads(flow_json.read_text(encoding="utf-8"))
        validate_table_d_flow_transfer(t_d, flow_data)
