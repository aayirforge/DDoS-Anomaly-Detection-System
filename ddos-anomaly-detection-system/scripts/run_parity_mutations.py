"""
Phase 7 Parity Mutation Testing Suite.
======================================
Executes mutation tests in an isolated scratch directory to prove that the parity
acceptance harness detects and fails on rule/threshold perturbations:
1. Mutation (i): Handshake completion timeout 2.0s -> 3.0s.
2. Mutation (ii): Condition B incomplete threshold 20 -> 25.
3. Mutation (iii): UDP volumetric threshold 40 -> 60 pkts/s.

Strict requirement:
Parity must FAIL on the affected runs for each mutation.
Results are saved to results/phase7_parity_mutations.json and rendered into
results/tables/table_s7_d_parity_mutations.md.
Scratch directory is deleted upon completion.
"""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = REPO_ROOT / "results"
TABLES_DIR = RESULTS_DIR / "tables"


def run_mutation_test() -> Dict[str, Any]:
    scratch_dir = Path("/tmp/scratch_repo_parity")
    if scratch_dir.exists():
        shutil.rmtree(scratch_dir)
    scratch_dir.mkdir(parents=True, exist_ok=True)

    mutation_results: List[Dict[str, Any]] = []

    try:
        # Copy source and scripts to scratch
        shutil.copytree(REPO_ROOT / "src", scratch_dir / "src")
        shutil.copytree(REPO_ROOT / "scripts", scratch_dir / "scripts")
        # Symlink results and lab to avoid duplicating large pcaps
        (scratch_dir / "results").symlink_to(REPO_ROOT / "results")
        (scratch_dir / "lab").symlink_to(REPO_ROOT / "lab")

        rule_engine_file = scratch_dir / "src/ddos_ads/rule_engine.py"
        original_code = rule_engine_file.read_text(encoding="utf-8")

        mutations = [
            {
                "id": "mut_1_handshake_timeout_3s",
                "name": "Mutation (i): Handshake Timeout 2.0s -> 3.0s",
                "description": "Increases incomplete handshake timeout from 2.0s to 3.0s",
                "find": "handshake_timeout: float = 2.0,",
                "replace": "handshake_timeout: float = 3.0,",
                "expected_affected": "TCP SYN Floods and Scans (first-alert delay increases by ~1.0s)",
            },
            {
                "id": "mut_2_cond_b_threshold_25",
                "name": "Mutation (ii): Condition B Threshold 20 -> 25",
                "description": "Increases concentrated incomplete SYN threshold from 20 to 25",
                "find": "syn_flood_thresh_cond_b: int = 20,",
                "replace": "syn_flood_thresh_cond_b: int = 25,",
                "expected_affected": "TCP SYN Floods operating near or at Condition B threshold",
            },
            {
                "id": "mut_3_udp_volumetric_threshold_60",
                "name": "Mutation (iii): UDP Volumetric Threshold 40 -> 60 pkts/s",
                "description": "Increases UDP volumetric threshold from 40 to 60 pkts/s",
                "find": "udp_volumetric_thresh: int = 40,",
                "replace": "udp_volumetric_thresh: int = 60,",
                "expected_affected": "UDP Volumetric Floods at 50 pps (fail to cross 60 pps threshold)",
            },
        ]

        for mut in mutations:
            print(f"\n[MUTATION TEST] Running {mut['name']}...")
            # Mutate rule_engine.py
            code_mut = original_code.replace(mut["find"], mut["replace"])
            if code_mut == original_code:
                raise RuntimeError(f"Failed to apply mutation {mut['id']}: target string not found")
            rule_engine_file.write_text(code_mut, encoding="utf-8")

            # Run parity script in scratch with strict sensitivity tolerance (0.05s)
            out_json = scratch_dir / f"{mut['id']}.json"
            cmd = [
                sys.executable,
                str(scratch_dir / "scripts/evaluate_phase7_parity.py"),
                "--out", str(out_json),
                "--tolerance-delay", "0.05",
            ]
            env = {"PYTHONPATH": str(scratch_dir / "src")}
            res = subprocess.run(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            if not out_json.is_file():
                raise RuntimeError(f"Mutation script did not generate output JSON: {res.stderr}")

            with open(out_json, "r", encoding="utf-8") as f:
                eval_data = json.load(f)

            failed_evals = [e for e in eval_data["evaluations"] if e["status"] == "FAIL"]
            failed_pcaps = [e["pcap"] for e in failed_evals]
            overall_status = eval_data["overall_status"]

            # Must FAIL
            parity_failed_as_expected = (overall_status == "FAIL" and len(failed_evals) > 0)
            print(f"Result: {len(failed_evals)} runs failed parity. Harness overall status: {overall_status} (Expected FAIL: {parity_failed_as_expected})")

            mutation_results.append({
                "mutation_id": mut["id"],
                "mutation_name": mut["name"],
                "description": mut["description"],
                "expected_affected": mut["expected_affected"],
                "total_runs_evaluated": eval_data["total_evaluations"],
                "failed_runs_count": len(failed_evals),
                "passed_runs_count": eval_data["total_passed"],
                "harness_overall_status": overall_status,
                "mutation_sensitivity_verified": parity_failed_as_expected,
                "failed_pcaps": failed_pcaps,
                "failed_details": [
                    {
                        "pcap": e["pcap"],
                        "scenario": e["scenario"],
                        "repeat": e["repeat"],
                        "streaming_delay": e["streaming_delay_sec"],
                        "ground_truth_delay": e["ground_truth_delay_sec"],
                        "delay_diff": e["delay_diff_sec"],
                        "streaming_alerted": e["streaming_alerted_sec"],
                        "ground_truth_alerted": e["ground_truth_alerted_sec"],
                        "alerted_diff": e["alerted_diff_sec"],
                    }
                    for e in failed_evals
                ]
            })

            # Revert rule_engine.py
            rule_engine_file.write_text(original_code, encoding="utf-8")

    finally:
        # Strict cleanup of scratch copy
        if scratch_dir.exists():
            shutil.rmtree(scratch_dir)
            print("\n[CLEANUP] Scratch copy /tmp/scratch_repo_parity safely deleted.")

    summary_data = {
        "total_mutations_tested": len(mutation_results),
        "all_mutations_detected": all(m["mutation_sensitivity_verified"] for m in mutation_results),
        "mutations": mutation_results,
    }

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out_summary_file = RESULTS_DIR / "phase7_parity_mutations.json"
    with open(out_summary_file, "w", encoding="utf-8") as f:
        json.dump(summary_data, f, indent=2)

    render_table_s7_d(summary_data)
    return summary_data


def render_table_s7_d(summary_data: Dict[str, Any]) -> Path:
    TABLES_DIR.mkdir(parents=True, exist_ok=True)
    out_table = TABLES_DIR / "table_s7_d_parity_mutations.md"

    lines = [
        "### Table S7-D: Phase 7 Rule & Threshold Parity Mutation Sensitivity Tests (`phase7_parity_mutations.json`)",
        "| Mutation Test | Parameter Perturbation | Affected Scenarios | Failed Runs Count | Parity Harness Status | Sensitivity Verified |",
        "| :--- | :--- | :--- | :---: | :---: | :---: |",
    ]

    for m in summary_data["mutations"]:
        name = m["mutation_name"]
        desc = m["description"]
        aff = m["expected_affected"]
        cnt = m["failed_runs_count"]
        st = m["harness_overall_status"]
        ver = "**PASS (Detected)**" if m["mutation_sensitivity_verified"] else "**FAIL (Undetected)**"

        lines.append(f"| **{name}** | {desc} | {aff} | **{cnt} / {m['total_runs_evaluated']}** | **{st}** | {ver} |")

    lines.append("")
    lines.append("#### Detailed Breakdown of Failed Runs per Mutation:")
    for m in summary_data["mutations"]:
        lines.append(f"##### {m['mutation_name']}:")
        lines.append(f"- **Failed Captures ({len(m['failed_pcaps'])} runs)**:")
        for pcap in m["failed_pcaps"]:
            lines.append(f"  - `{pcap}`")
        lines.append("")

    lines.append("*Mutation Acceptance Criteria: Any parameter perturbation MUST trigger parity failure (FAIL) in the parity evaluation harness on affected runs.*")
    lines.append("")

    with open(out_table, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print(f"[OK] Mutation table written to {out_table}")
    return out_table


if __name__ == "__main__":
    run_mutation_test()
