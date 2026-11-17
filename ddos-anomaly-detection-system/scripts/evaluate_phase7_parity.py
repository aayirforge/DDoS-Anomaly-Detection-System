"""
Phase 7 PCAP Replay Parity Evaluation Suite.
============================================
Evaluates all 40 Session 3 captures and the 900s baseline using the streaming
RuleEngine in replay mode, asserting that:
1. First-alert detection delay matches results/session3_evaluation.json within 1.0s.
2. Alerted seconds count matches results/session3_evaluation.json within 1s.
3. Benign baseline produces 0 false alarm seconds.
Any discrepancy is recorded as a failure.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from ddos_ads.rule_engine import RuleEngine

RESULTS_DIR = REPO_ROOT / "results"
CAPTURES_DIR = REPO_ROOT / "lab/captures/session3"


def run_parity_evaluation(
    output_path: Optional[Path] = None,
    tolerance_delay_sec: float = 0.25,
    tolerance_alerted_sec: int = 1,
    reference_streaming_path: Optional[Path] = None,
) -> Dict[str, Any]:
    if output_path is None:
        output_path = RESULTS_DIR / "phase7_parity_eval.json"
    engine = RuleEngine()

    ref_by_pcap = {}
    if reference_streaming_path and reference_streaming_path.is_file():
        with open(reference_streaming_path, "r", encoding="utf-8") as f:
            ref_json = json.load(f)
            ref_by_pcap = {e["pcap"]: e for e in ref_json.get("evaluations", [])}

    eval_json_path = RESULTS_DIR / "session3_evaluation.json"
    with open(eval_json_path, "r", encoding="utf-8") as f:
        gt_eval = json.load(f)

    results: List[Dict[str, Any]] = []
    total_passed = 0
    total_failed = 0

    # 1. Baseline Evaluation (900s)
    base_pcap = CAPTURES_DIR / "session3_benign_baseline_900s.pcap"
    base_res = engine.evaluate_pcap_streaming(base_pcap, duration_sec=900, is_baseline=True)
    base_fa = base_res["alerted_seconds_total"]
    gt_base_fa = gt_eval["benign_baseline"]["combined_active_defense_false_alarm_seconds"]

    if ref_by_pcap and base_pcap.name in ref_by_pcap:
        ref_e = ref_by_pcap[base_pcap.name]
        base_pass = (base_fa == ref_e["streaming_alerted_sec"] and base_fa == 0)
    else:
        base_pass = (base_fa == 0 and base_fa == gt_base_fa)

    if base_pass:
        total_passed += 1
    else:
        total_failed += 1

    results.append({
        "pcap": base_pcap.name,
        "scenario": "Benign Baseline (900s)",
        "repeat": 1,
        "streaming_delay_sec": base_res["first_detection_delay_sec"],
        "ground_truth_delay_sec": None,
        "delay_diff_signed": 0.0,
        "delay_diff_sec": 0.0,
        "delay_match": True,
        "streaming_alerted_sec": base_fa,
        "ground_truth_alerted_sec": gt_base_fa,
        "alerted_diff_sec": abs(base_fa - gt_base_fa),
        "alerted_match": (base_fa == gt_base_fa),
        "false_alarm_seconds": base_fa,
        "first_alert_class": base_res["first_alert_class"],
        "first_alert_volume": base_res["first_alert_volume"],
        "first_alert_distinct_sources": base_res["first_alert_distinct_sources"],
        "alert_seconds_set": base_res["alert_seconds_set"],
        "status": "PASS" if base_pass else "FAIL",
    })

    # 2. Attack Captures Evaluation (39 PCAPs)
    for cond_name, cond_data in gt_eval["attack_evaluations"].items():
        for rep_data in cond_data["repeats"]:
            run_id = rep_data["run_id"]
            pcap_file = CAPTURES_DIR / f"{run_id}.pcap"
            if not pcap_file.is_file():
                raise FileNotFoundError(f"Missing required pcap: {pcap_file}")

            st_res = engine.evaluate_pcap_streaming(pcap_file, duration_sec=120)

            gt_delay = rep_data["first_detection_delay_sec"]
            gt_alerted = rep_data["alerted_seconds_post_first_alert"]
            st_delay = st_res["first_detection_delay_sec"]
            st_alerted = st_res["alerted_seconds_post_first_alert"]

            differing_fields: List[str] = []

            if ref_by_pcap and pcap_file.name in ref_by_pcap:
                ref_e = ref_by_pcap[pcap_file.name]
                ref_delay = ref_e["streaming_delay_sec"]
                ref_volume = ref_e["first_alert_volume"]
                ref_srcs = ref_e["first_alert_distinct_sources"]
                ref_cls = ref_e["first_alert_class"]
                ref_set = ref_e.get("alert_seconds_set", [])

                diff_delay_signed = round(st_delay - ref_delay, 4) if (st_delay is not None and ref_delay is not None) else 0.0
                diff_delay_abs = round(abs(diff_delay_signed), 4)
                diff_alerted = abs(st_alerted - ref_e["streaming_alerted_sec"])

                ok_delay = (diff_delay_abs <= tolerance_delay_sec)
                ok_volume = (st_res["first_alert_volume"] == ref_volume)
                ok_sources = (st_res["first_alert_distinct_sources"] == ref_srcs)
                ok_class = (st_res["first_alert_class"] == ref_cls)
                ok_alerted_set = (st_res["alert_seconds_set"] == ref_set)

                if not ok_delay:
                    differing_fields.append(f"first_detection_delay_sec ({ref_delay}s -> {st_delay}s, diff={diff_delay_signed}s)")
                if not ok_volume:
                    differing_fields.append(f"first_alert_volume ({ref_volume} -> {st_res['first_alert_volume']})")
                if not ok_sources:
                    differing_fields.append(f"distinct_sources ({ref_srcs} -> {st_res['first_alert_distinct_sources']})")
                if not ok_class:
                    differing_fields.append(f"class ({ref_cls} -> {st_res['first_alert_class']})")
                if not ok_alerted_set:
                    differing_fields.append(f"alert_seconds_set ({len(ref_set)}s -> {len(st_res['alert_seconds_set'])}s)")

                ok_alerted = (diff_alerted <= tolerance_alerted_sec and ok_alerted_set)
                rep_pass = (ok_delay and ok_volume and ok_sources and ok_class and ok_alerted_set)
            else:
                diff_delay_signed = round(st_delay - gt_delay, 4) if (st_delay is not None and gt_delay is not None) else 0.0
                diff_delay_abs = round(abs(diff_delay_signed), 4)
                diff_alerted = abs(st_alerted - gt_alerted)

                ok_delay = (diff_delay_abs <= tolerance_delay_sec)
                ok_alerted = (diff_alerted <= tolerance_alerted_sec)
                rep_pass = (ok_delay and ok_alerted)

            if rep_pass:
                total_passed += 1
            else:
                total_failed += 1

            results.append({
                "pcap": pcap_file.name,
                "scenario": cond_name,
                "repeat": rep_data["repeat"],
                "streaming_delay_sec": st_delay,
                "ground_truth_delay_sec": gt_delay,
                "delay_diff_signed": diff_delay_signed,
                "delay_diff_sec": diff_delay_abs,
                "delay_match": ok_delay,
                "streaming_alerted_sec": st_alerted,
                "ground_truth_alerted_sec": gt_alerted,
                "alerted_diff_sec": diff_alerted,
                "alerted_match": ok_alerted,
                "false_alarm_seconds": 0,
                "first_alert_class": st_res["first_alert_class"],
                "first_alert_volume": st_res["first_alert_volume"],
                "first_alert_distinct_sources": st_res["first_alert_distinct_sources"],
                "alert_seconds_set": st_res["alert_seconds_set"],
                "differing_fields": differing_fields,
                "status": "PASS" if rep_pass else "FAIL",
            })

    max_abs_delay = max(abs(e["delay_diff_signed"]) for e in results)
    max_abs_alerted = max(e["alerted_diff_sec"] for e in results)

    summary = {
        "total_evaluations": len(results),
        "total_passed": total_passed,
        "total_failed": total_failed,
        "tolerance_delay_sec": tolerance_delay_sec,
        "tolerance_alerted_sec": tolerance_alerted_sec,
        "max_abs_delay_diff_sec": round(max_abs_delay, 4),
        "max_abs_alerted_diff_sec": max_abs_alerted,
        "overall_status": "PASS" if total_failed == 0 else "FAIL",
        "evaluations": results
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"\n[OK] Parity evaluation completed: {total_passed}/{len(results)} passed ({total_failed} failed).")
    print(f"Tolerance used: delay <= {tolerance_delay_sec}s, alerted <= {tolerance_alerted_sec}s")
    print(f"Max abs delay diff: {max_abs_delay:.4f}s | Max abs alerted diff: {max_abs_alerted}s")
    print(f"Results saved to {output_path}")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate PCAP replay parity against Session 3 ground truth")
    parser.add_argument("--out", type=Path, default=RESULTS_DIR / "phase7_parity_eval.json", help="Path to output JSON")
    parser.add_argument("--tolerance-delay", type=float, default=0.25, help="Tolerance for first-alert delay in seconds")
    parser.add_argument("--tolerance-alerted", type=int, default=1, help="Tolerance for alerted seconds count")
    parser.add_argument("--reference-streaming", type=Path, default=None, help="Path to streaming baseline JSON for mutation parity comparison")
    args = parser.parse_args()
    run_parity_evaluation(
        output_path=args.out,
        tolerance_delay_sec=args.tolerance_delay,
        tolerance_alerted_sec=args.tolerance_alerted,
        reference_streaming_path=args.reference_streaming,
    )
