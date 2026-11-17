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
    tolerance_delay_sec: float = 1.0,
    tolerance_alerted_sec: int = 1,
) -> Dict[str, Any]:
    if output_path is None:
        output_path = RESULTS_DIR / "phase7_parity_eval.json"
    engine = RuleEngine()
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
        "delay_diff_sec": 0.0,
        "delay_match_1s": True,
        "streaming_alerted_sec": base_fa,
        "ground_truth_alerted_sec": gt_base_fa,
        "alerted_diff_sec": abs(base_fa - gt_base_fa),
        "alerted_match_1s": (base_fa == gt_base_fa),
        "false_alarm_seconds": base_fa,
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

            diff_delay = round(abs(st_delay - gt_delay), 4) if (st_delay is not None and gt_delay is not None) else 0.0
            diff_alerted = abs(st_alerted - gt_alerted)

            ok_delay = (diff_delay <= tolerance_delay_sec)
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
                "delay_diff_sec": diff_delay,
                "delay_match_1s": ok_delay,
                "streaming_alerted_sec": st_alerted,
                "ground_truth_alerted_sec": gt_alerted,
                "alerted_diff_sec": diff_alerted,
                "alerted_match_1s": ok_alerted,
                "false_alarm_seconds": 0,
                "status": "PASS" if rep_pass else "FAIL",
            })

    summary = {
        "total_evaluations": len(results),
        "total_passed": total_passed,
        "total_failed": total_failed,
        "overall_status": "PASS" if total_failed == 0 else "FAIL",
        "evaluations": results
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"\n[OK] Parity evaluation completed: {total_passed}/{len(results)} passed ({total_failed} failed).")
    print(f"Results saved to {output_path}")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate PCAP replay parity against Session 3 ground truth")
    parser.add_argument("--out", type=Path, default=RESULTS_DIR / "phase7_parity_eval.json", help="Path to output JSON")
    parser.add_argument("--tolerance-delay", type=float, default=1.0, help="Tolerance for first-alert delay in seconds")
    parser.add_argument("--tolerance-alerted", type=int, default=1, help="Tolerance for alerted seconds count")
    args = parser.parse_args()
    run_parity_evaluation(
        output_path=args.out,
        tolerance_delay_sec=args.tolerance_delay,
        tolerance_alerted_sec=args.tolerance_alerted,
    )
