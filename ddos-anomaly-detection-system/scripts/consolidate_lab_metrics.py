"""Consolidate all Phase 6 lab benchmarks into results/lab_metrics.json."""

from __future__ import annotations

import json
from pathlib import Path


def main():
    feat_cmp_file = Path("results/lab_feature_comparison.json")
    benign_eval_file = Path("results/lab_benign_evaluation.json")
    attack_eval_file = Path("results/lab_attack_evaluation.json")

    with open(feat_cmp_file) as f:
        feat_cmp = json.load(f)

    with open(benign_eval_file) as f:
        benign_eval = json.load(f)

    with open(attack_eval_file) as f:
        attack_eval = json.load(f)

    lab_metrics = {
        "metadata": {
            "environment": "Docker isolated_lab_net (internal: true, zero outbound egress)",
            "containers": ["victim-web", "benign-client", "traffic-generator"],
            "mode": "alert-only",
        },
        "feature_comparison": feat_cmp,
        "benign_evaluation": benign_eval,
        "attack_evaluation": attack_eval,
    }

    out_file = Path("results/lab_metrics.json")
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w") as f:
        json.dump(lab_metrics, f, indent=2)

    print(f"Consolidated lab metrics successfully written to {out_file} ({out_file.stat().st_size} bytes).")


if __name__ == "__main__":
    main()
