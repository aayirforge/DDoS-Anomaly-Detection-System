"""
Recompute the authoritative 100-file manifest with descriptive header.
"""

import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CHECKSUMS_FILE = REPO_ROOT / "checksums.sha256"
TOP_CHECKSUMS_FILE = REPO_ROOT.parent / "checksums.sha256"

HEADER = """# Authoritative Production Release Manifest (Phase 7 Final Checks Release)
# Covers 100 of 416 tracked repository files.
# Scope Rationale: This manifest strictly tracks the 100 authoritative assets governing
# production detection, evaluation ground truth, frozen models, and core test harnesses:
# - Core algorithmic detection engine and live streaming pipeline (src/ddos_ads/)
# - Authoritative evaluation and parity ground truth JSONs (results/)
# - Benchmark reports and verification tables (results/tables/)
# - Frozen model checkpoints and feature definitions (models/)
# - Canonical capture manifests and calibration PCAPs (lab/captures/)
# - Core test suites and reproduction harnesses (tests/, scripts/)
# The remaining 316 tracked repository files consist of secondary exploratory scripts,
# raw per-session flow CSV dumps, Java CICFlowmeter artifacts, exploratory notebooks,
# and developmental test files that are outside the frozen production evaluation boundary.
"""

NEW_FILES = [
    "ddos-anomaly-detection-system/results/phase7_final_checks.json",
    "ddos-anomaly-detection-system/results/tables/table_s7_m_ack_masking_test.md",
    "ddos-anomaly-detection-system/results/tables/table_s7_n_handshake_refresh_test.md",
    "ddos-anomaly-detection-system/scripts/run_phase7_final_checks.py",
]

def main():
    with open(CHECKSUMS_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()
        
    file_list = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(maxsplit=1)
        if len(parts) == 2:
            file_list.append(parts[1])
            
    for nf in NEW_FILES:
        if nf not in file_list:
            file_list.append(nf)
            
    print(f"Total files in manifest list: {len(file_list)}")
    assert len(file_list) == 100, f"Expected 100 files, got {len(file_list)}"
    
    # Compute sha256 for each file from parent of REPO_ROOT (the git workspace root)
    workspace_root = REPO_ROOT.parent
    new_lines = [HEADER.strip(), ""]
    
    for rel_path in sorted(file_list):
        full_path = workspace_root / rel_path
        if not full_path.is_file():
            raise FileNotFoundError(f"Missing file: {full_path}")
        cmd = ["sha256sum", str(full_path)]
        out = subprocess.check_output(cmd, text=True).strip()
        h = out.split()[0]
        new_lines.append(f"{h}  {rel_path}")
        
    content = "\n".join(new_lines) + "\n"
    with open(CHECKSUMS_FILE, "w", encoding="utf-8") as f:
        f.write(content)
    with open(TOP_CHECKSUMS_FILE, "w", encoding="utf-8") as f:
        f.write(content)
        
    print(f"[OK] Successfully wrote {len(file_list)} checksums with header to {CHECKSUMS_FILE} and {TOP_CHECKSUMS_FILE}")

if __name__ == "__main__":
    main()


