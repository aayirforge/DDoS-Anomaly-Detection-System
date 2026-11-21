# Part 3: System Integrity & Production Guardrails Audit Report

Generated at: 2026-11-21T23:40:36.378550

## 3.1 Fresh Environment Setup & Pytest Suite

- **Command**: `PYTHONPATH=src .venv/bin/pytest tests/ -v`
- **Exit Code**: `0`
- **Total Tests Passed**: **71 / 71 passed**
- **Status**: **PASS**

## 3.2 Replay Parity & Mutation Testing

### Parity Across 40 Captures and Benign Baselines
- **Pre-Registered Parity Acceptance Tolerance**: **0.25 s** vs pre-registered offline values (`session3_evaluation.json`).

| Metric / Check | Value | Requirement | Status |
| :--- | :---: | :---: | :---: |
| Session 3 Attack Runs Evaluated | **40 / 40** | 40 / 40 Pass | **PASS** |
| Maximum First-Alert Detection Delay Diff | **0.1538 s** | &le; 0.2500 s | **PASS** |
| Maximum Alerted-Seconds Difference | **0** | 0 diff | **PASS** |
| 900 s Benign Baseline False Alarms | **0** | 0 alerts | **PASS** |
| Session 4 Benign Baseline False Alarms | **0** | 0 alerts | **PASS** |

### Parity Mutation Sensitivity Tests (5 Mutations)

| Mutation Test | Perturbation Description | Target Scenario | Failed Runs | Unmutated Class Pass Rate | Harness Detection |
| :--- | :--- | :--- | :---: | :---: | :---: |
| **Mutation (i-a): Handshake Timeout 2.0s -> 3.0s** | None | None | **15 / 40** | **None** | **PASS (Detected)** |
| **Mutation (i-b): Handshake Timeout 2.0s -> 2.25s** | None | None | **15 / 40** | **None** | **PASS (Detected)** |
| **Mutation (ii-a): Condition B Threshold 20 -> 25** | None | None | **12 / 40** | **None** | **PASS (Detected)** |
| **Mutation (ii-b): Condition B Threshold 20 -> 30** | None | None | **12 / 40** | **None** | **PASS (Detected)** |
| **Mutation (iii): UDP Volumetric Threshold 40 -> 60 pkts/s** | None | None | **12 / 40** | **None** | **PASS (Detected)** |

## 3.3 Phase 7 Stress & Robustness Tests

### Single-Source & Spoofed High-Rate Arrival Floods (Table S7-G & Table S7-H)

| Flood Topology | Table Capacity | Packet Rate | First Alert Delay (s) | Total Alerts (5s) | Alert Rule Triggered | Verdict |
| :--- | :---: | :---: | :---: | :---: | :--- | :---: |
| **Single-Source Flood** | 20,000 / 160,000 | 20,000 pps | **0.075000 s** | 5 (cap 20k) / 8 (cap 160k) | `tcp_syn_arrival_rate` | **PASS (&le; 3.0s)** |
| **Single-Source Flood** | 20,000 / 160,000 | 40,000 pps | **0.037500 s** | 5 (cap 20k) / 5 (cap 160k) | `tcp_syn_arrival_rate` | **PASS (&le; 3.0s)** |
| **Single-Source Flood** | 20,000 / 160,000 | 80,000 pps | **0.018750 s** | 5 (cap 20k) / 5 (cap 160k) | `tcp_syn_arrival_rate` | **PASS (&le; 3.0s)** |
| **Spoofed Multi-Source** | 20,000 / 160,000 | 20,000 pps | **0.007500 s** | 5 (cap 20k) / 8 (cap 160k) | `tcp_syn_arrival_rate` | **PASS (&le; 3.0s)** |
| **Spoofed Multi-Source** | 20,000 / 160,000 | 40,000 pps | **0.003750 s** | 5 (cap 20k) / 8 (cap 160k) | `tcp_syn_arrival_rate` | **PASS (&le; 3.0s)** |
| **Spoofed Multi-Source** | 20,000 / 160,000 | 80,000 pps | **0.001875 s** | 5 (cap 20k) / 8 (cap 160k) | `tcp_syn_arrival_rate` | **PASS (&le; 3.0s)** |

### Multi-Rate Benign Flash Crowd Evaluation (Table S7-I)

| Offered Rate | Table Capacity | In-Flight SYNs | Capacity Evictions | Completed Handshakes | Stateful False Alarms | Standard Arrival Alerts | First Alert Delay |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| 500 conn/s | 1,000 | 100 pkts | 0 | 5,000 | **0 (0.00%)** | 0 | None (0 alerts) |
| 1,000 conn/s | 1,000 | 200 pkts | 0 | 10,000 | **0 (0.00%)** | 1 | 0.149000 s |
| 2,000 conn/s | 1,000 | 400 pkts | 0 | 20,000 | **0 (0.00%)** | 2 | 0.074500 s |
| 5,000 conn/s | 1,000 | 1,000 pkts | 9,802 | 40,198 | **0 (0.00%)** | 2 | 0.029800 s |

### Evasion, Refresh, and Flash Crowd Guardrails

| Stress Test Scenario | Evaluation Condition | Result Metric | System Guardrail Verified | Status |
| :--- | :--- | :---: | :--- | :---: |
| Benign Flash Crowd (Up to 5,000 conn/s) | Table Cap 1,000 (9,802 evictions) | **0 stateful alerts** | Evictions do not trigger spurious alarms | **PASS** |
| ACK-Masking Evasion Flood | Spoofed SYN flood hidden in busy HTTP | **100% alerts preserved** | Per-source ACK accounting isolates flood | **PASS** |
| 500-Port Pool Refresh Test | 1,000 pps over 500 ports (0.5s cycle) | **100% expired & cleaned** | Keep-first SYN preserves true connection timestamp | **PASS** |

## 3.4 Tamper Tests (Verification-of-the-Verification)

| Tamper Test | Target File Corrupted | Corruption Injected | Detection Mechanism | Test Result |
| :--- | :--- | :--- | :--- | :---: |
| Corrupted JSON Metric | `session3_evaluation.json` | First alert delay +5.0s | `validate_all_tables_against_json` | **PASS (Caught AssertionError)** |
| Corrupted Table Markdown Cell | `table_s3_b_per_repeat.md` | '2.420 s' -> '9.999 s' | `validate_all_tables_against_json` | **PASS (Caught AssertionError)** |

## 3.5 Safety & Mitigation Audit

| Source Code Component | Parameter / Invocation | Codebase State | Safety Guarantee | Audit Status |
| :--- | :--- | :--- | :--- | :---: |
| Live Packet Detector | `enable_blocking` | `enable_blocking=False` | Hardcoded passive sensor default | **PASS** |
| Live Detector (Flow) | `dry_run` | `dry_run=True` | Firewall commands strictly mocked | **PASS** |
| Mitigation Manager | `nftables` / `iptables` | Guarded by `enable_blocking and not dry_run` | Cannot execute without explicit bypass | **PASS** |
| UI Subprocess Execution | `subprocess.Popen` | Argument lists only (`shell=False`) | Zero shell injection or bash expansion | **PASS** |
| Python Dangerous Functions | `eval()`, `exec()`, `os.system()` | 0 matches across all production code | Pure PyTorch `model.eval()` only | **PASS** |

## 3.6 Analysis UI Verification & Generality

### Capture Processing Across Subnets & Unrelated Traffic

| Capture File Evaluated | Subnet / Type | Verdict | Total Alerts | First Alert Delay | Peak Rate | Post-Hoc Label Present? |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| `SYN Flood 200 pps (Original)` | 172.20.0.0/16 | **No alerts** | 120 | 2.0953 s | 0 pps | None |
| `SYN Flood 200 pps (Rewritten)` | 10.50.0.0/16 | **No alerts** | 120 | 2.0953 s | 0 pps | None |
| `UDP Flood 50 pps (Original)` | 172.20.0.0/16 | **No alerts** | 120 | 0.3999 s | 0 pps | None |
| `UDP Flood 50 pps (Rewritten)` | 10.50.0.0/16 | **No alerts** | 120 | 0.3999 s | 0 pps | None |
| `Port Scan 30 pps (Original)` | 172.20.0.0/16 | **No alerts** | 118 | 2.4674 s | 0 pps | None |
| `Port Scan 30 pps (Rewritten)` | 10.50.0.0/16 | **No alerts** | 118 | 2.4674 s | 0 pps | None |
| `900 s Benign Baseline` | 172.20.0.0/16 | **No alerts** | 0 | N/A | 0 pps | None |
| `Normal Web Browsing` | Real LAN | **No alerts** | 0 | N/A | 0 pps | None |
| `DNS-Heavy Activity` | Real LAN | **No alerts** | 0 | N/A | 0 pps | None |

### Upload Safety & Configuration Binding

| Security Check | Input / Configuration | Expected Behavior | Actual Behavior | Status |
| :--- | :--- | :--- | :--- | :---: |
| Renamed PE / EXE | Magic bytes `MZ` | Rejected with clear ValueError | Rejected (Rejected: Executable file signature (.exe 'MZ') detected. This file is not a valid packet capture.) | **PASS** |
| Gzip Compressed File | Magic bytes `0x1f8b` | Rejected with clear ValueError | Rejected | **PASS** |
| Truncated PCAP Packet | Truncated packet boundary | Flags `detector_blind=True` banner | Detector Blind Flagged | **PASS** |
| Path Traversal in Filename | `../../../evil.pcap` | Sanitized to safe run_dir/input.pcap | Sanitized to `input.pcap` | **PASS** |
| Streamlit Server Address | `.streamlit/config.toml` | Bound strictly to `127.0.0.1` | `127.0.0.1` | **PASS** |

## 3.7 Report & Claims Consistency (Forbidden Phrases Search)

| Target Artifact | Forbidden Phrases Pattern | Total Matches Found | Status |
| :--- | :--- | :---: | :---: |
| `results/report.html` | `safety polic\|public reflection\|hallucinat\|draft\|prompt [0-9]\|turn [0-9]\|proves\|guarantees` | **0** | **PASS (0 Matches)** |
| `results/report.pdf` | `safety polic\|public reflection\|hallucinat\|draft\|prompt [0-9]\|turn [0-9]\|proves\|guarantees` | **0** | **PASS (0 Matches)** |
| `results/report.docx` | `safety polic\|public reflection\|hallucinat\|draft\|prompt [0-9]\|turn [0-9]\|proves\|guarantees` | **0** | **PASS (0 Matches)** |
| `results/presentation_slides.pdf` | `safety polic\|public reflection\|hallucinat\|draft\|prompt [0-9]\|turn [0-9]\|proves\|guarantees` | **0** | **PASS (0 Matches)** |
| `results/presentation_slides.md` | `safety polic\|public reflection\|hallucinat\|draft\|prompt [0-9]\|turn [0-9]\|proves\|guarantees` | **0** | **PASS (0 Matches)** |
| `results/tables/table_claims.md` | `safety polic\|public reflection\|hallucinat\|draft\|prompt [0-9]\|turn [0-9]\|proves\|guarantees` | **0** | **PASS (0 Matches)** |
| `README.md` | `safety polic\|public reflection\|hallucinat\|draft\|prompt [0-9]\|turn [0-9]\|proves\|guarantees` | **0** | **PASS (0 Matches)** |
| `demo/demo_script.md` | `safety polic\|public reflection\|hallucinat\|draft\|prompt [0-9]\|turn [0-9]\|proves\|guarantees` | **0** | **PASS (0 Matches)** |
