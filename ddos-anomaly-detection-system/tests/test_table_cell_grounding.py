"""Tests verifying that every table cell maps to its named JSON key and fails on mismatches."""

import json
from pathlib import Path
import pytest
from ddos_ads.table_validator import (
    validate_all_tables_against_json,
    validate_table_b_per_repeat,
    parse_markdown_table_rows,
)

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"

def test_all_table_cells_match_exact_json_keys():
    """Verify that all unmodified generated table markdown files pass per-cell validation."""
    validate_all_tables_against_json(RESULTS_DIR)

def test_validation_fails_on_swapped_delay(tmp_path):
    """Verify that swapping detection delay values between two runs causes immediate validation failure."""
    t_b = RESULTS_DIR / "tables" / "table_s3_b_per_repeat.md"
    assert t_b.exists(), f"Source table {t_b} must exist"
    
    content = t_b.read_text(encoding="utf-8")
    lines = content.splitlines()
    
    # Locate the lines for 50pps rep1 and rep2
    # In rep1, delay is 2.420 s; in rep2, delay is 2.442 s
    assert "2.420 s" in content and "2.442 s" in content
    
    # Swap the delay of rep1 and rep2 in a copy of the table
    modified_lines = []
    for l in lines:
        if "session3_tcp_syn_flood_50pps_rep1" in l:
            # Swap 2.420 s with 2.442 s
            modified_lines.append(l.replace("2.420 s", "2.442 s"))
        elif "session3_tcp_syn_flood_50pps_rep2" in l:
            # Swap 2.442 s with 2.420 s
            modified_lines.append(l.replace("2.442 s", "2.420 s"))
        else:
            modified_lines.append(l)
            
    bad_table = tmp_path / "table_s3_b_per_repeat.md"
    bad_table.write_text("\n".join(modified_lines) + "\n", encoding="utf-8")
    
    eval_json = RESULTS_DIR / "session3_evaluation.json"
    eval_data = json.loads(eval_json.read_text(encoding="utf-8"))
    
    with pytest.raises(AssertionError) as exc_info:
        validate_table_b_per_repeat(bad_table, eval_data)
        
    err_msg = str(exc_info.value)
    assert "first_detection_delay_sec" in err_msg
    assert "cell mismatch" in err_msg.lower()
    assert "2.420 s" in err_msg or "2.442 s" in err_msg
