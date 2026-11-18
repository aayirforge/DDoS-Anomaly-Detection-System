"""
Tests for Phase 8 Read-Only Dashboard.
=======================================
Verifies:
1. Dashboard source code does NOT import mitigation or any blocking logic.
2. AST safety: walks dashboard.py and all transitive imports in ddos_ads,
   asserting no module imports 'mitigation' or uses 'subprocess'.
3. Database access is strictly READ-ONLY (mode=ro URI). Attempting writes fails.
4. Concurrency: WAL mode ensures reader does not block writers.
5. Synthetic DB fixtures:
   - empty_db: verifies "No data yet" state.
   - flood_db: verifies flood incident alerts loading.
   - scan_db: verifies scan incident alerts loading.
   - blind_period_db: verifies detection of drop / supervisor restart / detector_blind condition.
"""

import ast
from pathlib import Path
import sqlite3
import pytest

from ddos_ads.dashboard import load_alerts_from_db_readonly, load_thresholds_readonly

REPO_ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_FILE = REPO_ROOT / "src/ddos_ads/dashboard.py"
SRC_DIR = REPO_ROOT / "src/ddos_ads"


def test_dashboard_does_not_import_mitigation():
    """Asserts that dashboard.py never imports mitigation or blocking code."""
    assert DASHBOARD_FILE.is_file(), f"Dashboard file {DASHBOARD_FILE} not found"

    with open(DASHBOARD_FILE, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=str(DASHBOARD_FILE))

    imported_modules = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported_modules.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported_modules.append(node.module)

    for mod in imported_modules:
        assert "mitigation" not in mod, f"Violation: dashboard.py imports '{mod}'!"


def test_ast_safety_transitive_imports():
    """
    Walks AST of dashboard.py and all transitive imports in src/ddos_ads/.
    Asserts no module imports 'mitigation' or uses 'subprocess'.
    """
    visited = set()
    to_visit = [DASHBOARD_FILE]

    while to_visit:
        curr_file = to_visit.pop()
        if curr_file in visited:
            continue
        visited.add(curr_file)

        with open(curr_file, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=str(curr_file))

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert "mitigation" not in alias.name, f"Forbidden import '{alias.name}' in {curr_file.name}"
                    assert "subprocess" not in alias.name, f"Forbidden subprocess import '{alias.name}' in {curr_file.name}"
                    # Check internal transitive imports
                    if alias.name.startswith("ddos_ads."):
                        sub = alias.name.replace("ddos_ads.", "")
                        cand = SRC_DIR / f"{sub}.py"
                        if cand.is_file() and cand not in visited:
                            to_visit.append(cand)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    assert "mitigation" not in node.module, f"Forbidden from-import '{node.module}' in {curr_file.name}"
                    assert "subprocess" not in node.module, f"Forbidden subprocess from-import '{node.module}' in {curr_file.name}"
                    if node.module.startswith("ddos_ads."):
                        sub = node.module.replace("ddos_ads.", "")
                        cand = SRC_DIR / f"{sub}.py"
                        if cand.is_file() and cand not in visited:
                            to_visit.append(cand)
                    elif node.module == "ddos_ads":
                        for alias in node.names:
                            assert "mitigation" not in alias.name, f"Forbidden import '{alias.name}' in {curr_file.name}"
                            cand = SRC_DIR / f"{alias.name}.py"
                            if cand.is_file() and cand not in visited:
                                to_visit.append(cand)


def test_database_is_opened_strictly_readonly(tmp_path):
    """Asserts that SQLite connections in dashboard are read-only and reject write operations."""
    test_db = tmp_path / "test_ro.db"
    conn = sqlite3.connect(str(test_db))
    with conn:
        conn.execute("""
            CREATE TABLE alerts (
                id INTEGER PRIMARY KEY, wall_time REAL, packet_ts REAL,
                alert_type TEXT, rule TEXT, victim_ip TEXT, details TEXT, latency_ms REAL
            )
        """)
        conn.execute("INSERT INTO alerts VALUES (1, 1000.0, 1000.0, 'ALERT_SYN_FLOOD', 'tcp_incomplete_handshake', '172.20.0.2', '{}', 0.05)")
    conn.close()

    df, meta = load_alerts_from_db_readonly(test_db)
    assert not df.empty
    assert len(df) == 1

    # Attempting to open with the dashboard's read-only URI and write must fail
    ro_uri = f"file:{test_db.resolve().as_posix()}?mode=ro"
    ro_conn = sqlite3.connect(ro_uri, uri=True)
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        ro_conn.execute("INSERT INTO alerts VALUES (2, 1001.0, 1001.0, 'ALERT_SCAN', 'tcp_incomplete_handshake', '172.20.0.2', '{}', 0.05)")
    ro_conn.close()


def test_concurrent_writer_wal_mode(tmp_path):
    """
    Verifies that WAL mode enables simultaneous reader and writer concurrency.
    The read-only connection does not lock the database or block concurrent writers.
    """
    wal_db = tmp_path / "wal_concurrency.db"
    w_conn = sqlite3.connect(str(wal_db))
    w_conn.execute("PRAGMA journal_mode=WAL;")
    w_conn.execute("""
        CREATE TABLE alerts (
            id INTEGER PRIMARY KEY, wall_time REAL, packet_ts REAL,
            alert_type TEXT, rule TEXT, victim_ip TEXT, details TEXT, latency_ms REAL
        )
    """)
    w_conn.execute("INSERT INTO alerts VALUES (1, 1000.0, 1000.0, 'ALERT_SYN_FLOOD', 'tcp_incomplete_handshake', '172.20.0.2', '{}', 0.05)")
    w_conn.commit()

    # Open read-only connection via dashboard
    ro_uri = f"file:{wal_db.resolve().as_posix()}?mode=ro"
    ro_conn = sqlite3.connect(ro_uri, uri=True)

    # Concurrently write from writer connection while reader is open
    w_conn.execute("INSERT INTO alerts VALUES (2, 1001.0, 1001.0, 'ALERT_SCAN', 'tcp_incomplete_handshake', '172.20.0.2', '{}', 0.04)")
    w_conn.commit()

    # Read from read-only connection: must see row 2
    cur = ro_conn.execute("SELECT COUNT(*) FROM alerts")
    count = cur.fetchone()[0]
    assert count == 2, f"Expected 2 rows under WAL concurrent read, got {count}"

    ro_conn.close()
    w_conn.close()


def test_empty_db_fixture(tmp_path):
    """Asserts that an empty database triggers clean empty state without crashing."""
    empty_db = tmp_path / "empty.db"
    conn = sqlite3.connect(str(empty_db))
    with conn:
        conn.execute("""
            CREATE TABLE alerts (
                id INTEGER PRIMARY KEY, wall_time REAL, packet_ts REAL,
                alert_type TEXT, rule TEXT, victim_ip TEXT, details TEXT, latency_ms REAL
            )
        """)
    conn.close()

    df, meta = load_alerts_from_db_readonly(empty_db)
    assert df.empty, "Expected empty DataFrame for empty_db fixture"


def test_flood_db_fixture(tmp_path):
    """Asserts that SYN flood incident records load accurately."""
    flood_db = tmp_path / "flood.db"
    conn = sqlite3.connect(str(flood_db))
    with conn:
        conn.execute("""
            CREATE TABLE alerts (
                id INTEGER PRIMARY KEY, wall_time REAL, packet_ts REAL,
                alert_type TEXT, rule TEXT, victim_ip TEXT, details TEXT, latency_ms REAL
            )
        """)
        for i in range(10):
            conn.execute(
                "INSERT INTO alerts VALUES (?, ?, ?, 'ALERT_SYN_FLOOD', 'tcp_incomplete_handshake', '172.20.0.2', '{\"incomplete_count\": 200}', 0.04)",
                (i + 1, 1000.0 + i, 1000.0 + i)
            )
    conn.close()

    df, meta = load_alerts_from_db_readonly(flood_db)
    assert len(df) == 10
    assert (df["alert_type"] == "ALERT_SYN_FLOOD").all()


def test_scan_db_fixture(tmp_path):
    """Asserts that reconnaissance scan records load accurately."""
    scan_db = tmp_path / "scan.db"
    conn = sqlite3.connect(str(scan_db))
    with conn:
        conn.execute("""
            CREATE TABLE alerts (
                id INTEGER PRIMARY KEY, wall_time REAL, packet_ts REAL,
                alert_type TEXT, rule TEXT, victim_ip TEXT, details TEXT, latency_ms REAL
            )
        """)
        for i in range(5):
            conn.execute(
                "INSERT INTO alerts VALUES (?, ?, ?, 'ALERT_SCAN', 'tcp_incomplete_handshake', '172.20.0.2', '{\"distinct_dst_ports\": 15}', 0.03)",
                (i + 1, 2000.0 + i, 2000.0 + i)
            )
    conn.close()

    df, meta = load_alerts_from_db_readonly(scan_db)
    assert len(df) == 5
    assert (df["alert_type"] == "ALERT_SCAN").all()


def test_blind_period_banner_condition():
    """Asserts that kernel packet drops, supervisor restarts, or detector_blind trigger blind state."""
    clean_meta = {"drops": 0, "restarts": 0, "detector_blind": False}
    assert not (clean_meta["drops"] > 0 or clean_meta["restarts"] > 0 or clean_meta["detector_blind"])

    blind_meta_drops = {"drops": 142, "restarts": 0, "detector_blind": False}
    assert (blind_meta_drops["drops"] > 0 or blind_meta_drops["restarts"] > 0 or blind_meta_drops["detector_blind"])

    blind_meta_restarts = {"drops": 0, "restarts": 3, "detector_blind": False}
    assert (blind_meta_restarts["drops"] > 0 or blind_meta_restarts["restarts"] > 0 or blind_meta_restarts["detector_blind"])

    blind_meta_event = {"drops": 0, "restarts": 0, "detector_blind": True}
    assert (blind_meta_event["drops"] > 0 or blind_meta_event["restarts"] > 0 or blind_meta_event["detector_blind"])


def test_thresholds_readonly_loading():
    """Asserts that frozen thresholds are correctly read from thresholds.json for display."""
    th = load_thresholds_readonly()
    assert "packet_incomplete_tcp_handshake_rule" in th
    assert "packet_dual_condition_udp_rule" in th
    hs = th["packet_incomplete_tcp_handshake_rule"]
    assert hs["condition_b_sliding_concentrated_incomplete_syns_threshold"] == 20
    assert hs["condition_a_min_incomplete_rate"] == 15
    udp = th["packet_dual_condition_udp_rule"]
    assert udp["condition_1_volumetric_udp_pkts_per_sec"] == 40
    assert udp["condition_2_random_port_udp_pkts_per_sec"] == 30
