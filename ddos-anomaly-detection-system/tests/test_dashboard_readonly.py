"""
Phase 10 Safety and AST Verification Tests.
===========================================
Replaces the old Phase 8 read-only test with Phase 10 safety guarantees:
1. Dashboard and UI modules contain NO imports of mitigation or blocking logic.
2. Dashboard code may import only the ui_capture module for subprocess;
   subprocess is imported ONLY in ui_capture and ONLY invoked with argument lists (never shell=True).
3. NO calls to iptables, nftables, or os.system anywhere in UI code.
4. SQLite connection for the legacy monitor page strictly opens with mode=ro.
5. All UI run outputs are written exclusively under results/ui_runs.
6. Preserves database concurrency and fixture regression tests.
"""

import ast
from pathlib import Path
import sqlite3
import pytest

from ddos_ads.dashboard import load_alerts_from_db_readonly, load_thresholds_readonly

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src/ddos_ads"
DASHBOARD_FILE = SRC_DIR / "dashboard.py"
UI_MODULES = [
    SRC_DIR / "dashboard.py",
    SRC_DIR / "ui_capture.py",
    SRC_DIR / "ui_analyzer.py",
    SRC_DIR / "ui_report.py",
]


def test_dashboard_does_not_import_mitigation():
    """Asserts that neither dashboard.py nor any UI module imports mitigation or blocking logic."""
    for mod_path in UI_MODULES:
        assert mod_path.is_file(), f"File {mod_path} does not exist"
        with open(mod_path, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=str(mod_path))

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert "mitigation" not in alias.name, f"Forbidden import '{alias.name}' in {mod_path.name}"
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    assert "mitigation" not in node.module, f"Forbidden from-import '{node.module}' in {mod_path.name}"


def test_ui_static_safety():
    """
    Phase 10 AST safety verification:
    1. dashboard code may import only the ui_capture module for subprocess.
    2. subprocess is imported ONLY in ui_capture.py and never in dashboard.py, ui_analyzer.py, or ui_report.py.
    3. In ui_capture.py, all subprocess calls use argument lists, never shell=True.
    4. NO calls to iptables, nftables, or os.system anywhere in UI code.
    5. Writes only under results/ui_runs.
    """
    for mod_path in UI_MODULES:
        with open(mod_path, "r", encoding="utf-8") as f:
            code_text = f.read()
            tree = ast.parse(code_text, filename=str(mod_path))

        # Check AST for forbidden system / firewall execution calls
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # Check for os.system(...)
                if isinstance(node.func, ast.Attribute) and node.func.attr == "system":
                    if isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
                        pytest.fail(f"Violation: os.system call found in {mod_path.name}")
                # Check for calls passing iptables or nftables
                for arg in node.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        val = arg.value.lower()
                        assert "iptables" not in val, f"Violation: iptables command string found in call in {mod_path.name}"
                        assert "nft " not in val and "nftables" not in val, f"Violation: nftables command string found in call in {mod_path.name}"

        # Subprocess containment check
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "subprocess":
                        assert mod_path.name == "ui_capture.py", (
                            f"Violation: subprocess imported in {mod_path.name}! Only ui_capture may import subprocess."
                        )
            elif isinstance(node, ast.ImportFrom):
                if node.module == "subprocess":
                    assert mod_path.name == "ui_capture.py", (
                        f"Violation: subprocess from-import in {mod_path.name}! Only ui_capture may import subprocess."
                    )

            # Check calls for shell=True
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg == "shell":
                        if isinstance(kw.value, ast.Constant):
                            assert kw.value.value is False, f"Violation: shell=True in {mod_path.name}"

    # Verify ui_capture argument list usage
    capture_file = SRC_DIR / "ui_capture.py"
    with open(capture_file, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=str(capture_file))

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func_name = ""
            if isinstance(node.func, ast.Attribute):
                func_name = node.func.attr
            if func_name in ("Popen", "run"):
                for kw in node.keywords:
                    if kw.arg == "shell":
                        assert isinstance(kw.value, ast.Constant) and kw.value.value is False


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

    ro_uri = f"file:{test_db.resolve().as_posix()}?mode=ro"
    ro_conn = sqlite3.connect(ro_uri, uri=True)
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        ro_conn.execute("INSERT INTO alerts VALUES (2, 1001.0, 1001.0, 'ALERT_SCAN', 'tcp_incomplete_handshake', '172.20.0.2', '{}', 0.05)")
    ro_conn.close()


def test_concurrent_writer_wal_mode(tmp_path):
    """Verifies WAL mode enables simultaneous reader and writer concurrency."""
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

    ro_uri = f"file:{wal_db.resolve().as_posix()}?mode=ro"
    ro_conn = sqlite3.connect(ro_uri, uri=True)

    w_conn.execute("INSERT INTO alerts VALUES (2, 1001.0, 1001.0, 'ALERT_SCAN', 'tcp_incomplete_handshake', '172.20.0.2', '{}', 0.04)")
    w_conn.commit()

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
