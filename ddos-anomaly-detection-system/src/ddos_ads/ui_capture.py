"""
Phase 10 UI Capture and Subprocess Module.
=========================================
Strict Safety Guarantees:
1. ONLY module in UI code that imports subprocess.
2. ALL subprocess invocations strictly use argument lists (NEVER shell=True).
3. Fixed command templates with duration cap (30s to 900s) and size cap (500 MB).
4. Strictly requires user permission acknowledgment checkbox before starting capture.
5. Rejects interfaces not present in the allowlist.
6. Handles unprivileged dumpcap execution gracefully without crashing, providing
   actionable remediation instructions for Linux (capabilities/wireshark group)
   and Windows (Npcap).
7. Manages capture process lifecycle with SIGTERM and drop-count accounting.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import signal
import subprocess
from typing import Any, Dict, List, Optional, Tuple

DUMPCAP_BIN = "dumpcap"
TSHARK_BIN = "tshark"
LIBREOFFICE_BIN = "libreoffice"

MIN_CAPTURE_DURATION_SEC = 30
MAX_CAPTURE_DURATION_SEC = 900  # 15 minutes
MAX_CAPTURE_FILESIZE_KB = 500_000  # 500 MB

UNPRIVILEGED_CAPTURE_MSG = (
    "dumpcap lacks network capture privileges. "
    "On Linux: configure packet capture capabilities with "
    "`sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap` or add your user "
    "to the wireshark group (`sudo usermod -aG wireshark $USER`) and start a new session. "
    "On Windows: install Npcap with WinPcap compatibility mode."
)


def check_dumpcap_privileges() -> Tuple[bool, str]:
    """
    Checks if dumpcap can enumerate interfaces and capture traffic.
    Returns (has_privileges, message). Never crashes.
    """
    try:
        cmd = [DUMPCAP_BIN, "-D"]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
        if res.returncode == 0 and res.stdout.strip():
            return True, "Capture privileges verified."
        stderr = res.stderr.strip()
        return False, f"{UNPRIVILEGED_CAPTURE_MSG}\n(dumpcap detail: {stderr})"
    except (subprocess.SubprocessError, OSError) as e:
        return False, f"{UNPRIVILEGED_CAPTURE_MSG}\n(system detail: {e})"


def get_allowed_interfaces() -> List[Tuple[str, str]]:
    """
    Retrieves the allowlist of capture interfaces listed by `dumpcap -D`.
    Returns list of (interface_identifier, display_name).
    Never crashes if unprivileged.
    """
    interfaces: List[Tuple[str, str]] = []
    try:
        cmd = [DUMPCAP_BIN, "-D"]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                # Line format: "1. eth0 [description]" or "1. eth0"
                match = re.match(r"^(\d+)\.\s+(\S+)(?:\s+\((.*?)\))?", line)
                if match:
                    idx, iface_name, desc = match.groups()
                    display = f"{iface_name} ({desc})" if desc else iface_name
                    interfaces.append((iface_name, display))
    except Exception:
        pass

    return interfaces


def build_dumpcap_command(
    iface: str,
    duration_sec: int,
    out_pcapng: Path,
    filesize_kb: int = MAX_CAPTURE_FILESIZE_KB,
    permission_acknowledged: bool = False,
    allowed_ifaces: Optional[List[str]] = None,
) -> List[str]:
    """
    Constructs the fixed-template dumpcap command.
    Enforces strict safety constraints:
    - User permission acknowledgment checkbox must be checked.
    - Interface must be in allowed interfaces list.
    - Duration must be capped between 30 and 900 seconds.
    - File size cap enforced.
    - Fixed template with argument list (NO shell).
    """
    if not permission_acknowledged:
        raise PermissionError(
            "Start refused: You must confirm that you own this network or have permission to capture on it."
        )

    if allowed_ifaces is not None and iface not in allowed_ifaces:
        raise ValueError(
            f"Interface '{iface}' is not in allowlist of available interfaces ({allowed_ifaces})."
        )

    if duration_sec < MIN_CAPTURE_DURATION_SEC or duration_sec > MAX_CAPTURE_DURATION_SEC:
        raise ValueError(
            f"Capture duration must be between {MIN_CAPTURE_DURATION_SEC} s and {MAX_CAPTURE_DURATION_SEC} s "
            f"(requested: {duration_sec} s)."
        )

    clamped_filesize = min(filesize_kb, MAX_CAPTURE_FILESIZE_KB)

    cmd = [
        DUMPCAP_BIN,
        "-i",
        str(iface),
        "-a",
        f"duration:{int(duration_sec)}",
        "-b",
        f"filesize:{int(clamped_filesize)}",
        "-w",
        str(out_pcapng),
    ]
    return cmd


def start_live_capture(cmd: List[str], permission_acknowledged: bool = False) -> subprocess.Popen:
    """
    Starts dumpcap as a background child process without shell.
    Strictly enforces permission acknowledgment flag in the backend function.
    """
    if not permission_acknowledged:
        raise PermissionError(
            "Start refused: You must confirm that you own this network or have permission to capture on it."
        )
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    return proc


def stop_live_capture(proc: subprocess.Popen, timeout_sec: float = 5.0) -> Tuple[int, str, str]:
    """
    Stops a running dumpcap capture by sending SIGTERM and waiting.
    Sends SIGKILL if process does not exit within timeout.
    Returns (returncode, stdout, stderr).
    """
    if proc.poll() is None:
        try:
            proc.terminate()
            proc.wait(timeout=timeout_sec)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    stdout, stderr = proc.communicate()
    return proc.returncode, stdout, stderr


def parse_dumpcap_drops(stderr_text: str) -> int:
    """
    Extracts dropped-packet count from dumpcap stderr text.
    """
    # Matches patterns like "Packets dropped: 14" or "Dropped: 14"
    match = re.search(r"[Pp]ackets dropped:\s*(\d+)", stderr_text)
    if match:
        return int(match.group(1))
    match_alt = re.search(r"dropped:\s*(\d+)", stderr_text)
    if match_alt:
        return int(match_alt.group(1))
    return 0


def get_pcap_metadata_and_packets(pcap_path: Path) -> Dict[str, Any]:
    """
    Runs tshark via argument list to extract packet count, timestamps, duration,
    and truncation status.
    """
    if not pcap_path.is_file():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    size_bytes = pcap_path.stat().st_size
    if size_bytes < 24:
        return {
            "packet_count": 0,
            "first_pkt_ts": None,
            "last_pkt_ts": None,
            "duration_sec": 0.0,
            "is_truncated": True,
            "destination_counts": {},
            "destination_timeseries": {},
            "raw_packet_records": [],
        }

    cmd = [
        TSHARK_BIN,
        "-r",
        str(pcap_path),
        "-T",
        "fields",
        "-e",
        "frame.time_epoch",
        "-e",
        "ip.src",
        "-e",
        "ip.dst",
        "-e",
        "ip.proto",
        "-e",
        "tcp.dstport",
        "-e",
        "udp.dstport",
    ]

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    first_ts: Optional[float] = None
    last_ts: Optional[float] = None
    packet_count = 0
    dst_counts: Dict[str, int] = {}
    dst_ts_map: Dict[str, List[float]] = {}
    packet_records: List[Dict[str, Any]] = []

    if proc.stdout:
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            parts = line.split("\t")
            if not parts or not parts[0]:
                continue
            try:
                ts = float(parts[0])
            except ValueError:
                continue

            packet_count += 1
            if first_ts is None:
                first_ts = ts
            last_ts = ts

            dst_ip = parts[2] if len(parts) > 2 and parts[2] else "unknown"
            if dst_ip != "unknown":
                dst_counts[dst_ip] = dst_counts.get(dst_ip, 0) + 1
                if dst_ip not in dst_ts_map:
                    dst_ts_map[dst_ip] = []
                dst_ts_map[dst_ip].append(ts)

            packet_records.append({
                "ts": ts,
                "src": parts[1] if len(parts) > 1 else "",
                "dst": dst_ip,
                "proto": parts[3] if len(parts) > 3 else "",
            })

    _, stderr = proc.communicate()
    is_truncated = False
    if proc.returncode != 0:
        is_truncated = True
    if stderr:
        low_err = stderr.lower()
        if any(term in low_err for term in ["cut short", "less than expected", "truncated", "damaged", "corrupt", "malformed"]):
            is_truncated = True
    if size_bytes > 24 and packet_count == 0:
        is_truncated = True

    duration = round((last_ts - first_ts), 4) if (first_ts is not None and last_ts is not None) else 0.0

    return {
        "packet_count": packet_count,
        "first_pkt_ts": first_ts,
        "last_pkt_ts": last_ts,
        "duration_sec": duration,
        "is_truncated": is_truncated,
        "destination_counts": dst_counts,
        "destination_timeseries": dst_ts_map,
        "raw_packet_records": packet_records,
    }


def convert_html_to_pdf_and_docx(html_path: Path, out_dir: Path) -> Tuple[Optional[Path], Optional[Path]]:
    """
    Converts HTML report to PDF and DOCX via LibreOffice headless.
    Argument lists only (NEVER shell=True).
    """
    pdf_path = out_dir / (html_path.stem + ".pdf")
    docx_path = out_dir / (html_path.stem + ".docx")

    # 1. Convert to PDF
    cmd_pdf = [
        LIBREOFFICE_BIN,
        "-env:UserInstallation=file:///tmp/lo_ui_inst",
        "--headless",
        "--infilter=HTML (StarWriter)",
        "--convert-to",
        "pdf",
        str(html_path),
        "--outdir",
        str(out_dir),
    ]
    try:
        res = subprocess.run(cmd_pdf, capture_output=True, text=True, timeout=60)
        if res.returncode != 0 or not pdf_path.is_file():
            pdf_path = None
    except Exception:
        pdf_path = None

    # 2. Convert to DOCX
    cmd_docx = [
        LIBREOFFICE_BIN,
        "-env:UserInstallation=file:///tmp/lo_ui_inst",
        "--headless",
        "--infilter=HTML (StarWriter)",
        "--convert-to",
        "docx",
        str(html_path),
        "--outdir",
        str(out_dir),
    ]
    try:
        res = subprocess.run(cmd_docx, capture_output=True, text=True, timeout=60)
        if res.returncode != 0 or not docx_path.is_file():
            docx_path = None
    except Exception:
        docx_path = None

    return pdf_path, docx_path
