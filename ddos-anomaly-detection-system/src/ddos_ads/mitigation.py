"""Automated network mitigation engine with nftables support, auto-expiring rules, and strict whitelisting."""

from __future__ import annotations

import ipaddress
from pathlib import Path
import shutil
import subprocess
import sys
import time
from typing import Dict, List, Optional, Set, Tuple

from ddos_ads.config import Config, load_config
from ddos_ads.utils import setup_logger

logger = setup_logger("ddos_ads.mitigation")


def get_system_dns_resolvers() -> List[str]:
    """Discover active DNS nameservers from /etc/resolv.conf."""
    resolvers: List[str] = []
    resolv_conf = Path("/etc/resolv.conf")
    if resolv_conf.is_file():
        try:
            with open(resolv_conf, "r", encoding="utf-8") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 2 and parts[0] == "nameserver":
                        resolvers.append(parts[1])
        except Exception as e:
            logger.warning(f"Unable to read /etc/resolv.conf: {e}")
    return resolvers


def get_default_gateways() -> List[str]:
    """Discover default route gateways from /proc/net/route or ip route."""
    gateways: List[str] = []
    route_file = Path("/proc/net/route")
    if route_file.is_file():
        try:
            with open(route_file, "r", encoding="utf-8") as f:
                header = f.readline()
                for line in f:
                    fields = line.strip().split()
                    if len(fields) >= 3 and fields[1] == "00000000":  # Default route
                        # Convert hex IP to dotted quad
                        hex_ip = fields[2]
                        ip_int = int(hex_ip, 16)
                        gw = f"{ip_int & 0xFF}.{(ip_int >> 8) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 24) & 0xFF}"
                        gateways.append(gw)
        except Exception as e:
            logger.warning(f"Unable to parse /proc/net/route: {e}")
    return gateways


def is_rfc1918(ip_str: str) -> bool:
    """Check if an IP address belongs to RFC 1918 private ranges."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except ValueError:
        return False


class MitigationManager:
    """
    Manages mitigation decisions and nftables filtering rules.

    SAFETY GUARANTEES:
      1. Default mode is strictly ALERT-ONLY. Active blocking requires explicit config + CLI flag.
      2. Whitelist ONLY suppresses blocking. It NEVER suppresses logging or alerting.
      3. Localhost (127.0.0.1, ::1), Default Gateways, and System DNS are ALWAYS whitelisted.
      4. RFC 1918 private IP exemption is a config option (default: OFF).
      5. Rules use kernel auto-expiring timeouts.
      6. Clean SIGINT handler flushes rules created by this session.
    """

    def __init__(
        self,
        config: Config,
        enable_blocking: bool = False,
        dry_run: bool = False,
    ) -> None:
        self.config = config
        # Blocking is enabled ONLY IF both config and runtime flag permit it
        config_blocking = config.get("mitigation.enable_blocking", False)
        self.enable_blocking = bool(enable_blocking and config_blocking)
        self.dry_run = dry_run or config.get("mitigation.dry_run", False)

        self.table = config.get("mitigation.nftables_table", "ddos_ads")
        self.chain = config.get("mitigation.nftables_chain", "filter_in")
        self.rule_timeout_sec = config.get("mitigation.rule_timeout_sec", 3600)
        self.consecutive_required = config.get("live_detection.consecutive_suspicious_windows", 3)
        self.cooldown_sec = config.get("live_detection.per_ip_cooldown_sec", 300)
        self.exempt_rfc1918 = config.get("mitigation.exempt_rfc1918", False)

        # Build immutable baseline whitelist
        self.mandatory_whitelist: Set[str] = {
            "127.0.0.1", "::1", "0.0.0.0", "localhost"
        }
        self.mandatory_whitelist.update(get_system_dns_resolvers())
        self.mandatory_whitelist.update(get_default_gateways())

        # Configured whitelist
        configured_wl = config.get("mitigation.whitelist_ips", [])
        self.configured_whitelist = set(configured_wl)

        # Dynamic state tracking
        self.consecutive_anomalies: Dict[str, int] = {}
        self.last_action_timestamp: Dict[str, float] = {}
        self.active_blocked_ips: Set[str] = set()

        self._nft_bin = shutil.which("nft")
        if self.enable_blocking and not self.dry_run:
            self._initialize_nftables_table()

    def _initialize_nftables_table(self) -> None:
        """Create dedicated nftables table and chain if they do not exist."""
        if not self._nft_bin:
            logger.warning("nftables binary 'nft' not found. Active blocking disabled.")
            self.enable_blocking = False
            return

        init_commands = [
            f"add table inet {self.table}",
            f"add chain inet {self.table} {self.chain} {{ type filter hook input priority -150 ; policy accept ; }}",
            f"add set inet {self.table} blocklist {{ type ipv4_addr ; flags timeout ; }}",
            f"add rule inet {self.table} {self.chain} ip saddr @blocklist drop",
        ]
        for cmd in init_commands:
            self._execute_nft(cmd)

    def _execute_nft(self, rule_str: str) -> bool:
        """Execute or simulate an nftables command."""
        full_cmd = ["nft", rule_str]
        if self.dry_run:
            logger.info(f"[DRY-RUN MITIGATION] { ' '.join(full_cmd) }")
            return True

        try:
            res = subprocess.run(full_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if res.returncode != 0:
                logger.error(f"nft command failed (exit {res.returncode}): {res.stderr.strip()}")
                return False
            return True
        except Exception as e:
            logger.error(f"Error running nftables command: {e}")
            return False

    def check_whitelist(self, ip_str: str) -> Tuple[bool, Optional[str]]:
        """
        Check if an IP address is protected by the whitelist.
        Returns:
            (is_whitelisted, reason)
        """
        clean_ip = ip_str.strip()

        # 1. Mandatory protection: Localhost, DNS, Default Gateway
        if clean_ip in self.mandatory_whitelist:
            return True, "mandatory_protected_infrastructure"

        # 2. Configured whitelist
        if clean_ip in self.configured_whitelist:
            return True, "configured_whitelist"

        # 3. Optional RFC 1918 exemption
        if self.exempt_rfc1918 and is_rfc1918(clean_ip):
            return True, "rfc1918_private_network"

        return False, None

    def evaluate_flow(
        self,
        ip_str: str,
        is_anomaly: bool,
        anomaly_score: float,
        timestamp: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Evaluate traffic flow against anomaly state, consecutive thresholds, cooldowns, and whitelisting.

        CRITICAL BEHAVIOR:
          - Whitelist ONLY suppresses active packet dropping.
          - Whitelist NEVER suppresses alerting or logging.
        """
        curr_time = timestamp or time.time()
        clean_ip = ip_str.strip()

        if clean_ip == "Unknown" or not clean_ip:
            return {"action": "IGNORE", "reason": "unknown_ip", "ip": clean_ip, "logged": False}

        # Update consecutive counter
        if is_anomaly:
            self.consecutive_anomalies[clean_ip] = self.consecutive_anomalies.get(clean_ip, 0) + 1
        else:
            self.consecutive_anomalies[clean_ip] = max(0, self.consecutive_anomalies.get(clean_ip, 0) - 1)

        count = self.consecutive_anomalies.get(clean_ip, 0)
        is_whitelisted, wl_reason = self.check_whitelist(clean_ip)

        decision: Dict[str, Any] = {
            "ip": clean_ip,
            "score": round(anomaly_score, 4),
            "consecutive_count": count,
            "is_anomaly": is_anomaly,
            "is_whitelisted": is_whitelisted,
            "whitelist_reason": wl_reason,
            "action": "NORMAL",
            "reason": "flow_benign",
            "logged": False,
        }

        if not is_anomaly:
            return decision

        # Anomaly detected: We ALWAYS log/alert regardless of whitelist status!
        decision["logged"] = True

        if count < self.consecutive_required:
            decision["action"] = "ALERT"
            decision["reason"] = f"anomaly_below_consecutive_threshold ({count}/{self.consecutive_required})"
            return decision

        # Consecutive threshold reached: Check cooldown
        last_action = self.last_action_timestamp.get(clean_ip, 0.0)
        if (curr_time - last_action) < self.cooldown_sec and clean_ip in self.active_blocked_ips:
            decision["action"] = "ALERT"
            decision["reason"] = f"cooldown_active ({int(curr_time - last_action)}s/{self.cooldown_sec}s)"
            return decision

        # Check whitelist before attempting active blocking
        if is_whitelisted:
            decision["action"] = "ALERT"
            decision["reason"] = f"blocking_suppressed_by_whitelist ({wl_reason})"
            return decision

        # Active blocking logic
        if self.enable_blocking:
            success = self.block_ip(clean_ip, timeout_sec=self.rule_timeout_sec)
            self.last_action_timestamp[clean_ip] = curr_time
            if success:
                decision["action"] = "BLOCKED"
                decision["reason"] = f"nftables_drop_rule_applied (timeout={self.rule_timeout_sec}s)"
                self.active_blocked_ips.add(clean_ip)
            else:
                decision["action"] = "ALERT"
                decision["reason"] = "nftables_command_failed"
        else:
            decision["action"] = "ALERT"
            decision["reason"] = "blocking_disabled_by_policy"

        return decision

    def block_ip(self, ip_str: str, timeout_sec: int = 3600) -> bool:
        """Add an auto-expiring drop rule to the nftables blocklist set."""
        rule = f"add element inet {self.table} blocklist {{ {ip_str} timeout {timeout_sec}s }}"
        logger.warning(f"MITIGATION ACTION: Applying nftables drop for IP {ip_str} (timeout={timeout_sec}s)...")
        return self._execute_nft(rule)

    def unblock_ip(self, ip_str: str) -> bool:
        """Manually remove an IP from the nftables blocklist set."""
        rule = f"delete element inet {self.table} blocklist {{ {ip_str} }}"
        logger.info(f"MITIGATION: Removing IP {ip_str} from nftables blocklist...")
        success = self._execute_nft(rule)
        if clean_ip := ip_str.strip() in self.active_blocked_ips:
            self.active_blocked_ips.discard(clean_ip)
        return success

    def cleanup_rules(self) -> None:
        """Clean shutdown: flush or delete created nftables table."""
        if not self.enable_blocking or self.dry_run:
            return

        logger.info("Cleaning up active nftables rules created during session...")
        cmd = f"delete table inet {self.table}"
        self._execute_nft(cmd)
        self.active_blocked_ips.clear()
