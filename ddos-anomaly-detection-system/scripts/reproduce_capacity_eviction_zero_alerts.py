"""
Reproduce spoofed SYN at 20k/40k/80k pps with table cap 20,000 producing 0 alerts.
Prints per-second table occupancy, eviction count, and incomplete_window size for the first 10 s.
"""

from __future__ import annotations
import random
from typing import Dict, List
from ddos_ads.rule_engine import RuleEngine

def run_reproduction():
    rates = [20_000, 40_000, 80_000]
    cap = 20_000
    duration_s = 10.0

    print("=== REPRODUCTION: Spoofed SYN Flood with Table Cap 20,000 ===")
    for rate in rates:
        print(f"\n--- Testing Rate: {rate:,} pps (Cap = {cap:,}) ---")
        engine = RuleEngine(victim_ip="172.20.0.2", max_handshakes=cap)
        rng = random.Random(42)
        sim_ts = 1000.0
        dt = 1.0 / rate
        
        alerts_by_sec = [0] * int(duration_s)
        total_alerts = 0
        
        for sec in range(int(duration_s)):
            prev_evictions = engine.capacity_evictions
            for _ in range(rate):
                sim_ts += dt
                src_ip = f"172.20.{rng.randint(10, 254)}.{rng.randint(1, 254)}"
                sport = rng.randint(1024, 65535)
                alerts = engine.process_packet(sim_ts, src_ip, "172.20.0.2", sport, 80, "tcp", syn=1, ack=0)
                if alerts:
                    alerts_by_sec[sec] += len(alerts)
                    total_alerts += len(alerts)
            
            sec_evictions = engine.capacity_evictions - prev_evictions
            print(
                f"Second {sec+1:2d} | Sim TS: {sim_ts:.1f} | "
                f"Table Occupancy: {len(engine.active_handshakes):,}/{cap:,} | "
                f"Sec Evictions: {sec_evictions:,} | Total Evictions: {engine.capacity_evictions:,} | "
                f"incomplete_window size: {len(engine.incomplete_window)} | "
                f"Alerts: {alerts_by_sec[sec]}"
            )
        print(f"Total Alerts emitted for {rate:,} pps: {total_alerts}")

if __name__ == "__main__":
    run_reproduction()
