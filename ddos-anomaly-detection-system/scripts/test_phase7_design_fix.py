"""
Test Phase 7 Design Fix:
1. 6 flood cases: 20k, 40k, 80k pps x 20k, 160k cap. All must alert within 3.0s. Print exact alert times.
2. Benign flash crowd of 5,000 connections (cap 1,000). Must produce 0 alerts.
"""

from __future__ import annotations
import json
from pathlib import Path
import random
from typing import Any, Dict, List
from ddos_ads.rule_engine import RuleEngine

def run_tests():
    rates = [20_000, 40_000, 80_000]
    caps = [20_000, 160_000]
    
    flood_results = []
    
    print("=== TESTING 6 FLOOD CASES (20k, 40k, 80k pps x 20k, 160k cap) ===")
    for cap in caps:
        for rate in rates:
            engine = RuleEngine(victim_ip="172.20.0.2", max_handshakes=cap)
            rng = random.Random(42)
            sim_ts = 1000.0
            dt = 1.0 / rate
            duration_s = 5.0
            total_pkts = int(rate * duration_s)
            
            first_alert_time_s = None
            first_alert_record = None
            total_alerts = 0
            
            for i in range(total_pkts):
                sim_ts += dt
                src_ip = f"172.20.{rng.randint(10, 254)}.{rng.randint(1, 254)}"
                sport = rng.randint(1024, 65535)
                alerts = engine.process_packet(sim_ts, src_ip, "172.20.0.2", sport, 80, "tcp", syn=1, ack=0)
                if alerts:
                    total_alerts += len(alerts)
                    if first_alert_time_s is None:
                        first_alert_time_s = round(sim_ts - 1000.0, 6)
                        first_alert_record = alerts[0].to_dict()
            
            res = {
                "table_capacity_cap": cap,
                "packet_rate_pps": rate,
                "first_alert_time_sec": first_alert_time_s,
                "alerts_within_3s": bool(first_alert_time_s is not None and first_alert_time_s <= 3.0),
                "total_alerts_5s": total_alerts,
                "first_alert_rule": first_alert_record.get("rule") if first_alert_record else None,
                "first_alert_type": first_alert_record.get("alert_type") if first_alert_record else None,
                "first_alert_details": first_alert_record.get("details") if first_alert_record else None,
            }
            flood_results.append(res)
            print(
                f"Cap: {cap:7,d} | Rate: {rate:6,d} pps | "
                f"First Alert Delay: {first_alert_time_s:.6f}s (<= 3.0s: {res['alerts_within_3s']}) | "
                f"Total Alerts: {total_alerts} | Rule: {res['first_alert_rule']}"
            )

    print("\n=== TESTING BENIGN FLASH CROWD (5,000 connections, table cap 1,000) ===")
    flash_engine = RuleEngine(victim_ip="172.20.0.2", max_handshakes=1000)
    fc_ts = 200.0
    fc_alerts = []
    
    # 5,000 legitimate clients connect (SYN followed by completing ACK)
    rng_fc = random.Random(123)
    pending_acks = []
    
    for i in range(5000):
        fc_ts += 0.001  # 1,000 connections / sec
        src_ip = f"10.0.{(i // 250) % 250}.{(i % 250) + 1}"
        sport = 1024 + (i % 60000)
        
        # Process scheduled ACKs
        while pending_acks and fc_ts >= pending_acks[0][0]:
            ack_ts, ack_ip, ack_port = pending_acks.pop(0)
            a = flash_engine.process_packet(ack_ts, ack_ip, "172.20.0.2", ack_port, 80, "tcp", syn=0, ack=1)
            fc_alerts.extend(a)
            
        a = flash_engine.process_packet(fc_ts, src_ip, "172.20.0.2", sport, 80, "tcp", syn=1, ack=0)
        fc_alerts.extend(a)
        pending_acks.append((fc_ts + 0.005, src_ip, sport))
        
    # Flush remaining ACKs
    while pending_acks:
        ack_ts, ack_ip, ack_port = pending_acks.pop(0)
        a = flash_engine.process_packet(ack_ts, ack_ip, "172.20.0.2", ack_port, 80, "tcp", syn=0, ack=1)
        fc_alerts.extend(a)
        
    print(f"Benign Flash Crowd: Connections=5,000 | Table Cap=1,000 | Capacity Evictions={flash_engine.capacity_evictions:,} | Alerts={len(fc_alerts)}")
    
    return flood_results, len(fc_alerts)

if __name__ == "__main__":
    run_tests()
