"""
Test 20k pps / cap 160,000 run for 120 seconds.
Inspect all alerts emitted (timestamps, counts, details).
"""

import random
from ddos_ads.rule_engine import RuleEngine

def test_20k_160k():
    engine = RuleEngine(victim_ip="172.20.0.2", max_handshakes=160_000)
    rng = random.Random(42)
    sim_ts = 1000.0
    rate = 20_000
    duration_s = 120
    dt = 1.0 / rate
    total_pkts = rate * duration_s
    
    benign_interval = rate
    benign_port = 10000
    pending_acks = []
    
    # We will step through and record alerts
    alerts_recorded = []
    
    # Let's run and check
    for i in range(total_pkts):
        sim_ts += dt
        while pending_acks and sim_ts >= pending_acks[0][0]:
            ack_ts, p = pending_acks.pop(0)
            a = engine.process_packet(ack_ts, "172.20.0.4", "172.20.0.2", p, 80, "tcp", syn=0, ack=1)
            if a:
                alerts_recorded.extend(a)
                
        src_ip = f"172.20.{rng.randint(10, 254)}.{rng.randint(1, 254)}"
        sport = rng.randint(1024, 65535)
        a = engine.process_packet(sim_ts, src_ip, "172.20.0.2", sport, 80, "tcp", syn=1, ack=0)
        if a:
            alerts_recorded.extend(a)
            
        if i % benign_interval == 0:
            benign_port += 1
            a = engine.process_packet(sim_ts, "172.20.0.4", "172.20.0.2", benign_port, 80, "tcp", syn=1, ack=0)
            if a:
                alerts_recorded.extend(a)
            pending_acks.append((sim_ts + 0.05, benign_port))
            
    print(f"Total alerts in 120s run: {len(alerts_recorded)}")
    for idx, alert in enumerate(alerts_recorded[:10]):
        print(f"Alert {idx+1}: ts={alert.packet_ts:.3f}, type={alert.alert_type}, rule={alert.rule}, details={alert.details}")
    if len(alerts_recorded) > 10:
        print(f"... and {len(alerts_recorded)-10} more alerts.")
        for idx, alert in enumerate(alerts_recorded[-3:]):
            print(f"Final Alert {len(alerts_recorded)-2+idx}: ts={alert.packet_ts:.3f}")

if __name__ == "__main__":
    test_20k_160k()
