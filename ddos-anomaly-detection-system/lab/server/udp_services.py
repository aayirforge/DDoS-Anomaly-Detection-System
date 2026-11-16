#!/usr/bin/env python3
"""
Multi-service UDP responder for Session 2c / Session 3 lab testing.
Listens on:
  - UDP 53: Mock DNS responder
  - UDP 123: Mock NTP responder
  - UDP 7: Mock Echo service
  - UDP 5004: Mock RTP media streaming sink
"""
import socket
import select
import struct
import time
import os

def build_dns_response(query_data):
    if len(query_data) < 12:
        return b"\x00" * 12
    tx_id = query_data[:2]
    flags = b"\x81\x80"  # Standard query response, No error
    qdcount = query_data[4:6]
    ancount = b"\x00\x01"  # 1 answer
    nscount = b"\x00\x00"
    arcount = b"\x00\x00"
    header = tx_id + flags + qdcount + ancount + nscount + arcount
    
    # Extract query name
    idx = 12
    while idx < len(query_data) and query_data[idx] != 0:
        idx += 1 + query_data[idx]
    idx += 5 # skip null byte, qtype, qclass
    question = query_data[12:idx]
    
    # Mock A record: name ptr 0xc00c, type A (1), class IN (1), TTL 300, len 4, IP 172.20.0.2
    answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\xac\x14\x00\x02"
    return header + question + answer

def build_ntp_response(query_data):
    # Standard 48-byte NTP response
    resp = bytearray(48)
    resp[0] = 0x24  # LI=0, VN=4, Mode=4 (server)
    resp[1] = 1     # Stratum 1
    resp[2] = 6     # Poll
    resp[3] = 0xec  # Precision
    struct.pack_into("!I", resp, 12, 0x4c4f434c) # Reference ID "LOCL"
    t = int(time.time() + 2208988800) # NTP epoch offset
    struct.pack_into("!II", resp, 40, t, 0) # Transmit timestamp
    return bytes(resp)

def run():
    sock_dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_dns.bind(("0.0.0.0", 53))
    
    sock_ntp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_ntp.bind(("0.0.0.0", 123))
    
    sock_echo = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_echo.bind(("0.0.0.0", 7))
    
    sock_rtp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_rtp.bind(("0.0.0.0", 5004))
    
    sockets = [sock_dns, sock_ntp, sock_echo, sock_rtp]
    print("UDP Multi-service responder active on ports 53, 123, 7, 5004...")
    
    while True:
        readable, _, _ = select.select(sockets, [], [])
        for s in readable:
            data, addr = s.recvfrom(2048)
            if s is sock_dns:
                resp = build_dns_response(data)
                s.sendto(resp, addr)
            elif s is sock_ntp:
                resp = build_ntp_response(data)
                s.sendto(resp, addr)
            elif s is sock_echo:
                s.sendto(b"ECHO: " + data, addr)
            elif s is sock_rtp:
                # Streaming sink: consume datagram, no response (unidirectional RTP)
                pass

if __name__ == "__main__":
    run()
