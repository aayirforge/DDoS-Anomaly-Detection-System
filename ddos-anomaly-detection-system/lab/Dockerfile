FROM python:3.11-slim

# Install network utilities for packet capture, routing checks, and traffic generation
RUN apt-get update && apt-get install -y --no-install-recommends \
    tshark \
    tcpdump \
    iproute2 \
    iputils-ping \
    curl \
    procps \
    ethtool \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
