#!/usr/bin/env bash
# Strict verification script for isolated internal-only lab network.
# Fails with exit code 1 if any container has an outbound Internet route.

set -euo pipefail

CONTAINERS=("victim-web" "benign-client" "traffic-generator")
NETWORK_NAME="lab_isolated_lab_net"

echo "================================================================================"
echo "          VERIFYING ISOLATED INTERNAL-ONLY DOCKER LAB NETWORK"
echo "================================================================================"

# 1. Verify Docker network configuration
echo "[1/4] Inspecting Docker network configuration..."
INTERNAL_VAL=$(docker network inspect "$NETWORK_NAME" --format '{{.Internal}}' 2>/dev/null || echo "false")
if [ "$INTERNAL_VAL" != "true" ]; then
    # Try finding network by substring
    ACTUAL_NET=$(docker network ls --filter name=isolated_lab_net --format '{{.Name}}' | head -n 1)
    if [ -n "$ACTUAL_NET" ]; then
        INTERNAL_VAL=$(docker network inspect "$ACTUAL_NET" --format '{{.Internal}}')
        NETWORK_NAME="$ACTUAL_NET"
    fi
fi

if [ "$INTERNAL_VAL" != "true" ]; then
    echo "[-] FAILED: Network '$NETWORK_NAME' is NOT internal (Internal = $INTERNAL_VAL). External routing is prohibited!" >&2
    exit 1
fi
echo "[+] Network '$NETWORK_NAME' verified with Internal = true."

# 2. Check routing table in each container
echo "[2/4] Verifying routing tables in all containers (default gateway check)..."
for c in "${CONTAINERS[@]}"; do
    DEF_ROUTE=$(docker exec "$c" ip route | grep -E '^default' || true)
    if [ -n "$DEF_ROUTE" ]; then
        echo "[-] FAILED: Container '$c' has an outbound default route: $DEF_ROUTE" >&2
        exit 1
    fi
    echo "[+] Container '$c': No default gateway present."
done

# 3. Attempt outbound probes (must all fail)
echo "[3/4] Verifying outbound egress is completely unreachable..."
for c in "${CONTAINERS[@]}"; do
    # Probe public IP 8.8.8.8
    if docker exec "$c" ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
        echo "[-] FAILED: Container '$c' successfully reached 8.8.8.8! Outbound route detected!" >&2
        exit 1
    fi

    # Probe public IP 1.1.1.1 via curl
    if docker exec "$c" curl -s --max-time 2 http://1.1.1.1 >/dev/null 2>&1; then
        echo "[-] FAILED: Container '$c' successfully reached 1.1.1.1 via HTTP! Outbound route detected!" >&2
        exit 1
    fi
    echo "[+] Container '$c': Outbound connections to external Internet are completely blocked."
done

# 4. Verify internal cross-container connectivity
echo "[4/4] Verifying internal inter-container connectivity..."
if ! docker exec benign-client curl -s --max-time 3 http://victim-web/api/v1/health >/dev/null; then
    echo "[-] FAILED: benign-client could not reach victim-web inside internal network!" >&2
    exit 1
fi
echo "[+] Internal connectivity confirmed: benign-client <-> victim-web."

echo "================================================================================"
echo "[SUCCESS] STRICT ISOLATION CONFIRMED: internal: true, zero outbound routes."
echo "================================================================================"
exit 0
