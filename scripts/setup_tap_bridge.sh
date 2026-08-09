#!/usr/bin/env bash
# scripts/setup_tap_bridge.sh
# Linux TAP Device & NAT Bridge Setup Script for aegis-sandbox
# Author: Kamran Saberifard
# License: Apache 2.0

set -euo pipefail

# Color formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

BRIDGE_NAME=${BRIDGE_NAME:-"aegis-br0"}
BRIDGE_IP=${BRIDGE_IP:-"172.16.0.1/24"}
SUBNET_RANGE=${SUBNET_RANGE:-"172.16.0.0/24"}

echo -e "${GREEN}[AEGIS-NET] Setting up Linux TAP Network Bridge for Firecracker MicroVMs...${NC}"

# 1. Require Root / Sudo Privileges
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[CRITICAL] This script must be run as root (use sudo).${NC}"
    exit 1
fi

# 2. Auto-detect Host Primary Egress Network Interface
HOST_IF=$(ip route show default | awk '/default/ {print $5}' | head -n1)
if [ -z "${HOST_IF}" ]; then
    echo -e "${RED}[CRITICAL] Could not auto-detect host default network interface.${NC}"
    exit 1
fi

echo -e "${YELLOW}[AEGIS-NET] Host Primary Egress Interface: ${HOST_IF}${NC}"
echo -e "${YELLOW}[AEGIS-NET] Aegis Bridge Interface        : ${BRIDGE_NAME} (${BRIDGE_IP})${NC}"

# 3. Create Bridge Interface if it does not exist
if ! ip link show "${BRIDGE_NAME}" &>/dev/null; then
    echo -e "${YELLOW}[AEGIS-NET] Creating Linux bridge ${BRIDGE_NAME}...${NC}"
    ip link add name "${BRIDGE_NAME}" type bridge
fi

# Assign IP to Bridge if not already assigned
if ! ip addr show dev "${BRIDGE_NAME}" | grep -q "${BRIDGE_IP}"; then
    ip addr add "${BRIDGE_IP}" dev "${BRIDGE_NAME}"
fi

# Bring Bridge Interface UP
ip link set dev "${BRIDGE_NAME}" up

# 4. Enable Kernel IPv4 Forwarding
echo -e "${YELLOW}[AEGIS-NET] Enabling IPv4 Kernel Packet Forwarding...${NC}"
sysctl -w net.ipv4.ip_forward=1 > /dev/null

# 5. Configure iptables NAT & Forwarding Rules
echo -e "${YELLOW}[AEGIS-NET] Configuring iptables MASQUERADE NAT Rules...${NC}"

# Allow forwarding from aegis-br0 to host egress interface
iptables -C FORWARD -i "${BRIDGE_NAME}" -o "${HOST_IF}" -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -i "${BRIDGE_NAME}" -o "${HOST_IF}" -j ACCEPT

# Allow established connections back into aegis-br0
iptables -C FORWARD -i "${HOST_IF}" -o "${BRIDGE_NAME}" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -i "${HOST_IF}" -o "${BRIDGE_NAME}" -m state --state RELATED,ESTABLISHED -j ACCEPT

# Enable NAT MASQUERADE for outbound microVM traffic
iptables -t nat -C POSTROUTING -s "${SUBNET_RANGE}" -o "${HOST_IF}" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s "${SUBNET_RANGE}" -o "${HOST_IF}" -j MASQUERADE

# 6. Helper Function: Create and Attach a TAP device for a specific sandbox ID
create_sandbox_tap() {
    local TAP_NAME=$1
    if ! ip link show "${TAP_NAME}" &>/dev/null; then
        echo -e "${YELLOW}[AEGIS-NET] Creating TAP device ${TAP_NAME}...${NC}"
        ip tuntap add dev "${TAP_NAME}" mode tap
        ip link set dev "${TAP_NAME}" master "${BRIDGE_NAME}"
        ip link set dev "${TAP_NAME}" up
    fi
}

# Optional argument: if TAP interface name passed as $1, attach it to bridge
if [ $# -ge 1 ]; then
    create_sandbox_tap "$1"
fi

echo -e "${GREEN}[AEGIS-SUCCESS] Network Bridge ${BRIDGE_NAME} configured and ready!${NC}"