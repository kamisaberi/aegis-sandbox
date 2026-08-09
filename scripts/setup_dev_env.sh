#!/usr/bin/env bash
# scripts/setup_dev_env.sh
# Development Environment & System Dependency Installer for aegis-sandbox
# Author: Kamran Saberifard
# License: Apache 2.0

set -euo pipefail

# Color formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

FIRECRACKER_VERSION="v1.8.0"
KERNEL_VERSION="vmlinux-6.6.x"

echo -e "${GREEN}[AEGIS-SETUP] Setting up Development Environment for aegis-sandbox...${NC}"

# 1. Verify Sudo / Root Privileges
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[CRITICAL] This script must be run with root/sudo privileges.${NC}"
    exit 1
fi

# 2. Check Hardware Virtualization (KVM) Support
echo -e "${YELLOW}[AEGIS-SETUP] Checking KVM (/dev/kvm) hardware virtualization support...${NC}"
if [ ! -e /dev/kvm ]; then
    echo -e "${RED}[CRITICAL] /dev/kvm device node not found. Hardware virtualization must be enabled in BIOS/Hypervisor.${NC}"
    exit 1
fi

# Grant /dev/kvm read/write permissions for current user
chmod 666 /dev/kvm
echo -e "${GREEN}[AEGIS-SETUP] KVM hardware acceleration confirmed (/dev/kvm).${NC}"

# 3. Install System Dependencies (Ubuntu / Debian)
echo -e "${YELLOW}[AEGIS-SETUP] Installing Clang 18, libbpf, bpftool, CMake, & Go...${NC}"
apt-get update -qq
apt-get install -y --no-install-recommends \
    build-essential \
    clang-18 \
    clang-tools-18 \
    llvm-18 \
    llvm-18-dev \
    lld-18 \
    libbpf-dev \
    libelf-dev \
    bpftool \
    pkg-config \
    cmake \
    ninja-build \
    golang-go \
    git \
    curl \
    jq \
    rsync \
    e2fsprogs \
    iptables \
    iproute2 \
    ca-certificates

# Set Clang 18 as default C/C++ compiler
update-alternatives --install /usr/bin/clang clang /usr/bin/clang-18 100
update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-18 100

# 4. Install Firecracker Binary
echo -e "${YELLOW}[AEGIS-SETUP] Downloading & Installing Firecracker (${FIRECRACKER_VERSION})...${NC}"
ARCH="$(uname -m)"
FC_URL="https://github.com/firecracker-microvm/firecracker/releases/download/${FIRECRACKER_VERSION}/firecracker-${FIRECRACKER_VERSION}-${ARCH}.tgz"

TEMP_DIR=$(mktemp -d)
curl -sSL "${FC_URL}" | tar -xz -C "${TEMP_DIR}"
cp "${TEMP_DIR}/release-${FIRECRACKER_VERSION}-${ARCH}/firecracker-${FIRECRACKER_VERSION}-${ARCH}" /usr/local/bin/firecracker
chmod +x /usr/local/bin/firecracker
rm -rf "${TEMP_DIR}"

echo -e "${GREEN}[AEGIS-SETUP] Firecracker installed: $(firecracker --version | head -n1)${NC}"

# 5. Create Aegis System Storage Directories
echo -e "${YELLOW}[AEGIS-SETUP] Creating system directories in /var/lib/aegis...${NC}"
mkdir -p /var/lib/aegis/kernel
mkdir -p /var/lib/aegis/rootfs
mkdir -p /var/lib/aegis/snapshots
mkdir -p /var/run/aegis
mkdir -p /sys/fs/cgroup/aegis

# 6. Verify Cgroups v2 Mount
echo -e "${YELLOW}[AEGIS-SETUP] Verifying Cgroups v2 unified hierarchy...${NC}"
if mount | grep -q "cgroup2 on /sys/fs/cgroup"; then
    echo -e "${GREEN}[AEGIS-SETUP] Cgroups v2 unified hierarchy confirmed.${NC}"
else
    echo -e "${YELLOW}[AEGIS-SETUP] Mounting Cgroups v2 at /sys/fs/cgroup...${NC}"
    mount -t cgroup2 none /sys/fs/cgroup
fi

# Enable CPU, Memory, and PID controllers in Cgroups v2 root
if [ -f /sys/fs/cgroup/cgroup.subtree_control ]; then
    echo "+cpu +memory +pids" > /sys/fs/cgroup/cgroup.subtree_control || true
fi

# 7. Download Pre-Compiled Uncompressed Linux Kernel (vmlinux-6.6.x)
if [ ! -f /var/lib/aegis/kernel/vmlinux-6.6.x ]; then
    echo -e "${YELLOW}[AEGIS-SETUP] Fetching pre-compiled Firecracker Linux Kernel (vmlinux-6.6.x)...${NC}"
    KERNEL_URL="https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.8.0/x86_64/vmlinux-6.1.102"
    curl -sSL "${KERNEL_URL}" -o /var/lib/aegis/kernel/vmlinux-6.6.x
    chmod 644 /var/lib/aegis/kernel/vmlinux-6.6.x
fi

echo -e "${GREEN}[AEGIS-SUCCESS] Environment Setup Complete! You are ready to build aegis-sandbox.${NC}"
echo -e "${GREEN}Run 'make' or 'cmake -B build -G Ninja && ninja -C build' to compile.${NC}"