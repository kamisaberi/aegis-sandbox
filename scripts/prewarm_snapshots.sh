#!/usr/bin/env bash
# scripts/prewarm_snapshots.sh
# Firecracker MicroVM Snapshot Pre-Warming Script for aegis-sandbox
# Author: Kamran Saberifard
# License: Apache 2.0

set -euo pipefail

# Color formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

FIRECRACKER_BIN=${FIRECRACKER_BIN:-"/usr/local/bin/firecracker"}
KERNEL_PATH=${KERNEL_PATH:-"/var/lib/aegis/kernel/vmlinux-6.6.x"}
ROOTFS_PATH=${ROOTFS_PATH:-"/var/lib/aegis/rootfs/alpine-python311.ext4"}
SNAPSHOT_DIR=${SNAPSHOT_DIR:-"/var/lib/aegis/snapshots"}
API_SOCKET="/tmp/aegis-prewarm.sock"

echo -e "${GREEN}[AEGIS-SNAPSHOT] Pre-Warming Firecracker MicroVM Snapshot...${NC}"

# 1. Verify Prerequisites
if [ ! -x "${FIRECRACKER_BIN}" ]; then
    echo -e "${RED}[CRITICAL] Firecracker binary not found or not executable: ${FIRECRACKER_BIN}${NC}"
    exit 1
fi

if [ ! -f "${KERNEL_PATH}" ]; then
    echo -e "${RED}[CRITICAL] Kernel image not found at: ${KERNEL_PATH}${NC}"
    exit 1
fi

if [ ! -f "${ROOTFS_PATH}" ]; then
    echo -e "${RED}[CRITICAL] RootFS image not found at: ${ROOTFS_PATH}${NC}"
    exit 1
fi

mkdir -p "${SNAPSHOT_DIR}"
rm -f "${API_SOCKET}" "${SNAPSHOT_DIR}/state.snap" "${SNAPSHOT_DIR}/mem.snap"

# Helper for curl REST API calls to Firecracker UNIX socket
fc_curl() {
    local method=$1
    local path=$2
    local data=${3:-"{}"}

    curl -s --unix-socket "${API_SOCKET}" \
        -X "${method}" "http://localhost${path}" \
        -H "Content-Type: application/json" \
        -d "${data}"
}

# 2. Launch Background Firecracker Process
echo -e "${YELLOW}[AEGIS-SNAPSHOT] Spawning temporary Firecracker process...${NC}"
"${FIRECRACKER_BIN}" --api-sock "${API_SOCKET}" &
FC_PID=$!

# Cleanup trap to kill Firecracker if script fails
trap 'kill -9 ${FC_PID} 2>/dev/null || true; rm -f "${API_SOCKET}"' EXIT

# Wait for UNIX domain socket file creation
for i in {1..50}; do
    if [ -S "${API_SOCKET}" ]; then
        break
    fi
    sleep 0.01
done

if [ ! -S "${API_SOCKET}" ]; then
    echo -e "${RED}[CRITICAL] Timed out waiting for Firecracker API socket.${NC}"
    exit 1
fi

# 3. Configure MicroVM Boot Source (Kernel)
echo -e "${YELLOW}[AEGIS-SNAPSHOT] Configuring Kernel Boot Source...${NC}"
fc_curl "PUT" "/boot-source" "{
    \"kernel_image_path\": \"${KERNEL_PATH}\",
    \"boot_args\": \"console=ttyS0 reboot=k panic=1 pci=off ip=172.16.0.2:::255.255.255.0::eth0:off\"
}"

# 4. Configure RootFS Drive
echo -e "${YELLOW}[AEGIS-SNAPSHOT] Configuring RootFS Drive...${NC}"
fc_curl "PUT" "/drives/rootfs" "{
    \"drive_id\": \"rootfs\",
    \"path_on_host\": \"${ROOTFS_PATH}\",
    \"is_root_device\": true,
    \"is_read_only\": false
}"

# 5. Configure Machine Resources (1 vCPU, 512 MB RAM)
echo -e "${YELLOW}[AEGIS-SNAPSHOT] Configuring Machine Resources...${NC}"
fc_curl "PUT" "/machine-config" "{
    \"vcpu_count\": 1,
    \"mem_size_mib\": 512
}"

# 6. Start Instance
echo -e "${YELLOW}[AEGIS-SNAPSHOT] Starting MicroVM Instance...${NC}"
fc_curl "PUT" "/actions" "{\"action_type\": \"InstanceStart\"}"

# Allow 1.5 seconds for Linux kernel & Go guest agent to complete pre-warming
echo -e "${YELLOW}[AEGIS-SNAPSHOT] Waiting 1.5s for guest initialization...${NC}"
sleep 1.5

# 7. Pause MicroVM Instance
echo -e "${YELLOW}[AEGIS-SNAPSHOT] Pausing MicroVM Instance...${NC}"
fc_curl "PATCH" "/vm" "{\"state\": \"Paused\"}"

# 8. Create Memory & State Snapshot
echo -e "${YELLOW}[AEGIS-SNAPSHOT] Exporting State and Memory Snapshots...${NC}"
fc_curl "PUT" "/snapshot/create" "{
    \"snapshot_type\": \"Full\",
    \"snapshot_path\": \"${SNAPSHOT_DIR}/state.snap\",
    \"mem_file_path\": \"${SNAPSHOT_DIR}/mem.snap\"
}"

# Kill temporary Firecracker process
kill -9 "${FC_PID}" 2>/dev/null || true
rm -f "${API_SOCKET}"

# 9. Verify Generated Snapshot Files
if [ -f "${SNAPSHOT_DIR}/state.snap" ] && [ -f "${SNAPSHOT_DIR}/mem.snap" ]; then
    STATE_SIZE=$(du -h "${SNAPSHOT_DIR}/state.snap" | cut -f1)
    MEM_SIZE=$(du -h "${SNAPSHOT_DIR}/mem.snap" | cut -f1)
    echo -e "${GREEN}[AEGIS-SUCCESS] MicroVM Snapshot Pre-Warmed Successfully!${NC}"
    echo -e "${GREEN}  • State Snapshot : ${SNAPSHOT_DIR}/state.snap (${STATE_SIZE})${NC}"
    echo -e "${GREEN}  • Memory Snapshot: ${SNAPSHOT_DIR}/mem.snap (${MEM_SIZE})${NC}"
else
    echo -e "${RED}[CRITICAL] Failed to generate snapshot files in ${SNAPSHOT_DIR}.${NC}"
    exit 1
fi