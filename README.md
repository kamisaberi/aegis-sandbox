# aegis-sandbox

[![C++20](https://img.shields.io/badge/C%2B%2B-20-blue.svg)](https://en.cppreference.com/w/cpp/20)
[![eBPF](https://img.shields.io/badge/eBPF-libbpf-red.svg)](https://ebpf.io/)
[![Firecracker](https://img.shields.io/badge/MicroVM-Firecracker_KVM-orange.svg)](https://firecracker-microvm.github.io/)
[![Go](https://img.shields.io/badge/Go-1.22%2B-00ADD8.svg)](https://go.dev/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

> **Sub-10ms Firecracker MicroVM & eBPF Isolation Engine for Autonomous AI Agent Code Execution.**

`aegis-sandbox` is an open-source, high-performance security runtime engineered specifically to isolate untrusted code (Python, Bash) executed by autonomous AI agents (e.g., AutoGPT, LangChain agents, Code Interpreter pipelines).

By combining **sub-10ms Firecracker microVM memory snapshot restoration** with real-time **Linux kernel eBPF tracepoints**, `aegis-sandbox` enforces zero-trust execution boundaries: blocking unauthorized system calls (`ptrace`, `bpf`, `init_module`), preventing SSRF exfiltration to cloud metadata endpoints (`169.254.169.254`), and strictly capping CPU, RAM, and PID resources via **Linux Cgroups v2**.

---

## 🏛️ System Architecture

```
                      +-------------------------------------------------+
                      |   AI Agent / User Application (gRPC Client)     |
                      +-------------------------------------------------+
                                               |
                                               v  (gRPC / Protobuf API)
                      +-------------------------------------------------+
                      |    aegis-cli / aegis-daemon (C++20 / Go Daemon) |
                      +-------------------------------------------------+
                               /                       \
                              /                         \
                             v                           v
  +------------------------------------+     +----------------------------------+
  | Linux Kernel eBPF Probes (C)       |     | Firecracker MicroVM (Guest)      |
  |                                    |     |                                  |
  | - sys_filter.bpf.c (Block Syscall) |     | - Isolated Linux Kernel 6.6.x     |
  | - net_filter.bpf.c (Drop Metadata) |     | - Go Init Guest Agent (PID 1)    |
  | - process_monitor.bpf.c            |     | - Isolated Python 3.11 Execution |
  +------------------------------------+     +----------------------------------+
```

---

## ✨ Key Features

- **Sub-10ms MicroVM Boot Times:** Leverages KVM memory snapshot pre-warming (`state.snap` & `mem.snap`) to instantiate pre-booted Python 3.11 microVM environments in **<8.5ms**.
- **Real-Time eBPF Syscall Enforcement:** Hooks into `raw_syscalls/sys_enter` to intercept non-whitelisted system calls (`ptrace`, `bpf`, `kexec_load`, `init_module`) and immediately issue **`SIGKILL`** before execution.
- **Anti-SSRF Network Egress Filtering:** Attaches to `cgroup/connect4` socket events to block connection attempts to cloud metadata IP (`169.254.169.254`) and internal RFC 1918 subnets.
- **Privilege Escalation Monitoring:** Tracks process genealogy and detects `execve` binary spawns or UID root escalation attempts inside sandboxed cgroups.
- **Cgroups v2 Resource Throttling:** Enforces hard caps on vCPU quotas (`cpu.max`), memory allocations (`memory.max`), and process counts (`pids.max`) to defend against fork bombs and DoS attacks.
- **Declarative Security Policies:** Supports human-readable YAML security profile specifications (`strict_python.yaml`, `bash_isolated.yaml`).

---

## 🛡️ Defended Attack Vectors

| Attack Vector | Simulated Penetration Test | `aegis-sandbox` Defense Mechanism |
| :--- | :--- | :--- |
| **Cloud Credential Theft (SSRF)** | `curl http://169.254.169.254/latest/meta-data/` | **eBPF `net_filter.bpf.o`** rejects `connect4` socket calls at kernel layer. |
| **Kernel Module Injection** | `init_module()` / `finit_module()` syscalls | **eBPF `sys_filter.bpf.o`** intercepts syscall and terminates process via `SIGKILL`. |
| **Process Memory Injection** | `ptrace(PTRACE_TRACEME, ...)` | **eBPF `sys_filter.bpf.o`** blocks `ptrace` (syscall 101) execution. |
| **Fork Bomb DoS Attack** | `while True: os.fork()` | **Linux Cgroups v2 `pids.max`** throttles and caps max process count (e.g., 100 PIDs). |
| **Host Filesystem Escape** | `chroot` / `pivot_root` attempts | **Firecracker MicroVM KVM boundary** + read-only rootfs mount. |

---

## 🛠️ Quick Start & Installation

### Prerequisites

- **OS:** Linux (Ubuntu 22.04 LTS / 24.04 LTS recommended with kernel 6.x)
- **Virtualization:** `/dev/kvm` hardware virtualization support enabled
- **Compiler:** Clang 18+ (with `clang -target bpf` support)
- **Dependencies:** `libbpf-dev`, `libelf-dev`, `bpftool`, `cmake`, `ninja-build`, `golang-go`

### Step 1: Install Dependencies & Firecracker

```bash
# Clone the repository
git clone https://github.com/kamisaberi/aegis-sandbox.git
cd aegis-sandbox

# Run the host environment installer script
sudo ./scripts/setup_dev_env.sh
```

### Step 2: Configure Network TAP & NAT Bridge

```bash
# Create aegis-br0 bridge interface and TAP network devices
sudo ./scripts/setup_tap_bridge.sh
```

### Step 3: Build Native C++ Library & eBPF Bytecode

```bash
# Configure build with CMake & Ninja
cmake -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Debug \
    -DAEGIS_BUILD_TESTS=ON

# Compile C++ core, eBPF bytecode, and CLI tool
ninja -C build
```

### Step 4: Pre-Warm MicroVM Snapshots (For Sub-10ms Boot)

```bash
# Pre-warm base microVM state and export memory snapshots
sudo ./scripts/prewarm_snapshots.sh
```

---

## 🚀 Usage Examples

### 1. Booting an Isolated MicroVM Sandbox

```bash
# Create and boot a new sandbox using the strict_python policy
sudo ./build/bin/aegis-cli create \
    --id sbx-test \
    --policy strict_python \
    --cpus 2 \
    --mem 512
```

### 2. Executing Untrusted AI Agent Code

```bash
# Execute Python script inside isolated sandbox
sudo ./build/bin/aegis-cli exec \
    --id sbx-test \
    --code "import math; print('Calculated PI:', math.pi)"
```

### 3. Testing eBPF Security Enforcement (Blocked Attack Simulation)

```bash
# Attempting a blocked syscall (ptrace) inside the sandbox
sudo ./build/bin/aegis-cli exec \
    --id sbx-test \
    --code "import ctypes; libc = ctypes.CDLL(None); libc.ptrace(0, 0, 0, 0)"

# Output:
# [AEGIS-SECURITY-ALERT] eBPF sys_filter probe blocked ptrace syscall (101).
# Execution terminated via SIGKILL. Exit Code: 137
```

### 4. Running Security Penetration Tests

```bash
# Run automated eBPF security integration & sandbox escape tests
sudo ./build/bin/test_ebpf_blocking
sudo ./build/bin/test_sandbox_escape
```

---

## 📊 Repository File Structure

```
aegis-sandbox/
├── api/aegis/v1/          # Protocol Buffer definitions (sandbox.proto)
├── ebpf/                  # Kernel eBPF C programs (sys_filter, net_filter, process_monitor)
├── include/aegis/         # C++20 public headers (ebpf_loader, cgroup_manager, sandbox_manager)
├── src/                   # C++20 core implementation files
├── cmd/aegis-cli/         # Command Line Interface tool (main.cpp)
├── guest/cmd/agent/       # Go Init Guest Agent running inside MicroVM (PID 1)
├── policy/                # YAML Security Policy files (strict_python.yaml)
├── scripts/               # Pre-warming snapshots, TAP bridge, & dev environment setup scripts
├── tests/                 # eBPF blocking tests, policy unit tests, & penetration tests
└── Dockerfile.rootfs      # Multi-stage Alpine ext4 RootFS image builder
```

---

## 📄 License

Distributed under the **Apache 2.0 License**. See [`LICENSE`](LICENSE) for details.

---

## 👤 Author & Contact

**Kamran Saberifard**  
*Visionary AI Architect, High-Performance Systems & AI Security Engineer*  

- **ORCID:** [0009-0002-7822-6168](https://orcid.org/0009-0002-7822-6168)
- **GitHub:** [@kamisaberi](https://github.com/kamisaberi)
- **LinkedIn:** [kamisaberi](https://linkedin.com/in/kamisaberi)
- **Email:** [kamisaberi@gmail.com](mailto:kamisaberi@gmail.com)
```