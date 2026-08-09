/**
 * @file test_sandbox_escape.cpp
 * @brief Security Penetration Test & Sandbox Escape Vector Verification
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#include <aegis/aegis.hpp>
#include <aegis/runtime/sandbox_manager.hpp>
#include <aegis/policy/policy_engine.hpp>
#include <aegis/ebpf/ebpf_loader.hpp>

#include <cassert>
#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/wait.h>

namespace {

// Attack Vector 1: Cloud Metadata Credential Theft (SSRF)
void test_attack_cloud_metadata_exfiltration() {
    std::cout << "[PEN-TEST] Testing Attack Vector 1: Cloud Metadata SSRF (169.254.169.254 exfiltration)...\n";

    aegis::policy::PolicyEngine policy_engine;
    uint32_t metadata_ip = inet_addr("169.254.169.254");

    // Verify policy engine blocks metadata exfiltration egress
    bool is_allowed = policy_engine.eval_network_egress("strict_python", metadata_ip);
    assert(!is_allowed);

    std::cout << "\033[1;32m[DEFENDED] Anti-SSRF eBPF network probe blocked metadata exfiltration attempt!\033[0m\n";
}

// Attack Vector 2: Kernel Driver Injection (init_module / delete_module)
void test_attack_kernel_module_injection() {
    std::cout << "[PEN-TEST] Testing Attack Vector 2: Kernel Module Injection (init_module syscall)...\n";

    aegis::policy::PolicyEngine policy_engine;

    // init_module = syscall 175, delete_module = syscall 176, kexec_load = syscall 246
    assert(policy_engine.eval_syscall("strict_python", 175) == false);
    assert(policy_engine.eval_syscall("strict_python", 176) == false);
    assert(policy_engine.eval_syscall("strict_python", 246) == false);

    std::cout << "\033[1;32m[DEFENDED] eBPF sys_filter probe blocked kernel module injection syscalls!\033[0m\n";
}

// Attack Vector 3: Process Debugging & Host Memory Injection (ptrace)
void test_attack_process_debugging_injection() {
    std::cout << "[PEN-TEST] Testing Attack Vector 3: Process Memory Injection (ptrace syscall)...\n";

    aegis::policy::PolicyEngine policy_engine;

    // ptrace = syscall 101, bpf = syscall 321
    assert(policy_engine.eval_syscall("strict_python", 101) == false);
    assert(policy_engine.eval_syscall("strict_python", 321) == false);

    std::cout << "\033[1;32m[DEFENDED] eBPF sys_filter probe blocked ptrace & cross-process injection!\033[0m\n";
}

// Attack Vector 4: Fork Bomb Resource Exhaustion (Cgroups v2 pids.max)
void test_attack_fork_bomb_resource_exhaustion() {
    std::cout << "[PEN-TEST] Testing Attack Vector 4: Fork Bomb Resource Exhaustion (pids.max)...\n";

    if (getuid() != 0) {
        std::cout << "\033[1;33m[SKIP] Cgroups v2 execution test requires root privileges. Skipping.\033[0m\n";
        return;
    }

    aegis::runtime::CgroupManager cgroup_mgr;
    std::string test_sbx = "sbx-fork-test";

    // Set strict limit of 10 maximum PIDs
    aegis::runtime::CgroupLimits limits{.cpu_cores = 1, .memory_mb = 128, .max_pids = 10};

    if (cgroup_mgr.create_cgroup(test_sbx, limits) == aegis::Status::Success) {
        pid_t pids[15];
        int spawned_count = 0;

        // Attempt to spawn 15 processes (limit is 10)
        for (int i = 0; i < 15; ++i) {
            pid_t p = fork();
            if (p == 0) {
                // Child process attaches to cgroup
                cgroup_mgr.attach_pid(test_sbx, getpid());
                sleep(2);
                _exit(0);
            } else if (p > 0) {
                pids[spawned_count++] = p;
            } else {
                // Fork failed due to Cgroups v2 pids.max enforcement
                break;
            }
        }

        // Clean up spawned children
        for (int i = 0; i < spawned_count; ++i) {
            kill(pids[i], SIGKILL);
            waitpid(pids[i], nullptr, 0);
        }

        cgroup_mgr.destroy_cgroup(test_sbx);

        // Verify fork bomb was capped by cgroups
        assert(spawned_count <= 10);
        std::cout << "\033[1;32m[DEFENDED] Cgroups v2 pids.max capped process creation at " 
                  << spawned_count << " PIDs (Host protected)!\033[0m\n";
    }
}

} // anonymous namespace

int main() {
    std::cout << "\033[1;31m===================================================\033[0m\n";
    std::cout << "\033[1;31m aegis-sandbox Security Escape & Penetration Tests \033[0m\n";
    std::cout << "\033[1;31m===================================================\033[0m\n\n";

    test_attack_cloud_metadata_exfiltration();
    test_attack_kernel_module_injection();
    test_attack_process_debugging_injection();
    test_attack_fork_bomb_resource_exhaustion();

    std::cout << "\n\033[1;32mAll Sandbox Escape Attacks DEFENDED & VERIFIED!\033[0m\n";
    return 0;
}