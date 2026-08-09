/**
 * @file test_policy_engine.cpp
 * @brief Unit Tests for YAML/JSON Security Policy Engine in aegis-sandbox
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#include <aegis/aegis.hpp>
#include <aegis/policy/policy_engine.hpp>

#include <cassert>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <arpa/inet.h>

namespace {

void test_syscall_name_resolution() {
    std::cout << "[TEST] Running Syscall Name Resolution Unit Tests...\n";

    auto sys_read = aegis::policy::PolicyEngine::resolve_syscall_name("read");
    assert(sys_read.has_value() && *sys_read == 0);

    auto sys_write = aegis::policy::PolicyEngine::resolve_syscall_name("write");
    assert(sys_write.has_value() && *sys_write == 1);

    auto sys_execve = aegis::policy::PolicyEngine::resolve_syscall_name("execve");
    assert(sys_execve.has_value() && *sys_execve == 59);

    auto sys_invalid = aegis::policy::PolicyEngine::resolve_syscall_name("non_existent_sys_call");
    assert(!sys_invalid.has_value());

    std::cout << "\033[1;32m[PASS] Syscall Name Resolution Verified!\033[0m\n";
}

void test_strict_python_policy_evaluation() {
    std::cout << "[TEST] Running Default Strict Python Policy Evaluation Tests...\n";

    aegis::policy::PolicyEngine engine;

    // Test Whitelisted Syscalls (read=0, write=1, openat=257, execve=59)
    assert(engine.eval_syscall("strict_python", 0) == true);   // read
    assert(engine.eval_syscall("strict_python", 1) == true);   // write
    assert(engine.eval_syscall("strict_python", 257) == true); // openat
    assert(engine.eval_syscall("strict_python", 59) == true);  // execve

    // Test Blacklisted High-Risk Syscalls (ptrace=101, bpf=321, reboot=169, init_module=175)
    assert(engine.eval_syscall("strict_python", 101) == false); // ptrace
    assert(engine.eval_syscall("strict_python", 321) == false); // bpf
    assert(engine.eval_syscall("strict_python", 169) == false); // reboot
    assert(engine.eval_syscall("strict_python", 175) == false); // init_module

    // Test Un-whitelisted Syscall Default Deny Mode (e.g., kexec_load=246)
    assert(engine.eval_syscall("strict_python", 246) == false);

    std::cout << "\033[1;32m[PASS] Strict Python Policy Evaluation Verified!\033[0m\n";
}

void test_network_egress_policy_evaluation() {
    std::cout << "[TEST] Running Network Anti-SSRF Policy Evaluation Tests...\n";

    aegis::policy::PolicyEngine engine;

    // 1. Cloud Metadata IP (169.254.169.254) must be blocked
    uint32_t metadata_ip = inet_addr("169.254.169.254");
    assert(engine.eval_network_egress("strict_python", metadata_ip) == false);

    // 2. Standard Public IP (e.g., 8.8.8.8) should be permitted
    uint32_t public_ip = inet_addr("8.8.8.8");
    assert(engine.eval_network_egress("strict_python", public_ip) == true);

    std::cout << "\033[1;32m[PASS] Network Anti-SSRF Policy Evaluation Verified!\033[0m\n";
}

void test_yaml_policy_loading() {
    std::cout << "[TEST] Running YAML Policy Parsing Test...\n";

    std::filesystem::path temp_yaml = "test_custom_policy.yaml";
    std::ofstream out(temp_yaml);
    out << "policy_name: \"test_custom\"\n"
        << "max_execution_time_sec: 10\n"
        << "network_rules:\n"
        << "  block_all_network_egress: true\n"
        << "  block_cloud_metadata_ips: true\n"
        << "syscall_rules:\n"
        << "  default_mode: \"strict_whitelist\"\n"
        << "  allowed_sys_calls: [\"read\", \"write\"]\n"
        << "  blocked_sys_calls: [\"execve\"]\n";
    out.close();

    aegis::policy::PolicyEngine engine;
    aegis::Status status = engine.load_from_yaml(temp_yaml);
    assert(status == aegis::Status::Success);

    // Test loaded custom policy rules
    assert(engine.eval_syscall("test_custom", 0) == true);   // read
    assert(engine.eval_syscall("test_custom", 1) == true);   // write
    assert(engine.eval_syscall("test_custom", 59) == false); // execve (explicitly blocked)

    // Test complete network egress blocking
    uint32_t public_ip = inet_addr("8.8.8.8");
    assert(engine.eval_network_egress("test_custom", public_ip) == false);

    std::filesystem::remove(temp_yaml);
    std::cout << "\033[1;32m[PASS] YAML Policy Parsing Verified!\033[0m\n";
}

} // anonymous namespace

int main() {
    std::cout << "\033[1;36m===================================================\033[0m\n";
    std::cout << "\033[1;36m aegis-sandbox Security Policy Engine Unit Tests   \033[0m\n";
    std::cout << "\033[1;36m===================================================\033[0m\n\n";

    test_syscall_name_resolution();
    test_strict_python_policy_evaluation();
    test_network_egress_policy_evaluation();
    test_yaml_policy_loading();

    std::cout << "\n\033[1;32mAll Policy Engine Unit Tests PASSED!\033[0m\n";
    return 0;
}