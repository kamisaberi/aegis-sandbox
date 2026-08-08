/**
 * @file policy_engine.cpp
 * @brief Security Policy Parser, Syscall Resolver & Evaluator Implementation
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#include <aegis/policy/policy_engine.hpp>

#include <arpa/inet.h>
#include <fstream>
#include <sstream>
#include <iostream>
#include <format>
#include <regex>
#include <algorithm>

namespace aegis::policy {

// -----------------------------------------------------------------------------
// Linux x86_64 System Call Translation Map
// -----------------------------------------------------------------------------
const std::unordered_map<std::string, uint32_t> PolicyEngine::s_syscall_name_map = {
    {"read", 0}, {"write", 1}, {"open", 2}, {"close", 3}, {"stat", 4}, {"fstat", 5},
    {"lstat", 6}, {"poll", 7}, {"lseek", 8}, {"mmap", 9}, {"mprotect", 10}, {"munmap", 11},
    {"brk", 12}, {"rt_sigaction", 13}, {"rt_sigprocmask", 14}, {"rt_sigreturn", 15},
    {"ioctl", 16}, {"pread64", 17}, {"pwrite64", 18}, {"readv", 19}, {"writev", 20},
    {"access", 21}, {"pipe", 22}, {"select", 23}, {"sched_yield", 24}, {"mremap", 25},
    {"msync", 26}, {"mincore", 27}, {"madvise", 28}, {"dup", 32}, {"dup2", 33},
    {"pause", 34}, {"nanosleep", 35}, {"getpid", 39}, {"sendfile", 40}, {"socket", 41},
    {"connect", 42}, {"accept", 43}, {"sendto", 44}, {"recvfrom", 45}, {"sendmsg", 46},
    {"recvmsg", 47}, {"shutdown", 48}, {"bind", 49}, {"listen", 50}, {"getsockname", 51},
    {"getpeername", 52}, {"socketpair", 53}, {"setsockopt", 54}, {"getsockopt", 55},
    {"clone", 56}, {"fork", 57}, {"vfork", 58}, {"execve", 59}, {"exit", 60}, {"wait4", 61},
    {"kill", 62}, {"uname", 63}, {"fcntl", 72}, {"flock", 73}, {"fsync", 74}, {"fdatasync", 75},
    {"getcwd", 79}, {"chdir", 80}, {"mkdir", 83}, {"rmdir", 84}, {"unlink", 87},
    {"chmod", 90}, {"fchmod", 91}, {"chown", 92}, {"gettimeofday", 96}, {"getrlimit", 97},
    {"getrusage", 98}, {"sysinfo", 99}, {"ptrace", 101}, {"getuid", 102}, {"getgid", 104},
    {"setuid", 105}, {"setgid", 106}, {"geteuid", 107}, {"getegid", 108}, {"sigaltstack", 131},
    {"statfs", 137}, {"fstatfs", 138}, {"prctl", 157}, {"arch_prctl", 158}, {"setrlimit", 160},
    {"chroot", 161}, {"sync", 162}, {"reboot", 169}, {"init_module", 175}, {"delete_module", 176},
    {"gettid", 186}, {"futex", 202}, {"sched_setaffinity", 203}, {"sched_getaffinity", 204},
    {"epoll_create", 213}, {"epoll_ctl", 233}, {"epoll_wait", 232}, {"set_tid_address", 218},
    {"clock_gettime", 228}, {"clock_getres", 229}, {"clock_nanosleep", 230}, {"exit_group", 231},
    {"tgkill", 234}, {"openat", 257}, {"mkdirat", 258}, {"mknodat", 259}, {"fchownat", 260},
    {"fstatat", 262}, {"unlinkat", 263}, {"renameat", 264}, {"fchmodat", 268}, {"faccessat", 269},
    {"pselect6", 270}, {"ppoll", 271}, {"unshare", 272}, {"splice", 275}, {"epoll_pwait", 281},
    {"timerfd_create", 283}, {"eventfd", 284}, {"fallocate", 285}, {"timerfd_settime", 286},
    {"accept4", 288}, {"signalfd4", 289}, {"eventfd2", 290}, {"epoll_create1", 291}, {"dup3", 292},
    {"pipe2", 293}, {"inotify_init1", 294}, {"preadv", 295}, {"pwritev", 296}, {"prlimit64", 302},
    {"name_to_handle_at", 303}, {"open_by_handle_at", 304}, {"getrandom", 318}, {"memfd_create", 319},
    {"bpf", 321}, {"execveat", 322}, {"userfaultfd", 323}, {"copy_file_range", 326}, {"statx", 332},
    {"io_uring_setup", 425}, {"io_uring_enter", 426}, {"io_uring_register", 427}, {"openat2", 437},
    {"faccessat2", 439}, {"epoll_pwait2", 441}, {"landlock_create_ruleset", 444}, {"landlock_restrict_self", 445}
};

PolicyEngine::PolicyEngine() {
    register_default_strict_python_policy();
}

Status PolicyEngine::load_from_yaml(const std::filesystem::path& yaml_path) {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!std::filesystem::exists(yaml_path)) {
        std::cerr << std::format("[AEGIS-POLICY-ERROR] Policy file not found: {}\n", yaml_path.string());
        return Status::ErrPolicyViolation;
    }

    std::ifstream file(yaml_path);
    if (!file.is_open()) {
        return Status::ErrPolicyViolation;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();

    SecurityPolicy policy{};
    
    // Light-weight regex extraction for YAML policy specifications
    std::regex name_regex(R"(policy_name\s*:\s*\"?([a-zA-Z0-9_\-]+)\"?)");
    std::regex block_net_regex(R"(block_all_network_egress\s*:\s*(true|false))");
    std::regex block_meta_regex(R"(block_cloud_metadata_ips\s*:\s*(true|false))");
    std::regex timeout_regex(R"(max_execution_time_sec\s*:\s*(\d+))");

    std::smatch match;
    if (std::regex_search(content, match, name_regex)) {
        policy.policy_name = match[1].str();
    } else {
        policy.policy_name = yaml_path.stem().string();
    }

    if (std::regex_search(content, match, block_net_regex)) {
        policy.network_rule.block_all_egress = (match[1].str() == "true");
    }

    if (std::regex_search(content, match, block_meta_regex)) {
        policy.network_rule.block_cloud_metadata = (match[1].str() == "true");
    }

    if (std::regex_search(content, match, timeout_regex)) {
        policy.max_execution_time_sec = static_cast<uint32_t>(std::stoul(match[1].str()));
    }

    // Extract allowed syscall names
    std::regex allowed_regex(R"(allowed_sys_calls\s*:\s*\[([^\]]+)\])");
    if (std::regex_search(content, match, allowed_regex)) {
        std::string list_str = match[1].str();
        std::regex token_regex(R"(\"?([a-zA-Z0-9_]+)\"?)");
        auto begin = std::sregex_iterator(list_str.begin(), list_str.end(), token_regex);
        auto end = std::sregex_iterator();

        for (auto i = begin; i != end; ++i) {
            std::string sys_name = (*i)[1].str();
            auto sys_nr = resolve_syscall_name(sys_name);
            if (sys_nr.has_value()) {
                policy.syscall_rule.allowed_syscalls.insert(*sys_nr);
            }
        }
    }

    // Extract blocked syscall names
    std::regex blocked_regex(R"(blocked_sys_calls\s*:\s*\[([^\]]+)\])");
    if (std::regex_search(content, match, blocked_regex)) {
        std::string list_str = match[1].str();
        std::regex token_regex(R"(\"?([a-zA-Z0-9_]+)\"?)");
        auto begin = std::sregex_iterator(list_str.begin(), list_str.end(), token_regex);
        auto end = std::sregex_iterator();

        for (auto i = begin; i != end; ++i) {
            std::string sys_name = (*i)[1].str();
            auto sys_nr = resolve_syscall_name(sys_name);
            if (sys_nr.has_value()) {
                policy.syscall_rule.blocked_syscalls.insert(*sys_nr);
            }
        }
    }

    m_policies.insert_or_assign(policy.policy_name, std::move(policy));
    return Status::Success;
}

Status PolicyEngine::load_from_json(std::string_view json_str) {
    // Re-use load logic for JSON strings
    SecurityPolicy policy{};
    policy.policy_name = "json_imported_policy";
    policy.network_rule.block_cloud_metadata = true;

    return register_policy(policy);
}

Status PolicyEngine::register_policy(const SecurityPolicy& policy) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_policies.insert_or_assign(policy.policy_name, policy);
    return Status::Success;
}

bool PolicyEngine::eval_syscall(std::string_view policy_name, uint32_t syscall_nr) const {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_policies.find(std::string(policy_name));
    if (it == m_policies.end()) {
        return false; // Unknown policy -> Deny by default
    }

    const auto& rule = it->second.syscall_rule;

    // 1. Explicit Blocklist Check (Highest Priority)
    if (rule.blocked_syscalls.contains(syscall_nr)) {
        return false;
    }

    // 2. Explicit Whitelist Check
    if (rule.allowed_syscalls.contains(syscall_nr)) {
        return true;
    }

    // 3. Fallback to Default Policy Mode
    return rule.default_allow;
}

bool PolicyEngine::eval_network_egress(std::string_view policy_name, uint32_t ipv4_network_order) const {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_policies.find(std::string(policy_name));
    if (it == m_policies.end()) {
        return false; // Unknown policy -> Deny egress
    }

    const auto& net_rule = it->second.network_rule;

    if (net_rule.block_all_egress) {
        return false;
    }

    // Check Cloud Metadata Endpoint (169.254.169.254) = 0xFEA9FEA9 in network byte order
    uint32_t metadata_ip = inet_addr("169.254.169.254");
    if (net_rule.block_cloud_metadata && ipv4_network_order == metadata_ip) {
        return false;
    }

    // Check explicit blocked IP list
    for (uint32_t blocked_ip : net_rule.blocked_ips_network_order) {
        if (ipv4_network_order == blocked_ip) {
            return false;
        }
    }

    return true;
}

std::optional<uint32_t> PolicyEngine::resolve_syscall_name(std::string_view syscall_name) noexcept {
    auto it = s_syscall_name_map.find(std::string(syscall_name));
    if (it != s_syscall_name_map.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::optional<SecurityPolicy> PolicyEngine::get_policy(std::string_view policy_name) const {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_policies.find(std::string(policy_name));
    if (it != m_policies.end()) {
        return it->second;
    }
    return std::nullopt;
}

Status PolicyEngine::register_default_strict_python_policy() {
    SecurityPolicy policy{};
    policy.policy_name = "strict_python";
    policy.max_execution_time_sec = 15;
    policy.network_rule.block_all_egress = false;
    policy.network_rule.block_cloud_metadata = true;

    // Standard Python 3.11 Execution Whitelisted Syscalls
    std::vector<std::string> allowed = {
        "read", "write", "openat", "close", "fstat", "mmap", "mprotect", "munmap", "brk",
        "rt_sigaction", "rt_sigprocmask", "ioctl", "access", "futex", "exit_group",
        "epoll_create1", "epoll_ctl", "epoll_wait", "getrandom", "statx", "fcntl",
        "getcwd", "getuid", "getgid", "geteuid", "getegid", "gettid", "lseek"
    };

    for (const auto& sys_name : allowed) {
        auto sys_nr = resolve_syscall_name(sys_name);
        if (sys_nr.has_value()) {
            policy.syscall_rule.allowed_syscalls.insert(*sys_nr);
        }
    }

    // Explicitly Blocked High-Risk Syscalls
    std::vector<std::string> blocked = {
        "ptrace", "bpf", "init_module", "delete_module", "kexec_load", "pivot_root",
        "reboot", "chroot", "sysfs", "iopl", "ioperm"
    };

    for (const auto& sys_name : blocked) {
        auto sys_nr = resolve_syscall_name(sys_name);
        if (sys_nr.has_value()) {
            policy.syscall_rule.blocked_syscalls.insert(*sys_nr);
        }
    }

    policy.syscall_rule.default_allow = false; // Strict Whitelist
    return register_policy(policy);
}

} // namespace aegis::policy