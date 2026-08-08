/**
 * @file policy_engine.hpp
 * @brief Security Policy Parser, Syscall Resolver & Evaluator Header for aegis-sandbox
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#pragma once

#include <aegis/aegis.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <filesystem>
#include <optional>
#include <mutex>

namespace aegis::policy {

/**
 * @brief Syscall whitelisting and blacklisting rule container.
 */
struct AEGIS_API SyscallPolicyRule {
    std::unordered_set<uint32_t> allowed_syscalls;
    std::unordered_set<uint32_t> blocked_syscalls;
    bool default_allow{false}; // Default: False (Strict Whitelist Mode)
};

/**
 * @brief Network egress filtering policy specification.
 */
struct AEGIS_API NetworkPolicyRule {
    bool block_all_egress{false};
    bool block_cloud_metadata{true}; // Blocks 169.254.169.254
    std::vector<std::string> blocked_cidrs;
    std::vector<uint32_t> blocked_ips_network_order;
};

/**
 * @brief Complete runtime security policy specification for a sandbox.
 */
struct AEGIS_API SecurityPolicy {
    std::string policy_name;
    SyscallPolicyRule syscall_rule;
    NetworkPolicyRule network_rule;
    uint32_t max_execution_time_sec{30};
};

/**
 * @brief Thread-safe Security Policy Engine and x86_64 Syscall Name Resolver.
 */
class AEGIS_API PolicyEngine {
public:
    PolicyEngine();
    ~PolicyEngine() = default;

    // Non-copyable, non-movable
    PolicyEngine(const PolicyEngine&) = delete;
    PolicyEngine& operator=(const PolicyEngine&) = delete;
    PolicyEngine(PolicyEngine&&) = delete;
    PolicyEngine& operator=(PolicyEngine&&) = delete;

    /**
     * @brief Parses and registers a security policy from a YAML configuration file.
     * @param yaml_path Path to the target YAML policy file.
     * @return Status::Success if policy was successfully parsed and loaded.
     */
    Status load_from_yaml(const std::filesystem::path& yaml_path);

    /**
     * @brief Parses and registers a security policy from a JSON configuration string.
     * @param json_str JSON formatted policy string.
     * @return Status::Success if policy was loaded.
     */
    Status load_from_json(std::string_view json_str);

    /**
     * @brief Programmatically registers a pre-configured SecurityPolicy object.
     * @param policy Policy struct to register.
     * @return Status::Success if registered.
     */
    Status register_policy(const SecurityPolicy& policy);

    /**
     * @brief Evaluates whether a specific x86_64 syscall number is allowed under a policy.
     * @param policy_name Target policy identifier.
     * @param syscall_nr Linux x86_64 syscall number.
     * @return True if syscall is permitted; False if blocked.
     */
    [[nodiscard]] bool eval_syscall(std::string_view policy_name, uint32_t syscall_nr) const;

    /**
     * @brief Evaluates whether an outbound IPv4 connection is permitted under a policy.
     * @param policy_name Target policy identifier.
     * @param ipv4_network_order Destination IPv4 address in network byte order.
     * @return True if connection is permitted; False if blocked.
     */
    [[nodiscard]] bool eval_network_egress(std::string_view policy_name, uint32_t ipv4_network_order) const;

    /**
     * @brief Maps a Linux x86_64 syscall name (e.g., "execve") to its integer syscall number.
     * @param syscall_name Name of the syscall.
     * @return Optional uint32_t containing the syscall number, or std::nullopt if unknown.
     */
    [[nodiscard]] static std::optional<uint32_t> resolve_syscall_name(std::string_view syscall_name) noexcept;

    /**
     * @brief Retrieves a copy of a registered policy specification.
     * @param policy_name Target policy identifier.
     * @return Optional SecurityPolicy struct if found.
     */
    [[nodiscard]] std::optional<SecurityPolicy> get_policy(std::string_view policy_name) const;

    /**
     * @brief Helper that constructs and registers the default "strict_python" security policy.
     */
    Status register_default_strict_python_policy();

private:
    mutable std::mutex m_mutex;
    std::unordered_map<std::string, SecurityPolicy> m_policies;
    static const std::unordered_map<std::string, uint32_t> s_syscall_name_map;
};

} // namespace aegis::policy