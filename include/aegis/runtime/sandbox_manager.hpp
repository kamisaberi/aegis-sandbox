/**
 * @file sandbox_manager.hpp
 * @brief Firecracker MicroVM Sandbox Manager & Orchestrator Header for aegis-sandbox
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#pragma once

#include <aegis/aegis.hpp>
#include <aegis/runtime/cgroup_manager.hpp>
#include <aegis/ebpf/ebpf_loader.hpp>
#include <aegis/ebpf/ring_buffer_reader.hpp>
#include <aegis/policy/policy_engine.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <optional>
#include <filesystem>
#include <chrono>

namespace aegis::runtime {

/**
 * @brief Configuration specification for instantiating a Firecracker MicroVM Sandbox.
 */
struct AEGIS_API SandboxConfig {
    std::string sandbox_id;
    RuntimeEnvironment environment{RuntimeEnvironment::Python311};
    CgroupLimits resource_limits;
    std::string security_policy_name{"strict_python"};
    bool use_snapshot_restore{true}; // Enables sub-10ms snapshot boot
    std::filesystem::path firecracker_bin_path{"/usr/local/bin/firecracker"};
    std::filesystem::path rootfs_image_path{"/var/lib/aegis/rootfs/alpine-python311.ext4"};
    std::filesystem::path kernel_image_path{"/var/lib/aegis/kernel/vmlinux-6.6.x"};
    std::filesystem::path snapshot_dir_path{"/var/lib/aegis/snapshots"};
};

/**
 * @brief Result payload returned after executing code inside a sandbox.
 */
struct AEGIS_API ExecutionResult {
    std::string sandbox_id;
    int exit_code{-1};
    std::string stdout_output;
    std::string stderr_output;
    double boot_time_ms{0.0};
    double execution_time_ms{0.0};
    bool security_violation_triggered{false};
    std::string security_rule_violated;
};

/**
 * @brief MicroVM Sandbox Instance Handle tracking active process state and socket paths.
 */
struct AEGIS_API SandboxInstance {
    SandboxConfig config;
    SandboxMetadata metadata;
    pid_t firecracker_pid{-1};
    std::filesystem::path socket_path;
    std::filesystem::path guest_vsock_path;
    int tap_fd{-1};
    bool is_active{false};
};

/**
 * @brief Thread-Safe Firecracker MicroVM & eBPF Security Sandbox Manager.
 */
class AEGIS_API SandboxManager {
public:
    explicit SandboxManager(
        std::shared_ptr<ebpf::EBPFLoader> ebpf_loader = nullptr,
        std::shared_ptr<policy::PolicyEngine> policy_engine = nullptr,
        std::filesystem::path base_runtime_dir = "/var/run/aegis"
    );
    ~SandboxManager();

    // Non-copyable, non-movable
    SandboxManager(const SandboxManager&) = delete;
    SandboxManager& operator=(const SandboxManager&) = delete;
    SandboxManager(SandboxManager&&) = delete;
    SandboxManager& operator=(SandboxManager&&) = delete;

    /**
     * @brief Creates, boots, and enforces security policies on a new Firecracker MicroVM Sandbox.
     * @param config Sandbox configuration specification.
     * @return Status::Success if microVM booted and eBPF policies are active.
     */
    Status create_sandbox(const SandboxConfig& config);

    /**
     * @brief Executes untrusted AI agent code (Python/Bash) inside an active isolated sandbox.
     * @param sandbox_id Target sandbox identifier.
     * @param code_payload Raw code string to execute.
     * @return ExecutionResult containing exit code, stdout, stderr, and eBPF security flags.
     */
    [[nodiscard]] ExecutionResult execute_code(std::string_view sandbox_id, std::string_view code_payload);

    /**
     * @brief Terminates a microVM instance, removes network interfaces, and clears Cgroups.
     * @param sandbox_id Target sandbox identifier.
     * @param force_wipe True to perform zero-trust memory wiping on teardown.
     * @return Status::Success if sandbox successfully terminated and cleaned up.
     */
    Status terminate_sandbox(std::string_view sandbox_id, bool force_wipe = true);

    /**
     * @brief Retrieves metadata for an active sandbox.
     * @param sandbox_id Target sandbox identifier.
     * @return Optional SandboxMetadata struct if sandbox exists.
     */
    [[nodiscard]] std::optional<SandboxMetadata> get_metadata(std::string_view sandbox_id) const;

    /**
     * @brief Terminates and cleans up all active sandboxes managed by this instance.
     */
    void terminate_all() noexcept;

private:
    std::shared_ptr<ebpf::EBPFLoader> m_ebpf_loader;
    std::shared_ptr<policy::PolicyEngine> m_policy_engine;
    std::unique_ptr<CgroupManager> m_cgroup_manager;
    std::filesystem::path m_base_runtime_dir;

    mutable std::mutex m_mutex;
    std::unordered_map<std::string, SandboxInstance> m_sandboxes;

    Status spawn_firecracker_process(SandboxInstance& instance);
    Status configure_firecracker_api(const SandboxInstance& instance);
    Status restore_firecracker_snapshot(const SandboxInstance& instance);
    Status setup_tap_interface(SandboxInstance& instance);
    Status apply_ebpf_policies(const SandboxInstance& instance);
    void handle_ebpf_security_event(const ebpf::SecurityEventVariant& event);
};

} // namespace aegis::runtime