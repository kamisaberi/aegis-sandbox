/**
 * @file cgroup_manager.hpp
 * @brief Linux Cgroups v2 Resource Isolation Manager Header for aegis-sandbox
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#pragma once

#include <aegis/aegis.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <filesystem>
#include <unordered_map>
#include <optional>
#include <mutex>

namespace aegis::runtime {

/**
 * @brief Resource constraint configuration for a Cgroups v2 sandbox container.
 */
struct AEGIS_API CgroupLimits {
    uint32_t cpu_cores{1};          // Number of vCPU cores allowed (e.g. 1 core = 100000 quota / 100000 period)
    uint32_t memory_mb{512};        // Hard RAM limit in Megabytes
    uint32_t vram_mb{0};            // Hard VRAM limit in Megabytes (0 if CPU only)
    uint32_t max_pids{100};         // Maximum simultaneous processes allowed
};

/**
 * @brief Information and file descriptors tracking an active Cgroup v2 directory.
 */
struct AEGIS_API CgroupInfo {
    std::string sandbox_id;
    std::filesystem::path cgroup_path;
    uint64_t cgroup_id{0};          // 64-bit inode number (matches bpf_get_current_cgroup_id())
    int cgroup_fd{-1};              // Open file descriptor to cgroup directory (for BPF attach)
    CgroupLimits limits;
};

/**
 * @brief Thread-safe Linux Cgroups v2 Resource Manager.
 */
class AEGIS_API CgroupManager {
public:
    explicit CgroupManager(std::filesystem::path root_cgroup_path = "/sys/fs/cgroup/aegis");
    ~CgroupManager();

    // Non-copyable, non-movable
    CgroupManager(const CgroupManager&) = delete;
    CgroupManager& operator=(const CgroupManager&) = delete;
    CgroupManager(CgroupManager&&) = delete;
    CgroupManager& operator=(CgroupManager&&) = delete;

    /**
     * @brief Creates a new Cgroups v2 directory for a sandbox and applies resource limits.
     * @param sandbox_id Unique sandbox identifier (e.g., "sbx-9f82a1").
     * @param limits Target hardware limits (CPU, RAM, max PIDs).
     * @return Status::Success if cgroup created and limits configured.
     */
    Status create_cgroup(std::string_view sandbox_id, const CgroupLimits& limits);

    /**
     * @brief Attaches a process ID (PID) to a sandbox's Cgroup v2 environment.
     * @param sandbox_id Target sandbox identifier.
     * @param pid Target process ID to attach.
     * @return Status::Success if PID written to cgroup.procs.
     */
    Status attach_pid(std::string_view sandbox_id, pid_t pid);

    /**
     * @brief Destroys and removes a sandbox's Cgroup v2 environment.
     * @param sandbox_id Target sandbox identifier.
     * @return Status::Success if PIDs cleared and directory removed.
     */
    Status destroy_cgroup(std::string_view sandbox_id);

    /**
     * @brief Retrieves the 64-bit Cgroup ID (inode) matching eBPF kernel lookups.
     * @param sandbox_id Target sandbox identifier.
     * @return 64-bit Cgroup ID or 0 if not found.
     */
    [[nodiscard]] uint64_t get_cgroup_id(std::string_view sandbox_id) const;

    /**
     * @brief Retrieves the open directory file descriptor for Cgroup BPF program attachment.
     * @param sandbox_id Target sandbox identifier.
     * @return File descriptor or -1 if not found.
     */
    [[nodiscard]] int get_cgroup_fd(std::string_view sandbox_id) const;

    /**
     * @brief Retrieves tracking info for an active Cgroup.
     * @param sandbox_id Target sandbox identifier.
     * @return Optional CgroupInfo struct if sandbox exists.
     */
    [[nodiscard]] std::optional<CgroupInfo> get_cgroup_info(std::string_view sandbox_id) const;

    /**
     * @brief Destroys all active Aegis Cgroups v2 environments managed by this instance.
     */
    void destroy_all() noexcept;

private:
    std::filesystem::path m_root_path;
    mutable std::mutex m_mutex;
    std::unordered_map<std::string, CgroupInfo> m_cgroups;

    Status apply_limits(const std::filesystem::path& cgroup_path, const CgroupLimits& limits);
    [[nodiscard]] static uint64_t fetch_inode_id(const std::filesystem::path& cgroup_path);
};

} // namespace aegis::runtime