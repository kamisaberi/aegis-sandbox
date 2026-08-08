/**
 * @file cgroup_manager.cpp
 * @brief Linux Cgroups v2 Resource Isolation Manager Implementation
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#include <aegis/runtime/cgroup_manager.hpp>

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#include <fstream>
#include <iostream>
#include <format>
#include <cstring>

namespace aegis::runtime {

namespace {

// Helper function to write a string value to a cgroup sysfs file
bool write_sysfs_file(const std::filesystem::path& file_path, std::string_view value) {
    std::ofstream file(file_path);
    if (!file.is_open()) {
        std::cerr << std::format("[AEGIS-CGROUP-ERROR] Failed to open sysfs file for writing: {}\n", file_path.string());
        return false;
    }
    file << value;
    return file.good();
}

} // anonymous namespace

CgroupManager::CgroupManager(std::filesystem::path root_cgroup_path)
    : m_root_path(std::move(root_cgroup_path)) {
    
    // Ensure the root aegis cgroup directory exists (/sys/fs/cgroup/aegis)
    std::error_code ec;
    std::filesystem::create_directories(m_root_path, ec);
    if (ec) {
        std::cerr << std::format("[AEGIS-CGROUP-ERROR] Failed to create root cgroup directory {}: {}\n", 
                                  m_root_path.string(), ec.message());
    } else {
        // Enable CPU, Memory, and PID controllers in subtree control
        std::filesystem::path subtree_control = m_root_path.parent_path() / "cgroup.subtree_control";
        write_sysfs_file(subtree_control, "+cpu +memory +pids");
    }
}

CgroupManager::~CgroupManager() {
    destroy_all();
}

Status CgroupManager::create_cgroup(std::string_view sandbox_id, const CgroupLimits& limits) {
    std::lock_guard<std::mutex> lock(m_mutex);

    std::string sbx_id(sandbox_id);
    if (m_cgroups.contains(sbx_id)) {
        return Status::ErrInvalidSandboxID;
    }

    std::filesystem::path cgroup_path = m_root_path / sbx_id;
    std::error_code ec;

    // 1. Create cgroup v2 directory
    std::filesystem::create_directories(cgroup_path, ec);
    if (ec) {
        std::cerr << std::format("[AEGIS-CGROUP-ERROR] Failed to create cgroup dir {}: {}\n", 
                                  cgroup_path.string(), ec.message());
        return Status::ErrCgroupQuotaExceeded;
    }

    // 2. Apply CPU, Memory, and PID limits to sysfs files
    Status status = apply_limits(cgroup_path, limits);
    if (status != Status::Success) {
        std::filesystem::remove_all(cgroup_path, ec);
        return status;
    }

    // 3. Extract 64-bit inode ID for eBPF map indexing
    uint64_t cgroup_id = fetch_inode_id(cgroup_path);
    if (cgroup_id == 0) {
        std::filesystem::remove_all(cgroup_path, ec);
        return Status::ErrCgroupQuotaExceeded;
    }

    // 4. Open file descriptor to cgroup directory (for BPF attach)
    int cgroup_fd = open(cgroup_path.c_str(), O_DIRECTORY | O_RDONLY | O_CLOEXEC);
    if (cgroup_fd < 0) {
        std::cerr << std::format("[AEGIS-CGROUP-ERROR] Failed to open cgroup FD for {}: {}\n", 
                                  cgroup_path.string(), std::strerror(errno));
        std::filesystem::remove_all(cgroup_path, ec);
        return Status::ErrCgroupQuotaExceeded;
    }

    CgroupInfo info{
        .sandbox_id = sbx_id,
        .cgroup_path = cgroup_path,
        .cgroup_id = cgroup_id,
        .cgroup_fd = cgroup_fd,
        .limits = limits
    };

    m_cgroups.insert_or_assign(sbx_id, std::move(info));
    return Status::Success;
}

Status CgroupManager::apply_limits(const std::filesystem::path& cgroup_path, const CgroupLimits& limits) {
    // 1. Configure CPU Limit (cpu.max)
    // Formula: quota_us = cores * 100000, period_us = 100000
    uint64_t cpu_quota = static_cast<uint64_t>(limits.cpu_cores) * 100000ULL;
    std::string cpu_max_str = std::format("{} 100000", cpu_quota);
    if (!write_sysfs_file(cgroup_path / "cpu.max", cpu_max_str)) {
        return Status::ErrCgroupQuotaExceeded;
    }

    // 2. Configure Memory Limit (memory.max)
    uint64_t memory_bytes = static_cast<uint64_t>(limits.memory_mb) * 1024ULL * 1024ULL;
    std::string memory_max_str = std::format("{}", memory_bytes);
    if (!write_sysfs_file(cgroup_path / "memory.max", memory_max_str)) {
        return Status::ErrCgroupQuotaExceeded;
    }

    // 3. Configure Maximum Process ID Limit (pids.max)
    std::string pids_max_str = std::format("{}", limits.max_pids);
    if (!write_sysfs_file(cgroup_path / "pids.max", pids_max_str)) {
        return Status::ErrCgroupQuotaExceeded;
    }

    return Status::Success;
}

Status CgroupManager::attach_pid(std::string_view sandbox_id, pid_t pid) {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_cgroups.find(std::string(sandbox_id));
    if (it == m_cgroups.end()) {
        return Status::ErrInvalidSandboxID;
    }

    // Write target PID to cgroup.procs sysfs file
    std::filesystem::path procs_file = it->second.cgroup_path / "cgroup.procs";
    std::string pid_str = std::format("{}", pid);

    if (!write_sysfs_file(procs_file, pid_str)) {
        return Status::ErrCgroupQuotaExceeded;
    }

    return Status::Success;
}

Status CgroupManager::destroy_cgroup(std::string_view sandbox_id) {
    std::lock_guard<std::mutex> lock(m_mutex);

    std::string sbx_id(sandbox_id);
    auto it = m_cgroups.find(sbx_id);
    if (it == m_cgroups.end()) {
        return Status::ErrInvalidSandboxID;
    }

    // Close directory FD
    if (it->second.cgroup_fd >= 0) {
        close(it->second.cgroup_fd);
    }

    // Remove sysfs directory recursively
    std::error_code ec;
    std::filesystem::remove_all(it->second.cgroup_path, ec);

    m_cgroups.erase(it);
    return Status::Success;
}

uint64_t CgroupManager::get_cgroup_id(std::string_view sandbox_id) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_cgroups.find(std::string(sandbox_id));
    if (it != m_cgroups.end()) {
        return it->second.cgroup_id;
    }
    return 0;
}

int CgroupManager::get_cgroup_fd(std::string_view sandbox_id) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_cgroups.find(std::string(sandbox_id));
    if (it != m_cgroups.end()) {
        return it->second.cgroup_fd;
    }
    return -1;
}

std::optional<CgroupInfo> CgroupManager::get_cgroup_info(std::string_view sandbox_id) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_cgroups.find(std::string(sandbox_id));
    if (it != m_cgroups.end()) {
        return it->second;
    }
    return std::nullopt;
}

uint64_t CgroupManager::fetch_inode_id(const std::filesystem::path& cgroup_path) {
    struct stat st{};
    if (stat(cgroup_path.c_str(), &st) == 0) {
        return static_cast<uint64_t>(st.st_ino);
    }
    return 0;
}

void CgroupManager::destroy_all() noexcept {
    std::lock_guard<std::mutex> lock(m_mutex);

    std::error_code ec;
    for (auto& [id, info] : m_cgroups) {
        if (info.cgroup_fd >= 0) {
            close(info.cgroup_fd);
            info.cgroup_fd = -1;
        }
        std::filesystem::remove_all(info.cgroup_path, ec);
    }
    m_cgroups.clear();
}

} // namespace aegis::runtime