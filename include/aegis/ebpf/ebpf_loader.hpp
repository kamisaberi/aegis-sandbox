/**
 * @file ebpf_loader.hpp
 * @brief libbpf C++20 RAII Loader & BPF Map Manager for aegis-sandbox
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#pragma once

#include <aegis/aegis.hpp>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <memory>
#include <filesystem>
#include <mutex>
#include <span>

namespace aegis::ebpf {

/**
 * @brief Metadata for a loaded eBPF program instance.
 */
struct AEGIS_API EBPFProgramMetadata {
    std::string program_name;
    std::string object_file_path;
    bool is_loaded{false};
    bool is_attached{false};
};

/**
 * @brief RAII Manager for loading eBPF bytecode objects and populating BPF Maps.
 */
class AEGIS_API EBPFLoader {
public:
    EBPFLoader();
    ~EBPFLoader();

    // Non-copyable, non-movable (Resource management wrapper around libbpf pointers)
    EBPFLoader(const EBPFLoader&) = delete;
    EBPFLoader& operator=(const EBPFLoader&) = delete;
    EBPFLoader(EBPFLoader&&) = delete;
    EBPFLoader& operator=(EBPFLoader&&) = delete;

    /**
     * @brief Loads and verifies an eBPF BPF bytecode object file (.bpf.o).
     * @param object_path Path to the compiled BPF object file.
     * @return Status::Success if bytecode loaded and verified by kernel BPF verifier.
     */
    Status load_bpf_object(const std::filesystem::path& object_path);

    /**
     * @brief Attaches a loaded eBPF tracepoint program (e.g., raw_syscalls/sys_enter).
     * @param prog_name Name of BPF program section (e.g., "handle_sys_enter").
     * @param tp_category Tracepoint category (e.g., "raw_syscalls").
     * @param tp_name Tracepoint event name (e.g., "sys_enter").
     * @return Status::Success if tracepoint link attached successfully.
     */
    Status attach_tracepoint(std::string_view prog_name, std::string_view tp_category, std::string_view tp_name);

    /**
     * @brief Attaches a cgroup socket connect filter (cgroup/connect4) to a target cgroup FD.
     * @param prog_name Name of BPF program section (e.g., "aegis_cgroup_connect4").
     * @param cgroup_fd File descriptor of target cgroup v2 directory.
     * @return Status::Success if attached to target cgroup.
     */
    Status attach_cgroup_connect4(std::string_view prog_name, int cgroup_fd);

    /**
     * @brief Updates the aegis_monitored_cgroups BPF Hash Map.
     * @param cgroup_id Linux cgroup v2 64-bit ID.
     * @param is_monitored True to enable monitoring, False to disable.
     * @return Status::Success if BPF map updated.
     */
    Status set_cgroup_monitored(uint64_t cgroup_id, bool is_monitored);

    /**
     * @brief Updates the aegis_syscall_policy BPF Array Map.
     * @param syscall_nr Linux x86_64 syscall number.
     * @param is_blocked 0 = Allowed, 1 = Blocked/SIGKILL.
     * @return Status::Success if policy updated in kernel memory.
     */
    Status set_syscall_policy(uint32_t syscall_nr, uint8_t is_blocked);

    /**
     * @brief Updates the aegis_blocked_ips BPF Hash Map for anti-SSRF protection.
     * @param ipv4_network_order Destination IPv4 address in network byte order.
     * @param is_blocked True to block egress connections to this IP.
     * @return Status::Success if IP rule loaded into BPF map.
     */
    Status set_blocked_ip(uint32_t ipv4_network_order, bool is_blocked);

    /**
     * @brief Retrieves file descriptor for a named BPF map (e.g., for BPF Ring Buffer creation).
     * @param map_name Name of BPF map defined in C code (e.g., "aegis_security_events").
     * @return BPF map file descriptor, or -1 if not found.
     */
    [[nodiscard]] int get_map_fd(std::string_view map_name) const;

    /**
     * @brief Detaches all BPF links and unloads BPF objects from kernel memory.
     */
    void detach_all() noexcept;

private:
    mutable std::mutex m_mutex;
    struct bpf_object* m_bpf_obj{nullptr};
    std::vector<struct bpf_link*> m_bpf_links;
    std::unordered_map<std::string, EBPFProgramMetadata> m_programs;
    bool m_is_loaded{false};
};

} // namespace aegis::ebpf