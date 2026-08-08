/**
 * @file ebpf_loader.cpp
 * @brief libbpf C++20 RAII Loader & BPF Map Manager Implementation
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#include <aegis/ebpf/ebpf_loader.hpp>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <fcntl.h>

#include <iostream>
#include <format>
#include <cstring>

namespace aegis::ebpf {

EBPFLoader::EBPFLoader() = default;

EBPFLoader::~EBPFLoader() {
    detach_all();
}

Status EBPFLoader::load_bpf_object(const std::filesystem::path& object_path) {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!std::filesystem::exists(object_path)) {
        std::cerr << std::format("[AEGIS-EBPF-ERROR] BPF Object file not found: {}\n", object_path.string());
        return Status::ErrEBPFProbeLoadFailed;
    }

    // 1. Open BPF Object File via libbpf
    m_bpf_obj = bpf_object__open_file(object_path.c_str(), nullptr);
    if (!m_bpf_obj) {
        std::cerr << std::format("[AEGIS-EBPF-ERROR] Failed to open BPF object: {}\n", object_path.string());
        return Status::ErrEBPFProbeLoadFailed;
    }

    // 2. Load BPF Object into Kernel (Triggers Kernel BPF Verifier)
    int err = bpf_object__load(m_bpf_obj);
    if (err < 0) {
        std::cerr << std::format("[AEGIS-EBPF-ERROR] Kernel BPF Verifier rejected object {}: {}\n", 
                                  object_path.string(), std::strerror(-err));
        bpf_object__close(m_bpf_obj);
        m_bpf_obj = nullptr;
        return Status::ErrEBPFProbeLoadFailed;
    }

    // 3. Enumerate loaded BPF programs and populate program metadata map
    struct bpf_program* prog = nullptr;
    bpf_object__for_each_program(prog, m_bpf_obj) {
        const char* prog_name = bpf_program__name(prog);
        if (prog_name) {
            EBPFProgramMetadata meta{
                .program_name = std::string(prog_name),
                .object_file_path = object_path.string(),
                .is_loaded = true,
                .is_attached = false
            };
            m_programs.insert_or_assign(std::string(prog_name), std::move(meta));
        }
    }

    m_is_loaded = true;
    return Status::Success;
}

Status EBPFLoader::attach_tracepoint(std::string_view prog_name, std::string_view tp_category, std::string_view tp_name) {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_bpf_obj || !m_is_loaded) {
        return Status::ErrEBPFProbeLoadFailed;
    }

    struct bpf_program* prog = bpf_object__find_program_by_name(m_bpf_obj, prog_name.data());
    if (!prog) {
        std::cerr << std::format("[AEGIS-EBPF-ERROR] BPF Program '{}' not found in object.\n", prog_name);
        return Status::ErrEBPFProbeLoadFailed;
    }

    // Attach tracepoint program using libbpf
    struct bpf_link* link = bpf_program__attach_tracepoint(prog, tp_category.data(), tp_name.data());
    if (!link) {
        std::cerr << std::format("[AEGIS-EBPF-ERROR] Failed to attach tracepoint '{}/{}': {}\n", 
                                  tp_category, tp_name, std::strerror(errno));
        return Status::ErrEBPFProbeLoadFailed;
    }

    m_bpf_links.push_back(link);

    auto it = m_programs.find(std::string(prog_name));
    if (it != m_programs.end()) {
        it->second.is_attached = true;
    }

    return Status::Success;
}

Status EBPFLoader::attach_cgroup_connect4(std::string_view prog_name, int cgroup_fd) {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_bpf_obj || !m_is_loaded || cgroup_fd < 0) {
        return Status::ErrEBPFProbeLoadFailed;
    }

    struct bpf_program* prog = bpf_object__find_program_by_name(m_bpf_obj, prog_name.data());
    if (!prog) {
        std::cerr << std::format("[AEGIS-EBPF-ERROR] BPF Program '{}' not found in object.\n", prog_name);
        return Status::ErrEBPFProbeLoadFailed;
    }

    struct bpf_link* link = bpf_program__attach_cgroup(prog, cgroup_fd);
    if (!link) {
        std::cerr << std::format("[AEGIS-EBPF-ERROR] Failed to attach cgroup socket connect filter to FD {}: {}\n", 
                                  cgroup_fd, std::strerror(errno));
        return Status::ErrEBPFProbeLoadFailed;
    }

    m_bpf_links.push_back(link);

    auto it = m_programs.find(std::string(prog_name));
    if (it != m_programs.end()) {
        it->second.is_attached = true;
    }

    return Status::Success;
}

Status EBPFLoader::set_cgroup_monitored(uint64_t cgroup_id, bool is_monitored) {
    std::lock_guard<std::mutex> lock(m_mutex);

    int map_fd = get_map_fd("aegis_monitored_cgroups");
    if (map_fd < 0) {
        // Fallback search for process monitor map
        map_fd = get_map_fd("aegis_monitored_cgroups_proc");
    }

    if (map_fd < 0) {
        return Status::ErrEBPFProbeLoadFailed;
    }

    uint8_t val = is_monitored ? 1 : 0;
    int err = bpf_map_update_elem(map_fd, &cgroup_id, &val, BPF_ANY);
    if (err != 0) {
        std::cerr << std::format("[AEGIS-EBPF-ERROR] Failed to update cgroup map for ID {}: {}\n", 
                                  cgroup_id, std::strerror(errno));
        return Status::ErrEBPFProbeLoadFailed;
    }

    return Status::Success;
}

Status EBPFLoader::set_syscall_policy(uint32_t syscall_nr, uint8_t is_blocked) {
    std::lock_guard<std::mutex> lock(m_mutex);

    int map_fd = get_map_fd("aegis_syscall_policy");
    if (map_fd < 0) {
        return Status::ErrEBPFProbeLoadFailed;
    }

    int err = bpf_map_update_elem(map_fd, &syscall_nr, &is_blocked, BPF_ANY);
    if (err != 0) {
        std::cerr << std::format("[AEGIS-EBPF-ERROR] Failed to set policy for syscall {}: {}\n", 
                                  syscall_nr, std::strerror(errno));
        return Status::ErrEBPFProbeLoadFailed;
    }

    return Status::Success;
}

Status EBPFLoader::set_blocked_ip(uint32_t ipv4_network_order, bool is_blocked) {
    std::lock_guard<std::mutex> lock(m_mutex);

    int map_fd = get_map_fd("aegis_blocked_ips");
    if (map_fd < 0) {
        return Status::ErrEBPFProbeLoadFailed;
    }

    uint8_t val = is_blocked ? 1 : 0;
    int err = bpf_map_update_elem(map_fd, &ipv4_network_order, &val, BPF_ANY);
    if (err != 0) {
        std::cerr << std::format("[AEGIS-EBPF-ERROR] Failed to update blocked IP map: {}\n", std::strerror(errno));
        return Status::ErrEBPFProbeLoadFailed;
    }

    return Status::Success;
}

int EBPFLoader::get_map_fd(std::string_view map_name) const {
    if (!m_bpf_obj) {
        return -1;
    }

    struct bpf_map* map = bpf_object__find_map_by_name(m_bpf_obj, map_name.data());
    if (!map) {
        return -1;
    }

    return bpf_map__fd(map);
}

void EBPFLoader::detach_all() noexcept {
    std::lock_guard<std::mutex> lock(m_mutex);

    // Destroy all attached BPF links
    for (struct bpf_link* link : m_bpf_links) {
        if (link) {
            bpf_link__destroy(link);
        }
    }
    m_bpf_links.clear();

    // Close and unload BPF object from kernel
    if (m_bpf_obj) {
        bpf_object__close(m_bpf_obj);
        m_bpf_obj = nullptr;
    }

    for (auto& [name, meta] : m_programs) {
        meta.is_attached = false;
        meta.is_loaded = false;
    }

    m_is_loaded = false;
}

} // namespace aegis::ebpf