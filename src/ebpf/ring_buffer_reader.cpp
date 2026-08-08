/**
 * @file ring_buffer_reader.cpp
 * @brief eBPF Ring Buffer Security Event Reader Implementation
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#include <aegis/ebpf/ring_buffer_reader.hpp>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include <iostream>
#include <format>
#include <cstring>
#include <arpa/inet.h>

namespace aegis::ebpf {

namespace {

// C-compatible struct definitions matching eBPF kernel layouts
struct RawSyscallEvent {
    uint64_t timestamp_ns;
    uint32_t pid;
    uint32_t tgid;
    uint32_t cgroup_id;
    uint32_t syscall_nr;
    char comm[16];
    uint8_t action_taken;
};

struct RawNetworkEvent {
    uint64_t timestamp_ns;
    uint32_t pid;
    uint32_t tgid;
    uint32_t cgroup_id;
    uint32_t dst_ip;
    uint16_t dst_port;
    uint8_t proto;
    uint8_t action_taken;
    char comm[16];
};

struct RawProcessEvent {
    uint64_t timestamp_ns;
    uint32_t pid;
    uint32_t tgid;
    uint32_t ppid;
    uint32_t cgroup_id;
    uint32_t uid;
    uint32_t gid;
    uint8_t is_privilege_escalation;
    uint8_t action_taken;
    char comm[16];
    char filename[256];
};

} // anonymous namespace

RingBufferReader::RingBufferReader() = default;

RingBufferReader::~RingBufferReader() {
    stop_polling();
    if (m_ring_buf) {
        ring_buffer__free(m_ring_buf);
        m_ring_buf = nullptr;
    }
}

Status RingBufferReader::init(int ring_buffer_map_fd, SecurityEventCallback callback) {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (ring_buffer_map_fd < 0 || !callback) {
        return Status::ErrEBPFProbeLoadFailed;
    }

    m_user_callback = std::move(callback);

    // Create libbpf ring_buffer manager instance with static C callback bridge
    m_ring_buf = ring_buffer__new(
        ring_buffer_map_fd,
        RingBufferReader::raw_sample_callback,
        this,
        nullptr
    );

    if (!m_ring_buf) {
        std::cerr << "[AEGIS-EBPF-ERROR] Failed to instantiate libbpf ring buffer manager.\n";
        return Status::ErrEBPFProbeLoadFailed;
    }

    return Status::Success;
}

int RingBufferReader::raw_sample_callback(void* ctx, void* data, size_t size) {
    if (!ctx || !data || size == 0) {
        return 0;
    }

    auto* reader = static_cast<RingBufferReader*>(ctx);
    reader->dispatch_event(data, size);
    return 0;
}

void RingBufferReader::dispatch_event(const void* data, size_t size) {
    if (!m_user_callback) return;

    // Decode event variant based on binary payload size matching kernel structs
    if (size == sizeof(RawSyscallEvent)) {
        const auto* raw = static_cast<const RawSyscallEvent*>(data);
        SecuritySyscallEvent event{
            .timestamp_ns = raw->timestamp_ns,
            .pid = raw->pid,
            .tgid = raw->tgid,
            .cgroup_id = raw->cgroup_id,
            .syscall_nr = raw->syscall_nr,
            .comm = std::string(raw->comm, strnlen(raw->comm, sizeof(raw->comm))),
            .action_taken = raw->action_taken
        };
        m_user_callback(event);

    } else if (size == sizeof(RawNetworkEvent)) {
        const auto* raw = static_cast<const RawNetworkEvent*>(data);
        SecurityNetworkEvent event{
            .timestamp_ns = raw->timestamp_ns,
            .pid = raw->pid,
            .tgid = raw->tgid,
            .cgroup_id = raw->cgroup_id,
            .dst_ip_network_order = raw->dst_ip,
            .dst_port = raw->dst_port,
            .protocol = raw->proto,
            .action_taken = raw->action_taken,
            .comm = std::string(raw->comm, strnlen(raw->comm, sizeof(raw->comm)))
        };
        m_user_callback(event);

    } else if (size == sizeof(RawProcessEvent)) {
        const auto* raw = static_cast<const RawProcessEvent*>(data);
        SecurityProcessEvent event{
            .timestamp_ns = raw->timestamp_ns,
            .pid = raw->pid,
            .tgid = raw->tgid,
            .ppid = raw->ppid,
            .cgroup_id = raw->cgroup_id,
            .uid = raw->uid,
            .gid = raw->gid,
            .is_privilege_escalation = (raw->is_privilege_escalation != 0),
            .action_taken = raw->action_taken,
            .comm = std::string(raw->comm, strnlen(raw->comm, sizeof(raw->comm))),
            .filename = std::string(raw->filename, strnlen(raw->filename, sizeof(raw->filename)))
        };
        m_user_callback(event);
    }
}

int RingBufferReader::poll(int timeout_ms) {
    if (!m_ring_buf) {
        return -1;
    }

    int err = ring_buffer__poll(m_ring_buf, timeout_ms);
    if (err < 0) {
        std::cerr << std::format("[AEGIS-EBPF-ERROR] Ring buffer poll failed: {}\n", std::strerror(-err));
    }
    return err;
}

Status RingBufferReader::start_polling() {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_is_polling.load() || !m_ring_buf) {
        return Status::ErrEBPFProbeLoadFailed;
    }

    m_is_polling.store(true);

    // Spawn dedicated background polling thread
    m_polling_thread = std::thread([this]() {
        while (m_is_polling.load()) {
            int err = this->poll(100); // 100ms poll timeout
            if (err < 0 && m_is_polling.load()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        }
    });

    return Status::Success;
}

void RingBufferReader::stop_polling() noexcept {
    if (m_is_polling.exchange(false)) {
        if (m_polling_thread.joinable()) {
            m_polling_thread.join();
        }
    }
}

} // namespace aegis::ebpf