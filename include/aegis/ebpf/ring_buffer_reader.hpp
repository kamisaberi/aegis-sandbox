/**
 * @file ring_buffer_reader.hpp
 * @brief Thread-Safe C++20 eBPF Ring Buffer Security Event Reader for aegis-sandbox
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#pragma once

#include <aegis/aegis.hpp>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include <cstdint>
#include <string>
#include <variant>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>

namespace aegis::ebpf {

/**
 * @brief Event structure matching sys_filter.bpf.c kernel payload.
 */
struct AEGIS_API SecuritySyscallEvent {
    uint64_t timestamp_ns{0};
    uint32_t pid{0};
    uint32_t tgid{0};
    uint32_t cgroup_id{0};
    uint32_t syscall_nr{0};
    std::string comm;
    uint8_t action_taken{0}; // 1 = SIGKILL, 2 = BLOCKED
};

/**
 * @brief Event structure matching net_filter.bpf.c kernel payload.
 */
struct AEGIS_API SecurityNetworkEvent {
    uint64_t timestamp_ns{0};
    uint32_t pid{0};
    uint32_t tgid{0};
    uint32_t cgroup_id{0};
    uint32_t dst_ip_network_order{0};
    uint16_t dst_port{0};
    uint8_t protocol{0};
    uint8_t action_taken{0}; // 0 = ALLOWED, 1 = BLOCKED
    std::string comm;
};

/**
 * @brief Event structure matching process_monitor.bpf.c kernel payload.
 */
struct AEGIS_API SecurityProcessEvent {
    uint64_t timestamp_ns{0};
    uint32_t pid{0};
    uint32_t tgid{0};
    uint32_t ppid{0};
    uint32_t cgroup_id{0};
    uint32_t uid{0};
    uint32_t gid{0};
    bool is_privilege_escalation{false};
    uint8_t action_taken{0}; // 0 = LOGGED, 1 = SIGKILL
    std::string comm;
    std::string filename;
};

/**
 * @brief Variant type encapsulating any incoming eBPF security event.
 */
using SecurityEventVariant = std::variant<
    SecuritySyscallEvent,
    SecurityNetworkEvent,
    SecurityProcessEvent
>;

/**
 * @brief Callback function signature for receiving parsed security events in C++.
 */
using SecurityEventCallback = std::function<void(const SecurityEventVariant&)>;

/**
 * @brief Thread-safe C++20 Ring Buffer Reader consuming eBPF kernel security events.
 */
class AEGIS_API RingBufferReader {
public:
    RingBufferReader();
    ~RingBufferReader();

    // Non-copyable, non-movable
    RingBufferReader(const RingBufferReader&) = delete;
    RingBufferReader& operator=(const RingBufferReader&) = delete;
    RingBufferReader(RingBufferReader&&) = delete;
    RingBufferReader& operator=(RingBufferReader&&) = delete;

    /**
     * @brief Initializes the ring buffer reader with a target BPF map file descriptor.
     * @param ring_buffer_map_fd File descriptor of the BPF_MAP_TYPE_RINGBUF map.
     * @param callback Function invoked whenever a security event is received.
     * @return Status::Success if ring buffer opened successfully.
     */
    Status init(int ring_buffer_map_fd, SecurityEventCallback callback);

    /**
     * @brief Polls the ring buffer once with a specified timeout.
     * @param timeout_ms Timeout duration in milliseconds.
     * @return Number of records consumed, or negative status error code.
     */
    int poll(int timeout_ms = 100);

    /**
     * @brief Starts a dedicated background polling thread.
     */
    Status start_polling();

    /**
     * @brief Stops the background polling thread and joins it.
     */
    void stop_polling() noexcept;

    [[nodiscard]] bool is_polling() const noexcept { return m_is_polling.load(); }

private:
    static int raw_sample_callback(void* ctx, void* data, size_t size);
    void dispatch_event(const void* data, size_t size);

    struct ring_buffer* m_ring_buf{nullptr};
    SecurityEventCallback m_user_callback;
    std::thread m_polling_thread;
    std::atomic<bool> m_is_polling{false};
    std::mutex m_mutex;
};

} // namespace aegis::ebpf