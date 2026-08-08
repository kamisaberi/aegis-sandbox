/**
 * @file sys_filter.bpf.c
 * @brief eBPF Kernel System Call Filtering & Enforcement Engine for aegis-sandbox
 * @author Kamran Saberifard
 * @license Apache 2.0 / Dual BSD
 * 
 * Compilation (via Clang):
 *   clang -O2 -target bpf -g -D__TARGET_ARCH_x86 \
 *     -Iebpf/include -I/usr/include/bpf \
 *     -c ebpf/sys_filter.bpf.c -o ebpf_obj/sys_filter.bpf.o
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define SIGKILL 9
#define EPERM 1

/**
 * @brief Event structure emitted to the user-space ring buffer upon a security violation.
 */
struct security_event {
    u64 timestamp_ns;
    u32 pid;
    u32 tgid;
    u32 cgroup_id;
    u32 syscall_nr;
    char comm[TASK_COMM_LEN];
    u8 action_taken; // 1 = SIGKILL, 2 = BLOCKED
};

/* License Declaration required by Linux kernel loader */
char _license[] SEC("license") = "GPL";

// -----------------------------------------------------------------------------
// BPF Maps Definition
// -----------------------------------------------------------------------------

/**
 * @brief Hash Map tracking sandboxed Cgroup IDs.
 * Key: u64 (Cgroup ID) | Value: u8 (1 = Sandboxed, 0 = Unmonitored)
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, u8);
} aegis_monitored_cgroups SEC(".maps");

/**
 * @brief Array Map defining whitelisted/blacklisted System Calls.
 * Key: u32 (Syscall Number) | Value: u8 (0 = Allowed, 1 = Blocked/Kill)
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 512);
    __type(key, u32);
    __type(value, u8);
} aegis_syscall_policy SEC(".maps");

/**
 * @brief BPF Ring Buffer Map for emitting real-time security violation events to C++ user-space.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB Ring Buffer
} aegis_security_events SEC(".maps");

// -----------------------------------------------------------------------------
// BPF Tracepoint Program
// -----------------------------------------------------------------------------

/**
 * @brief Intercepts raw syscall entries in the Linux Kernel.
 */
SEC("tracepoint/raw_syscalls/sys_enter")
int handle_sys_enter(struct trace_event_raw_sys_enter *ctx) {
    u64 cgroup_id = bpf_get_current_cgroup_id();

    // 1. Check if the current process belongs to a monitored aegis-sandbox Cgroup
    u8 *is_monitored = bpf_map_lookup_elem(&aegis_monitored_cgroups, &cgroup_id);
    if (!is_monitored || *is_monitored == 0) {
        return 0; // Unmonitored process; allow execution unconditionally
    }

    u32 syscall_nr = (u32)ctx->id;

    // 2. Lookup Syscall Policy in the BPF Map
    u8 *policy_action = bpf_map_lookup_elem(&aegis_syscall_policy, &syscall_nr);
    
    // If policy action is 1 (BLOCKED/KILL), trigger enforcement
    if (policy_action && *policy_action == 1) {
        
        // Reserve an event entry in the BPF ring buffer
        struct security_event *event = bpf_ringbuf_reserve(&aegis_security_events, sizeof(struct security_event), 0);
        
        if (event) {
            u64 pid_tgid = bpf_get_current_pid_tgid();
            
            event->timestamp_ns = bpf_ktime_get_ns();
            event->pid = pid_tgid >> 32;
            event->tgid = (u32)pid_tgid;
            event->cgroup_id = (u32)cgroup_id;
            event->syscall_nr = syscall_nr;
            event->action_taken = 1; // SIGKILL

            bpf_get_current_comm(&event->comm, sizeof(event->comm));

            // Submit the alert event to user-space
            bpf_ringbuf_submit(event, 0);
        }

        // Immediately terminate the process before the syscall executes
        bpf_send_signal(SIGKILL);
    }

    return 0;
}