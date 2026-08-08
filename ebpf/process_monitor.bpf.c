/**
 * @file process_monitor.bpf.c
 * @brief eBPF Kernel Process Execution & Privilege Escalation Monitor for aegis-sandbox
 * @author Kamran Saberifard
 * @license Apache 2.0 / Dual BSD
 * 
 * Compilation (via Clang):
 *   clang -O2 -target bpf -g -D__TARGET_ARCH_x86 \
 *     -Iebpf/include -I/usr/include/bpf \
 *     -c ebpf/process_monitor.bpf.c -o ebpf_obj/process_monitor.bpf.o
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define MAX_PATH_LEN 256
#define SIGKILL 9

/* License Declaration required by Linux kernel loader */
char _license[] SEC("license") = "GPL";

/**
 * @brief Structure representing a process execution event emitted to user-space.
 */
struct process_exec_event {
    u64 timestamp_ns;
    u32 pid;
    u32 tgid;
    u32 ppid;
    u32 cgroup_id;
    u32 uid;
    u32 gid;
    u8 is_privilege_escalation; // 1 = UID changed or root exec attempt
    u8 action_taken;            // 0 = LOGGED, 1 = SIGKILL
    char comm[TASK_COMM_LEN];
    char filename[MAX_PATH_LEN];
};

// -----------------------------------------------------------------------------
// BPF Maps Definition
// -----------------------------------------------------------------------------

/**
 * @brief Hash Map tracking sandboxed Cgroup IDs.
 * Key: u64 (Cgroup ID) | Value: u8 (1 = Sandboxed)
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, u8);
} aegis_monitored_cgroups_proc SEC(".maps");

/**
 * @brief BPF Ring Buffer Map for emitting real-time process execution events to C++ user-space.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB Ring Buffer
} aegis_process_events SEC(".maps");

// -----------------------------------------------------------------------------
// BPF Syscall Tracepoint Hook
// -----------------------------------------------------------------------------

/**
 * @brief Tracepoint struct matching sys_enter_execve parameters.
 */
struct trace_event_raw_sys_enter_execve {
    u64 unused;
    long id;
    const char *filename;
    const char *const *argv;
    const char *const *envp;
};

/**
 * @brief Intercepts execve() system calls inside monitored sandboxed cgroups.
 */
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve_enter(struct trace_event_raw_sys_enter_execve *ctx) {
    u64 cgroup_id = bpf_get_current_cgroup_id();

    // 1. Verify if process belongs to a monitored aegis-sandbox cgroup
    u8 *is_monitored = bpf_map_lookup_elem(&aegis_monitored_cgroups_proc, &cgroup_id);
    if (!is_monitored || *is_monitored == 0) {
        return 0; // Unmonitored process; skip
    }

    // 2. Reserve an event entry in the BPF ring buffer
    struct process_exec_event *event = bpf_ringbuf_reserve(&aegis_process_events, sizeof(struct process_exec_event), 0);
    if (!event) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 uid_gid = bpf_get_current_uid_gid();

    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = pid_tgid >> 32;
    event->tgid = (u32)pid_tgid;
    event->cgroup_id = (u32)cgroup_id;
    event->uid = (u32)uid_gid;
    event->gid = (u32)(uid_gid >> 32);
    event->action_taken = 0; // LOGGED default

    // Extract parent PID (PPID) using CO-RE helper
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent_task = BPF_CORE_READ(task, real_parent);
    event->ppid = BPF_CORE_READ(parent_task, tgid);

    // Read process executable name
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Read target binary path string safely from user space
    if (ctx->filename) {
        bpf_probe_read_user_str(&event->filename, sizeof(event->filename), ctx->filename);
    } else {
        event->filename[0] = '\0';
    }

    // 3. Detect Privilege Escalation (e.g. UID == 0 execution inside non-root container)
    if (event->uid == 0) {
        event->is_privilege_escalation = 1;
        event->action_taken = 1; // SIGKILL
    } else {
        event->is_privilege_escalation = 0;
    }

    // Submit event report to C++ user-space reader
    bpf_ringbuf_submit(event, 0);

    // 4. Terminate process immediately if privilege escalation was detected
    if (event->is_privilege_escalation) {
        bpf_send_signal(SIGKILL);
    }

    return 0;
}