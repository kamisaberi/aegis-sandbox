/**
 * @file net_filter.bpf.c
 * @brief eBPF Kernel Network Egress & Metadata Anti-SSRF Filter for aegis-sandbox
 * @author Kamran Saberifard
 * @license Apache 2.0 / Dual BSD
 * 
 * Compilation (via Clang):
 *   clang -O2 -target bpf -g -D__TARGET_ARCH_x86 \
 *     -Iebpf/include -I/usr/include/bpf \
 *     -c ebpf/net_filter.bpf.c -o ebpf_obj/net_filter.bpf.o
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TASK_COMM_LEN 16

/* License Declaration required by Linux kernel loader */
char _license[] SEC("license") = "GPL";

/**
 * @brief Structure representing a blocked network connection event emitted to user-space.
 */
struct net_security_event {
    u64 timestamp_ns;
    u32 pid;
    u32 tgid;
    u32 cgroup_id;
    u32 dst_ip;      // IPv4 in Network Byte Order
    u16 dst_port;    // Destination Port
    u8 proto;        // Protocol (TCP/UDP)
    u8 action_taken; // 0 = ALLOWED, 1 = BLOCKED
    char comm[TASK_COMM_LEN];
};

// -----------------------------------------------------------------------------
// BPF Maps Definition
// -----------------------------------------------------------------------------

/**
 * @brief Hash Map storing blocked IPv4 addresses (Network Byte Order).
 * Key: u32 (IPv4 Address) | Value: u8 (1 = Blocked)
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u32);
    __type(value, u8);
} aegis_blocked_ips SEC(".maps");

/**
 * @brief BPF Ring Buffer for emitting real-time network security alerts to C++ user-space.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB Ring Buffer
} aegis_net_events SEC(".maps");

// -----------------------------------------------------------------------------
// BPF Cgroup Socket Connect Hook
// -----------------------------------------------------------------------------

/**
 * @brief Intercepts IPv4 connect() calls initiated within sandboxed cgroups.
 */
SEC("cgroup/connect4")
int aegis_cgroup_connect4(struct bpf_sock_addr *ctx) {
    // Only inspect IPv4 socket connections
    if (ctx->family != AF_INET) {
        return 1; // Allow IPv6/other protocols unless explicitly restricted
    }

    u32 dst_ip = ctx->user_ip4;
    u16 dst_port = bpf_ntohs((u16)ctx->user_port);

    // 1. Hardcoded Protection: Block Cloud Provider Metadata IP (169.254.169.254)
    // 169.254.169.254 in Network Byte Order = 0xFEA9FEA9
    u32 metadata_ip = bpf_hltonl(0xA9FEA9FE); 

    u8 is_blocked = 0;
    if (dst_ip == metadata_ip) {
        is_blocked = 1;
    } else {
        // 2. Dynamic Policy Lookup in BPF Hash Map
        u8 *policy = bpf_map_lookup_elem(&aegis_blocked_ips, &dst_ip);
        if (policy && *policy == 1) {
            is_blocked = 1;
        }
    }

    // 3. Handle Blocked Connection
    if (is_blocked) {
        // Reserve an alert entry in the BPF ring buffer
        struct net_security_event *event = bpf_ringbuf_reserve(&aegis_net_events, sizeof(struct net_security_event), 0);
        
        if (event) {
            u64 pid_tgid = bpf_get_current_pid_tgid();
            
            event->timestamp_ns = bpf_ktime_get_ns();
            event->pid = pid_tgid >> 32;
            event->tgid = (u32)pid_tgid;
            event->cgroup_id = (u32)bpf_get_current_cgroup_id();
            event->dst_ip = dst_ip;
            event->dst_port = dst_port;
            event->proto = (u8)ctx->protocol;
            event->action_taken = 1; // BLOCKED

            bpf_get_current_comm(&event->comm, sizeof(event->comm));

            bpf_ringbuf_submit(event, 0);
        }

        // Return 0 to reject the socket connection attempt at the kernel layer
        return 0;
    }

    // Return 1 to allow legitimate socket connections
    return 1;
}