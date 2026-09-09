# Chapter 19: eBPF for Security

## What This Chapter Covers

- eBPF for security monitoring
- LSM (Linux Security Module) hooks
- Seccomp with eBPF
- Network security
- File integrity monitoring
- Building security tools

---

## 19.1 eBPF Security Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                 eBPF SECURITY LAYERS                        │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  LSM Hooks (Linux Security Module)                  │   │
│  │  - File access, socket operations, process actions  │   │
│  │  - Can DENY operations (not just observe)           │   │
│  └─────────────────────────────────────────────────────┘   │
│                            │                                │
│                            ▼                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  XDP/TC (Network Security)                          │   │
│  │  - Packet filtering, DDoS protection                │   │
│  │  - Firewall, load balancing                         │   │
│  └─────────────────────────────────────────────────────┘   │
│                            │                                │
│                            ▼                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Kprobes/Tracepoints (Monitoring)                   │   │
│  │  - System call monitoring                           │   │
│  │  - Process behavior analysis                        │   │
│  └─────────────────────────────────────────────────────┘   │
│                            │                                │
│                            ▼                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Seccomp (Sandboxing)                               │   │
│  │  - Syscall filtering                                │   │
│  │  - Process sandboxing                               │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 19.2 LSM eBPF Programs

LSM (Linux Security Module) hooks allow eBPF programs to **enforce security policies**:

```c
// lsm_deny.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Map: blocked PIDs
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000);
    __type(key, __u32);
    __type(value, __u8);
} blocked_pids SEC(".maps");

// LSM hook: file open
SEC("lsm/file_open")
int BPF_PROG(deny_file_open, struct file *file)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Check if PID is blocked
    if (bpf_map_lookup_elem(&blocked_pids, &pid)) {
        bpf_printk("Denied file open for PID %d\n", pid);
        return -EPERM;  // Return negative to deny
    }

    return 0;  // Return 0 to allow
}

// LSM hook: socket connect
SEC("lsm/socket_connect")
int BPF_PROG(deny_socket_connect, struct socket *sock, struct sockaddr *addr, int addrlen)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (bpf_map_lookup_elem(&blocked_pids, &pid)) {
        bpf_printk("Denied socket connect for PID %d\n", pid);
        return -EPERM;
    }

    return 0;
}

// LSM hook: task execution
SEC("lsm/bprm_check_security")
int BPF_PROG(deny_exec, struct linux_binprm *bprm)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (bpf_map_lookup_elem(&blocked_pids, &pid)) {
        bpf_printk("Denied exec for PID %d\n", pid);
        return -EPERM;
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
```

### 19.2.1 Available LSM Hooks

```c
// File operations
lsm/file_open
lsm/file_permission
lsm/file_receive
lsm/file_ioctl
lsm/file_lock
lsm/file_fcntl

// Socket operations
lsm/socket_create
lsm/socket_bind
lsm/socket_connect
lsm/socket_listen
lsm/socket_accept
lsm/socket_sendmsg
lsm/socket_recvmsg

// Task operations
lsm/task_alloc
lsm/task_free
lsm/task_setnice
lsm/task_setioprio
lsm/task_prlimit
lsm/bprm_check_security

// inode operations
lsm/inode_create
lsm/inode_unlink
lsm/inode_rename
lsm/inode_getattr
lsm/inode_setattr
```

---

## 19.3 Seccomp with eBPF

Seccomp (Secure Computing) with eBPF allows syscall filtering:

```c
// seccomp_filter.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Map: allowed syscalls per process
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000);
    __type(key, __u32);     // PID
    __type(value, __u64);   // Bitmask of allowed syscalls
} allowed_syscalls SEC(".maps");

SEC("cgroup/sysctl")
int seccomp_filter(struct bpf_sysctl *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 *allowed = bpf_map_lookup_elem(&allowed_syscalls, &pid);

    if (!allowed)
        return 0;  // No restrictions

    // Check if syscall is allowed
    // (Simplified — actual seccomp uses different hooks)
    return 0;
}

char _license[] SEC("license") = "GPL";
```

---

## 19.4 Network Security with XDP

```c
// xdp_security.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Map: blocked IPs
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, __u8);
} blocked_ips SEC(".maps");

// Map: rate limits per IP
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, __u64);  // Last packet timestamp
} rate_limits SEC(".maps");

// Map: connection tracking
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, struct conn_key);
    __type(value, struct conn_state);
} connections SEC(".maps");

struct conn_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 protocol;
};

struct conn_state {
    __u64 packets;
    __u64 bytes;
    __u64 last_seen;
    __u8 state;
};

#define RATE_LIMIT_NS 1000000000  // 1 second

SEC("xdp")
int xdp_security_filter(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parse Ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IP
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;

    // Check blocked IPs
    if (bpf_map_lookup_elem(&blocked_ips, &ip->saddr))
        return XDP_DROP;

    // Rate limiting
    __u64 now = bpf_ktime_get_ns();
    __u64 *last = bpf_map_lookup_elem(&rate_limits, &ip->saddr);
    if (last && (now - *last) < RATE_LIMIT_NS)
        return XDP_DROP;  // Rate limited

    bpf_map_update_elem(&rate_limits, &ip->saddr, &now, BPF_ANY);

    // TCP-specific checks
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return XDP_DROP;

        // SYN flood protection
        if (tcp->syn && !tcp->ack) {
            // Track SYN packets
            // ...
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

---

## 19.5 File Integrity Monitoring

```c
// file_integrity.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define PATH_MAX 256
#define TASK_COMM_LEN 16

struct file_event {
    __u32 pid;
    __u32 uid;
    char comm[TASK_COMM_LEN];
    char path[PATH_MAX];
    __u32 operation;  // 0=open, 1=modify, 2=delete, 3=rename
    __u64 timestamp;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Map: protected paths
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000);
    __type(key, char[PATH_MAX]);
    __type(value, __u8);
} protected_paths SEC(".maps");

static __always_inline void report_event(struct pt_regs *ctx, const char *path, __u32 op)
{
    struct file_event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->operation = op;
    e->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(e->path, sizeof(e->path), path);

    bpf_ringbuf_submit(e, 0);
}

SEC("lsm/path_unlink")
int BPF_PROG(monitor_delete, struct path *dir, struct dentry *dentry)
{
    // Report file deletion
    // (Simplified — actual path extraction is more complex)
    return 0;
}

SEC("lsm/file_permission")
int BPF_PROG(monitor_access, struct file *file, int mask)
{
    // Report file access
    return 0;
}

char _license[] SEC("license") = "GPL";
```

---

## 19.6 Rust Security Tool Example

```rust
// ebpf/src/main.rs
#![no_std]
#![no_main]

use aya_bpf::{
    macros::{lsm, map},
    programs::LsmContext,
    maps::HashMap,
    bindings::file,
};

#[map]
static BLOCKED_PIDS: HashMap<u32, u8> = HashMap::with_max_entries(1000, 0);

#[lsm]
pub fn file_open(ctx: LsmContext) -> i32 {
    let file: *const file = ctx.arg(0);

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    if BLOCKED_PIDS.get(&pid).is_some() {
        return -1;  // EPERM
    }

    0  // Allow
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
```

---

## 19.7 Summary

- **LSM hooks** allow enforcing security policies (deny operations)
- **XDP** for network security (DDoS, firewall)
- **Seccomp** for syscall filtering
- **File integrity monitoring** with LSM hooks
- Return **negative values** to deny, 0 to allow
- Requires `CAP_BPF` and `CAP_SYS_ADMIN` for LSM

---

## 19.8 Looking Ahead

Chapter 20 covers **performance tuning** — optimizing eBPF programs for speed and efficiency.

---

*Next: [Chapter 20 — Performance Tuning](./20-performance.md)*
