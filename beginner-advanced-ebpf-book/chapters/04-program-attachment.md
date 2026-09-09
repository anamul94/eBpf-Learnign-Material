# Chapter 8: Program Attachment & Hook Points

## What This Chapter Covers

- How eBPF programs connect to kernel events
- All program types: kprobe, tracepoint, XDP, cgroup, LSM, etc.
- Attachment mechanisms and tools
- Program lifecycle: load, attach, detach
- **Why:** Knowing where and how to attach is what turns compiled eBPF bytecode into a running tracing or networking tool. Without proper attachment, the program does nothing.

---

## 8.1 Attachment Overview

An eBPF program is useless unless it's attached to a kernel hook. The hook is what triggers the program to execute. Different program types attach to different hook points, and each has its own:

- Attachment mechanism
- Context structure (what data the program receives)
- Return value semantics
- Performance characteristics

### The attachment flow

```
1. Write eBPF program (C or Rust)
2. Compile to bytecode (clang -target bpf)
3. Generate skeleton (bpftool gen skeleton)
4. Load program (bpftool prog load, or libbpf BPF_PROG_LOAD)
5. Attach to hook (bpftool prog attach, or libbpf attach)
6. Program runs when hook fires
7. Detach (bpftool prog detach) or program unloads
```

---

## 8.2 Kprobes — Dynamic Function Tracing

### What they are

Kprobes (Kernel Probes) let you attach an eBPF program to **any kernel function address**. They consist of:

- **probe** (kprobe): fires when the function is **entered**
- **retprobe** (kretprobe): fires when the function **returns**
- **uprobe**: user-space probe (rarely used for eBPF, more for bpftrace)

### Attachment

```c
// kprobe: enter function
SEC("kprobe/sys_accept")
int kprobe_sys_accept(struct pt_regs *ctx) {
    // ctx->ax, ctx->bx, etc. contain register state at entry
    // ctx->arg1, ctx->arg2, etc. contain arguments
    return 0;
}

// kretprobe: return from function
SEC("kretprobe/sys_accept")
int kretprobe_sys_accept(struct pt_regs *ctx) {
    // ctx contains register state at return
    // return value is in ctx->ax (x86-64) or ctx->ret (ARM)
    return 0;
}
```

### Context: `struct pt_regs`

R10 (frame pointer) points to `struct pt_regs`, which contains:

```
struct pt_regs {
    __u16 vector;     // Interrupt vector number
    __u144 reserved;   // Padding
    __u32 flags;      // CPU flags
    __u32 bx, cx, dx; // Saved registers
    __u32 si, di;     // Source/dest index
    __u32 bp;         // Base pointer
    __u32 sp;         // Stack pointer
    __u32 si, di;     // Additional
    __u64 ax, bx, cx, dx; // General purpose (32-bit halves)
    __u64 di, si, gp, tp; // Additional
    __u64 error;      // Error code (if from interrupt)
    __u64 ip;         // Instruction pointer
    __u64 sp;         // Stack pointer (redundant)
    __u64 pc;         // Program counter
};
```

### Key registers accessible via ctx

| Register | Meaning | Access in eBPF |
|----------|---------|----------------|
| R0-R5 | Temporary / return values | Writable |
| R6 | Frame pointer (rbp) | Stack base |
| R7-R9 | Callee-saved | Must preserve |
| R10 | **Read-only frame** | Points to pt_regs |
| ... from pt_regs | ax, bx, cx, dx, ip, sp, flags | Via `bpf_get_reg(ctx, offset)` |

### Helper: getting register values

```c
// Get the return value (ax register)
__u64 ret = bpf_get_current_ctx(ctx); // not a real helper
// Instead, access via ctx->ax or raw offset
// Common pattern:
// __u64 retval = (long)ctx->ax;
```

### When to use kprobe vs kretprobe

| Scenario | Use |
|----------|-----|
| Trace function entry, inspect args | `SEC("kprobe/func_name")` |
| Trace function return, inspect retval | `SEC("kretprobe/func_name")` |
| Both entry and return | Two separate programs, or use kprobe + kretprobe |
| Function doesn't return (panic/noreturn) | Only kprobe on entry |

### Limitations

- Cannot kprobe: `inline` functions (may be inlined), architecture-dependent limitations, some arch-specific restrictions on kprobe targets
- Verifier checks: can't kprobe from interrupt context unless specifically allowed

---

## 8.3 Tracepoints — Static Kernel Probes

### What they are

Tracepoints are **statically defined** points in the kernel (hundreds exist). They're the preferred tracing mechanism when available because:

- **Lower overhead**: JIT-compiled specially for the tracepoint
- **No probe contention**: Multiple tracers can attach simultaneously
- **Stable API**: Kernel developers guarantee compatibility

### Finding tracepoints

```bash
# List all tracepoints
sudo bpftool tracepoint list

# List tracepoints for a specific subsystem
sudo bpftool tracepoint list syscalls
```

### Common tracepoint categories

| Category | Example tracepoints |
|----------|--------------------|
| `syscalls` | `sys_enter_execve`, `sys_enter_openat`, `sys_enter_read` |
| `sched` | `sched_process_fork`, `sched_switch`, `sched_process_exit` |
| `net` | `netif_receive_skb`, `tcp_connection_close`, `udp_sendmsg` |
| `block` | `block_rq_submit`, `block_rq_complete` |
| `irq` | `irq_handler_entry`, `irq_handler_exit` |
| `bpf` | `bpf_raw_api_calls`, `bpf_prog_load` |

### Attachment

```c
// Attach to sys_enter_execve tracepoint
SEC("tp/syscalls/sys_enter_execve")
int trace_sys_enter_execve(struct trace_event_raw_sys_enter *ctx) {
    // ctx->nr: syscall number (59 = execve on x86-64)
    // ctx->args[0-5]: syscall arguments
    // ctx->args[0]: const char __user *filename
    return 0;
}
```

### Tracepoint context structure

For `sys_enter_execve`:

```c
struct trace_event_raw_sys_enter {
    __u64 unused;
    __u32 nr;           // Syscall number
    __u32 flags;
    __u64 args[6];      // Syscall arguments (up to 6)
};
```

For `sched_switch`:

```c
struct trace_event_raw_sched_switch {
    __u64 prev_pid;
    __u32 prev_prio;
    __s8 prev_pid_ts[16]; // task comm
    __u64 next_pid;
    __u32 next_prio;
    __s8 next_comm[16];
    __u64 flags;
};
```

### Advantages over kprobes

| Advantage | Detail |
|-----------|--------|
| **Stability** | Kernel guarantees not to remove tracepoints |
| **Multiple attaches** | Many eBPF programs can attach to same tracepoint |
| **Lower overhead** | Verifier knows the template; JIT is optimized |
| **Structured data** | Context has named fields, not raw registers |

### When tracepoints aren't enough

- Function not instrumented with a tracepoint
- Need to trace a specific line number, not just function entry
- Need access to register state that tracepoint doesn't expose
- Want to trace user-space functions (use uprobes instead)

---

## 8.4 XDP — eXpress Data Path

### What it is

XDP (eXpress Data Path) is the **fastest** way to process network packets in Linux. It runs at the very top of the network stack, right after the NIC driver pulls the packet from the wire.

### Attachment points

| Level | Mechanism | Command |
|-------|-----------|---------|
| **Driver level** | `netdev_xdp_register()` | `ip link set dev eth0 xdp obj prog_fd` |
| **Generic** | `tc` qdisc with bpf | `tc qdisc add dev eth0 cls bpf xdp` |
| **Attach/detach** | Dynamic, runtime | `ip link set dev eth0 xdp off` |

### XDP program structure

```c
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_prog(struct xdp_md *md) {
    // Packet bounds: md->data to md->data_end
    // Available: md->data, md->data_end
    // Return values: XDP_PASS, XDP_DROP, XDP_REDIRECT, XDP_TX, XDP_TX
    
    void *data_end = (void *)(long)md->data_end;
    void *data = (void *)(long)md->data;
    
    // Basic: drop all packets
    if (data_end - data > 200)  // Minimal sanity check
        return XDP_DROP;
    
    // Pass everything else
    return XDP_PASS;
}
```

### Return values

| Value | Meaning |
|-------|---------|
| `XDP_PASS` (0) | Pass to normal network stack |
| `XDP_DROP` (1) | Drop the packet |
| `XDP_TX` (2) | Transmit out of interface (from helper) |
| `XDP_REDIRECT` (3) | Redirect to another interface (via `bpf_redirect`) |
| `XDP_ABORTED` (4) | Verifier/error; program not loaded |

### Helper functions (XDP-specific)

```c
// Redirect to another interface (index ifindex)
bpf_redirect_iface(ifindex, 0);

// Redirect to specific CPU's TX queue
bpf_redirect_cpu(cpu_id, 0);

// Get interface index from name
bpf_get_ifindex(ctx, "eth0");
```

### Performance

- **Latency**: ~microseconds (vs ~100µs for normal stack)
- **Throughput**: Can saturate 10Gb+ links
- **Context**: `struct xdp_md` with `data` and `data_end` pointers
- **Limitations**: 2KB max packet inspection (TPACK_SIZE); cannot modify large portions of packet

### When to use XDP

| Use case | Why XDP |
|----------|---------|
| Packet filtering | Drop malicious traffic at driver level |
| Traffic redirection | Route based on payload, source, destination |
| Port mirroring | Copy packets to monitoring tools |
| Load balancing | Distribute connections across backends |
| Observability | Count/packet insights with minimal latency |

### When NOT to use XDP

| Reason | Alternative |
|--------|-------------|
| Need full protocol parsing | Use tc/bpf socket filters instead |
| Must modify packet payload extensively | Use regular BPF with `tc` qdisc |
| Complex routing decisions | Use kernel routing table + XDP redirect subset |
| Debugging driver issues | Use kprobes/tracepoints |

---

## 8.5 cgroup — Control Group Attachment

### What it is

cgroup (control group) BPF programs attach to cgroups and can inspect/throttle:

- **cgroup network**: Bandwidth limiting, packet filtering per cgroup
- **cgroup skb**: Per-socket-buffer inspection
- **cgroup device**: Device access filtering

### Attachment

```bash
# Load program
sudo bpftool prog load xdp.o /sys/fs/bpf/xdp_prog

# Attach to cgroup
sudo bpftool cgroup attach /sys/fs/cgroup/mycgroup/xdp_prog fd 27

# Or via iproute2
sudo ip cgroup add 5700:1 attach xdp /sys/fs/bpf/xdp_prog
```

### cgroup SKB program

```c
SEC("cgroup/skb")
int cgroup_skb_prog(struct bpf_cgroup_ctx *ctx) {
    // ctx->cgroup_uid: cgroup's effective UID
    // ctx->net: network namespace info
    // Can look up maps, check bandwidth, etc.
    return 0;
}
```

### Use cases

- Per-cgroup bandwidth metering
- Network policy enforcement per group
- Container traffic isolation (Kubernetes, Docker)

---

## 8.6 LSM — Linux Security Modules

### What it is

LSM hooks are **security hooks** throughout the kernel. eBPF can now extend LSM behavior without kernel module recompilation.

### Common LSM hooks

| Hook | When it fires | eBPF program type |
|------|---------------|-------------------|
| `lsm/bpf/` (generic) | eBPF-specific LSM hook | `lsm` program type |
| `security_socket_create` | Socket creation | lsm or socket_filter |
| `security_file_open` | File open | lsm |
| `security_task_create` | Process creation | lsm |
| `security_binder_set_attrs` | Binder IPC | lsm |

### Example: Trace file opens

```c
SEC("lsm/file_open")
int trace_file_open(struct file *filp) {
    // filp->f_path.dentry->d_name: filename
    // Current task: bpf_get_current_comm()
    return 0;
}
```

### Loading LSM programs

```bash
# Load and auto-attach to all LSM hooks
sudo bpftool prog load lsm_prog.o /sys/fs/bpf/lsm_prog

# The program attaches to every available LSM hook automatically
```

### Limitations

- Not all LSMs support eBPF extension
- Requires kernel with `CONFIG_SECURITY_SELINUX` or similar
- Hook availability depends on loaded LSMs (AppArmor, SELinux, Landlock, etc.)

---

## 8.7 Uprobes — User-Space Probes (Advanced)

### What they are

Uprobes let you probe user-space functions, similar to kprobes but in userspace:

```c
SEC("uprobe/libc.so:free")
int uprobe_free(void *ctx) {
    // ctx contains pointer to called function's args
    // Can trace when specific library functions are called
    return 0;
}
```

### Limitations for eBPF

- Not all eBPF frameworks support uprobes natively
- Usually requires separate userspace tracing (ltrace, strace)
- More commonly used with bpftrace than raw libbpf

---

## 8.8 Program Lifecycle

### Load

```c
// Using libbpf:
skel = bpf_object__open_file("prog.o");
bpf_object__load(skel);

// Using bpftool:
sudo bpftool prog load prog.o /sys/fs/bpf/test
```

### Attach

```c
// Using libbpf:
err = bpf_program__attach_kprobe(bpf_program__find_by_title(skel->progs, "sys_enter_execve"), 0);

// Using bpftool:
sudo bpftool prog attach /sys/fs/bpf/test tag <tag_from_skeleton>
```

### Runtime

- Program executes when hook fires
- Runs in interrupt context (for XDP, some kprobes) or process context
- Must return quickly (typically < 10µs for XDP)
- Can update maps, ring buffers, or modify return values

### Detach/Unload

```c
// Detach
sudo bpftool prog detach /sys/fs/bpf/test

// Unload
sudo bpftool prog unload 27
```

---

## 8.9 Attachment Tools Comparison

| Tool | Best for | Command style |
|------|----------|---------------|
| **bpftool** | Low-level, scriptable | `bpftool prog load/attach/detach` |
| **libbpf** | C/Rust programs, integrated | `bpf_object__open_load_attach()` |
| **iproute2** | XDP, cgroup attachment | `ip link set dev eth0 xdp ...` |
| **cilium/ebpf** | Rust, high-level | `aya::programs::Xdp` |
| **bpftrace** | Interactive tracing, one-liners | `bpftrace -e 'kprobe:func { ... }'` |
| **perf** | Profiling, overhead analysis | `perf record -e kprobe:func` |

---

## 8.10 Summary

| Program Type | Hook Point | Context (R10) | Best Use |
|--------------|------------|---------------|----------|
| **KPROBE** | Any kernel function | `struct pt_regs *` | Function tracing, register inspection |
| **KRETPROBE** | Function return | `struct pt_regs *` | Return values, post-condition checks |
| **TRACEPOINT** | Static kernel points | `struct trace_event_*` | Low-overhead, stable tracing |
| **XDP** | Network driver entry | `struct xdp_md *` | Packet filtering, high-speed networking |
| **CGROUP/SKB** | cgroup network iface | `struct bpf_cgroup_ctx *` | Per-cgroup bandwidth, policy |
| **LSM** | Security hooks | varies by LSM | Security enforcement, tracing |
| **UPROBE** | User-space functions | varies | Library function tracing (advanced) |

---

## 8.11 Looking Ahead

In Chapter 9, we'll write our **first complete eBPF program** — a tracepoint-based syscall counter. You'll see maps, ring buffers, and the libbpf skeleton API all come together.

*Next: [Chapter 9 — First eBPF Program: Tracepoint Counter](./09-first-ebpf-c.md)*