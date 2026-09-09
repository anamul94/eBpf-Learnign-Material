# Chapter 10: Kprobes and Kretprobes — Dynamic Kernel Tracing

## What This Chapter Covers

- Dynamic vs static tracing
- How kprobes work
- Kprobes for function entry
- Kretprobes for function return
- Fentry/fexit (modern alternative)
- Reading function arguments
- Practical examples

---

## 10.1 Dynamic vs Static Tracing

| Type | Attachment | Stability | Coverage |
|------|------------|-----------|----------|
| **Tracepoints** | Static, defined in kernel source | Stable ABI | Limited to defined points |
| **Kprobes** | Dynamic, any kernel function | May break across versions | Any non-inline function |
| **Fentry/Fexit** | Dynamic via BPF trampoline | May break | Any function (with BTF) |

**When to use what:**
- **Tracepoints**: When available, prefer these (stable, documented)
- **Kprobes**: When no tracepoint exists for your use case
- **Fentry/Fexit**: When you need maximum performance and have BTF

---

## 10.2 How Kprobes Work

Kprobes work by **replacing an instruction** at the target address with a breakpoint. When the CPU hits this breakpoint:

```
┌─────────────────────────────────────────────────────────────┐
│                    KPROBE MECHANISM                         │
│                                                             │
│  1. User registers kprobe at function address              │
│                                                             │
│  2. Kernel saves the original instruction                   │
│     and replaces it with a breakpoint (int3 on x86)        │
│                                                             │
│  3. When CPU hits the breakpoint:                          │
│     ├── Save CPU registers (pt_regs)                        │
│     ├── Call pre_handler (your eBPF program)               │
│     ├── Execute original instruction (single-step)         │
│     ├── Call post_handler (if registered)                  │
│     └── Continue normal execution                          │
│                                                             │
│  4. For kretprobe:                                         │
│     ├── Save return address on entry                       │
│     ├── Replace return address with trampoline             │
│     ├── On return, trampoline calls your program           │
│     └── Original return address restored                   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 10.3 Kprobe Example

### 10.3.1 eBPF Program

```c
// kprobe_example.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16

struct event {
    __u32 pid;
    __u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[256];
    __u64 timestamp;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Kprobe on do_sys_openat2 (kernel >= 5.6) or do_sys_open
SEC("kprobe/do_sys_openat2")
int BPF_KPROBE(trace_do_sys_openat2, int dfd, const char *filename, struct open_how *how)
{
    struct event *e;

    // Reserve ring buffer space
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    // Fill event data
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Safely read filename from userspace
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);

    // Submit event
    bpf_ringbuf_submit(e, 0);

    return 0;
}

char _license[] SEC("license") = "GPL";
```

### 10.3.2 Understanding BPF_KPROBE Macro

```c
// BPF_KPROBE is a helper macro that:
// 1. Defines the function with pt_regs *ctx as first argument
// 2. Extracts function arguments from registers
// 3. Handles architecture differences

// This:
SEC("kprobe/do_sys_openat2")
int BPF_KPROBE(trace_do_sys_openat2, int dfd, const char *filename, struct open_how *how)

// Expands to something like:
SEC("kprobe/do_sys_openat2")
int trace_do_sys_openat2(struct bpf_raw_tracepoint_ctx *ctx)
{
    int dfd = (int)PT_REGS_PARM1((struct pt_regs *)ctx);
    const char *filename = (const char *)PT_REGS_PARM2((struct pt_regs *)ctx);
    struct open_how *how = (struct open_how *)PT_REGS_PARM3((struct pt_regs *)ctx);
    // ... function body
}
```

---

## 10.4 Kretprobe Example

```c
// kretprobe_example.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct event {
    __u32 pid;
    int ret;        // Return value
    __u64 duration; // Execution time in ns
    __u64 timestamp;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Store entry timestamps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u64);     // pid_tgid
    __type(value, __u64);   // entry timestamp
} start_times SEC(".maps");

// Kprobe: entry
SEC("kprobe/do_sys_openat2")
int BPF_KPROBE(trace_entry, int dfd, const char *filename, struct open_how *how)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 ts = bpf_ktime_get_ns();

    bpf_map_update_elem(&start_times, &pid_tgid, &ts, BPF_ANY);
    return 0;
}

// Kretprobe: return
SEC("kretprobe/do_sys_openat2")
int BPF_KRETPROBE(trace_exit, int ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *start_ts;
    struct event *e;

    // Lookup entry timestamp
    start_ts = bpf_map_lookup_elem(&start_times, &pid_tgid);
    if (!start_ts)
        return 0;

    // Calculate duration
    __u64 duration = bpf_ktime_get_ns() - *start_ts;

    // Clean up
    bpf_map_delete_elem(&start_times, &pid_tgid);

    // Skip fast calls (optional filtering)
    if (duration < 1000)  // Less than 1 microsecond
        return 0;

    // Submit event
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = pid_tgid >> 32;
    e->ret = ret;
    e->duration = duration;
    e->timestamp = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
```

---

## 10.5 Fentry/Fexit — Modern Alternative

Fentry/fexit use BPF trampolines instead of breakpoints — much faster:

```c
// fentry_example.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Fentry: function entry (BPF trampoline)
SEC("fentry/do_sys_openat2")
int BPF_PROG(trace_fentry, int dfd, const char *filename, struct open_how *how)
{
    // Direct access to arguments — no pt_regs needed
    bpf_printk("open: %s\n", filename);
    return 0;
}

// Fexit: function exit (BPF trampoline)
SEC("fexit/do_sys_openat2")
int BPF_PROG(trace_fexit, int dfd, const char *filename, struct open_how *how, int ret)
{
    // ret is the return value
    bpf_printk("open returned: %d\n", ret);
    return 0;
}

char _license[] SEC("license") = "GPL";
```

### 10.5.1 Fentry vs Kprobe Performance

| Aspect | Kprobe | Fentry |
|--------|--------|--------|
| Mechanism | Breakpoint (int3) | BPF trampoline |
| Overhead | ~1000 cycles | ~100 cycles |
| Arguments | Via pt_regs | Direct |
| Return value | Separate kretprobe | Same program |
| Kernel version | 3.18+ | 5.5+ |
| BTF required | No | Yes |

---

## 10.6 Reading Function Arguments

### 10.6.1 Using BPF_KPROBE (Recommended)

```c
// Arguments are automatically extracted
SEC("kprobe/vfs_read")
int BPF_KPROBE(trace_vfs_read, struct file *file, char *buf, size_t count, loff_t *pos)
{
    // Direct access to arguments
    bpf_printk("read: count=%zu\n", count);
    return 0;
}
```

### 10.6.2 Using PT_REGS (Manual)

```c
SEC("kprobe/vfs_read")
int trace_vfs_read(struct pt_regs *ctx)
{
    // Manual extraction from registers
    struct file *file = (struct file *)PT_REGS_PARM1(ctx);
    char *buf = (char *)PT_REGS_PARM2(ctx);
    size_t count = (size_t)PT_REGS_PARM3(ctx);
    loff_t *pos = (loff_t *)PT_REGS_PARM4(ctx);

    bpf_printk("read: count=%zu\n", count);
    return 0;
}
```

### 10.6.3 Architecture-Specific Registers

| Argument | x86_64 | ARM64 |
|----------|--------|-------|
| PARM1 | rdi | x0 |
| PARM2 | rsi | x1 |
| PARM3 | rdx | x2 |
| PARM4 | rcx | x3 |
| PARM5 | r8 | x4 |
| Return value | rax | x0 |

---

## 10.7 Practical Example: File Open Monitor

```c
// file_monitor.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define PATH_MAX 256
#define TASK_COMM_LEN 16

struct event {
    __u32 pid;
    __u32 uid;
    int ret;
    char comm[TASK_COMM_LEN];
    char filename[PATH_MAX];
    __u64 timestamp;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Configuration: target PID (0 = all)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} config SEC(".maps");

SEC("fentry/do_sys_openat2")
int BPF_PROG(trace_file_open, int dfd, const char *filename,
             struct open_how *how)
{
    __u32 key = 0;
    __u32 *target_pid;
    struct event *e;

    // Check filter
    target_pid = bpf_map_lookup_elem(&config, &key);
    if (target_pid && *target_pid) {
        __u32 pid = bpf_get_current_pid_tgid() >> 32;
        if (pid != *target_pid)
            return 0;
    }

    // Reserve event
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    // Fill event
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->timestamp = bpf_ktime_get_ns();
    e->ret = 0;  // Will be updated on exit
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
```

---

## 10.8 Finding Function Names

```bash
# List all kernel functions
sudo cat /proc/kallsyms | head -20

# Search for specific function
sudo cat /proc/kallsyms | grep do_sys_open

# Check if function is available for kprobe
sudo cat /sys/kernel/debug/kprobes/available

# List currently registered kprobes
sudo cat /sys/kernel/debug/kprobes/list
```

---

## 10.9 Summary

- **Kprobes** let you hook any kernel function dynamically
- **BPF_KPROBE** macro simplifies argument access
- **Kretprobes** capture return values
- **Fentry/fexit** are faster alternatives using BPF trampolines
- Use **bpf_probe_read_user_str** for userspace strings
- Check **/proc/kallsyms** for available functions

---

## 10.10 Looking Ahead

Chapter 11 covers **XDP (eXpress Data Path)** — high-performance packet processing at the network driver level.

---

*Next: [Chapter 11 — XDP: Express Data Path](./11-xdp.md)*
