# Chapter 18: CO-RE — Compile Once, Run Everywhere

## What This Chapter Covers

- The portability problem in eBPF
- What BTF is and how it enables CO-RE
- BPF_CORE_READ macros
- Field relocations
- Building portable eBPF programs
- CO-RE with Rust

---

## 18.1 The Portability Problem

Traditional eBPF programs have a problem: **they break across kernel versions**.

```c
// This works on kernel 5.15 but breaks on 5.16:
struct task_struct *task = ...;
pid_t pid = task->pid;  // Field offset changed!
```

**Why it breaks:**
- Kernel struct layouts change between versions
- Field offsets, types, and names change
- New fields are added, old fields are removed

**Traditional solutions:**
1. **Compile on target** — Requires kernel headers on every machine
2. **Hardcode offsets** — Breaks on every kernel update
3. **Multiple versions** — Maintenance nightmare

**CO-RE solves this** by using BTF (BPF Type Format) to adapt at load time.

---

## 18.2 What is BTF?

BTF (BPF Type Format) is metadata about kernel types embedded in the kernel image:

```
┌─────────────────────────────────────────────────────────────┐
│                    BTF OVERVIEW                             │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Kernel Image (vmlinux)                             │   │
│  │  ┌─────────────────────────────────────────────┐    │   │
│  │  │  BTF Section                                │    │   │
│  │  │  - Type definitions (structs, enums, etc.)  │    │   │
│  │  │  - Field offsets and types                  │    │   │
│  │  │  - Function signatures                      │    │   │
│  │  └─────────────────────────────────────────────┘    │   │
│  └─────────────────────────────────────────────────────┘   │
│                            │                                │
│                            ▼                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  eBPF Program (ELF)                                 │   │
│  │  ┌─────────────────────────────────────────────┐    │   │
│  │  │  Relocation Records                         │    │   │
│  │  │  - "I need task_struct->pid"                │    │   │
│  │  │  - libbpf resolves at load time             │    │   │
│  │  └─────────────────────────────────────────────┘    │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**BTF is available in:**
- `/sys/kernel/btf/vmlinux` — Kernel BTF
- Each eBPF program's ELF section — Program BTF

---

## 18.3 BPF_CORE_READ Macros

### 18.3.1 Basic Usage

```c
#include <bpf/bpf_core_read.h>

// Instead of direct access:
// pid_t pid = task->pid;  // BREAKS across versions

// Use BPF_CORE_READ:
pid_t pid = BPF_CORE_READ(task, pid);  // PORTABLE

// Nested access:
__u64 inode = BPF_CORE_READ(task, mm, exe_file, f_inode, i_ino);
```

### 18.3.2 Available Macros

```c
// Read a field
BPF_CORE_READ(dst, field)

// Read into a variable
BPF_CORE_READ_INTO(dst, src, field)

// Read from pointer
BPF_CORE_READ_PTR_INTO(dst, src, field)

// Check if field exists
bpf_core_field_exists(struct task_struct, field)

// Get field size
bpf_core_field_size(struct task_struct, field)

// Check type exists
bpf_core_type_exists(struct task_struct)

// Check enum value exists
bpf_core_enum_value_exists(enum, value)
```

### 18.3.3 CO-RE Read Example

```c
SEC("tp/sched/sched_process_exec")
int trace_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // CO-RE reads — portable across kernel versions
    pid_t pid = BPF_CORE_READ(task, pid);
    pid_t tgid = BPF_CORE_READ(task, tgid);
    uid_t uid = BPF_CORE_READ(task, cred, uid.val);
    struct mm_struct *mm = BPF_CORE_READ(task, mm);

    // Check if field exists before reading
    if (bpf_core_field_exists(task, start_boottime)) {
        u64 start_time = BPF_CORE_READ(task, start_boottime);
        // Use start_time
    }

    bpf_printk("exec: pid=%d uid=%d\n", pid, uid);
    return 0;
}
```

---

## 18.4 How CO-RE Works

```
┌─────────────────────────────────────────────────────────────┐
│                    CO-RE FLOW                               │
│                                                             │
│  1. COMPILE TIME                                            │
│     ┌─────────────────────────────────────────────────┐    │
│     │  Source: BPF_CORE_READ(task, pid)               │    │
│     │  Compiler: Records relocation                   │    │
│     │  ELF: Contains BTF + relocation records         │    │
│     └─────────────────────────────────────────────────┘    │
│                            │                                │
│                            ▼                                │
│  2. LOAD TIME                                               │
│     ┌─────────────────────────────────────────────────┐    │
│     │  libbpf: Reads program BTF                      │    │
│     │  libbpf: Reads kernel BTF (/sys/kernel/btf/...) │    │
│     │  libbpf: Resolves relocations                   │    │
│     │  libbpf: Patches instructions with offsets      │    │
│     └─────────────────────────────────────────────────┘    │
│                            │                                │
│                            ▼                                │
│  3. RUNTIME                                                 │
│     ┌─────────────────────────────────────────────────┐    │
│     │  Program runs with correct field offsets        │    │
│     │  Works on any kernel with BTF support           │    │
│     └─────────────────────────────────────────────────┘    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 18.5 Handling Kernel Version Differences

### 18.5.1 Field Existence Checks

```c
// Check if field exists before reading
if (bpf_core_field_exists(struct task_struct, start_boottime)) {
    // Kernel >= 5.5
    u64 start = BPF_CORE_READ(task, start_boottime);
} else {
    // Fallback for older kernels
    u64 start = BPF_CORE_READ(task, start_time);
}
```

### 18.5.2 Type Existence Checks

```c
// Check if type exists
if (bpf_core_type_exists(struct cgroup)) {
    // Use cgroup type
}
```

### 18.5.3 Enum Value Checks

```c
// Check if enum value exists
if (bpf_core_enum_value_exists(enum tcp_flags, TCP_FLAG_CWR)) {
    // Use TCP_FLAG_CWR
}
```

---

## 18.6 CO-RE with Rust (Aya)

```rust
// ebpf/src/main.rs
use aya_bpf::{
    helpers::*,
    macros::kprobe,
    programs::ProbeContext,
};

#[kprobe]
pub fn do_sys_openat2(ctx: ProbeContext) -> u32 {
    // Get current task
    let task = bpf_get_current_task() as *const task_struct;

    // CO-RE style access using aya-bpf
    let pid = unsafe { (*task).pid };
    let tgid = unsafe { (*task).tgid };

    // For full CO-RE, use aya-bpf's portable accessors
    // (Aya handles relocations at load time)

    0
}
```

### 18.6.1 Aya CO-RE with aya-tool

```bash
# Generate Rust types from BTF
aya-tool generate task_struct > task_struct.rs

// Use generated types
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct task_struct {
    pub pid: i32,
    pub tgid: i32,
    // ... other fields
}
```

---

## 18.7 Building Portable Programs

### 18.7.1 C with libbpf

```bash
# Compile with BTF info
clang -target bpf -g -O2 -c program.bpf.c -o program.bpf.o

# The -g flag includes BTF information
# libbpf uses this for CO-RE relocations
```

### 18.7.2 Rust with Aya

```bash
# Aya automatically includes BPF info
cargo build --target bpfel-unknown-none --release

# aya-tool generates portable types
aya-tool generate <type_name> > types.rs
```

---

## 18.8 BTF Files

### 18.8.1 Kernel BTF

```bash
# Check if kernel has BTF
ls /sys/kernel/btf/vmlinux

# Dump kernel BTF
bpftool btf dump file /sys/kernel/btf/vmlinux format raw

# Generate vmlinux.h from BTF
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

### 18.8.2 Small BTF for Embedded

```bash
# For systems without BTF, use small BTF files
# Download from: https://github.com/aquasecurity/btfhub

# Example: Use BTF for specific kernel version
bpftool btf dump file 5.15.0-0.btf format c > vmlinux.h
```

---

## 18.9 Summary

- **CO-RE** enables portable eBPF programs
- **BTF** provides type information for relocations
- **BPF_CORE_READ** macros for portable field access
- **Field existence checks** for version compatibility
- **libbpf** resolves relocations at load time
- **Aya** supports CO-RE with aya-tool

---

## 18.10 Looking Ahead

Chapter 19 covers **eBPF for security** — LSM hooks, seccomp, and security monitoring.

---

*Next: [Chapter 19 — eBPF for Security](./19-security.md)*
