# Chapter 13: CO-RE — Compile Once, Run Everywhere

## What This Chapter Covers

- CO-RE (Compile Once, Run Everywhere): writing eBPF programs that work across different kernel versions
- BTF (BPF Type Format) as the enabling technology
- Using libbpf features for portability: map type stretching, structure matching
- Testing CO-RE programs across kernel versions
- **Why:** In production environments, you cannot control or predict the kernel version running on each node. CO-RE lets you compile an eBPF program once and deploy it everywhere, from kernel 4.15 to 6.5+.

---

## 13.1 The CO-RE Problem

### Why kernel version matters

eBPF programs interact with kernel structures (`task_struct`, `vm_area_struct`, `pt_regs`, etc.) and helper functions. These change across kernel versions:

| Kernel change | Impact on eBPF |
|---------------|----------------|
| Adding a field to `task_struct` | Field offset shifts; program reading wrong offset |
| Removing a helper function | Verifier rejects `e_call` to non-existent helper |
| Changing struct layout | BTF type IDs change, verifier rejects |
| New kernel features | Programs may want to use new helpers/maps |

Without CO-RE: You must recompile eBPF programs for each kernel version. Maintaining multiple versions becomes unmanageable.

### CO-RE solution

CO-RE uses **BTF (BPF Type Format)** type information to resolve types at load time, not compile time. The same compiled bytecode can run on different kernel versions because:

1. **BTF in kernel**: `/sys/kernel/btf/vmlinux` provides kernel type info
2. **BTF in eBPF object**: Program's BTF describes what it expects
3. **libbpf middleware**: At load time, libbpf merges program BTF with kernel BTF and patches offsets

### Result: Same .bpf.o works on kernel 4.18, 5.4, 5.15, 6.1, 6.5+

---

## 13.2 BTF — The Enabling Technology

### What BTF provides

BTF embeds type information in two places:

1. **vmlinux BTF**: Embedded in the kernel (`CONFIG_BTF=y`), exposed at `/sys/kernel/btf/vmlinux`
2. **Program BTF**: Embedded in the compiled eBPF object (`-g` clang flag generates debug info)

### BTF fields relevant to CO-RE

| BTF feature | CO-RE benefit |
|-------------|---------------|
| **Struct field offsets** | libbpf patches program references to match kernel layout |
| **Type IDs** | Verifier checks types using kernel BTF, not compile-time types |
| **Enum values** | Programs can pattern-match on kernel-enum values |
| **Function prototypes** | Helper call signatures verified against kernel BTF |

### Generating BTF

```bash
# 1. Generate vmlinux.h (for clang compilation)
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# 2. Compile eBPF program with BTF debug info
clang -target bpf -g -O2 -I. program.bpf.c -o program.bpf.o

# 3. Verify BTF is in the object
bpftool prog show id <prog_id> --json | python3 -c "import sys,json; d=json.load(sys.stdin); print('Has BTF:', 'btf_info' in d.get('prog_info', {}))"
```

### Without BTF: CO-RE is impossible

You'd need to manually `#ifdef` every kernel version difference, maintain separate compilations, and track struct layout changes manually.

---

## 13.3 libbpf CO-RE Features

### Map type stretching

When a program compiles a map type that doesn't exist in the kernel, libbpf can "stretch" (expand) it:

```c
// Program defines
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, struct some_struct);  // 64 bytes
} my_map SEC(".maps");
```

If kernel supports `BPF_MAP_TYPE_HASH` with max 32-byte values, libbpf stretches the value to fit, or the program gracefully degrades.

### Structure matching

libbpf matches program-defined structures against kernel structures:

```c
// Program sees (via BTF):
struct my_struct {
    __u32 id;      // offset 0
    __u64 timeout; // offset 4
    // ... more fields
};

// libbpf patches: if kernel's equivalent struct has different layout,
// libbpf adjusts the offset references automatically
```

### Function matching

Helper calls are verified against kernel BTF, not compile-time function signatures. If a helper exists in the kernel but with a slightly different signature, libbpf handles the bridging.

---

## 13.4 Practical CO-RE Example

### Example: Tracing a field that changes between kernel versions

Suppose `task_struct->pid` location changes or `task_struct->comm` size changes between kernel versions. With CO-RE, the same program works.

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// Map: count syscalls per process
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);  // process PID
    __type(value, __u64); // call count
} syscall_count SEC(".maps");

// kprobe on sys_enter_openat
SEC("kprobe/sys_enter_openat")
int trace_openat(struct pt_regs *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 *count;
    
    // Read process comm - size may vary between kernels
    // With CO-RE and BTF, this just works
    char comm[TASK_COMM_LEN];
    bpf_probe_read_user(comm, TASK_COMM_LEN, &current->comm);
    
    // Update map
    count = bpf_map_lookup_elem(&syscall_count, &pid);
    if (count)
        __sync_fetch_and_add(count, 1);
    else {
        __u64 val = 1;
        bpf_map_update_elem(&syscall_count, &pid, &val, BPF_ANY);
    }
    
    return 0;
}
```

### What makes this CO-RE compatible:

1. `TASK_COMM_LEN` is defined in `vmlinux.h` and matches kernel's `TS_COMM_LEN`
2. `current->comm` access is verified via BTF for bounds
3. Map type `HASH` with `__u32` key is widely supported across kernel versions
4. `bpf_probe_read_user` bounds checked using BTF type sizes

### Without CO-RE, you'd need:

```c
// Version-specific code
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 0)
    // Old kernel: comm is 16 bytes, at offset X
    bpf_probe_read(&comm, 16, &current->comm);
#else
    // New kernel: comm might be different
    bpf_probe_read_user(&comm, TASK_COMM_LEN, &current->comm);
#endif
```

---

## 13.8 CO-RE Checklist

| Checklist item | Why it matters |
|----------------|----------------|
| **`#include "vmlinux.h"`** | Generates BTF-aware type definitions from current kernel |
| **`#define BPF_CORE_READ`** | Macro for reading struct fields safely across kernels |
| **`BPF_CORE_READ_NEXT`** | For linked list traversal (e.g., `task->children`) |
| **No hardcoded struct offsets** | Let libbpf/BTF resolve at load time |
| **Use standard types** (`__u32`, `__u64`) | Portable across architectures and kernel versions |
| **Test on target kernels** | Verify on at least 2 kernel versions if possible |
| **Enable CONFIG_BTF** | kernel config must have BTF enabled (`zcat /proc/config.gz | grep BTF`) |
| **Compile with `-g`** | Generate debug info for BTF in eBPF object |

### Verifying CO-RE compatibility

```bash
# Load program and check BTF info
sudo bpftool prog show id <id> --json

# Look for: prog_info.btf_info
# If present, CO-RE is supported

# List maps and programs
sudo bpftool prog show
sudo bpftool map show

# Test on multiple kernels (if available)
# Same .bpf.o file should load on each
```

---

## 13.9 CO-RE vs. Traditional Versioning

| Aspect | CO-RE | Traditional (per-kernel) |
|--------|-------|--------------------------|
| **Compile** | Once | Once per kernel version |
| **Deploy** | Single .bpf.o file | Multiple files, version-specific |
| **Maintain** | One codebase | Separate #ifdef branches |
| **Kernel support** | 4.18+/5.8+/6.1+ depending on features | Any, but requires maintenance |
| **Overhead** | Small (BTF merge at load) | Zero at runtime, but dev overhead |
| **Flexibility** | Deploy to unknown kernels | Only to known kernel versions |

### When CO-RE is essential

| Scenario | Reason |
|----------|--------|
| **Cloud-native deployment** | Nodes run different kernel versions (even within same distro) |
| **Kernel update cycles** | Nodes update at different times |
| **Long-term tool lifecycle** | Tool must work for years across kernel evolution |
| **Distribution (Cilium, etc.)** | Must work on customer kernels without recompile |

### When traditional versioning may suffice

| Scenario | Reason |
|----------|--------|
| **Fixed kernel environment** | All nodes run same known kernel (e.g., internal CI cluster) |
| **Short tool lifecycle** | Tool used for months, not years |
| **Development / testing only** | Not deployed to production nodes |

---

## 13.10 Summary

| CO-RE Concept | Key Takeaway |
|---------------|--------------|
| **BTF is the foundation** | Type information enables load-time patching |
| **libbpf middleware** | Merges program BTF with kernel BTF automatically |
| **Single .bpf.o file** | Compile once, run on kernel 4.18 through latest |
| **vmlinux.h generation** | `bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h` |
| **Test on multiple kernels** | Verify compatibility before production deployment |

---

## 13.11 Looking Ahead

Chapter 14 covers **Rust eBPF Integration** — bringing Rust's type safety and the libbpf-rs/aya ecosystem to eBPF development. You'll learn how Rust's compile-time checks complement CO-RE's runtime portability, and how to build production Rust eBPF tools.

*Next: [Chapter 14 — Rust eBPF Ecosystem](./14-rust-ecosystem.md)*