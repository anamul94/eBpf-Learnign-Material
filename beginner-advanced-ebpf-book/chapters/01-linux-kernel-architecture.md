# Chapter 1: Linux Kernel Architecture & Core Concepts

## What This Chapter Covers

- Linux kernel organization: subsystems, boot process, kernel boot command line
- The process lifecycle: from creation to termination
- Kernel subsystems: scheduler, memory management, filesystem, networking
- Reading kernel documentation and source code
- **Why:** Understanding kernel architecture is essential before instrumenting it with eBPF. You need to know where data lives and how the kernel is organized.

---

## 1.1 Kernel Organization

The Linux kernel is a monolithic kernel with modular architecture. Key subsystems:

| Subsystem | Header | Key Data Structures |
|-----------|--------|---------------------|
| **Process scheduling** | `include/sched/` | `task_struct`, `run_queue` |
| **Memory management** | `include/mm/` | `mm_struct`, `vm_area_struct`, `page` |
| **Filesystem** | `include/linux/fs.h` | `file`, `inode`, `super_block` |
| **Networking** | `include/net/` | `sock`, `socket_buff` |
| **Security** | `include/linux/` | `cred`, `task_fallback_mm` |

### Key Concept: `task_struct`

Every process in Linux is represented by a `task_struct` (defined in `include/linux/sched.h`). This is the central process descriptor containing:

- Process state: `running`, `running`, `interruptible`, `uninterruptible`, `stopped`, `dead`
- PID, parent PID, thread group
- Credentials (UID, GIDs, capabilities)
- Memory descriptors (`mm_struct` if process has memory)
- File descriptor table (`struct fdtable`)
- Signal handling
- CPU context (`thread_struct`)

### The kernel boot process

```
1. CPU reset -> vectors -> setup_arch
2. MMU init -> page tables
3. Memory zones -> page allocation
4. Subsystem init -> sched, fs, net, security
5. Init process (pid 1) -> /sbin/init or systemd
6. System enters user space
```

### Reading kernel documentation

- `man 7 linux-overspec` - high-level overview
- `Documentation/` in kernel source (organized by subsystem)
- `https://kernel.org/doc/html/latest/` - online version
- `grep` and `awk` the source for specific structures

---

## 1.2 Process Creation & Termination

### `fork()`, `vfork()`, `clone()`

| Syscall | Copies memory | Shares memory | Use case |
|---------|--------------|---------------|----------|
| `fork()` | Full copy-on-write | Parent/child independent | General process creation |
| `vfork()` | Parent suspended | Child writes to parent's memory | Legacy pattern (rarely used now) |
| `clone()` | Customizable | Customizable | `pthread_create()`, `fork()` semantics |

### Process termination flow

1. `do_exit()` - kernel function called by exiting process
2. `reparent()` - child inherits children of defunct parent
3. `put_task_struct()` - decrement usage count
4. `schedule()` - select next process to run
5. `ptrace` listeners notified (if being traced)
6. `SIGCHLD` sent to parent

### Key data structures in process creation

```c
// Simplified: what fork() actually does
struct task_struct *child = fork_create_child();
copy_thread(clone_flags, child);  // Copy registers, stack, etc.
```

---

## 1.3 Memory Management Virtualization

### Virtual memory areas (`vm_area_struct`)

Each process has a `mm_struct` containing a linked list of `vm_area_struct` (VMA). VMAs represent contiguous virtual memory regions with specific properties:

```c
struct vm_area_struct {
    unsigned long vm_start;     // Start address
    unsigned long vm_end;       // End address
    unsigned long vm_flags;     // Protection/sharing flags
    struct vm_operations_struct *vm_ops; // Operations (fault, close, etc.)
    struct file *vm_file;       // Associated file (if mapped from file)
    const struct vm *vm_file;   // Inode for ext4, etc.
    struct list_head vm_list;   // Linked list in mm_struct
};
```

### Key VMA flags

- `VM_READ`, `VM_WRITE`, `VM_EXEC` - permission flags
- `VM_SHARED`, `VM_MAYSHARE` - shared mapping
- `VM_PAGE_FAULT` - may generate page faults
- `VM_LOCKED` - memory locked in RAM

### Page allocation

Kernel page allocator manages physical memory:

- **Zones**: DMA, DMA32, Normal, Movable, Highmem (arch-dependent)
- **Slab allocator**: `kmalloc()`, `kfree()` - caches frequently allocated objects
- **Page flags**: `PG_reserved`, `PG_reclaim`, `PG_condemned`

### How eBPF interacts with memory

eBPF programs can:
- Read kernel memory via `bpf_probe_read()` (safe, verifier-checked)
- Use maps to share data with userspace
- Allocate stack memory (limited to 512 bytes)
- Use per-CPU maps for concurrent access without locking

---

## 1.4 Filesystem & VFS

### Virtual Filesystem Switch (VFS)

The VFS provides a common interface between the kernel and filesystem implementations. Key objects:

| Object | Purpose |
|--------|---------|
| `super_block` | Filesystem-specific metadata (mounted root, operations) |
| `inode` | Inode-specific metadata (operations, permissions) |
| `file` | Open file description (file descriptor, flags, private data) |
| `dentry` | Directory entry (name-to-inode mapping, cache) |

### File structure

```c
struct file {
    const struct file_operations *f_op;  // Operations (read, write, mmap, etc.)
    mode_t f_mode;                       // Read/write mode
    loff_t f_pos;                        // Read/write position
    struct inode *f_inode;               // Associated inode
    void *f_data;                        // Filesystem-specific data
    const struct file_operations *f_op;  // Operations vector
};
```

### System calls related to files

- `open()`, `openat()` - open/create a file
- `read()`, `write()` - I/O operations
- `mmap()` - map device or file into memory
- `close()` - release file descriptor
- `ioctl()` - device-specific control

### How eBPF interacts with filesystem

eBPF can trace:
- `sys_open` / `sys_openat` kprobes - syscalls entered
- VFS functions: `vfs_open`, `filp_open`, `kernel_open`
- File operations: `fs_read`, `fs_write`, `fs_mmap`
- Filesystem-specific hooks (ext4, btrfs, etc. via LSMs)

---

## 1.5 Networking Basics

### Socket structure

```c
struct socket {
    struct sock *sk;           // Protocol-specific socket struct
    struct file *file;         // Associated file (if opened)
    short state;               // Socket state (TCP_ESTABLISHED, etc.)
    short type;                // Socket type (SOCK_STREAM, SOCK_DGRAM)
    short ops;                 // Protocol operations
    struct proto *prot;        // Protocol definition
};
```

### Key networking data structures

| Structure | Purpose |
|-----------|---------|
| `struct sock` | Core socket state (reference count, ops, memory) |
| `struct sk_buff` | Packet buffer (linear data, head/tail pointers) |
| `struct net_device` | Network interface description |
| `struct tcphdr` / `struct udphdr` | Transport layer headers |

### Network packet flow

```
1. Packet arrives at NIC -> driver interrupt
2. NIC DMA -> memory -> softirq (NET_RX)
3. __netif_receive_skb() -> protocol driver (IP, TCP/UDP)
4. Routing decision -> output path
5. XDP hook (if attached) -> earliest possible point
6. Protocol processing -> socket buffer
7. Delivered to application via recv()/read()
```

### eBPF networking hooks

- **XDP** (eXpress Data Path): Driver level, ~nanosecond latency
- **tc**: Traffic control hooks (qdisc, cls_u32, cls_bpf)
- **cgroup**: cgroup network subsys
- **lxc / container**: Network namespace attachments
- **sk_receive_buff**, `sock_ops`: Socket level

---

## 1.6 System Calls - The User-Kernel Boundary

### What is a system call?

A system call (syscall) is the programmatic way a user program requests a service from the kernel. All syscalls go through `syscall` instruction (x86-64) or `ecall` (ARM/RISC-V), which triggers a context switch to kernel mode.

### System call numbers (x86-64 Linux)

| Number | Syscall | Number | Syscall |
|--------|---------|--------|---------|
| 0 | `read` | 60 | `exit` |
| 1 | `write` | 61 | `exit_group` |
| 2 | `open` | 62 | `wait4` |
| 3 | `close` | 63 | `kill` |
| 4 | `creat` | 64 | `uname` |
| 5 | `openat` | 65 | `gettimeofday` |
| ... | ... | ... | ... |
| 257 | `bpf` | 318 | `faccessat2` |
| 337 | `pidfd_open` | 339 | `perf_event_open` |

### The `bpf` system call

```c
long sys_bpf(enum bpf_cmd cmd, union bpf_attr *attrs,
             unsigned int size);
```

Common `bpf` commands:

| Command | Purpose |
|---------|---------|
| `BPF_MAP_CREATE` | Create a BPF map |
| `BPF_PROG_LOAD` | Load/compile eBPF program |
| `BPF_PROG_ATTACH` | Attach program to kernel hook |
| `BPF_PROG_DETACH` | Detach program from hook |
| `BPF_OBJ_GET` | Get BPF object FD |
| `BPF_QUERY` | Query BPF state/attributes |

### Why trace system calls?

- Understand application behavior (what files are opened, what networks are used)
- Performance analysis (syscall latency, frequency)
- Security monitoring (unusual syscall patterns)
- Debugging kernel-driver interactions

### Tracing syscalls with eBPF

```c
// kprobe on do_sys_open
SEC("kprobe/do_sys_open")
int trace_open(struct pt_regs *ctx) {
    // ctx->args[0] = filename (const char __user *)
    // ctx->args[1] = flags (int)
    // ctx->args[2] = mode (mode_t)
    // bpf_probe_read_user() to read user memory safely
    return 0;
}
```

---

## 1.7 Kernel Synchronization

### Why synchronization matters

The kernel is preemptive and multi-core. Without proper synchronization:
- Race conditions corrupt data
- Use-after-free bugs crash systems
- Memory reordering causes unexpected behavior

### Lock types

| Lock type | Scope | Context | Example |
|-----------|-------|---------|---------|
| `spinlock_t` | Small critical sections | Interrupt/softirq safe | `read_lock(&name_lock)` |
| `mutex` | Longer critical sections | Sleeping allowed | `mutex_lock(&name_mutex)` |
| `rwlock` | Read-mostly | Interrupt safe | `read_lock_irqsave()` |
| `percpu counter` | Per-CPU data | No locking needed | `percpu_counter_add()` |
| `seqlock` | Read-copy-update | Userspace read mostly | `__seqlock()` |

### Reference counting (`kref`)

```c
struct kref {
    atomic_t refcount;
};

void kref_get(struct kref *k);
void kref_put(struct kref *k, void (*release)(struct kref *));
```

### How eBPF handles synchronization

eBPF programs run with disabled preemption (in most cases) and can:
- Use `bpf_spin_lock()` / `bpf_spin_unlock()` for map operations
- Use per-CPU maps for lock-free concurrent access
- Use `bpf_map_update_elem()` with proper flags
- Rely on the verifier to catch invalid lock patterns

---

## 1.8 Summary

| Concept | Key Takeaway |
|---------|-------------|
| `task_struct` | Central process descriptor; essential for tracing process context |
| `vm_area_struct` | Virtual memory regions; understanding helps read kernel memory |
| VFS objects (`inode`, `file`, `dentry`) | Filesystem interaction; syscall targets |
| `sock`, `sk_buff` | Networking fundamentals; eBPF hook points |
| Syscalls | User-kernel boundary; primary eBPF trace points |
| Synchronization | Kernel concurrency primitives; important for correct eBPF map access |

---

## 1.9 Looking Ahead

In the next chapter, we'll focus on **eBPF fundamentals**: what makes eBPF safe, how the verifier works, the instruction set, and the complete program lifecycle from source to running in the kernel.

If you're uncomfortable with any of the concepts in this chapter, review the Linux Kernel Documentation or *Linux Kernel Development* (Robert Love) before proceeding.

*Next: [Chapter 2 — eBPF Fundamentals](./02-ebpf-fundamentals.md)*