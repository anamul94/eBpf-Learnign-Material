# Chapter 6: Linux System Programming Projects

## What This Chapter Covers

- Hands-on projects that consolidate Linux systems programming fundamentals
- Building small tools using kernel interfaces: procfs, sysfs, kprobes, tracepoints
- Applying the data structure knowledge from Chapter 5 in practical scenarios
- **Why:** Reading about kernel data structures is different from interacting with them. These projects give you practical experience with the Linux syscalls, filesystems, and tracing mechanisms that eBPF builds upon.

---

## 6.1 Project 1: Process Enumerator via `/proc`

### Objective

Write a userspace program that reads `/proc` to enumerate all running processes, displaying their PID, PPID, state, and command name. This project reinforces understanding of `task_struct`, `procfs`, and process enumeration.

### Approach

```c
// Open /proc/[pid]/status and /proc/[pid]/cmdline
// Read kernel structures through virtual filesystem
// Cross-reference with kernel's process list
```

### What you'll learn

- `/proc` filesystem layout and conventions
- Reading `VmSize`, `VmRSS`, `State` from `/proc/[pid]/status`
- Reading executable name from `/proc/[pid]/cmdline`
- Enumerating PIDs from `/proc/sys/kernel/pid_max` and `/proc/[pid]/`
- How userspace infers kernel state without eBPF

### Sample output

```
$ ./proc_enumerator
PID   PPID  STATE    COMMAND
1     0     S        init
2     1     S        kthreadd
4     2     S    workqueue: ...
1234  567   S+       my_application
...
```

### Skills reinforced

- File I/O (`fopen`, `fgets`, `fclose`)
- String parsing (`strtok`, `sscanf`)
- System calls (`open`, `read`, `close`)
- `/proc` pseudo-filesystem conventions

---

## 6.2 Project 2: Kernel Symbol Lookup via `kallsyms`

### Objective

Build a tool that reads `/proc/kallsyms` to list all kernel symbols and their addresses. This helps understand kernel symbol export and the relationship between virtual addresses and kernel text.

### Approach

```c
// Open /proc/kallsyms
// Read lines: address type name
// Filter by prefix (e.g., do_, sys_, __init)
// Optionally cross-reference with /proc/kallsyms2
```

### What you'll learn

- `/proc/kallsyms` format and permissions (root required)
- Kernel symbol naming conventions
- Relationship between symbol addresses and kernel text layout
- How tools like `size`, `nm`, `readelf` get kernel info

### Sample output

```
$ ./kallsyms_list | head -20
0000000000000000 T __init_begin
0000000000000123 T do_fork
0000000000000456 T sys_calls
...
```

### Skills reinforced

- Reading structured text files
- Hex address parsing
- Symbol resolution basics

---

## 6.3 Project 3: Kprobe-Based Syscall Counter

### Objective

Build a minimal eBPF program (building on Chapter 9) that counts how many times `sys_open` is called system-wide, and prints the count to userspace every second. This combines kernel data structure knowledge with eBPF programming.

### Approach

```c
// Uses kprobe on do_sys_open
// Increments BPF_MAP_TYPE_ARRAY counter
// Userspace reads map via bpftool or /sys/fs/bpf/
```

### What you'll learn

- kprobe attachment to `do_sys_open` (the implementation of the `open` syscall)
- Using array maps for simple counters
- Polling maps from userspace
- Interpreting syscall numbers and function names

### Skills reinforced

- From Chapter 9: map operations, kprobe attachment
- From Chapter 5: accessing task structure, process context
- CLI argument parsing, signal handling, periodic timer

---

## 6.4 Project 4: Network Interface Statistics

### Objective

Write a tool that reads network interface statistics from the kernel, either via `/sys/class/net/<iface>/statistics/` or via eBPF XDP programs attached to the interface.

### Approach

```bash
# Read via sysfs
cat /sys/class/net/eth0/statistics/rx_packets
cat /sys/class/net/eth0/statistics/tx_bytes

# Or via eBPF XDP program that counts packets per interface
```

### What you'll learn

- `/sys/class/net/` directory structure
- Network interface statistics (rx/tx packets, bytes, errors, drops)
- How eBPF XDP integrates with network driver stack
- Difference between driver-level stats and kernel-level stats

### Skills reinforced

- sysfs traversal
- Understanding network driver metrics
- Optional: XDP program basics from Chapter 8

---

## 6.5 Project 5: Filesystem Event Monitor

### Objective

Build a userspace tool that monitors file open/close events using `inotify` or kprobes on `do_sys_open`/`do_sys_close`, similar to the eBPF program from Chapter 9 but using different kernel interfaces.

### Approach (inotify-based)

```c
// Initialize inotify instance
// Add watches on directories
// Read events: OPEN, CLOSE, MOVE, CREATE
// Print: filename, directory, event type
```

### What you'll learn

- `inotify` Linux kernel feature for file monitoring
- Comparing inotify vs eBPF tracing
- Reading event masks and cookie values
- Performance considerations (inotify watch limits, buffer sizes)

### Skills reinforced

- I/O multiplexing (`select`, `poll`, `read`)
- `/dev/inotify` device interface
- Event-driven programming

---

## 6.6 Comparing Approaches: inotify vs eBPF vs /proc

| Aspect | `/proc` | `inotify` | eBPF kprobe |
|--------|---------|-----------|-------------|
| **Privilege** | Any user | Any user | Root required |
| **Scope** | Snapshot at read time | Per-directory watches | System-wide, any kernel function |
| **Performance** | Low (per-process read) | Medium (event-driven) | Very low overhead (JIT compiled) |
| **Context** | Userspace process state | Userspace event delivery | Kernel state at probe point |
| **Stability** | Stable (legacy) | Stable (since 2.6.13) | Kernel-version-dependent |
| **Use case** | Process enumeration, stats | File monitoring, IDE features | Observability, security, profiling |

### When to use which

| Scenario | Recommended approach |
|----------|---------------------|
| List all processes running | `/proc` filesystem |
| Monitor specific directory for changes | `inotify` |
| Trace every syscall entry/exit | eBPF kprobe |
| Filter network traffic at driver level | eBPF XDP |
| Real-time performance analysis | eBPF tracepoints/hrtimer |

---

## 6.7 Summary

| Project | Key Concept | Tool/Interface |
|---------|-------------|----------------|
| 1: Process Enumerator | `/proc` filesystem | File I/O, parsing |
| 2: Symbol Lookup | `/proc/kallsyms` | Text file reading |
| 3: Syscall Counter | eBPF kprobe | Map operations, kprobes |
| 4: Network Stats | sysfs | Directory traversal |
| 5: File Monitor | `inotify` | Event-driven I/O |

---

## 6.8 Phase 1 Recap

### What You've Learned

| Area | Key Takeaways |
|------|---------------|
| **Kernel Architecture** | `task_struct`, subsystems, boot process |
| **Process Management** | `fork`/`vfork`/`clone`, scheduling, termination |
| **Memory Management** | `vm_area_struct`, page allocation, slab allocator |
| **Filesystem** | VFS, `inode`, `file`, `dentry`, syscalls |
| **Networking** | `sock`, `sk_buff`, packet flow, XDP |
| **System Calls** | Entry/exit boundary, numbers, common patterns |
| **Synchronization** | Spinlocks, mutexes, reference counting |
| **Data Structures** | `task_struct`, `mm_struct`, `fs_struct`, `nsproxy` |

### Preparation for Phase 2

With Phase 1 complete, you now have the foundation to:
- Understand what eBPF programs are inspecting (Chapters 7-12)
- Read and write eBPF programs that interact with kernel data (Chapters 13-18)
- Build practical observability and networking tools (Chapters 19-24)

*You're ready to move into eBPF fundamentals. The next chapter introduces the verifier, instruction set, and execution model that make eBPF safe and powerful.*

*Next: [Chapter 7 — eBPF Fundamentals: Verifier & ISA](./07-ebpf-fundamentals.md)* (Note: This overlaps with the chapter I already wrote as 02-ebpf-fundamentals.md - you may want to consolidate or rename)