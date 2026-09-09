# Chapter 5: Linux Kernel Data Structures Deep Dive

## What This Chapter Covers

- In-depth exploration of the core kernel data structures you'll interact with via eBPF
- `task_struct`, `mm_struct`, `vm_area_struct`, `files_struct`, `fs_struct`
- How these structures are laid out in memory and how eBPF programs can safely read them
- **Why:** eBPF programs frequently need to inspect process context, memory mappings, open files, and namespaces. Understanding the kernel's internal data layout is essential for writing correct `bpf_probe_read` calls and interpreting the data you collect.

---

## 5.1 The Master Structure: `task_struct`

Every process in Linux is represented by `task_struct` (defined in `include/linux/sched.h`). It's the root of all process-related inspection from eBPF.

### Key Sub-Sections

| Sub-structure | Purpose | eBPF Access |
|--------------|---------|-------------|
| `pid` | Process ID allocation | `task->pid`, `task->tgid` |
| `real_parent`, `parent` | Parent chain | Recursive traversal |
| `children`, `sibling` | Linked list of children | `list_for_each_entry` in kernel, direct inspection from eBPF |
| `group_leader` | PID equivalence | `task->pid == task->group_leader->pid` |
| `exit_state`, `exit_code` | Termination info | Check before dereferencing |
| `sighand` | Signal handling | `task->sighand->action[]` |
| `signal` | Signal state | `task->signal->sig` |
| `seccomp` | Secure computing mode | `task->seccomp` |
| `nsproxy` | Namespaces | `task->nsproxy->mnt_ns` |
| `files` | Open file descriptors | `task->files->fd` |
| `fs` | FS-specific data | `task->fs->pwd` |
| `mm` | Memory descriptor | `task->mm` (may be NULL during exec) |
| `thread_group` | Thread group info | `task->group_leader` |

### Memory Layout (simplified)

```
task_struct (≈ 1.6KB on x86-64)
├── pid, tgid
├── real_parent, parent
├── children (singly linked list)
├── group_leader
├── signal (refcount, pending)
├── sighand
├── seccomp
├── nsproxy (pointer to namespace proxy)
├── files (pointer to file table)
├── fs (pointer to fs info)
├── mm (pointer to memory management, or NULL)
└── thread_struct (CPU context, registers)
```

### Accessing from eBPF

```c
// Get current task structure pointer
// R10 (frame pointer) for kprobe points to struct pt_regs,
// but we can use bpf_get_current_task() to get task_struct *

struct task_struct *task = bpf_get_current_task(ctx);

// Access common fields
__u32 pid = task->pid;
__u32 tgid = task->tgid;

// Read a string safely (uses bpf_probe_read internally)
char comm[TASK_COMM_LEN];
bpf_probe_read_user(comm, TASK_COMM_LEN, task->comm);
```

### Null-safety

- `task->mm` can be NULL (e.g., during context switch, or when a process is in kernel thread mode)
- `task->files` can be NULL (for kernel threads)
- Always check before nested dereference

---

## 5.2 Memory Descriptor: `mm_struct`

`mm_struct` (defined in `include/mm_types.h`) describes a process's virtual memory layout. It's pointed to by `task_struct->mm` and is NULL for kernel threads.

### Key Fields

| Field | Type | Purpose |
|-------|------|---------|
| `mmap` | `struct vm_area_struct *` | Linked list of VMA regions, rooted at this mmap |
| `mmap_sem` | `struct semaphore` | Lock for writing to mmap (mmap, munmap, mprotect) |
| `page_table_lock` | `spinlock_t` | Lock for page table walks |
| `mmap_lock` | `spinlock_t` | Alternative lock for mmap operations |
| `start_code`, `end_code` | `unsigned long` | Text segment boundaries |
| `start_data`, `end_data` | `unsigned long` | Data segment boundaries |
| `start_brk`, `brk` | `unsigned long` | Program break (heap) boundaries |
| `start_stack` | `unsigned long` | Initial stack pointer |
| `rss` | `unsigned long` | Resident set size (pages) |

### VMA Linked List

The `mmap` field points to a linked list of `vm_area_struct`, sorted by address. Each VMA represents a contiguous virtual memory region.

```c
// Traversing VMA list from eBPF
struct vm_area_struct *vma = mm->mmap;
while (vma) {
    // Process vma...
    vma = vma->vm_next;
}
```

### Why `mm` can be NULL from eBPF

- Kernel threads don't have an `mm` (they use the init_mm or no MMU context)
- During `execve`, the old `mm` is freed and a new one hasn't been set up yet
- Between `fork` and `exec`, the child has a copy-on-write `mm`

### eBPF access pattern

```c
// Safe check before accessing mm fields
struct mm_struct *mm = bpf_get_current_mm(ctx);
if (!mm)
    return 0;  // No memory descriptor (kernel thread or exec in progress)

// Now safe to read mm fields
unsigned long code_start = mm->start_code;
unsigned long code_end = mm->end_code;
```

---

## 5.3 File Descriptor Table: `files_struct`

`files_struct` (defined in `include/linux/files.h`) manages all open file descriptors for a process.

### Key Fields

| Field | Type | Purpose |
|-------|------|---------|
| `fd` | `struct fdtable *` | Hash table of open file descriptors |
| `next_fd` | `int` | Next available file descriptor number |
| `max_fd` | `int` | Highest allocated FD number |
| `close_on_exec` | `unsigned long [N]` | Bitmask of FDs to close on exec |
| `umask` | `mode_t` | File creation mode mask |

### `fdtable` structure

```c
struct fdtable {
    unsigned int max_fds;
    struct file **fd;        // Array of file pointers (fd index -> struct file)
    unsigned int *close_on_exec;
    unsigned int *open_fds;  // Bitmask of open FDs
    int *freed;
};
```

### Accessing open FDs from eBPF

```c
struct task_struct *task = bpf_get_current_task(struct);
struct files_struct *f = task->files;
if (!f)
    return 0;

// Get the fd table
struct fdtable *ft = f->fd;
if (!ft)
    return 0;

// Iterate over open file descriptors
int fd;
for (fd = 0; fd < ft->max_fd; fd++) {
    struct file *file = ft->fd[fd];
    if (file) {
        // File is open; inspect via file->f_path, file->f_op, etc.
    }
}
```

### Common eBPF use case: trace sys_open

```c
SEC("kprobe/do_sys_open")
int trace_open(struct pt_regs *ctx)
{
    struct task_struct *task = bpf_get_current_task(ctx);
    struct files_struct *files = task->files;
    if (!files)
        return 0;
    
    // The filename argument is in ctx (register or stack)
    // But we can also inspect the file table later
    
    return 0;
}
```

---

## 5.4 Namespaces: `nsproxy`

`nsproxy` (namespace proxy) provides access to the namespaces a process belongs to. Defined in `include/linux/nsproxy.h`.

### Key Namespaces

| Namespace | Kernel struct | Common use |
|------------|-------------|------------|
| **PID** | `task_struct->pid_ns` | Process ID isolation |
| **NET** | `net` namespace | Network stack isolation (sockets, interfaces) |
| **Mount** | `mnt_ns` | Mount points, filesystem layout |
| **UTS** | `uts_ns` | Hostname, domain name |
| **IPC** | `ipc_ns` | System V / POSIX IPC objects |
| **CGROUP** | cgroup namespace | cgroup hierarchy visibility |

### Accessing from eBPF

```c
struct task_struct *task = bpf_get_current_task(ctx);
struct nsproxy *ns = task->nsproxy;
if (!ns)
    return 0;

// Get PID namespace
struct pid_ns *pid_ns = task->pid_ns;
// Or via nsproxy
struct pid_ns *pid_ns = ns->pid_ns;

// Get network namespace
struct net *net = ns->net;  // struct net is the network namespace
```

### Why namespaces matter for eBPF

- **Container visibility**: eBPF programs can see (or not see) containers based on namespace membership
- **Network policies**: Cilium and other tools use namespace-aware eBPF
- **PID filtering**: Filter events by container PID vs host PID

### Common pattern: map key includes namespace

```c
// Use namespace PID as part of the map key to avoid collisions
// between containers that might use the same PIDs
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);  // key = combined pid + ns offset
    __type(value, __u64);
} per_pid_stats SEC(".maps");
```

---

## 5.5 Filesystem Structure: `fs_struct`

`fs_struct` (defined in `include/linux/fs_struct.h`) manages filesystem-related state.

### Key Fields

| Field | Purpose |
|-------|---------|
| `pwd` | Current working directory (dentry/inode) |
| `root` | Root directory (dentry/inode) |
| `executable` | Executable file (dentry/inode) |
| `uvcount` | Reference count for umount |
| `namespace` | Mount namespace |

### Common eBPF use case: trace chdir/getcwd

```c
SEC("kprobe/vfs_set.cwd")
int trace_set_cwd(struct pt_regs *ctx)
{
    struct task_struct *task = bpf_get_current_task(ctx);
    struct fs_struct *fs = task->fs;
    if (!fs)
        return 0;
    
    // fs->pwd contains the new working directory
    // Could read dentry name, inode number, etc.
    return 0;
}
```

---

## 5.6 Summary of Key Structures

| Structure | Key Field(s) | Typical eBPF Use |
|-----------|-------------|------------------|
| `task_struct` | `pid`, `comm`, `parent`, `children`, `mm`, `files`, `fs`, `nsproxy` | Process tracing, counting, filtering |
| `mm_struct` | `mmap`, `start_code`, `end_code`, `brk`, `rss` | Memory footprint, code segment inspection |
| `vm_area_struct` | `vm_start`, `vm_end`, `vm_flags`, `vm_file`, `vm_next` | Per-region memory inspection, heap/stack detection |
| `files_struct` | `fd`, `max_fd`, `close_on_exec` | Open file descriptor tracking |
| `nsproxy` | `pid_ns`, `net`, `mnt_ns` | Namespace-aware tracing |
| `fdtable` | `fd[]`, `max_fd`, `open_fds`, `close_on_exec` | Per-FD inspection |

---

## 5.7 Safe Inspection with `bpf_probe_read`

The golden rule of eBPF kernel inspection:

> **Never dereference a kernel pointer directly from eBPF.** Always use the `bpf_probe_read*` family of helpers, which the verifier will check for safety.

### Basic patterns

```c
// Read a __u32 from kernel memory
__u32 val;
bpf_probe_read(&val, sizeof(val), &some_kernel_var);

// Read a string (with bounds)
char comm[TASK_COMM_LEN];
bpf_probe_read_user(comm, sizeof(comm), task->comm);

// Read struct member within bounds
struct some_struct {
    __u32 id;
    __u64 timeout;
} s;
bpf_probe_read(&s, sizeof(s), &kernel_var);
```

### Why `bpf_probe_read_user` vs `bpf_probe_read_kernel`

- **`bpf_probe_read_user`**: Copies from user-space address. Use when the kernel pointer references user memory (e.g., `task->comm` lives in user-visible portion, or the pointer itself came from userspace).
- **`bpf_probe_read_kernel`**: Copies from kernel space. Default choice for most kernel pointer inspection.
- **Default**: When in doubt, use `bpf_probe_read` which the verifier will resolve based on BTF type information.

### BTF and safe inspection

The Memory Formatting Table (BTF) embedded in the kernel and eBPF objects tells the verifier:
- The size of each struct field
- Which fields are pointers vs values
- Whether a pointer originates from userspace or kernel space

Without BTF, you must manually specify sizes and use the appropriate `*_user`/`*_kernel` helper.

---

## 5.8 Common Mistakes

| Mistake | Consequence | Fix |
|---------|-------------|-----|
| **Dereferencing NULL `task->mm`** | Verifier error or undefined behavior | Always: `if (mm) { ... }` |
| **Reading beyond string bounds** | Verifier error: "out of bounds access" | Use `TASK_COMM_LEN` or explicit size |
| **Assuming `files` is never NULL** | Kernel panic in edge cases | Check: `if (task->files) { ... }` |
| **Accessing freed memory** | Use-after-free, verifier rejection | Use kprobe/kretprobe pairs carefully; be aware of task lifecycle |
| **Not considering CPU context** | Wrong data for per-CPU situations | Use per-CPU maps when concurrent access is needed |

---

## 5.9 Looking Ahead

Chapter 6 completes Phase 1 with **Linux System Programming Projects** — hands-on exercises that consolidate the kernel data structure knowledge and prepare you for writing eBPF programs that interact with live kernel state.

*Next: [Chapter 6 — Linux System Programming Projects](./06-sys-prog-projects.md)*