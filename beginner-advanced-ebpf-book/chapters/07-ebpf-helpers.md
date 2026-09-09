# Chapter 7: eBPF Helpers & Kernel API

## What This Chapter Covers

- The 200+ eBPF helper functions available in the kernel
- How to use helpers for common operations: map access, memory reading, time, etc.
- Helper categories and when to use each type
- **Why:** eBPF programs are extremely constrained — you cannot call arbitrary C functions. Helpers are the only way to interact with kernel services, and choosing the right helper is critical for both correctness and verifier approval.

---

## 7.1 Helper Function Overview

All eBPF helpers follow the naming convention `bpf_<name>`. They're called via the eBPF instruction `e_call` (or `helpx` instruction), and the verifier checks each helper's preconditions.

### Helper categories

| Category | Purpose | Key Helpers |
|----------|---------|-------------|
| **Map operations** | Create, lookup, update, delete maps | `bpf_map_lookup_elem`, `bpf_map_update_elem`, `bpf_map_delete_elem` |
| **Memory inspection** | Read kernel/user memory safely | `bpf_probe_read`, `bpf_probe_read_user`, `bpf_probe_read_kernel` |
| **Time & stats** | Get timestamps, CPU stats | `bpf_ktime_get_ns`, `bpf_get_ns_time`, `bpf_get_current_time_seconds` |
| **Task inspection** | Read process state, credentials | `bpf_get_current_pid_tgid`, `bpf_get_current_uid_gid`, `bpf_get_current_comm` |
| **Packet inspections** (XDP) | Packet metadata, redirection | `bpf_xdp_redirect`, `bpf_redirect_iface`, `bpf_tx` |
| **Return value modification** | Modify return values | `bpfModifyReturn`, `bpf_exit` |
| **Buffer operations** | Copy data between contexts | `bpf_probe_write_user`, `bpf_copy_from_user`, `bpf_copy_to_user` |

### Helper function signature pattern

Most helpers follow this pattern:

```c
// Return type: __u64 (most common)
// Arguments: register operands or stack values
// The verifier checks: type safety, bounds, initializedness
```

```c
// Example: read current time in nanoseconds
// R0 = return value (implicit, assigned by helper)
// R1-R5: scratch registers (clobbered)
```

After the helper executes:
- R0 typically contains the return value
- R1-R5 are clobbered (you must save/restore if needed)
- R6-R9 should be preserved (callee-saved convention)

---

## 7.2 Map Helper Functions

These are the most frequently used helpers in eBPF programs.

### `bpf_map_lookup_elem`

```c
int bpf_map_lookup_elem(int map_fd, const void *key, void *value, u32 flags);
```

- **map_fd**: File descriptor of the BPF map (from skeleton or `bpf()` syscall)
- **key**: Pointer to the key value (size depends on map definition)
- **value**: Pointer to where the value will be written (must have adequate space)
- **flags**: Currently must be 0
- **Return**: 0 on success (key found), -1 on failure (key not found)

```c
// Usage in eBPF program
__u32 key = bpf_get_current_pid_tgid() >> 32;  // Use PID as key
__u64 value = 0;
int ret = bpf_map_lookup_elem(&execve_count_map, &key, &value, 0);
if (ret == 0) {
    // value now contains the current counter
    // Can increment and update
}
```

### `bpf_map_update_elem`

```c
int bpf_map_update_elem(int map_fd, const void *key, const void *value, u64 flags);
```

- **flags**: One of `BPF_ANY`, `BPF_NOEXIST`, `BPF_EXCHANGE`
- **BPF_ANY**: Overwrite if exists, create if not (most common)
- **BPF_NOEXIST**: Create only if key doesn't exist (atomic initialization)
- **BPF_EXCHANGE**: Swap with existing value

```c
// Atomic counter increment
__u32 key = 0;
__u64 value = 1;  // New value (1 for increment)
bpf_map_update_elem(&counter_map, &key, &value, BPF_ANY);
// Next lookup will return the incremented value
```

### `bpf_map_delete_elem`

```c
int bpf_map_delete_elem(int map_fd, const void *key);
```

- Deletes the entry matching `key` from the map
- Returns 0 on success, -1 on error

---

## 7.3 Memory Reading Helpers

eBPF programs cannot arbitrarily read kernel memory. These helpers provide safe, verifier-checked access.

### `bpf_probe_read`

```c
void bpf_probe_read(void *dst, u32 size, const void *off);
```

- **dst**: Destination in eBPF program (must be large enough)
- **size**: Number of bytes to read
- **off**: Kernel source address (as offset from a known base, or a struct field access)

```c
// Read a __u32 from a task_struct field
__u32 pid;
bpf_probe_read(&pid, sizeof(pid), &task->pid);
```

### `bpf_probe_read_user`

```c
void bpf_probe_read_user(void *dst, u32 size, const void *off);
```

- Same as `bpf_probe_read` but source is assumed to be user memory
- Use when the pointer might point to user-space (e.g., filename from syscall args)
- Verifier is stricter about bounds

```c
// Read filename from user space (syscall argument)
char filename[64];
bpf_probe_read_user(filename, sizeof(filename), (void *)ctx->args[0]);
```

### `bpf_probe_read_kernel`

```c
void bpf_probe_read_kernel(void *dst, u32 size, const void *off);
```

- Source is always kernel space
- Can be used when you know the data is in kernel memory
- Slightly less restrictive than `*_user`

```c
// Read kernel variable safely
unsigned long val;
bpf_probe_read_kernel(&val, sizeof(val), &some_kernel_var);
```

### Best practice: Use BTF-aware access

With BTF (BPF Type Format) enabled (default in modern kernels), you can access struct fields directly:

```c
// BTF-aware: verifier knows the struct layout and field offset
bpf_probe_read(&task->pid, sizeof(task->pid), &task->pid);
// Equivalent to the line above, but BTF makes it safer
```

Without BTF, you must provide the full source pointer and rely on your size calculations being correct.

---

## 7.4 Task/Process Helpers

These helpers extract common information from the current task context.

### `bpf_get_current_pid_tgid`

```c
// Returns: upper 32 bits = PID, lower 32 bits = TGID (thread group ID)
// R0 = bpf_get_current_pid_tgid() >> 32 gives PID
// R0 = bpf_get_current_pid_tgid() & 0xFFFFFFFF gives TGID
```

```c
SEC("kprobe/do_sys_open")
int trace_open(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    // Use pid or tgid for map keys, filtering, etc.
    return 0;
}
```

### `bpf_get_current_uid_gid`

```c
// Returns: upper 32 bits = UID, lower 32 bits = GID
__u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
__u32 gid = bpf_get_current_uid_gid() >> 32;
```

### `bpf_get_current_comm`

```c
void bpf_get_current_comm(char *buf, u32 buf_len);
```
- Copies the process name (comm field from task_struct) into buf
- Limited to TASK_COMM_LEN (16) bytes including null terminator
- Safe, verifier-checked

```c
char comm[TASK_COMM_LEN];
bpf_get_current_comm(comm, sizeof(comm));
```

### `bpf_get_current_cgroup_uid`

```c
// Returns the cgroup UID (used for LSM security labeling)
```

---

## 7.5 Time Helpers

eBPF programs need timestamps for profiling, histograms, and timing.

### `bpf_ktime_get_ns`

```c
// Returns: monotonic time in nanoseconds since boot
__u64 ns = bpf_ktime_get_ns();
```

Use case: measuring latency, adding timestamps to events.

### `bpf_get_ns_time`

```c
// Returns: wall-clock time in nanoseconds (may be adjusted by NTP)
// More precise for elapsed time between two points
__u64 start = bpf_get_ns_time();
// ... do work ...
__u64 elapsed = bpf_get_ns_time() - start;
```

### `bpf_get_current_time_seconds`

```c
// Returns: current time as seconds since epoch (time64_t)
// Coarser granularity, but useful for human-readable timestamps
__u64 seconds = bpf_get_current_time_seconds();
```

### Choosing the right timer

| Helper | Granularity | Use case |
|--------|-------------|----------|
| `bpf_ktime_get_ns` | Nanoseconds | Precise latency measurement, histograms |
| `bpf_get_ns_time` | Nanoseconds | Elapsed time between two points in same program |
| `bpf_get_current_time_seconds` | Seconds | Human-readable timestamps, log correlation |

---

## 7.6 Return Value Modification Helpers

Some eBPF program types (especially kretprobe and LSM) can modify the return value of the probed function.

### `bpfModifyReturn`

```c
// Modify the return value of a kretprobe
// R0 should contain the new return value before this helper is called
bpfModifyReturn(ctx, new_value);
```

```c
// Example: always return 0 from a function (hide operation)
SEC("kretprobe/some_function")
int ret_some_function(struct pt_regs *ctx) {
    bpfModifyReturn(ctx, 0);
    return 0;
}
```

### `bpfExit`

```c
// Explicitly exit the eBPF program with a return value
// Equivalent to the `exit` instruction with R0 = value
bpfExit(ctx, 0);
```

---

## 7.7 Common Helper Patterns

### Pattern 1: Lookup map, increment counter

```c
SEC("kprobe/do_sys_open")
int trace_open(struct pt_regs *ctx) {
    __u32 key = 0;
    __u64 *count;
    
    // 1. Lookup current count
    count = bpf_map_lookup_elem(&counter_map, &key);
    if (!count)
        return 0;  // Map not fully initialized
    
    // 2. Increment atomically
    __sync_fetch_and_add(count, 1);
    
    // 3. Read back for event streaming
    e->count = *count;
    
    return 0;
}
```

### Pattern 2: Read process info, store in map

```c
SEC("kprobe/sys_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(comm, sizeof(comm));
    
    // Store in hash map keyed by PID
    struct {
        __u32 pid;
        __u32 uid;
        char comm[TASK_COMM_LEN];
    } event = {pid, uid, {0}};
    bpf_probe_read(event.comm, sizeof(event.comm), comm);
    
    bpf_map_update_elem(&process_map, &pid, &event, BPF_ANY);
    
    return 0;
}
```

### Pattern 3: Read kernel memory safely

```c
// Read a struct field from the current task
struct some_struct {
    __u32 id;
    __u64 timeout;
} s;

bpf_probe_read(&s, sizeof(s), &current->some_struct);
// Or more explicitly:
bpf_probe_read(&s.id, sizeof(s.id), &current->id);
bpf_probe_read(&s.timeout, sizeof(s.timeout), &current->timeout);
```

---

## 7.8 Verifier Constraints on Helpers

Not all helpers can be called from all program types. The verifier checks:

| Constraint | Detail |
|------------|--------|
| **Map type compatibility** | `bpf_map_lookup_elem` works on hash/array maps; not on ringbuf/queue |
| **Context access** | Helpers like `bpf_get_current_task` work only in certain program types (kprobe, tracepoint) |
| **Memory bounds** | `bpf_probe_read` size must be provably within bounds of the source object |
| **Helper-specific checks** | e.g., `bpf_redirect` only works in XDP; `bpfModifyReturn` only in kretprobe/LCK |
| **State tracking** | Helper calls can reset verifier's state tracking; be mindful of instruction ordering |

### Verifier error example

```
verifier rejected program: helper call bpf_map_lookup_elem
  type mismatch: expected __u32 key, got __u64 key
```

**Fix**: Ensure key type matches map definition (`__type(key, __u32)` in map definition).

---

## 7.10 Summary

| Helper Category | Key Functions | Typical Program Types |
|-----------------|---------------|----------------------|
| **Map operations** | `bpf_map_lookup_update_delete` | All (map must match type) |
| **Memory read** | `bpf_probe_read*_user/kernel` | Most, with BTF assistance |
| **Task inspection** | `bpf_get_current_pid_tgid`, `comm`, `uid/gid` | kprobe, tracepoint, XDP |
| **Time** | `bpf_ktime_get_ns`, `get_ns_time`, `get_time_seconds` | All |
| **Return modify** | `bpfModifyReturn` | kretprobe, LSM |
| **Packet** | `bpf_xdp_redirect`, `redirect_iface` | XDP only |

---

## 7.11 Looking Ahead

Chapter 8 covers **eBPF Links** — the modern attachment API that replaces the older `bpftool`/`libbpf` imperative approach with a more ergonomic, reference-counted model. Links are especially important for Rust eBPF development (aya, libbpf-rs) and for properly managing program lifecycle.

*Next: [Chapter 8 — eBPF Links & Advanced Attachment](./08-ebpf-links.md)*