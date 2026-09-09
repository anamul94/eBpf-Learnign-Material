# Chapter 6: eBPF Maps — Sharing Data Between Kernel and Userspace

## What This Chapter Covers

- What eBPF maps are and why they matter
- All map types and when to use each
- Map creation, access, and lifecycle
- Per-CPU maps for high-performance counting
- Ring buffers for event streaming
- Map of maps for dynamic dispatch
- Userspace map access patterns

---

## 6.1 What Are eBPF Maps?

eBPF maps are **key-value stores** that live in kernel memory. They're the primary mechanism for:

1. **Kernel → Userspace communication** — eBPF programs write data, userspace reads it
2. **Userspace → Kernel communication** — Userspace configures programs via maps
3. **Program → Program communication** — One program writes, another reads
4. **State persistence** — Data survives across program invocations

```
┌─────────────────────────────────────────────────────────────┐
│                    eBPF MAP ARCHITECTURE                    │
│                                                             │
│  ┌─────────────────┐         ┌─────────────────┐           │
│  │   Kernel Space  │         │  Userspace      │           │
│  │                 │         │                 │           │
│  │  ┌───────────┐  │         │  ┌───────────┐  │           │
│  │  │ eBPF      │  │  bpf()  │  │ libbpf /  │  │           │
│  │  │ Program   │──┼─syscall─┼─▶│ libpf-rs  │  │           │
│  │  └─────┬─────┘  │         │  └─────┬─────┘  │           │
│  │        │        │         │        │        │           │
│  │        ▼        │         │        ▼        │           │
│  │  ┌───────────┐  │         │  ┌───────────┐  │           │
│  │  │   Map     │  │◀───────▶│  │   Map     │  │           │
│  │  │ (kernel   │  │  shared │  │ (access   │  │           │
│  │  │  memory)  │  │  memory │  │  via fd)  │  │           │
│  │  └───────────┘  │         │  └───────────┘  │           │
│  │                 │         │                 │           │
│  └─────────────────┘         └─────────────────┘           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 6.2 Map Types — The Complete Reference

### 6.2.1 Generic Maps

| Map Type | Description | Use Case |
|----------|-------------|----------|
| `BPF_MAP_TYPE_HASH` | Hash table with arbitrary keys | General key-value storage |
| `BPF_MAP_TYPE_ARRAY` | Array indexed by integer | Fixed-size lookup tables, counters |
| `BPF_MAP_TYPE_PERCPU_HASH` | Per-CPU hash table | High-performance counting (no locks) |
| `BPF_MAP_TYPE_PERCPU_ARRAY` | Per-CPU array | Per-CPU counters, statistics |
| `BPF_MAP_TYPE_LRU_HASH` | LRU eviction hash table | Caches with automatic eviction |
| `BPF_MAP_TYPE_LRU_PERCPU_HASH` | Per-CPU LRU hash | Per-CPU caches |

### 6.2.2 Program-Specific Maps

| Map Type | Description | Use Case |
|----------|-------------|----------|
| `BPF_MAP_TYPE_PROG_ARRAY` | Array of program FDs | Tail call dispatch |
| `BPF_MAP_TYPE_PERF_EVENT_ARRAY` | Perf event output | Streaming events to userspace |
| `BPF_MAP_TYPE_RINGBUF` | Ring buffer | Modern event streaming |

### 6.2.3 Special-Purpose Maps

| Map Type | Description | Use Case |
|----------|-------------|----------|
| `BPF_MAP_TYPE_STACK_TRACE` | Stack trace storage | Profiling, debugging |
| `BPF_MAP_TYPE_CGROUP_ARRAY` | Cgroup references | Cgroup operations |
| `BPF_MAP_TYPE_QUEUE` | FIFO queue | Ordered event processing |
| `BPF_MAP_TYPE_STACK` | LIFO stack | Ordered event processing |
| `BPF_MAP_TYPE_SOCKMAP` | Socket references | Socket redirection |
| `BPF_MAP_TYPE_SOCKHASH` | Socket hash table | Socket redirection |
| `BPF_MAP_TYPE_DEVMAP` | Network device references | XDP redirect |
| `BPF_MAP_TYPE_CPUMAP` | CPU references | XDP CPU redirect |
| `BPF_MAP_TYPE_XSKMAP` | XDP socket references | XDP to userspace |
| `BPF_MAP_TYPE_REUSEPORT_SOCKARRAY` | Socket references | SO_REUSEPORT |
| `BPF_MAP_TYPE_STRUCT_OPS` | Kernel struct operations | Kernel extension |
| `BPF_MAP_TYPE_BLOOM_FILTER` | Bloom filter | Probabilistic membership |
| `BPF_MAP_TYPE_TASK_STORAGE` | Task-local storage | Per-task data |
| `BPF_MAP_TYPE_INODE_STORAGE` | Inode-local storage | Per-inode data |
| `BPF_MAP_TYPE_SK_STORAGE` | Socket-local storage | Per-socket data |

---

## 6.3 Map Declaration Syntax

### 6.3.1 BTF-Style Declaration (Modern)

```c
// Hash map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, struct process_info);
} processes SEC(".maps");

// Array map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u64);
} histogram SEC(".maps");

// Per-CPU array
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} scratch SEC(".maps");

// Ring buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  // 256 KB
} events SEC(".maps");

// Program array (for tail calls)
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 10);
    __type(key, __u32);
    __type(value, __u32);
} prog_array SEC(".maps");
```

### 6.3.2 Legacy Declaration (Still Works)

```c
struct bpf_map_def SEC("maps") processes = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct process_info),
    .max_entries = 10000,
};
```

---

## 6.4 Map Operations

### 6.4.1 Kernel-Side Operations

```c
// Lookup
void *bpf_map_lookup_elem(struct bpf_map *map, const void *key);
// Returns: pointer to value, or NULL if not found

// Update (insert or replace)
long bpf_map_update_elem(struct bpf_map *map, const void *key,
                         const void *value, __u64 flags);
// Flags: BPF_ANY (create or update), BPF_NOEXIST (create only),
//        BPF_EXIST (update only)

// Delete
long bpf_map_delete_elem(struct bpf_map *map, const void *key);

// Get next key (for iteration)
long bpf_map_get_next_key(struct bpf_map *map, const void *key,
                          void *next_key);

// Lookup and delete (atomic)
void *bpf_map_lookup_and_delete_elem(struct bpf_map *map, const void *key);
```

### 6.4.2 Atomic Operations

```c
// Atomic add (for counters)
__sync_fetch_and_add(value, increment);

// Atomic compare-and-swap
__sync_val_compare_and_swap(value, old, new);

// Atomic OR/AND/XOR
__sync_fetch_or(value, mask);
__sync_fetch_and(value, mask);
```

---

## 6.5 Per-CPU Maps — High-Performance Counting

Per-CPU maps give each CPU its own copy of the data, eliminating the need for locking:

```c
// Per-CPU counter map
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} packet_count SEC(".maps");

SEC("xdp")
int count_packets(struct xdp_md *ctx) {
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&packet_count, &key);
    if (count)
        __sync_fetch_and_add(count, 1);  // No lock needed!
    return XDP_PASS;
}
```

**Why Per-CPU maps are fast:**
- No atomic operations needed (each CPU has its own data)
- No cache line bouncing between CPUs
- No lock contention

**Trade-off:** Userspace must sum across all CPUs:

```c
// Userspace: sum per-CPU values
__u64 total = 0;
for (int cpu = 0; cpu < num_cpus; cpu++) {
    total += values[cpu];
}
```

---

## 6.6 Ring Buffer — Modern Event Streaming

The ring buffer is the preferred way to send events from kernel to userspace:

```c
// Kernel side
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  // 256 KB ring buffer
} events SEC(".maps");

struct event {
    __u32 pid;
    __u32 uid;
    char comm[16];
    __u64 timestamp;
};

SEC("tp/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    // Reserve space in the ring buffer
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;  // Buffer full — skip this event

    // Fill the event
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Submit to userspace
    bpf_ringbuf_submit(e, 0);
    return 0;
}
```

### 6.6.1 Ring Buffer Flags

```c
// Reserve flags
bpf_ringbuf_reserve(&rb, size, 0);        // Block if buffer full
bpf_ringbuf_reserve(&rb, size, BPF_RB_NO_WAKEUP);  // Don't notify userspace
bpf_ringbuf_reserve(&rb, size, BPF_RB_FORCE_WAKEUP);  // Always notify

// Submit flags
bpf_ringbuf_submit(e, 0);                // Normal submit
bpf_ringbuf_submit(e, BPF_RB_NO_WAKEUP); // Don't wake userspace
bpf_ringbuf_submit(e, BPF_RB_FORCE_WAKEUP);  // Always wake userspace

// Discard (don't submit)
bpf_ringbuf_discard(e, 0);
```

### 6.6.2 Ring Buffer vs Perf Event Array

| Feature | Ring Buffer | Perf Event Array |
|---------|-------------|------------------|
| Memory efficiency | Shared ring buffer | Per-CPU buffers |
| Event ordering | FIFO order | Per-CPU ordering |
| Data loss | Can overwrite old events | Can drop if buffer full |
| API complexity | Simple reserve/submit | More complex |
| Kernel version | 5.8+ | 4.1+ |

---

## 6.7 Map of Maps — Dynamic Dispatch

Map of maps allows storing map references in maps:

```c
// Inner map template
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} inner_map SEC(".maps");

// Outer map (map of maps)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 10);
    __type(key, __u32);
    __array(values, inner_map);
} outer_map SEC(".maps");

// Usage: store map FD in outer map
int outer_key = 0;
bpf_map_update_elem(&outer_map, &outer_key, &inner_map_fd, BPF_ANY);
```

---

## 6.8 Userspace Map Access

### 6.8.1 C (libbpf)

```c
// Get map FD by name
int map_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "events"));

// Lookup
__u32 key = 0;
__u64 value;
bpf_map_lookup_elem(map_fd, &key, &value);

// Update
__u64 new_value = 42;
bpf_map_update_elem(map_fd, &key, &new_value, BPF_ANY);

// Delete
bpf_map_delete_elem(map_fd, &key);

// Iterate
__u32 cur_key, next_key;
bpf_map_get_next_key(map_fd, NULL, &next_key);  // Get first key
do {
    cur_key = next_key;
    bpf_map_lookup_elem(map_fd, &cur_key, &value);
    // Process value...
    bpf_map_get_next_key(map_fd, &cur_key, &next_key);
} while (next_key_valid);
```

### 6.8.2 Rust (libpf-rs / Aya)

```rust
use aya::maps::{Map, Array, HashMap, RingBuf};

// Array map access
let mut array: Array<_, u64> = Array::try_from(bpf.map_mut("counters")?)?;
let value = array.get(&0, 0)?;
array.set(0, 42, 0)?;

// HashMap access
let mut hash: HashMap<_, u32, ProcessInfo> = HashMap::try_from(bpf.map("processes")?)?;
if let Some(info) = hash.get(&pid, 0)? {
    println!("Process: {:?}", info);
}
hash.insert(pid, info, 0)?;

// Ring buffer (async)
let mut ring_buf = RingBuf::try_from(bpf.map_mut("events")?)?;
while let Some(event) = ring_buf.next().await {
    println!("Event: {:?}", event);
}
```

---

## 6.9 Map Lifecycle

```
┌─────────────────────────────────────────────────────────────┐
│                    MAP LIFECYCLE                            │
│                                                             │
│  1. DEFINITION                                              │
│     └─▶ Declared in eBPF source with SEC(".maps")          │
│                                                             │
│  2. CREATION                                                │
│     └─▶ Created by libbpf when loading the BPF object      │
│     └─▶ Kernel allocates memory for the map                │
│     └─▶ Returns a file descriptor (fd)                     │
│                                                             │
│  3. USAGE                                                   │
│     └─▶ Kernel programs access via helper functions        │
│     └─▶ Userspace accesses via fd                          │
│     └─▶ Data persists across program invocations           │
│                                                             │
│  4. PINNING (optional)                                      │
│     └─▶ Map pinned to BPF filesystem (/sys/fs/bpf/)        │
│     └─▶ Survives after loading process exits               │
│     └─▶ Other processes can access via path                │
│                                                             │
│  5. CLEANUP                                                 │
│     └─▶ Map destroyed when last fd is closed               │
│     └─▶ Or when unpinned from BPF filesystem               │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 6.9.1 Pinning Maps

```c
// Pin a map to the BPF filesystem
bpf_map__pin(map, "/sys/fs/bpf/my_map");

// Unpin
bpf_map__unpin(map, "/sys/fs/bpf/my_map");

// Reuse a pinned map (in another program)
int fd = bpf_obj_get("/sys/fs/bpf/my_map");
```

---

## 6.10 Map Sizing and Memory

### 6.10.1 Memory Considerations

```c
// Each map entry consumes memory
// Hash map: key_size + value_size + overhead (~64 bytes)
// Array map: max_entries * value_size

// Example: 10,000 entries, 8-byte key, 32-byte value
// Hash map: ~10,000 * (8 + 32 + 64) = ~1 MB
// Array map: 10,000 * 32 = ~320 KB
```

### 6.10.2 Choosing max_entries

```c
// Too small: map full errors, missed events
// Too large: wasted memory

// Guidelines:
// - Counters: 1-256 entries
// - Process tracking: 10,000-100,000 entries
// - Connection tracking: 100,000-1,000,000 entries
// - Ring buffer: 64KB-16MB (power of 2)
```

---

## 6.11 Practical Map Patterns

### Pattern 1: Per-PID Counter

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);     // PID
    __type(value, __u64);   // Syscall count
} syscall_count SEC(".maps");

SEC("tp/syscalls/sys_enter_read")
int count_read(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 *count = bpf_map_lookup_elem(&syscall_count, &pid);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 init = 1;
        bpf_map_update_elem(&syscall_count, &pid, &init, BPF_ANY);
    }
    return 0;
}
```

### Pattern 2: Histogram

```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 256);  // 256 buckets
    __type(key, __u32);
    __type(value, __u64);
} latency_hist SEC(".maps");

static __always_inline int log2(__u64 val) {
    int bucket = 0;
    while (val > 1) {
        val >>= 1;
        bucket++;
    }
    return bucket;
}

SEC("tp/block/block_rq_complete")
int hist_latency(struct trace_event_raw_block_rq_complete *ctx) {
    __u64 latency = bpf_ktime_get_ns() - ctx->sector;  // Simplified
    __u32 bucket = log2(latency);
    if (bucket >= 256)
        bucket = 255;

    __u64 *count = bpf_map_lookup_elem(&latency_hist, &bucket);
    if (count)
        __sync_fetch_and_add(count, 1);
    return 0;
}
```

### Pattern 3: Configuration Map

```c
struct config {
    __u32 target_pid;
    __u32 enable_logging;
    __u64 threshold;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} config_map SEC(".maps");

SEC("tp/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    __u32 key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg)
        return 0;

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (cfg->target_pid && cfg->target_pid != pid)
        return 0;  // Filter: only trace target PID

    // ... trace the openat
    return 0;
}
```

---

## 6.12 Summary

- **eBPF maps** are key-value stores shared between kernel and userspace
- **Hash maps** for arbitrary keys, **arrays** for integer indices
- **Per-CPU maps** for lock-free high-performance counting
- **Ring buffers** for streaming events to userspace
- **Program arrays** for tail call dispatch
- Maps are accessed via **file descriptors** from userspace
- **Pinning** maps makes them persist beyond the loading process
- Choose **max_entries** carefully to balance memory and capacity

---

## 6.13 Looking Ahead

Chapter 7 covers **eBPF helper functions** — the functions that eBPF programs call to interact with the kernel. These are the "syscalls" of eBPF.

---

*Next: [Chapter 7 — eBPF Helper Functions](./07-ebpf-helpers.md)*
