# Chapter 7: eBPF Maps & Data Structures

## What This Chapter Covers

- All BPF map types and their semantics
- Map API: lookup, update, delete, iterate
- Map flags and update strategies
- Sharing data between kernel and userspace
- **Why:** Maps are the primary communication channel between eBPF programs and userspace. Understanding map types and operations is essential for any eBPF tool.

---

## 7.1 Map Overview

Maps are key-value stores baked into the kernel. They're the **only** way to get data from kernel space to userspace (aside from trace output like `bpf_trace_printk`). Every map is defined in the BPF program's ELF section `.maps` and gets a file descriptor (FD) userspace can interact with via the `bpf()` syscall.

### Why maps matter

| Use case | Map type | Reason |
|----------|----------|--------|
| Per-CPU counters | `BPF_MAP_TYPE_PERCPU_ARRAY` | No locking, one value per CPU |
| Global statistics | `BPF_MAP_TYPE_HASH` | O(1) lookups, arbitrary keys |
| Periodic snapshots | `BPF_MAP_TYPE_ARRAY` | Simple sequential access |
| Event streaming | `BPF_MAP_TYPE_RINGBUF` | Producers and consumers, async |
| Packet metadata | `BPF_MAP_TYPE_QUEUE` | FIFO, multi-writer support |

---

## 7.2 Map Definition Syntax

Every map follows this template:

```c
struct {
    __uint(type, BPF_MAP_TYPE_XXX);     // Map type
    __uint(max_entries, N);             // Maximum entries (0 = unlimited)
    __type(key, KEY_TYPE);              // Key type (must be integer or pointer)
    __type(value, VALUE_TYPE);          // Value type
} map_name SEC(".maps");              // Section name MUST be .maps
```

### Key components

| Field | Purpose | Constraints |
|-------|---------|-------------|
| `__uint(type, ...)` | Map type | Must be one of 15+ BPF_MAP_TYPE_* values |
| `__uint(max_entries, N)` | Size limit | 0 = unlimited (but verifier may reject huge maps); typical: 1-1024 |
| `__type(key, ...)` | Key type | Must be an integer type (`__u8` through `__u64`) or `void` |
| `__type(value, ...)` | Value type | Any valid eBPF data type |
| `SEC(".maps")` | Section name | **Must** be exactly `.maps` or skeleton generation fails |

### Key type restrictions

- Keys must be **immutable** via eBPF (no write-back from userspace changing the key's internal structure)
- Keys should be small (prefer `__u32` or smaller) for hash performance
- Multiple keys can't overlap in a way the verifier can't distinguish

### Value type restrictions

- Values can be any eBPF type: `__u8`, `__u16`, `__u32`, `__u64`, `__s32`, `__s64`, `int`, `short`, `char`, pointer to data in map, or struct
- Map values are **zero-initialized** when a new key is first seen (unless `BPF_MAP_TYPE_PERCPU`)

---

## 7.3 Map Types Detailed

### `BPF_MAP_TYPE_HASH`

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} counter_map SEC(".maps");
```

- **Behavior**: Chained hash table, O(1) average lookup
- **Key**: Any integer type up to `__u64`
- **Value**: Any eBPF type
- **Use case**: Counters, lookup tables, per-process tracking
- **Collision handling**: Linear probe within bucket; verifier ensures bounds

### `BPF_MAP_TYPE_ARRAY`

```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u64);
} global_counter SEC(".maps");
```

- **Behavior**: Fixed-size array, indexed by key
- **Key**: `__u32` (0 to max_entries-1)
- **Value**: Any eBPF type
- **Use case**: Configuration constants, global state, simple counters
- **Advantage**: Deterministic iteration, no hashing overhead
- **Disadvantage**: Must know key space ahead of time; sparse keys waste entries

### `BPF_MAP_TYPE_PERCPU`

```c
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} per_cpu_counter SEC(".maps");
```

- **Behavior**: One value per online CPU. Reads/writes are lock-free.
- **Key**: Ignored or must be `0` (hardware-dependent)
- **Value**: Any eBPF type
- **Userspace read**: Returns array of per-CPU values; size = `nr_cpu_ids * value_size`
- **Use case**: Per-CPU statistics, per-CPU flags, lock-free counters

### `BPF_MAP_TYPE_PERCPU_ARRAY`

```c
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);   // CPU index
    __type(value, __u64); // Value per CPU
} per_cpu_stats SEC(".maps");
```

- **Behavior**: Per-CPU array where key selects which CPU's value
- **Key**: CPU index (0 to nr_cpu_ids-1), or BPF_CPU_ID for auto-index
- **Value**: Any eBPF type
- **Use case**: When you need per-CPU but with arbitrary key selection

### `BPF_MAP_TYPE_RINGBUF`

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  // 256 KB
} events SEC(".maps");
```

- **Behavior**: Circular buffer, producer (kernel) / consumer (userspace)
- **Key**: Ignored
- **Value**: Struct describing the event (must fit within ring buffer entry size)
- **Size**: `max_entries` specifies buffer capacity in bytes
- **Flags**: `BPF_RINGBUF_ATOMIC` or `BPF_RINGBUF_NO_HASH` (rarely needed)
- **Use case**: High-throughput event streaming, packet metadata, trace events
- **API**: `bpf_ringbuf_reserve()`, `bpf_ringbuf_submit()`, `bpf_ringbuf_poll()`

### `BPF_MAP_TYPE_QUEUE`

```c
struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u64);
} event_queue SEC(".maps");
```

- **Behavior**: FIFO queue, multi-writer support (unlike array which is single-writer)
- **Key**: Used for dequeue identification
- **Value**: Any eBPF type
- **Use case**: Async event delivery, packet batches, multi-producer scenarios
- **Advantage**: Multiple eBPF programs can push to same queue; single consumer dequeues

### Other map types

| Type | Behavior | Niche use |
|------|----------|-----------|
| `BPF_MAP_TYPE_DEPRECATED` | LRU hash, evicts old entries | Cache-like workloads, memory-limited scenarios |
| `BPF_MAP_TYPE_STACK` | LIFO stack, per-CPU | Interrupt context, call tracing |
| `BPF_MAP_TYPE_PERCPU_STACK` | Per-CPU LIFO | Softirq/IRQ context tracking |
| `BPF_MAP_TYPE_HASH_OF_MAPS` | Nested maps | Hierarchical state, multi-level counters |

---

## 7.4 Map Operations (Kernel Side)

### Lookup

```c
__u32 key = 42;
__u64 value = 0;
int ret = bpf_map_lookup_elem(&map_fd, &key, &value, sizeof(value));
// ret == 0: success, value filled in
// ret == -1: key not found
```

- **Returns**: 0 on success, -1 on error (key not found counts as success with undefined value)
- **Important**: Always check the return value! A return of 0 means the key existed; you cannot assume the value is valid if you didn't check.

### Update

```c
__u32 key = 42;
__u64 value = 123;
int ret = bpf_map_update_elem(&map_fd, &key, &value, BPF_ANY);
// BPF_ANY: overwrite if exists, create if not
// BPF_NOEXIST: create only if key doesn't exist (error if it does)
// BPF_EXCHANGE: swap with existing value
```

### Delete

```c
__u32 key = 42;
int ret = bpf_map_delete_elem(&map_fd, &key);
// ret == 0: deleted (or didn't exist, some implementations return 0)
// ret == -1: error
```

### Get next key (iteration)

```c
__u32 key = 0;
__u32 next_key;
// First call returns first key, subsequent calls return next
while (bpf_map_get_next_key(&map_fd, &key, &next_key) == 0) {
    // Process next_key
    key = next_key;
}
```

---

## 7.5 Map Operations (Userspace Side)

After loading the BPF program, maps have file descriptors accessible at:

```
/sys/fs/bpf/<map_name>
```

Or via `bpftool`:

```bash
# List all maps
sudo bpftool map show

# Show map info
sudo bpftool map show name counter_map

# Dump map contents
sudo bpftool map dump name counter_map
```

### Opening maps from userspace (C)

```c
#include <bpf/libbpf.h>

// Open map by name from BPF object
int map_fd = bpf_map__fd(skel->maps.counter_map);
// Or open by path
int map_fd = bpf_obj_get("/sys/fs/bpf/counter_map");
```

### Reading map values (userspace C)

```c
#include <bpf/bpf.h>
#include <stdio.h>

__u32 key = 0;
__u64 value;
uint_t val_size = sizeof(value);
int ret = bpf(map_fd, BPF_MAP_LOOKUP_ELEM, &key, val_size, &value, 0);
if (ret == 0) {
    printf("Key %u: value = %llu\n", key, value);
}
```

### Rust (libbpf-rs)

```rust
use libbpf_rs::{OpenFlags, BPFObject};

let obj = BPFObject::open_file("program.bpf.o", &OpenFlags::default())?;
let map = obj.map("map_name")?;
let fd = map.fd();
```

---

## 7.6 Map Update Strategies

### `BPF_ANY`

```c
bpf_map_update_elem(&map, &key, &val, BPF_ANY);
// Always succeeds (unless max_entries reached)
// If key exists: overwrites value
// If key doesn't exist: creates new entry
```

### `BPF_NOEXIST`

```c
bpf_map_update_elem(&map, &key, &val, BPF_NOEXIST);
// Succeeds only if key does NOT already exist
// Useful: atomic initialization
```

### `BPF_EXCHANGE`

```c
bpf_map_update_elem(&map, &key, &val, BPF_EXCHANGE);
// Swaps the new value with the existing one
// Returns old value in the third argument (if provided)
```

### When to use which

| Strategy | When to use |
|----------|-------------|
| `BPF_ANY` | General purpose: counter increment, value update |
| `BPF_NOEXIST` | First-time initialization, atomic setup |
| `BPF_EXCHANGE` | Swap patterns, token passing, algorithms requiring old value |

---

## 7.7 Common Mistakes

| Mistake | Consequence | Fix |
|---------|-------------|-----|
| **Not checking lookup return** | Dereferencing NULL → verifier rejection or kernel panic | Always: `if (ret == 0) { ... }` |
| **Using wrong key type** | Verifier error: "invalid key type" | Use `__u32` or `__u64`; avoid pointers as keys |
| **Map too large** | Verifier rejects: "max_entries too big" | Keep reasonable sizes; 0 = unlimited but not recommended |
| **Concurrent updates without per-CPU** | Race conditions, lost updates | Use `BPF_MAP_TYPE_PERCPU` for counters |
| **Ring buffer too small** | Events lost, `bpf_ringbuf_reserve` returns NULL | Use 256KB-1MB for typical tracing; adjust based on workload |
| **Forgetting SEC(".maps")** | Linker error: "no .maps section" | Always include the section attribute |

---

## 7.8 Summary

| Map Type | Key Type | Value Type | Best Use |
|----------|----------|------------|----------|
| `HASH` | Any integer | Any | Counters, lookups, per-process data |
| `ARRAY` | `__u32` 0..N | Any | Config, global state, simple counts |
| `PERCPU` | Ignored/0 | Any | Per-CPU stats, lock-free counters |
| `PERCPU_ARRAY` | CPU index | Any | Per-CPU with arbitrary key selection |
| `RINGBUF` | Ignored | Struct | Event streaming, async data |
| `QUEUE` | `__u32` | Any | Multi-producer FIFO, events |
| `DEPRECATED` | Any | Any | LRU cache, memory-limited |

---

## 7.9 Looking Ahead

In Chapter 8, we'll cover **program attachment**: how to connect eBPF programs to kernel hooks (tracepoints, kprobes, XDP, etc.). Maps will continue to be central as we'll often need to configure programs via maps (e.g., filter lists, attachment configs).

*Next: [Chapter 8 — Program Attachment & Hook Points](./08-program-attachment.md)*