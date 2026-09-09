# Chapter 20: Performance Tuning and Optimization

## What This Chapter Covers

- eBPF performance characteristics
- Optimizing map access
- Reducing instruction count
- Batch operations
- JIT compilation
- Profiling eBPF programs
- Best practices for high-throughput

---

## 20.1 eBPF Performance Characteristics

```
┌─────────────────────────────────────────────────────────────┐
│                 eBPF PERFORMANCE HIERARCHY                  │
│                                                             │
│  Fastest          ┌─────────────────────────────────────┐  │
│  ▲                │  Per-CPU maps (no locking)          │  │
│  │                └─────────────────────────────────────┘  │
│  │                ┌─────────────────────────────────────┐  │
│  │                │  Array maps (O(1) lookup)           │  │
│  │                └─────────────────────────────────────┘  │
│  │                ┌─────────────────────────────────────┐  │
│  │                │  Hash maps (single lookup)          │  │
│  │                └─────────────────────────────────────┘  │
│  │                ┌─────────────────────────────────────┐  │
│  │                │  Ring buffer reserve/submit         │  │
│  │                └─────────────────────────────────────┘  │
│  │                ┌─────────────────────────────────────┐  │
│  │                │  Helper function calls              │  │
│  │                └─────────────────────────────────────┘  │
│  Slowest          ┌─────────────────────────────────────┐  │
│  ▼                │  Probe reads (bpf_probe_read)       │  │
│                   └─────────────────────────────────────┘  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 20.2 Map Optimization

### 20.2.1 Use Per-CPU Maps for Counters

```c
// SLOW: Global counter with atomic operations
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} counter SEC(".maps");

SEC("xdp")
int slow_counter(struct xdp_md *ctx) {
    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(&counter, &key);
    if (val)
        __sync_fetch_and_add(val, 1);  // Atomic — slow!
    return XDP_PASS;
}

// FAST: Per-CPU counter (no atomic needed)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} percpu_counter SEC(".maps");

SEC("xdp")
int fast_counter(struct xdp_md *ctx) {
    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(&percpu_counter, &key);
    if (val)
        *val += 1;  // No atomic — fast!
    return XDP_PASS;
}
```

### 20.2.2 Use Array Maps for Fixed Keys

```c
// SLOW: Hash map for small fixed range
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u64);
} hash_map SEC(".maps");

// FAST: Array map for small fixed range
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u64);
} array_map SEC(".maps");
```

### 20.2.3 LRU Maps for Caches

```c
// Use LRU maps to avoid manual eviction
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);  // Auto-evicts least recently used
    __type(key, __u32);
    __type(value, struct cache_entry);
} cache SEC(".maps");
```

---

## 20.3 Instruction Count Optimization

### 20.3.1 Minimize Helper Calls

```c
// SLOW: Multiple helper calls
SEC("xdp")
int slow(struct xdp_md *ctx) {
    __u64 ts1 = bpf_ktime_get_ns();
    // ... process ...
    __u64 ts2 = bpf_ktime_get_ns();
    __u64 duration = ts2 - ts1;
    bpf_printk("Duration: %llu\n", duration);
    return XDP_PASS;
}

// FAST: Fewer helper calls
SEC("xdp")
int fast(struct xdp_md *ctx) {
    // Only call helpers when necessary
    return XDP_PASS;
}
```

### 20.3.2 Use Bounded Loops

```c
// SLOW: Unbounded loop (verifier rejects or limits)
for (int i = 0; i < dynamic_len; i++) {
    // ...
}

// FAST: Bounded loop with constant max
#pragma unroll
for (int i = 0; i < 16; i++) {
    if (i >= actual_len)
        break;
    // ...
}
```

### 20.3.3 Avoid Unnecessary Checks

```c
// SLOW: Redundant checks
if (data + sizeof(struct ethhdr) > data_end)
    return XDP_DROP;
if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
    return XDP_DROP;

// FAST: Single check for total length
if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
    return XDP_DROP;
```

---

## 20.4 Batch Operations

### 20.4.1 Batch Map Lookup

```c
// Userspace: Batch lookup
__u32 keys[100];
__u64 values[100];
__u32 count = 100;

// Batch lookup (kernel 5.6+)
bpf_map_lookup_batch(map_fd, NULL, NULL, keys, values, &count, NULL);
```

### 20.4.2 Batch Map Update

```c
// Userspace: Batch update
__u32 keys[100];
__u64 values[100];
__u32 count = 100;

// Batch update (kernel 5.6+)
bpf_map_update_batch(map_fd, keys, values, &count, NULL);
```

### 20.4.3 Batch Delete

```c
// Userspace: Batch delete
__u32 keys[100];
__u32 count = 100;

// Batch delete (kernel 5.6+)
bpf_map_delete_batch(map_fd, keys, &count, NULL);
```

---

## 20.5 Ring Buffer Optimization

### 20.5.1 Reserve Once, Submit Once

```c
// SLOW: Multiple reserves
struct event *e1 = bpf_ringbuf_reserve(&rb, sizeof(*e1), 0);
if (e1) {
    // Fill e1
    bpf_ringbuf_submit(e1, 0);
}

struct event *e2 = bpf_ringbuf_reserve(&rb, sizeof(*e2), 0);
if (e2) {
    // Fill e2
    bpf_ringbuf_submit(e2, 0);
}

// FAST: Batch events in single reserve (if possible)
// Or use BPF_RB_NO_WAKEUP for non-critical events
struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), BPF_RB_NO_WAKEUP);
if (e) {
    // Fill e
    bpf_ringbuf_submit(e, BPF_RB_NO_WAKEUP);
}
```

### 20.5.2 Right-Size the Ring Buffer

```c
// Too small: Events dropped
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024);  // 4 KB — too small!
} events SEC(".maps");

// Right-sized: 256KB-1MB typical
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  // 256 KB
} events SEC(".maps");
```

---

## 20.6 JIT Compilation

### 20.6.1 Verify JIT is Enabled

```bash
# Check JIT status
sysctl net.core.bpf_jit_enable
# Should be 1 (enabled)

# Enable JIT
sudo sysctl -w net.core.bpf_jit_enable=1

# Check JIT compiled programs
bpftool prog show
# Look for "jited" in the tag
```

### 20.6.2 JIT Optimization Tips

```c
// 1. Use -O2 optimization
// clang -target bpf -O2 -c program.bpf.c -o program.bpf.o

// 2. Avoid complex control flow
// 3. Use simple data types
// 4. Minimize function calls
```

---

## 20.7 Profiling eBPF Programs

### 20.7.1 Using bpftool

```bash
# Show program run count and time
bpftool prog show

# Output:
# 42: xdp  name xdp_filter  tag abc123  run_time_ns 1234567  run_cnt 1000000

# Calculate average:
# avg_ns = run_time_ns / run_cnt
```

### 20.7.2 Using perf

```bash
# Profile eBPF program execution
sudo perf record -e 'bpf:bpf_prog_run' -a sleep 10
sudo perf report

# Profile specific program
sudo perf record -e 'bpf:bpf_prog_run' -p $(pgrep my_ebpf_tool) sleep 10
```

### 20.7.3 Using bpf_stats

```bash
# Enable BPF stats
sudo sysctl -w kernel.bpf_stats_enabled=1

# Read stats
cat /proc/bpf_stats

# Or with bpftool
bpftool prog show --stats
```

---

## 20.8 XDP-Specific Optimizations

### 20.8.1 Early Exit

```c
SEC("xdp")
int xdp_optimized(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Check minimum length first
    if (data + 54 > data_end)  // eth(14) + ip(20) + tcp(20)
        return XDP_PASS;  // Too small, pass to stack

    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;  // Not IPv4, pass to stack

    struct iphdr *ip = (void *)(eth + 1);
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;  // Not TCP, pass to stack

    // Only parse TCP if we need to
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    // ...

    return XDP_PASS;
}
```

### 20.8.2 XDP_REDIRECT for Bypass

```c
// Fast path: redirect to userspace via XDP
SEC("xdp")
int xdp_fastpath(struct xdp_md *ctx)
{
    // Process in XDP, redirect to userspace socket
    return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);
}
```

---

## 20.9 Memory Optimization

### 20.9.1 Minimize Stack Usage

```c
// SLOW: Large stack allocation
struct large_event e;  // Uses stack space

// FAST: Use ring buffer
struct large_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
if (e) {
    // Fill e
    bpf_ringbuf_submit(e, 0);
}
```

### 20.9.2 Use Appropriate Value Sizes

```c
// SLOW: Using u64 for small values
struct {
    __type(key, __u32);
    __type(value, __u64);  // 8 bytes for a flag?
} flags SEC(".maps");

// FAST: Use appropriate size
struct {
    __type(key, __u32);
    __type(value, __u8);  // 1 byte for a flag
} flags SEC(".maps");
```

---

## 20.10 Summary

- **Per-CPU maps** for lock-free counting
- **Array maps** for fixed-size lookups
- **Minimize helper calls** in hot paths
- **Batch operations** from userspace
- **Right-size ring buffers** (256KB-1MB)
- **Enable JIT** for native performance
- **Profile** with bpftool and perf
- **Early exit** in XDP programs

---

## 20.11 Looking Ahead

Chapter 21 covers **testing and debugging** — unit testing, integration testing, and debugging techniques.

---

*Next: [Chapter 21 — Testing and Debugging](./21-testing-debugging.md)*
