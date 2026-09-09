# Chapter 10: Observability Tools & Histograms

## What This Chapter Covers

- Building eBPF-based observability tools for collecting and displaying kernel statistics
- Histogram patterns: latency, distribution, frequency
- Ring buffer vs perf event buffer for event streaming
- Userspace display algorithms for visualizing kernel data
- **Why:** The whole point of eBPF observability is to answer "what's happening in my system?" in real-time. This chapter teaches you to collect data in meaningful ways and present it to users.

---

## 10.1 Observability Patterns

eBPF observability tools typically follow these patterns:

| Pattern | Data structure | Use case |
|---------|---------------|----------|
| **Simple counter** | BPF_MAP_TYPE_ARRAY / HASH | Total events, error counts |
| **Histogram (fixed buckets)** | BPF_MAP_TYPE_PERCPU_ARRAY | Latency buckets (0-1ms, 1-5ms, etc.) |
| **Percentile tracking** | BPF_MAP_TYPE_PERCPU + bpf_lcm | p95, p99 latency |
| **Frequency distribution** | BPF_MAP_TYPE_HASH | Syscall frequency per user |
| **Ring buffer events** | BPF_MAP_TYPE_RINGBUF | Per-event data (comm, pid, timestamp) |

---

## 10.2 Building a Latency Histogram

### Objective

Measure the latency of a kernel operation (e.g., sys_open, file read) and display a histogram of the distribution.

### Approach

1. **kprobe** on the entry function (record timestamp via `bpf_ktime_get_ns()`)
2. **kretprobe** on the return function (record delta = return_ts - entry_ts)
3. **Update histogram map** with the latency bucket
4. **Userspace** reads map and displays histogram

### eBPF Program Structure

The eBPF program needs to:
1. On kprobe entry: save the timestamp in a per-CPU variable or map
2. On kretprobe: compute latency = return_timestamp - entry_timestamp
3. Determine which histogram bucket the latency falls into
4. Increment the counter for that bucket

### Bucket Definition

Typical latency histogram buckets (in nanoseconds):

| Bucket index | Latency range | Use case |
|-------------|--------------|----------|
| 0 | 0 - 1 µs | Ultra-fast path |
| 1 | 1 - 4 µs | Cache hit |
| 2 | 4 - 8 µs | L1 cache |
| 3 | 8 - 16 µs | L2 cache |
| 4 | 16 - 1 µs | Main memory |
| 5 | 1 - 4 ms | Disk I/O |
| 6 | 4 - 15 ms | Network round-trip |
| 7 | 15+ ms | Slow paths, locks |

### Implementation Outline

```c
// Per-CPU storage for entry timestamps
// Key = current PID (or just use CPU index), Value = timestamp

// kprobe entry
int handle_entry(struct pt_regs *ctx) {
    __u64 *tsp;
    tsp = bpf_map_lookup_elem(&entry_ts_map, &cpuid);
    if (tsp)
        *tsp = bpf_ktime_get_ns();
    return 0;
}

// kretprobe entry
int handle_return(struct pt_regs *ctx) {
    __u64 *tsp, latency;
    tsp = bpf_map_lookup_elem(&entry_ts_map, &cpuid);
    if (!tsp)
        return 0;  // No matching entry
    
    latency = bpf_ktime_get_ns() - *tsp;
    
    // Determine bucket
    int bucket = determine_bucket(latency);
    
    // Increment histogram counter
    __u32 key = bucket;
    __u64 *count = bpf_map_lookup_elem(&latency_hist, &key);
    if (count)
        __sync_fetch_and_add(count, 1);
    
    // Clean up entry timestamp
    bpf_map_delete_elem(&entry_ts_map, &cpuid);
    return 0;
}
```

### Bucket Determination Function

```c
static int determine_bucket(__u64 latency_ns) {
    // Convert to microseconds for bucketing
    __u64 latency_us = latency_ns / 1000;
    
    if (latency_us < 1)
        return 0;   // 0-1 µs
    else if (latency_us < 4)
        return 1;   // 1-4 µs
    else if (latency_us < 8)
        return 2;   // 4-8 µs
    else if (latency_us < 16)
        return 3;   // 8-16 µs
    else if (latency_us < 1000)
        return 4;   // 16 µs - 1 ms
    else if (latency_us < 4000)
        return 5;   // 1-4 ms
    else if (latency_us < 15000)
        return 6;   // 4-15 ms
    else
        return 7;   // 15+ ms
}
```

### Userspace: Reading and Displaying the Histogram

```c
// After loading and attaching the eBPF program:
// Periodically read the histogram map and display

while (running) {
    // Read all 8 buckets (per-CPU, so need to sum)
    int i;
    long total_counts[8] = {0};
    
    for (i = 0; i < 8; i++) {
        __u64 val;
        // Per-CPU array: need to read each CPU's value
        // Simplified: just read key i
        int fd = bpf_map__fd(latency_hist.map);
        // ... read per-CPU values, sum them
    }
    
    // Display histogram
    printf("Latency Histogram (ns):\n");
    for (i = 0; i < 8; i++) {
        printf("[%d]: %ld events  |  ", i, total_counts[i]);
        // Draw stars proportional to count
        int j;
        for (j = 0; j < total_counts[i] / 10; j++)
            printf("*");
        printf("\n");
    }
    
    sleep(1);  // Update every second
}
```

---

## 10.3 Ring Buffer for Event Streaming

### Ring Buffer vs. Histogram Maps

| Feature | Histogram Map | Ring Buffer |
|---------|--------------|-------------|
| **Data type** | Aggregated counts | Individual events |
| **Update pattern** | Atomic increment | Reserve + submit + return |
| **Consumption** | Periodic map read | Poll from ring buffer |
| **Loss behavior** | Overwrite at max_entries | Overwrite when full (non-blocking) |
| **Best use case** | Statistics, counters | Tracing, real-time events |

### Ring Buffer API (kernel side)

```c
// Reserve space for an event
struct event *e = bpf_ringbuf_reserve(&ringbuf, sizeof(*e), 0);
if (!e)
    return 0;  // Buffer full

// Fill in event data
e->pid = bpf_get_current_pid_tgid() >> 32;
e->ts = bpf_ktime_get_ns();

// Submit to userspace
bpf_ringbuf_submit(e, 0);
```

### Userspace: Polling Ring Buffer

```c
#include <bpf/libbpf.h>

// Create ring buffer from map FD
struct ring_buffer *rb = ring_buffer__new(
    bpf_map__fd(map_fd),
    handle_event,  // Callback for each event
    NULL,          // Optional free callback
    NULL           // Optional context
);

if (!rb) {
    fprintf(stderr, "Failed to create ring buffer\n");
    return 1;
}

// Main loop
while (running) {
    err = ring_buffer__poll(rb, 100);  // 100ms timeout
    if (err == -EINTR)
        break;
    if (err < 0) {
        fprintf(stderr, "Poll error: %d\n", err);
        break;
    }
}

// Cleanup
ring_buffer__free(rb);
```

### Event Handler Callback

```c
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    
    // Print event data
    printf("%-6d %-16s %8llu ns\n", 
           e->pid, e->comm, e->timestamp);
    
    return 0;
}
```

---

## 10.4 Combining Histogram + Ring Buffer

A powerful pattern combines both: histogram for aggregated statistics + ring buffer for detailed event inspection.

### Example: Syscall latency with details

1. **Histogram map**: Tracks latency distribution (8 buckets)
2. **Ring buffer**: Streams individual events with full details

### eBPF Program

```c
// Histogram for aggregated latencies
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} latency_hist SEC(".maps");

// Ring buffer for per-event details
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// kprobe + kretprobe program
SEC("kprobe/sys_enter_open")
int kprobe_sys_enter_open(struct pt_regs *ctx) {
    // Reserve ring buffer space
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    
    // Store entry timestamp (use map keyed by PID/tgid)
    __u32 key = bpf_get_current_pid_tgid() >> 32;
    __u64 *tsp = bpf_map_lookup_elem(&entry_ts_map, &key);
    if (tsp)
        *tsp = bpf_ktime_get_ns();
    else
        // First time seeing this PID, create entry
        bpf_map_update_elem(&entry_ts_map, &key, &tmp_ts, BPF_ANY);
    
    return 0;
}

// kretprobe
SEC("kretprobe/sys_enter_open")
int kretprobe_sys_enter_open(struct pt_regs *ctx) {
    __u32 key = bpf_get_current_pid_tgid() >> 32;
    __u64 *tsp = bpf_map_lookup_elem(&entry_ts_map, &key);
    if (!tsp)
        return 0;
    
    __u64 latency = bpf_ktime_get_ns() - *tsp;
    
    // Update histogram
    int bucket = determine_bucket(latency);
    __u32 k = bucket;
    __u64 *count = bpf_map_lookup_elem(&latency_hist, &k);
    if (count)
        __sync_fetch_and_add(count, 1);
    
    // Submit event to ring buffer
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->pid = bpf_get_current_pid_tgid() >> 32;
        e->timestamp = latency;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    }
    
    // Clean up entry
    bpf_map_delete_elem(&entry_ts_map, &key);
    return 0;
}
```

### Userspace: Dual Output

```c
// Main loop polls both histogram and ring buffer
while (running) {
    // 1. Update and display histogram
    display_histogram(latency_hist);
    
    // 2. Poll ring buffer for recent events
    // (or let callback print as events come in)
    
    sleep(1);
}
```

---

## 10.5 Common Mistakes

| Mistake | Consequence | Fix |
|---------|-------------|-----|
| **Not checking ring buffer return** | Lost events silently | Always: `if (!e) return 0;` |
| **Bucket out of bounds** | Verifier error or map corruption | Ensure bucket index < max_entries |
| **Per-CPU map without CPU iteration** | Missing data in userspace | Sum values from all CPUs, or use single-CPU map |
| **Forgetting to clear entry timestamps** | Stale timestamps, wrong latency calc | Delete entry in kretprobe after use |
| **Ring buffer too small** | Frequent "buffer full" drops | Use 256KB-1MB for typical tracing; adjust based on event rate |

---

## 10.6 Summary

| Tool | Data Structure | Best Use |
|------|---------------|----------|
| **Simple counter** | BPF_MAP_TYPE_HASH/ARRAY | Total events, error counts |
| **Histogram** | BPF_MAP_TYPE_PERCPU_ARRAY | Latency distribution, frequency |
| **Ring buffer** | BPF_MAP_TYPE_RINGBUF | Per-event streaming, detailed tracing |
| **Combined** | Both together | Aggregated stats + detailed events |

---

## 10.7 Looking Ahead

Chapter 11 covers **eBPF Security** — using LSM hooks and other security mechanisms to enforce policies, restrict access, and build secure observability tools. You'll learn how to write eBPF programs that can intercept and modify kernel behavior securely.

*Next: [Chapter 11 — eBPF Security](./11-security.md)*