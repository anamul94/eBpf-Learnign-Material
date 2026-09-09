# Chapter 12: Performance Tuning

## What This Chapter Covers

- Optimizing eBPF programs for minimal overhead and maximum throughput
- Efficient map operations, batch processing, and CPU pinning
- JIT compilation flags, instruction counting, and profiling
- Production deployment considerations: resource limits, privilege separation, lifecycle management
- **Why:** eBPF programs run in the kernel and any inefficiency directly impacts system performance. A poorly written eBPF program can itself become a performance bottleneck. This chapter teaches you to write lean, mean observability tools.

---

## 12.1 Overhead Considerations

eBPF program overhead consists of:

| Component | Typical cost | Mitigation |
|-----------|--------------|------------|
| **Probe entry/exit** | 0.5-2 µs per trigger | Use tracepoints over kprobes when available |
| **Verifier check** | At load time only | None at runtime |
| **JIT compilation** | At load time only | None at runtime (code is cached) |
| **Instruction execution** | 10-100 ns per probe | Minimize instruction count |
| **Map operations** | 100-500 ns per update | Batch updates, per-CPU maps |
| **Ring buffer submit** | 50-200 ns per event | Larger batch, better buffer sizes |
| **Context switch** | If probe causes switch | Avoid; most probes don't switch |

### The "ice9" principle

> "If you remove the one thing that's causing the problem, the rest won't matter."

Same applies to eBPF: find and remove the single biggest overhead source first.

---

## 12.2 Minimizing Instruction Count

### What the verifier counts

The verifier enforces a **maximum instruction limit** (originally 4096, now effectively ~1 million with advancements). Each eBPF instruction costs CPU cycles. Programs with fewer instructions:

- Load faster
- Have smaller verifier analysis time
- Run with lower per-instruction overhead

### Instruction counting patterns

| Pattern | Instruction count | Better alternative |
|---------|------------------|--------------------|
| **Repeated function calls** | High (call/return) | Inline logic, use helpers |
| **Nested if-else chains** | Moderate | Switch-like patterns, lookup tables |
| **Map lookups in hot path** | Moderate | Cache frequently-used values, per-CPU |
| **String operations** | Variable | Avoid in hot path; use for init only |
| **64-bit arithmetic** | Slightly more than 32-bit | Use 32-bit when possible |

### Example: Counter increment

```c
// 3-instruction version (efficient)
__sync_fetch_and_add(&counter, 1);

// vs 5-instruction version (less efficient)
__u64 *p = bpf_map_lookup_elem(&map, &key);
if (p) *p += 1;
```

### Example: String copy (avoid in hot path)

```c
// DON'T do this in kprobe return path:
// - Involves strlen, malloc, copy - many instructions
// - Can block, cause page faults

// INSTEAD: 
// - Copy fixed-size field directly
// - Use bpf_probe_read into pre-allocated buffer
char comm[TASK_COMM_LEN];
bpf_probe_read(&comm, sizeof(comm), &task->comm);
```

---

## 12.3 Efficient Map Operations

### Per-CPU maps vs. shared maps

| Map type | Contention | Overhead | Use case |
|----------|------------|----------|----------|
| **Shared hash/array** | High (spinlock) | Lock every access | Global counters, small lookups |
| **Per-CPU array** | None (per-CPU) | Near-zero | Per-CPU statistics, no locking |
| **Per-CPU hash** | None (per-CPU buckets) | Very low | Per-CPU state, no cross-CPU sync |
| **LRU hash** | Medium (per-CPU binlock) | Moderate | Caches, dynamic entries |

### When to use per-CPU

Use per-CPU maps when:
- You're counting events per CPU (no need to aggregate across CPUs in-kernel)
- You want lock-free access (zero contention)
- The data is only read from userspace after aggregation

### Batch map updates

Instead of updating the map on every event event, batch updates:

```c
// Instead of per-event update:
// __sync_fetch_and_add(&counter, 1);  // Every event

// Use a per-CPU batch counter:
static __thread __u64 local_count = 0;
local_count++;

// Periodically flush from userspace or on context switch:
// Can use a timer, signal, or explicit flush call
```

### Map element size matters

Smaller values = less memory, better cache performance:

```c
// 8-byte value vs 1-byte value
// Both store a counter, but 8-byte aligns better on 64-bit systems
// Use __u32 if values fit (saves half the memory)
```

---

## 12.4 JIT & Runtime Optimization

### x86-64 JIT is optimizing

The x86-64 JIT compiler produces very efficient native code. Overhead is typically:

- **< 1 µs** from probe trigger to native code execution
- **~10-50 ns** per instruction (near-native speed)

### ARM64 JIT

Similar performance on ARM64, but some helper calls may be slightly slower due to calling convention differences.

### bpffilters / custom JIT

Some use cases compile eBPF to custom ISAs (BPFsteam, bpftime). These can have different performance characteristics.

### Profile-guided optimization

Some Linux distributions and tools use PGO for the JIT, but this is not yet standard.

---

## 12.5 Profiling eBPF Programs

### Tools for analyzing eBPF overhead

| Tool | What it shows |
|------|---------------|
| `perf record -e bpftrace` | Overall overhead from eBPF tools |
| `perf stat -e cpu-clock` | CPU time used by the tracing tool |
| `bpftool profile` | Instruction counts, hot spots (if supported) |
| `dmesg | grep verifier` | Verifier errors/warnings |
| `cpu latency stats` | Per-CPU latency introduced by eBPF |

### Measuring overhead

```bash
# Measure overhead of a syscall tracer
perf stat -e cpu-clock,sched:sched_switch sudo ./my_tracer

# Compare with and without eBPF
perf stat -e cpu-clock sudo ./baseline_command
```

### Interpreting results

| Metric | Good | Needs investigation | Problem |
|--------|------|--------------------|---------|
| **Overhead %** | < 1% of CPU | 1-5% | > 5% |
| **Per-event ns** | < 1 µs | 1-5 µs | > 5 µs |
| **Frequency** | Events as expected | 2x-5x expected | Unexpected rate (might indicate bug) |

---

## 12.6 XDP Performance Optimization

### XDP is fast, but can be faster

XDP can process packets at 10Gb+ speeds, but optimization matters:

### Optimization 1: Early exit

```c
// Drop known-bad packets immediately
if (unlikely(data_end - data < 64))  // Minimal packet size
    return XDP_DROP;
```

### Optimization 2: Minimize map lookups

```c
// Cache frequently-used values outside the fast path
// Or use per-CPU maps to avoid cross-CPU contention
```

### Optimization 3: Avoid expensive operations

```c
// DON'T in XDP:
// - Complex protocol parsing (TCP headers, etc.)
// - Memory allocation (kmalloc, kfree)
// - Recursive function calls
// - Lock acquisition

// INSTEAD:
// - Basic packet inspection only
// - Use pre-allocated buffers
// - Simple decision logic
// - Return XDP_PASS for complex processing
```

### Optimization 4: Return value choice

| Return | Cost implication |
|--------|-----------------|
| `XDP_PASS` | Pass to kernel stack (normal processing) |
| `XDP_DROP` | Drop (saves downstream processing) |
| `XDP_TX` | Re-transmit (requires helper, more costly) |
| `XDP_REDIRECT` | Redirect to another interface (helper call) |

---

## 12.7 Production Resource Management

### rlimits for eBPF

eBPF programs use kernel resources that need to be bounded:

```bash
# Increase RLIMIT_MEMLOCK for older kernels
# Required for BPF program loading with JIT in some cases
ulimit -l unlimited

# Or set explicitly in userspace
struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
setrlimit(RLIMIT_MEMLOCK, &rlim);
```

### Map size limits

```c
// Always set reasonable max_entries
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);  // Not 0 (unlimited, may be rejected)
    __type(key, __u32);
    __type(value, __u64);
} my_map SEC(".maps");
```

### Privilege separation

| Scenario | Recommended approach |
|----------|---------------------|
| **Development** | Run as root on dev machine |
| **Production** | Use cap_bpf capability only; drop other caps |
| **Multi-tenant** | Each tenant gets own BPF map/fd; use map FD isolation |
| **Cluster (Cilium etc.)** | Node-local maps + cluster-wide maps via etcd/kvstore |

### Program lifecycle in production

1. **Load** with specific tag for identification
2. **Attach** to correct hook points
3. **Monitor** load errors and verifier logs
4. **Rotate/unload** old programs before deploying new versions
5. **Detach** cleanly on update (avoid zombie programs)

---

## 12.8 Summary

| Optimization Area | Key Technique | Impact |
|------------------|---------------|--------|
| **Instruction count** | Minimize hot-path instructions | 20-30% faster execution |
| **Map choice** | Per-CPU for per-CPU data | Zero contention, ~10% overhead reduction |
| **Batch updates** | Flush periodically vs. per-event | 5-10x fewer map operations |
| **XDP optimizations** | Early exit, minimal ops | Higher packet throughput |
| **Resource limits** | rlimits, map max_entries | System stability |
| **Measurement** | perf stat, overhead % | Targeted optimization |

---

## 12.8 Looking Ahead

Chapter 13 concludes the comprehensive eBPF book with **Advanced Topics & Production Deployment** — covering CO-RE (Compile Once, Run Everywhere), production-grade tool lifecycle, Rust integration patterns, and the future of eBPF. You'll have all the concepts needed to build production-grade eBPF tools.

*Next: [Chapter 13 — CO-RE: Compile Once, Run Everywhere](./13-core.md)*