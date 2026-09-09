# Chapter 2: eBPF Fundamentals — Architecture & Verifier

## What This Chapter Covers

- eBPF history and evolution from classic BPF
- The eBPF instruction set architecture (ISA)
- The kernel verifier: safety guarantees and constraints
- eBPF execution model: register model, memory, helpers
- **Why:** Understanding the verifier and execution model is the single most important skill in eBPF development. It's what makes eBPF safe to run in the kernel.

---

## 2.1 From Classic BPF to eBPF

### Classic BPF (cBPF, 1992)

Original BPF was designed for packet filtering (tcpdump, etc.):

- 32-bit accumulator (A) and index register (X)
- 32-bit instructions with 8-byte immediates
- Limited to ~4096 instructions
- Filter only — could not modify state, only accept/reject packets
- Architecture: stackless, simple

### eBPF (Extended BPF, 2014+)

Major extensions in Linux 3.18:

| Feature | Classic BPF | eBPF |
|---------|-------------|------|
| **Registers** | 2 (A, X) | 10 general-purpose (R0-R9) |
| **Instructions** | ~4K limit | ~1M limit (verifier-bounded) |
| **Stack** | Fixed 1024 bytes | 512-byte frame + 512 bytes |
| **Memory access** | Limited | `bpf_probe_read` family |
| **Helpers** | ~50 | 200+ (bpf_*) |
| **Maps** | Not supported | 10+ map types |
| **Attachment** | Limited (datalink only) | kprobe, tracepoint, XDP, cgroup, LSM |
| **Safety** | Trust the user | Verifier-enforced |

### Why the changes?

The kernel needed a general-purpose programmability layer, not just packet filtering. eBPF enables:
- Tracing any kernel function (kprobes)
- Tracing static points (tracepoints)
- Network packet processing (XDP)
- Security policy enforcement (LSM)
- Performance analysis (histograms, metrics)

---

## 2.2 eBPF Instruction Set Architecture

### Registers (64-bit, but upper 32 bits often limited)

| Register | Purpose |
|----------|---------|
| R0-R5 | Temporary/return values |
| R6-R9 | Context (frame pointer) - must be preserved |
| R10 | Read-only frame pointer (hardware context) |
| R0-R5 | Return values from helpers |

### Key instructions

| Instruction | Operation | Notes |
|-------------|-----------|-------|
| `ld` | Load immediate | `ld R0, #42` |
| `ldx` | Load index | `ldx R0, mem[R1]` |
| `st` | Store | `st R0, mem[R1]` |
| `add`, `sub`, `mul`, `div` | Arithmetic | 32-bit operations |
| `and`, `or`, `xor` | Bitwise |  |
| `lsh`, `rsh` | Logical shifts | |
| `tax`, `txa` | Move between A and X | |
| `exit` | Exit program | Return value in R0 |
| `alu64` | 64-bit ALU (some architectures) | |

### Instruction encoding

Each instruction is 32 bits:

```
bits:  31    24 23    16 15    8  7    0
       opcode imm modifier src dst
```

- **opcode** (7 bits): operation type
- **imm** (8 bits): immediate value or index
- **modifier** (1 bit): 0 = alu, 1 = load/store
- **src/dst** (8 bits each): register indices (0-15)

### 64-bit vs 32-bit operations

eBPF is primarily 32-bit, but some architectures support 64-bit ALU operations (`alu64`). The verifier tracks 32-bit vs 64-bit state separately.

### Helper call instructions

`eBPF` programs call kernel functions via `eBPF` helpers:

```c
// Read current timestamp in nanoseconds
R0 = bpf_ktime_get_ns();

// Look up value in a map
// R0 = map_fd, R1 = key, R2 = value pointer
```

All helpers begin with `bpf_` and have specific verifier checks.

---

## 2.3 The eBPF Verifier — The Most Important Concept

### What the verifier does

Before any eBPF program is loaded, the kernel's verifier performs a **mathematical proof** that the program:

1. **Terminates** — No infinite loops (bounded loops only)
2. **No out-of-bounds memory access** — Stack, map, and kernel memory
3. **No uninitialized memory reads** — All reads initialized or proven safe
4. **No invalid pointer arithmetic** — Bounds checked
5. **Complexity limits** — Instruction count, loop nesting, etc.

If the program passes, the kernel **guarantees** it won't crash or corrupt memory. If it fails, the load is rejected with an error log.

### Verifier workflow

```
1. Parse eBPF ELF bytecode
2. Construct control flow graph (CFG)
3. Data-flow analysis: track register states
4. Prove safety properties on all paths
5. If safe: compile to native code (JIT)
6. If unsafe: reject with verbose error
```

### Common verifier errors (and how to fix them)

| Error | Cause | Fix |
|-------|-------|-----|
| `unbounded loop` | `for (;;) {}` or `while (1)` without break condition | Use unrolling or bounded counter |
| `potential out-of-bounds access` | Array index not proven within `max_entries` | Use correct key type/size, or verify key |
| `unsafe pointer arithmetic` | Casting between pointer sizes without proof | Use `bpf_probe_read` family instead |
| `uninitialized variable` | Register used before being set | Initialize all registers before use |
| `verifier rejected program` | Too many instructions (>1M) | Refactor to smaller program, use helper calls |

### Reading verifier errors

```bash
# Load program and see log
sudo bpftool prog load test.bpf.o /sys/fs/bpf/test 2>&1 | head -30

# Or via libbpf
# The log appears in dmesg or /sys/kernel/debug/bpf/log
```

### Why the verifier matters for Rust

Rust's type system catches many errors at compile time that the verifier would catch at load time. However:
- FFI to C still requires `unsafe`
- Raw pointer arithmetic bypasses Rust checks
- Map value sizes must match between Rust and C
- BTF (BPF Type Format) helps the verifier understand Rust types

---

## 2.4 eBPF Execution Model

### Register model

```
R0-R5:  Temporary / return values (clobbered by helpers)
R6:     Frame pointer (RBP) - typically points to stack start
R7-R9:  Callee-saved registers (must be preserved by program)
R10:    Read-only frame pointer (task context, program state)
    - Points to beginning of program context
    - Contains: ctx pointer, packet data (for XDP), etc.
```

### Memory model

| Memory type | Size | Access |
|-------------|------|--------|
| **Stack** | 512 bytes (per-program) | Stack-relative addressing |
| **Maps** | Configurable (max_entries * entry_size) | Map FD + key/value operations |
| **Kernel memory** | Via helpers only | `bpf_probe_read`, `bpf_probe_read_user` |
| **Packet data** (XDP only) | Up to `TPACK_SIZE` (2048 bytes) | ctx->data, ctx->data_end pointers |

### Program context

Depending on program type, R10 (frame pointer) contains:

| Program type | R10 contains |
|--------------|--------------|
| **kprobe** | `struct pt_regs *` (register state at probe point) |
| **tracepoint** | `struct trace_event_raw_*` (trace event data) |
| **XDP** | `struct xdp_md *` (packet bounds: data, data_end) |
| **cgroup** | `struct bpf_cgroup_ctx *` (cgroup data) |
| **lsm** | `struct lsm_hook_ctx *` (security hook context) |

### Instruction lifetime

1. **Load**: ELF bytecode parsed, verified, JIT-compiled
2. **Attach**: Program linked to kernel hook (kprobe, tracepoint, etc.)
3. **Trigger**: Hook fires (function call, packet arrival, syscall)
4. **Execute**: JIT-compiled code runs (nanoseconds typically)
5. **Exit**: Return value propagated to userspace via maps/ring buffer

### Helper functions

200+ built-in helpers, categorized:

| Category | Examples |
|----------|----------|
| **Map operations** | `bpf_map_lookup_elem`, `bpf_map_update_elem`, `bpf_map_delete_elem` |
| **Packet inspection** (XDP) | `bpf_pkt_type`, `bpf_rcv_enqueue`, `bpf_xdp_redirect` |
| **Task inspection** | `bpf_get_current_pid_tgid`, `bpf_get_current_comm`, `bpf_probe_read` |
| **Time** | `bpf_ktime_get_ns`, `bpf_get_ns_time`, `bpf_get_current_time_seconds` |
| **Memory** | `bpf_probe_read`, `bpf_probe_read_user`, `bpf_probe_read_kernel` |
| **Return values** | `bpf_trace_return`, `bpfModifyReturn`, `bpfExit` |

---

## 2.5 eBPF Map Types

Maps are key-value stores shared between kernel and userspace (or between programs). Type matters for performance and semantics:

| Map type | Behavior | Best use case |
|----------|----------|---------------|
| `BPF_MAP_TYPE_HASH` | Key-value, O(1) lookup | Counters, lookups, per-CPU stats |
| `BPF_MAP_TYPE_ARRAY` | Fixed-size array, sequential scan | Global counters, configuration |
| `BPF_MAP_TYPE_PERCPU` | One map per CPU | Per-CPU counters, no locking |
| `BPF_MAP_TYPE_PERCPU_ARRAY` | Per-CPU array, index = CPU | CPU-specific state |
| `BPF_MAP_TYPE_RINGBUF` | Ring buffer, prod-consumer | Event streaming to userspace |
| `BPF_MAP_TYPE_QUEUE` | FIFO queue, multi-writer | Packet metadata, async events |
| `BPF_MAP_TYPE_DEPRECATED` | LRU, hash with LRU eviction | Cache-like workloads |

### Map API (common helpers)

```c
// Lookup
bpf_map_lookup_elem(map_fd, &key, &value, size);

// Update
bpf_map_update_elem(map_fd, &key, &value, flags);

// Delete
bpf_map_delete_elem(map_fd, &key);

// Iterate (advancing)
bpf_map_get_next_key(map_fd, &last_key, &next_key);
```

---

## 2.6 Program Types & Attachment Points

### Summary of eBPF program types

| Type | Hook point | Context (R10) | Key helpers |
|------|------------|---------------|-------------|
| **SK_REUSEPORT** | Socket filter | `struct sock *` | `bpf_sk_lookup`, `bpf_redirect` |
| **XDP** | Network driver entry | `struct xdp_md *` | `bpf_xdp_redirect`, `bpf_drop`, `bpf_send` |
| **SOCKET_FILTER** | Socket receive | `struct sock *` | `bpf_sk_under_cgroup`, `bpf_alloc_skb` |
| **KPROBE** | Any kernel function | `struct pt_regs *` | `bpf_probe_read`, `bpf_get_current_pid_tgid` |
| **KRETPROBE** | Kernel function return | `struct pt_regs *` | Same as kprobe, after return |
| **TRACEPOINT** | Static tracepoints | `struct trace_event_raw_*` | `bpf_trace_printk`, map updates |
| **CGROUP_SKB** | cgroup network iface | `struct bpf_cgroup_ctx *` | `bpf_cgroup_classify`, `bpf_map_lookup_elem` |
| **CGROUP_SOCK** | cgroup socket | `struct bpf_cgroup_ctx *` | Same |
| **LSM** | Security hooks (bind, execve, etc.) | varies by LSM | `bpf_lsm_to_metadata` |

### Attachment mechanisms

| Mechanism | Tool | Notes |
|-----------|------|-------|
| **kprobe** | `bpftrace`, `libbpf`, `perf` | Any kernel function via address |
| **tracepoint** | `bpftrace`, `perf`, `bpftool` | Static points, lower overhead |
| **XDP** | `iproute2`, `libbpf` | Driver level, zero-copy |
| **cgroup** | `iproute2`, Cilium | Resource control, attachment via `bpftool` |
| **LSM** | Custom modules | Security hooks, compiled into kernel |
| **uprobe** | `bpftrace`, `perf` | User-space probe points |

---

## 2.7 BTF — BPF Type Format

### What is BTF?

BTF (BPF Type Format) is debug info embedded in eBPF ELF objects and the kernel. It provides:

- **Type information**: struct sizes, field offsets, enum values
- **CO-RE (Compile Once, Run Everywhere)**: same compiled program works on different kernel versions
- **Verifier assistance**: the verifier uses BTF to validate pointer arithmetic and field access

### BTF sources

1. **vmlinux BTF**: embedded in kernel (`/sys/kernel/btf/vmlinux`)
2. **Program BTF**: embedded in the compiled eBPF object
3. **External BTF**: loaded separately via `bpftool`

### Why BTF matters for Rust

When writing eBPF in Rust (via libbpf-rs or Aya):
- BTF allows the verifier to understand Rust `struct` layouts
- Field offsets are verified automatically
- Same Rust code can compile for multiple kernel versions
- Without BTF, you'd need manual size/offset constants

### Generating BTF

```bash
# Generate vmlinux.h for compilation
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Or via clang flags
clang -target bpf -g -O2 -D__TARGET_ARCH_x86 \
      -I. program.bpf.c -o program.bpf.o
```

---

## 2.8 Summary

| Concept | Key Takeaway |
|---------|-------------|
| **eBPF vs cBPF** | eBPF is general-purpose; cBPF is packet-filter-only |
| **Verifier** | Mathematical safety proof; gates program loading |
| **Registers** | R0-R10, R10 is read-only frame pointer |
| **Stack** | 512 bytes, stack-relative addressing |
| **Maps** | 10+ types, key-value storage |
| **Program types** | kprobe, tracepoint, XDP, cgroup, LSM, etc. |
| **BTF** | Type info for CO-RE and verifier assistance |

---

## 2.9 Looking Ahead

In Chapter 3, we'll start writing actual eBPF programs. You'll learn how to:
- Write C source compiled to eBPF bytecode
- Use libbpf skeleton API for userspace loading
- Define and use maps
- Attach to tracepoints and kprobes

The verifier concepts from this chapter will help you understand why certain code patterns work and others are rejected.

*Next: [Chapter 3 — First eBPF Programs in C](./03-first-ebpf-c.md)*