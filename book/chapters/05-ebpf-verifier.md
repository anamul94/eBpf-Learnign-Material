# Chapter 5: The eBPF Verifier — Safety Through Static Analysis

## What This Chapter Covers

- Why the verifier exists and what it guarantees
- How the verifier analyzes programs step by step
- Common verifier errors and how to fix them
- The type system the verifier uses
- Practical patterns that satisfy the verifier
- Advanced verifier concepts: speculation, precision, liveness

---

## 5.1 Why the Verifier Exists

The verifier solves a fundamental problem: **How do you let untrusted code run in the kernel safely?**

The answer is **static analysis** — analyzing the program *before* it runs to prove it will never:

1. Crash the kernel
2. Hang the system (infinite loop)
3. Access invalid memory
4. Leak kernel data
5. Exceed resource limits

If the verifier can prove safety, the program is allowed to run. If it can't prove safety, the program is rejected.

**This is a guarantee, not a best-effort check.** A verified program cannot crash the kernel. This is what makes eBPF revolutionary — you get kernel programmability with the safety of userspace.

---

## 5.2 How the Verifier Works — Step by Step

The verifier performs a **simulation** of the program execution, tracking the state of every register at every instruction.

### 5.2.1 Control Flow Graph (CFG) Construction

First, the verifier builds a graph of all possible execution paths:

```
┌─────────────────────────────────────────────────────────────┐
│                    CONTROL FLOW GRAPH                       │
│                                                             │
│    ┌──────────┐                                             │
│    │ Entry    │ R1 = ctx, R0 = 0                            │
│    └────┬─────┘                                             │
│         │                                                   │
│         ▼                                                   │
│    ┌──────────┐                                             │
│    │ Lookup   │ R0 = bpf_map_lookup_elem(&map, &key)       │
│    └────┬─────┘                                             │
│         │                                                   │
│         ▼                                                   │
│    ┌──────────┐                                             │
│    │ Check    │ if R0 == 0                                  │
│    └────┬─────┘                                             │
│    yes/ │ \no                                               │
│    ┌────┘   └────┐                                          │
│    ▼             ▼                                          │
│ ┌──────┐    ┌──────────┐                                    │
│ │Exit  │    │ Use R0   │ R2 = *(u64 *)(R0 + 0)             │
│ │return│    └────┬─────┘                                    │
│ └──────┘         │                                          │
│                  ▼                                          │
│             ┌──────────┐                                    │
│             │ Update   │ *(u64 *)(R0 + 0) = R2 + 1         │
│             └────┬─────┘                                    │
│                  │                                          │
│                  ▼                                          │
│             ┌──────────┐                                    │
│             │ Exit     │ return R0                          │
│             └──────────┘                                    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 5.2.2 State Tracking

For each instruction, the verifier tracks:

```
Register State:
┌─────────┬────────────────┬─────────────┬──────────────┐
│ Register│ Type           │ Min Value   │ Max Value    │
├─────────┼────────────────┼─────────────┼──────────────┤
│ R0      │ SCALAR_VALUE   │ 0           │ 4294967295   │
│ R1      │ PTR_TO_CTX     │ -           │ -            │
│ R2      │ PTR_TO_MAP_VAL │ -           │ -            │
│ R6      │ SCALAR_VALUE   │ 100         │ 200          │
│ R10     │ PTR_TO_STACK   │ -           │ -            │
└─────────┴────────────────┴─────────────┴──────────────┘
```

### 5.2.3 Path Exploration

The verifier follows all branches, maintaining separate states for each path:

```
Path 1 (R0 == 0):  → R0 is NULL, exit
Path 2 (R0 != 0):  → R0 is valid pointer, continue

At merge point (after if-else):
  R0 state depends on which path was taken
  The verifier tracks this precisely
```

---

## 5.3 The Verifier's Type System

The verifier uses a rich type system to track what each register contains:

### 5.3.1 Scalar Types

```
SCALAR_VALUE: An unknown integer
  - Tracks min/max bounds
  - Tracks whether it could be zero
  - Used for counters, flags, computed values
```

### 5.3.2 Pointer Types

```
PTR_TO_CTX:          Pointer to program context (e.g., xdp_md, pt_regs)
PTR_TO_MAP_KEY:      Pointer to a map key
PTR_TO_MAP_VALUE:    Pointer to a map value
PTR_TO_MAP_VALUE_OR_NULL: Pointer to map value, or NULL (from lookup)
PTR_TO_STACK:        Pointer to stack (R10)
PTR_TO_PACKET:       Pointer to packet data (XDP)
PTR_TO_SOCKET:       Pointer to socket structure
PTR_TO_BTF_ID:       Pointer to a kernel structure (with BTF type info)
PTR_TO_MEM:          Pointer to memory (generic)
PTR_TO_BUF:          Pointer to buffer
```

### 5.3.3 Null Tracking

```c
// The verifier tracks NULL checks precisely:

__u64 *val = bpf_map_lookup_elem(&map, &key);
// val has type: PTR_TO_MAP_VALUE_OR_NULL

if (val != 0) {
    // Inside this block: val has type PTR_TO_MAP_VALUE
    // The verifier knows val is not NULL here
    *val += 1;  // OK!
}

// After the if block: val is PTR_TO_MAP_VALUE_OR_NULL again
// *val += 1;  // Would be rejected!
```

---

## 5.4 Common Verifier Errors and Solutions

### 5.4.1 "R0 type=map_value_or_null expected=map_value"

```c
// ERROR: Forgetting NULL check
__u64 *val = bpf_map_lookup_elem(&map, &key);
*val += 1;  // R0 might be NULL!

// FIX: Check for NULL first
__u64 *val = bpf_map_lookup_elem(&map, &key);
if (val)
    *val += 1;  // Verifier knows val is non-NULL here
```

### 5.4.2 "invalid access to map value, value_size=X off=Y size=Z"

```c
// ERROR: Out-of-bounds access
struct value { __u32 a; __u32 b; };  // size = 8
struct value *v = bpf_map_lookup_elem(&map, &key);
if (v) {
    __u64 x = *(__u64 *)(v + 1);  // Reading past the value!
}

// FIX: Stay within bounds
if (v) {
    __u32 a = v->a;  // OK: offset 0, size 4, within 8-byte value
    __u32 b = v->b;  // OK: offset 4, size 4, within 8-byte value
}
```

### 5.4.3 "BPF program is too large"

```c
// ERROR: Program exceeds 1M instructions (after inlining)

// FIX 1: Use tail calls to split the program
bpf_tail_call(ctx, &prog_array, index);

// FIX 2: Use #pragma unroll carefully
// FIX 3: Simplify logic
// FIX 4: Move complex processing to userspace
```

### 5.4.4 "back-edge from insn X to Y"

```c
// ERROR: Unbounded loop
for (int i = 0; i < n; i++) {  // n is dynamic
    // ...
}

// FIX: Bound the loop
#pragma unroll
for (int i = 0; i < 10; i++) {  // Constant bound
    // ...
}
```

### 5.4.5 "R1 invalid mem access 'inv'"

```c
// ERROR: Reading uninitialized memory
__u32 x;        // Uninitialized!
if (x == 42) {  // Verifier rejects: x might be uninitialized
    // ...
}

// FIX: Initialize before use
__u32 x = 0;
if (x == 42) {  // OK
    // ...
}
```

### 5.4.6 "helper call is not allowed"

```c
// ERROR: Using a helper not allowed for this program type
SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    bpf_get_current_pid_tgid();  // Not allowed in XDP context!
}

// FIX: Use only helpers valid for your program type
SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    __u64 ts = bpf_ktime_get_ns();  // OK: allowed in XDP
}
```

---

## 5.5 Verifier-Assisted Bounds Checking

The verifier tracks value ranges and can prove bounds checks automatically:

```c
// The verifier tracks that 'index' is between 0 and 9
__u32 index = bpf_get_current_pid_tgid() & 0xF;  // 0-15
if (index < 10) {                                  // Verifier knows: 0-9
    arr[index] = 42;                               // OK: verifier proves bounds
}
```

```
Verifier state tracking:
  index = bpf_get_current_pid_tgid() & 0xF
    → index: SCALAR_VALUE, min=0, max=15

  if (index < 10):
    → index: SCALAR_VALUE, min=0, max=9 (in this branch)

  arr[index]:
    → Verifier checks: index (0-9) < array_size (10)
    → ACCESS ALLOWED
```

---

## 5.6 The Verifier's Function Model

When the verifier encounters a function call:

```
1. Check if it's a known helper function
   → Look up in helper table
   → Validate argument types match helper signature

2. Check call depth (max 32 nested calls)

3. Simulate the call:
   → Save callee-saved registers (R6-R9)
   → Pass arguments (R1-R5)
   → R0 = return value (type depends on helper)

4. Continue analysis after the call
```

### 5.6.1 Static Inline Functions

```c
// The verifier inlines static functions
static __always_inline __u32 process(__u32 val) {
    return val * 2;
}

// After inlining, the verifier sees:
// R0 = R1 * 2  (directly, no call overhead)
```

### 5.6.2 Non-Static Functions

```c
// Non-static functions are called but must be traceable
__u32 helper(__u32 val) {  // Must be defined before use
    return val + 1;
}

// The verifier will analyze the function body
// and track its effects on registers
```

---

## 5.7 Precision and Speculation Tracking

Modern verifiers track **precise** register values and **speculative** execution paths:

### 5.7.1 Precise Tracking

```c
if (R1 == 100) {
    // Verifier knows R1 == 100 here (precise)
    R2 = R1 + 1;  // R2 = 101 (precise)
}
```

### 5.7.2 Speculative Tracking

```c
if (ptr != NULL) {
    // Main path: ptr is valid
    *ptr = 42;
} else {
    // Speculative path: ptr is NULL
    // Verifier tracks this path too, but it won't be executed
    // This prevents Spectre-style attacks
}
```

---

## 5.8 Verifier Log — Understanding the Output

When verification fails, the verifier provides a detailed log:

```
Requesting program load from the kernel...
Loader error:
0: (b7) r1 = 1                    # R1 = 1
1: (15) if r1 == 0x0 goto pc+2    # if R1 == 0, jump to 4
2: (b7) r0 = 0                    # R0 = 0
3: (95) exit                       # return R0
4: (79) r2 = *(u64 *)(r1 + 0)     # R2 = *(u64 *)(R1 + 0)

Verification failed: invalid access to map value
R1 type=scalar expected=map_value

Failed to load program
```

**How to read this:**
1. The verifier shows the instruction where it failed
2. It shows the register state at that point
3. It explains what type it expected vs. what it got

---

## 5.9 Helper Function Return Value Tracking

Each helper function has a known return type:

```c
// Helper return type examples:
bpf_map_lookup_elem()    → PTR_TO_MAP_VALUE_OR_NULL
bpf_ktime_get_ns()       → SCALAR_VALUE (u64 timestamp)
bpf_get_current_pid_tgid() → SCALAR_VALUE (u64)
bpf_probe_read()         → SCALAR_VALUE (0 or negative error)
bpf_ringbuf_reserve()    → PTR_TO_MAP_VALUE_OR_NULL
```

The verifier uses these types to track register state after calls.

---

## 5.10 BTF and Type Information

BTF (BPF Type Format) provides type information that the verifier uses:

```c
// With BTF, the verifier knows struct field types
struct task_struct {
    pid_t pid;        // BTF knows this is int (32-bit)
    char comm[16];    // BTF knows this is char[16]
    // ...
};

// BPF_CORE_READ uses BTF to:
// 1. Find the field offset
// 2. Know the field type
// 3. Validate the access
pid_t pid = BPF_CORE_READ(task, pid);
```

---

## 5.11 Practical Verifier Patterns

### Pattern 1: Safe Map Access

```c
static __always_inline __u64 *safe_lookup(struct bpf_map *map, __u32 *key) {
    __u64 *val = bpf_map_lookup_elem(map, key);
    if (!val)
        return NULL;
    return val;
}

// Usage:
__u64 *counter = safe_lookup(&counters, &key);
if (counter)
    __sync_fetch_and_add(counter, 1);
```

### Pattern 2: Bounded Iteration

```c
// Safe bounded loop
#define MAX_ITER 64
for (__u32 i = 0; i < MAX_ITER; i++) {
    if (i >= actual_count)
        break;
    // Process item i
}
```

### Pattern 3: Safe String Copy

```c
// Helper for safe string copy from kernel space
static __always_inline int read_comm(char *dst, __u32 size) {
    // bpf_get_current_comm is a helper that safely copies
    return bpf_get_current_comm(dst, size);
}
```

### Pattern 4: Packet Bounds Checking (XDP)

```c
SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Every packet access must be bounds-checked
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;  // Packet too small

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;  // Packet too small

    // Now safe to access eth and ip
    if (ip->protocol == IPPROTO_TCP)
        return XDP_DROP;

    return XDP_PASS;
}
```

---

## 5.12 Verifier Complexity Limits

The verifier enforces limits to keep verification tractable:

| Limit | Value | Why |
|-------|-------|-----|
| Max instructions | 1,000,000 | Prevents excessive verification time |
| Max tail calls | 32 | Limits call depth |
| Max function calls | 32 nested | Prevents stack overflow |
| Max loop iterations | Must be provably bounded | Prevents infinite loops |
| Max stack size | 512 bytes | Fixed stack size |
| Max instructions per program | 1M (after unrolling) | Keeps JIT manageable |

---

## 5.13 Debugging Verifier Errors

### 5.13.1 Enable Verbose Logging

```bash
# Enable verifier debug logging
echo 1 > /proc/sys/kernel/bpf_stats_enabled

# Load with verbose errors
bpftool prog load program.o /sys/fs/bpf/program verbose
```

### 5.13.2 Use bpftool to Inspect

```bash
# Load and get detailed error
bpftool prog load program.o /sys/fs/bpf/program 2>&1

# Dump the verifier log
bpftool prog load program.o /sys/fs/bpf/program verbose 2>&1 | tail -100
```

### 5.13.3 Common Debugging Strategy

1. **Read the error message carefully** — it tells you exactly what's wrong
2. **Look at the instruction number** — it points to the failing instruction
3. **Check register types** — ensure pointers are NULL-checked
4. **Verify bounds** — ensure all memory accesses are within bounds
5. **Simplify** — comment out code until it passes, then add back gradually

---

## 5.14 Summary

- The **verifier** statically analyzes eBPF programs for safety
- It tracks **register types** and **value ranges** at every instruction
- Common errors: missing NULL checks, out-of-bounds access, uninitialized reads
- Always **NULL-check** map lookups and **bounds-check** memory accesses
- The verifier log tells you **exactly** what's wrong
- Understanding the verifier is the **most important skill** in eBPF

---

## 5.15 Looking Ahead

Now that you understand how the verifier works, Chapter 6 covers **eBPF maps** — the data structures that let kernel and userspace communicate.

---

*Next: [Chapter 6 — eBPF Maps](./06-ebpf-maps.md)*
