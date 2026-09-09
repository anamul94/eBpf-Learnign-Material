# Chapter 4: eBPF Architecture — How It Works Inside the Kernel

## What This Chapter Covers

- The eBPF virtual machine and its registers
- eBPF instructions and how they're executed
- The verifier's role and how it analyzes programs
- JIT compilation to native code
- How eBPF programs attach to kernel hooks
- The complete execution flow from load to runtime

---

## 4.1 The eBPF Virtual Machine

At its core, eBPF is a **virtual machine** that runs inside the Linux kernel. It's a simple, RISC-like architecture designed for safety and speed.

### 4.1.1 Registers

The eBPF VM has a small, fixed set of registers:

| Register | Purpose |
|----------|---------|
| `R0` | Return value (function calls, program exit) |
| `R1` - `R5` | Function arguments (caller-saved) |
| `R6` - `R9` | Callee-saved registers |
| `R10` | Frame pointer (read-only, points to stack) |

That's it. **11 registers total.** This simplicity makes verification tractable.

```
┌─────────────────────────────────────────────────┐
│              eBPF Register File                  │
├─────────┬───────────────────────────────────────┤
│   R0    │ Return value                          │
├─────────┼───────────────────────────────────────┤
│   R1    │ Argument 1 / Context pointer          │
├─────────┼───────────────────────────────────────┤
│   R2    │ Argument 2                            │
├─────────┼───────────────────────────────────────┤
│   R3    │ Argument 3                            │
├─────────┼───────────────────────────────────────┤
│   R4    │ Argument 4                            │
├─────────┼───────────────────────────────────────┤
│   R5    │ Argument 5                            │
├─────────┼───────────────────────────────────────┤
│   R6    │ Callee-saved                          │
├─────────┼───────────────────────────────────────┤
│   R7    │ Callee-saved                          │
├─────────┼───────────────────────────────────────┤
│   R8    │ Callee-saved                          │
├─────────┼───────────────────────────────────────┤
│   R9    │ Callee-saved                          │
├─────────┼───────────────────────────────────────┤
│  R10    │ Frame pointer (read-only)             │
└─────────┴───────────────────────────────────────┘
```

### 4.1.2 The Stack

eBPF has a small, fixed-size stack:

- **512 bytes** per program
- Used for local variables
- Accessed via `R10` (frame pointer) with negative offsets
- Grows downward (like x86)

```
┌───────────────────────┐ High address
│                       │
│    (unused space)     │
│                       │
├───────────────────────┤ R10 (frame pointer)
│                       │
│    Local variables    │
│    (up to 512 bytes)  │
│                       │
├───────────────────────┤ Low address
│         ...           │
└───────────────────────┘
```

### 4.1.3 Instruction Set

eBPF instructions are 64-bit wide, fixed-size:

```
┌─────────┬────────┬────────┬─────────┬─────────────────┐
│  opcode │  dst   │  src   │  offset │     imm         │
│  8 bits │ 4 bits │ 4 bits │ 16 bits │    32 bits      │
└─────────┴────────┴────────┴─────────┴─────────────────┘
```

Instruction classes:
- **ALU operations**: Add, subtract, multiply, divide, bitwise ops
- **Jump operations**: Conditional and unconditional branches
- **Memory operations**: Load and store (to/from stack and maps)
- **Call operations**: Call helper functions

---

## 4.2 eBPF Instructions — A Closer Look

### 4.2.1 ALU Operations

```c
// C code                          // eBPF instructions (conceptual)
x += 42;                          // ADD_IMM: R0 += 42
y = x * 3;                        // MUL_IMM: R1 = R0, MUL R1, 3
flags &= ~O_NONBLOCK;             // AND_IMM: R2 &= 0xFFFFFDFF
index = hash % size;              // MOD_IMM: R3 = R4 % 1024
```

### 4.2.2 Memory Operations

```c
// Stack access (via R10)
char buf[64];                     // Stack space allocated at compile time
buf[0] = 'A';                     // STX_MEM: [R10 + offset] = 'A'

// Map access (via helper functions)
bpf_map_lookup_elem(&map, &key);  // CALL: bpf_map_lookup_elem(R1, R2)
```

### 4.2.3 Helper Function Calls

Helper functions are the eBPF program's interface to the kernel:

```c
// C code
__u64 ts = bpf_ktime_get_ns();

// eBPF bytecode (conceptual)
// R1 = address of map (or NULL for some helpers)
// R2 = address of key
// CALL bpf_ktime_get_ns  →  R0 = return value
```

### 4.2.4 Control Flow

```c
// Conditional
if (value > 100) { ... }

// eBPF bytecode (conceptual)
// JGT_IMM: if R0 > 100, jump +2 instructions
// ... else branch ...
// JMP: jump +1 (skip if branch)
// ... if branch ...
```

---

## 4.3 The Verifier — Static Analysis Engine

The verifier is the most critical component of eBPF. It performs **static analysis** to prove program safety before execution.

### 4.3.1 What the Verifier Checks

```
┌─────────────────────────────────────────────────────────────┐
│                    VERIFIER CHECKS                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. Control Flow Graph (CFG) Validation                     │
│     ├── No unreachable instructions                         │
│     ├── No out-of-bounds jumps                              │
│     └── No infinite loops                                   │
│                                                             │
│  2. Register State Tracking                                 │
│     ├── Type tracking (scalar, pointer, map value, etc.)    │
│     ├── Bounds tracking (min/max values)                    │
│     ├── NULL tracking (was this pointer checked?)           │
│     └── Initialization tracking (was this register set?)    │
│                                                             │
│  3. Memory Safety                                           │
│     ├── Stack bounds (R10 + offset within 512 bytes)        │
│     ├── Map value bounds (offset within value size)         │
│     ├── No out-of-bounds access                             │
│     └── No use-after-free                                   │
│                                                             │
│  4. Termination Proof                                       │
│     ├── Loop bounds must be provable                        │
│     ├── No backward jumps that could loop infinitely        │
│     └── Program complexity limit (1M instructions)          │
│                                                             │
│  5. Helper Function Validation                              │
│     ├── Correct argument types                              │
│     ├── Context-appropriate helpers only                    │
│     └── Return value handling                               │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 4.3.2 Register State Tracking

The verifier tracks the state of every register at every instruction:

```
Instruction 1: R1 = map_lookup_elem(&map, &key)
    → R1: PTR_TO_MAP_VALUE_OR_NULL, map=&map, value_size=8

Instruction 2: if (R1 == 0) goto exit
    → Path A (R1 == 0): R1 is NULL, jump to exit
    → Path B (R1 != 0): R1: PTR_TO_MAP_VALUE, offset=0, size=8

Instruction 3 (Path B): R0 = *(u64 *)(R1 + 0)
    → R0: SCALAR_VALUE (loaded from map)
    → Verifier confirms: R1 is valid pointer, offset 0 is within bounds

Instruction 4: exit: return R0
```

### 4.3.3 Verifier Error Messages

When the verifier rejects a program, it tells you why:

```
; R0 = bpf_map_lookup_elem(&map, &key)
; if (R0 == 0) goto exit
; *(u64 *)(R0 + 0) += 1    ← This is where it fails

invalid access to map value, value_size=8 off=0 size=8
R0 type=map_value_or_null expected=map_value
```

The verifier is saying: "R0 might be NULL (map_value_or_null), but you're trying to dereference it. I need you to check for NULL first."

---

## 4.4 JIT Compilation

After verification, eBPF bytecode is compiled to native machine code:

```
┌─────────────────────────────────────────────────────────────┐
│                    JIT COMPILATION                          │
│                                                             │
│  eBPF Bytecode          x86-64 Native Code                  │
│  ─────────────          ──────────────────                  │
│  MOV R0, 0              xor %eax, %eax                      │
│  ADD R0, 42             add $42, %eax                       │
│  STX_MEM [R10-4], R0    mov %eax, -4(%rbp)                  │
│  CALL bpf_map_lookup    call bpf_map_lookup_elem            │
│  JEQ R0, 0, +2          test %eax, %eax; je .exit           │
│  LDX_MEM R1, [R0+0]     mov (%rax), %ecx                    │
│  ADD R1, 1              add $1, %ecx                        │
│  STX_MEM [R0+0], R1     mov %ecx, (%rax)                    │
│  EXIT                   ret                                 │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

The JIT compiler is architecture-specific:
- x86-64, ARM64, RISC-V, s390, PowerPC, SPARC, MIPS
- Each has its own JIT backend
- The JIT maps eBPF registers to native registers where possible

**Performance:** JIT-compiled eBPF runs at near-native speed. The overhead is typically just a few nanoseconds per program invocation.

---

## 4.5 Program Types and Attachment Points

eBPF programs are categorized by what they attach to:

### 4.5.1 Tracing Programs

| Type | Description | Attachment |
|------|-------------|------------|
| `BPF_PROG_TYPE_KPROBE` | Dynamic kernel function tracing | Any kernel function |
| `BPF_PROG_TYPE_KRETPROBE` | Kernel function return tracing | Return of any kernel function |
| `BPF_PROG_TYPE_TRACEPOINT` | Static tracepoints | Pre-defined kernel tracepoints |
| `BPF_PROG_TYPE_RAW_TRACEPOINT` | Raw tracepoints (no args parsing) | Pre-defined tracepoints |
| `BPF_PROG_TYPE_PERF_EVENT` | Perf events | Hardware/software perf counters |

### 4.5.2 Networking Programs

| Type | Description | Attachment |
|------|-------------|------------|
| `BPF_PROG_TYPE_XDP` | Express Data Path | Network driver (earliest point) |
| `BPF_PROG_TYPE_SCHED_CLS` | Traffic control classifier | TC ingress/egress |
| `BPF_PROG_TYPE_SCHED_ACT` | Traffic control action | TC ingress/egress |
| `BPF_PROG_TYPE_SOCKET_FILTER` | Socket-level filtering | Socket recv |
| `BPF_PROG_TYPE_SOCK_OPS` | Socket operations | TCP events |
| `BPF_PROG_TYPE_CGROUP_SKB` | Cgroup socket buffer | Cgroup network hooks |

### 4.5.3 Security Programs

| Type | Description | Attachment |
|------|-------------|------------|
| `BPF_PROG_TYPE_LSM` | Linux Security Module | LSM hooks |
| `BPF_PROG_TYPE_CGROUP_SOCK` | Cgroup socket operations | Cgroup socket creation |
| `BPF_PROG_TYPE_CGROUP_DEVICE` | Cgroup device access | Cgroup device control |

---

## 4.6 The Complete Execution Flow

Let's trace what happens from writing code to execution:

```
┌─────────────────────────────────────────────────────────────────┐
│  1. DEVELOPMENT                                                 │
│                                                                 │
│  Write C/Rust source → Compile with Clang/Rustc (target bpf)   │
│  → Produce ELF .o file with BTF info, maps, programs            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  2. LOADING (userspace)                                         │
│                                                                 │
│  libbpf/libpf-rs reads ELF → Creates maps via bpf() syscall    │
│  → Loads program bytecode → Submits to kernel                   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  3. VERIFICATION (kernel)                                       │
│                                                                 │
│  Verifier analyzes bytecode → Checks safety properties          │
│  → If rejected: error returned to userspace                     │
│  → If accepted: proceed to JIT                                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  4. JIT COMPILATION (kernel)                                    │
│                                                                 │
│  eBPF bytecode → Native machine code for current CPU            │
│  → Stored in memory, ready for execution                        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  5. ATTACHMENT (kernel)                                         │
│                                                                 │
│  Program attached to hook point (tracepoint, kprobe, XDP, etc.) │
│  → Program is now "live" and will trigger on events             │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  6. EXECUTION (kernel, on event)                                │
│                                                                 │
│  Event triggers → Program executes → Reads/writes maps          │
│  → Submits events to ring buffer → Returns                      │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  7. DATA COLLECTION (userspace)                                 │
│                                                                 │
│  Userspace reads maps → Reads ring buffer events                │
│  → Processes, displays, or exports data                         │
└─────────────────────────────────────────────────────────────────┘
```

---

## 4.7 eBPF Context — What Programs Receive

Each program type receives a different context structure:

### 4.7.1 Tracepoint Context

```c
// For SEC("tp/syscalls/sys_enter_execve")
struct trace_event_raw_sys_enter {
    __u64 unused;
    __u32 nr;           // Syscall number
    __u32 flags;
    __u64 args[6];      // Syscall arguments
};
```

### 4.7.2 XDP Context

```c
// For SEC("xdp")
struct xdp_md {
    __u32 data;         // Start of packet data
    __u32 data_end;     // End of packet data
    __u32 data_meta;    // Metadata pointer
    // ... other fields
};
```

### 4.7.3 Kprobe Context

```c
// For SEC("kprobe/do_sys_open")
// Receives struct pt_regs — the CPU registers at probe hit
struct pt_regs {
    unsigned long r15;
    unsigned long r14;
    // ... all CPU registers
};
```

---

## 4.8 eBPF Tail Calls

eBPF programs can call other eBPF programs using **tail calls**:

```c
// Program A: dispatch based on condition
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 10);
    __type(key, __u32);
    __type(value, __u32);
} prog_array SEC(".maps");

SEC("xdp")
int dispatcher(struct xdp_md *ctx) {
    __u32 key = get_packet_type(ctx);
    bpf_tail_call(ctx, &prog_array, key);
    return XDP_PASS;  // Fallback if tail call fails
}

// Program B: handles TCP packets
SEC("xdp")
int handle_tcp(struct xdp_md *ctx) {
    // Process TCP
    return XDP_PASS;
}

// Program C: handles UDP packets
SEC("xDP")
int handle_udp(struct xdp_md *ctx) {
    // Process UDP
    return XDP_PASS;
}
```

**Why tail calls matter:**
- Overcome the 1M instruction limit per program
- Enable modular program design
- Allow runtime program replacement (swap programs in the array)

---

## 4.9 eBPF Map Access from Userspace

Maps are the communication channel between kernel and userspace:

```
┌─────────────────────────────────────────────────────────────┐
│                    eBPF MAP ACCESS                          │
│                                                             │
│  Kernel Space                Userspace                      │
│  ───────────                 ──────────                     │
│                              bpf_map_lookup_elem()          │
│  ┌─────────┐                 bpf_map_update_elem()          │
│  │         │ ◄────────────►  bpf_map_delete_elem()          │
│  │   Map   │                 bpf_map_get_next_key()          │
│  │         │                                               │
│  └─────────┘                                               │
│                                                             │
│  Both kernel and userspace access the same map via fd       │
└─────────────────────────────────────────────────────────────┘
```

---

## 4.10 Summary

- eBPF is a **virtual machine** with 11 registers and 512-byte stack
- **Instructions** are 64-bit fixed-size, RISC-like
- The **verifier** performs static analysis to prove safety
- **JIT compilation** converts eBPF bytecode to native machine code
- Programs attach to **hooks**: tracepoints, kprobes, XDP, sockets, LSM
- **Maps** are the communication channel between kernel and userspace
- **Tail calls** enable program chaining and modularity

---

## 4.11 Looking Ahead

Now that you understand the architecture, Chapter 5 dives deep into **the verifier** — the most important concept in eBPF development. Understanding the verifier will save you countless hours of debugging.

---

*Next: [Chapter 5 — The eBPF Verifier](./05-ebpf-verifier.md)*
