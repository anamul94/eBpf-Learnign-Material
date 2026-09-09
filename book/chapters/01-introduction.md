# Chapter 1: Introduction to Systems Programming and eBPF

## What This Chapter Covers

- Why systems programming matters in the modern world
- The evolution of kernel programmability
- What eBPF is and why it's revolutionary
- How C, Rust, and libpf-rs fit together
- What we'll build throughout this book

---

## 1.1 Why Systems Programming?

When you write a web application in Python or JavaScript, you're standing on layers upon layers of abstraction. Your code runs in a runtime, on top of a framework, on top of an operating system, on top of hardware. This is great for productivity — but when something goes wrong, or when you need to understand *why* your application behaves a certain way, those layers become walls.

Systems programming is about working close to the metal. It's about understanding:

- **Memory** — where your data lives, how it's laid out, who owns it
- **CPU** — how instructions execute, how the kernel schedules work
- **Hardware** — how devices communicate, how data flows through the system
- **The kernel** — the operating system core that manages everything

Systems programmers build the foundations that everyone else relies on: operating systems, databases, web servers, network stacks, and — increasingly — observability and security tools.

### The Traditional Problem

For decades, if you wanted to extend the kernel's behavior, you had two options:

1. **Write a kernel module** — Load your code directly into the kernel. Powerful, but dangerous. A bug crashes the entire system. Development is slow, debugging is painful, and distributing modules across different kernel versions is a nightmare.

2. **Use kernel facilities** — Work with what the kernel gives you: `iptables`, `strace`, `perf`, etc. Safe, but limited. You can only observe or modify what the kernel developers anticipated you'd need.

Both approaches have a fundamental problem: **the kernel is a shared resource that must be stable and secure**. Letting arbitrary code run in it is inherently risky.

---

## 1.2 Enter eBPF — Safe Kernel Programmability

eBPF (Extended Berkeley Packet Filter) changes the equation entirely. It lets you run custom code inside the Linux kernel **safely**, **dynamically**, and **without recompiling the kernel or loading modules**.

### A Brief History

The story begins in 1992, with the original BPF (Berkeley Packet Filter), created by Steven McCanne and Van Jacobson at Berkeley. The idea was elegant: instead of copying all packet data to userspace and filtering there, run a small program *inside the kernel* that decides which packets to keep. This made tools like `tcpdump` dramatically faster.

For 25 years, BPF remained a niche networking tool. Then, starting around 2014, Alexei Starovoitov and others at Facebook began extending it dramatically:

- **2014**: eBPF introduced in Linux 3.18 — new registers, new instructions, maps
- **2015**: eBPF attached to kprobes for tracing
- **2016**: XDP (eXpress Data Path) for high-speed networking
- **2017**: eBPF becomes a separate subsystem, BTF introduced
- **2018**: CO-RE (Compile Once, Run Everywhere) with BTF
- **2019+**: eBPF explodes — used by Cilium, Falco, Pixie, and hundreds of tools
- **2021+**: Rust eBPF ecosystem matures with Aya and libpf-rs

Today, eBPF is one of the fastest-growing areas in Linux. It's used by every major cloud company and powers critical infrastructure worldwide.

### What Makes eBPF Special?

eBPF isn't just "code in the kernel." It has three properties that make it unique:

**1. Safety Through the Verifier**

Before any eBPF program runs, the kernel's *verifier* analyzes it. The verifier checks:
- No infinite loops (or bounded loops only)
- No out-of-bounds memory access
- No uninitialized memory reads
- No invalid pointer arithmetic
- Program size and complexity limits

If the program passes verification, the kernel **guarantees** it won't crash, hang, or corrupt memory. This is a mathematical proof, not a best-effort check.

**2. JIT Compilation**

Once verified, eBPF programs are compiled to native machine code using a JIT (Just-In-Time) compiler. Your eBPF program runs at near-native speed — there's no interpretation overhead.

**3. Dynamic Attachment**

eBPF programs can be loaded and unloaded at runtime, without restarting the system or affecting running applications. You can attach to kernel functions, tracepoints, network hooks, and security points — all while the system is live.

---

## 1.3 The eBPF Ecosystem Landscape

Before we dive into code, let's understand the landscape. eBPF development involves two sides:

### Kernel-Side (the eBPF program)

This is the code that runs inside the kernel. It's written in a restricted subset of C (or Rust, compiled to the same eBPF bytecode). It's small, fast, and constrained by the verifier.

### Userspace-Side (the loader/controller)

This is the code that loads the eBPF program into the kernel, manages its lifecycle, reads data from maps, and handles events. It can be written in any language — C, Rust, Go, Python.

### The Languages

| Language | Role | Libraries |
|----------|------|-----------|
| **C** | Traditional eBPF development | libbpf, BCC |
| **Rust** | Modern eBPF development | Aya, libpf-rs, redbpf |
| **Go** | Userspace loading | cilium/ebpf, gobpf |
| **Python** | Prototyping, scripting | BCC |
| **C++** | Rarely used | libbpf (C API) |

In this book, we focus on **C for understanding the foundations** and **Rust with libpf-rs for modern development**.

---

## 1.4 Why C, Why Rust?

### C — The Foundation

C is the lingua franca of systems programming. The Linux kernel is written in C. libbpf (the standard eBPF library) is written in C. Every eBPF tutorial, every kernel example, every production tool — they all start with C.

Learning C for eBPF gives you:
- Understanding of how eBPF maps to hardware concepts
- Ability to read kernel code and existing tools
- Foundation for understanding what Rust is abstracting away

But C has problems: manual memory management, no type safety, buffer overflows, use-after-free bugs. In kernel programming, these aren't just security issues — they're verifier rejections or worse, kernel panics.

### Rust — The Modern Alternative

Rust gives you systems-level control with memory safety guarantees. For eBPF specifically:

- **Ownership model** maps naturally to eBPF's resource management (file descriptors, map handles)
- **Type system** catches errors at compile time that the verifier would catch at load time
- **Zero-cost abstractions** mean you pay nothing for safety
- **Async/await** makes userspace event handling ergonomic
- **Cargo** provides a modern build system and dependency management

The Rust eBPF ecosystem, particularly **Aya** and **libpf-rs**, brings these benefits to eBPF development without sacrificing power.

### libpf-rs — The Bridge

libpf-rs (also known as `pf-rs` or part of the Aya ecosystem) is a Rust library specifically designed for eBPF development. It provides:

- Type-safe bindings to libbpf functionality
- Ergonomic map access
- Async support for event streaming
- Integration with the Rust eBPF toolchain

We'll use libpf-rs as our primary Rust library throughout Part IV and beyond.

---

## 1.5 What We'll Build

Throughout this book, we'll build progressively more complex eBPF tools. Here's a preview:

### Beginner Projects
- **Hello eBPF** — A minimal program that prints "Hello, World!" from kernel space
- **Syscall Counter** — Count how many times a specific syscall is called
- **Process Tracer** — Log process executions in real-time

### Intermediate Projects
- **Network Monitor** — Track TCP connections and bandwidth per process
- **Latency Histogram** — Measure block I/O latency and display as a histogram
- **File Access Auditor** — Watch which files are opened by specific processes

### Advanced Projects
- **XDP Firewall** — High-performance packet filtering at the driver level
- **LSM Security Module** — Enforce security policies using eBPF LSM hooks
- **Full Observability Stack** — A complete tool that combines multiple eBPF program types with a Rust async runtime

---

## 1.6 How eBPF Programs Work — The Big Picture

Before we write any code, let's understand the complete lifecycle of an eBPF program:

```
┌─────────────────────────────────────────────────────────────┐
│                    DEVELOPMENT TIME                         │
│                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │  Write eBPF  │───▶│  Compile to  │───▶│   Generate   │  │
│  │  Source (C/  │    │  eBPF Byte-  │    │   ELF Object │  │
│  │  Rust)       │    │  code        │    │   File       │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    LOAD TIME                                │
│                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │  Userspace   │───▶│  Kernel      │───▶│  Verifier    │  │
│  │  Loader      │    │  Receives    │    │  Checks      │  │
│  │  (libbpf/    │    │  Program     │    │  Safety      │  │
│  │  libpf-rs)   │    │              │    │              │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│                                                 │           │
│                                                 ▼           │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │  Program     │◀───│  JIT Compile │◀───│  Verified    │  │
│  │  Attached    │    │  to Native   │    │  Successfully│  │
│  │  to Hook     │    │  Code        │    │              │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    RUNTIME                                  │
│                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │  Kernel      │───▶│  eBPF        │───▶│  eBPF Writes │  │
│  │  Event       │    │  Program     │    │  to Maps /   │  │
│  │  Triggers    │    │  Executes    │    │  Ring Buffer │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│                                                 │           │
│                                                 ▼           │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │  Userspace   │◀───│  Read from   │◀───│  Data in     │  │
│  │  Processes   │    │  Maps/Ring   │    │  Kernel      │  │
│  │  Data        │    │  Buffer      │    │              │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

This flow is the same whether you write in C or Rust. The difference is in the tooling and ergonomics.

---

## 1.7 Key Concepts You'll Master

Here's a preview of the core concepts we'll explore in depth:

### eBPF Programs
Small functions that run in kernel context. They're event-driven — they execute when something happens (a function is called, a packet arrives, a syscall is made).

### eBPF Maps
Key-value stores shared between kernel and userspace, or between different eBPF programs. They're the primary communication channel.

### Hooks
The attachment points where eBPF programs connect to kernel events: tracepoints, kprobes, XDP, socket filters, LSM hooks, and more.

### Helper Functions
A curated set of functions that eBPF programs can call: `bpf_map_lookup_elem`, `bpf_probe_read`, `bpf_trace_printk`, `bpf_ktime_get_ns`, and 200+ more.

### BTF (BPF Type Format)
Type information embedded in the kernel and eBPF programs that enables CO-RE — the ability to compile an eBPF program once and run it on different kernel versions.

### Verifier
The kernel component that statically analyzes eBPF programs for safety. Understanding the verifier is the single most important skill in eBPF development.

---

## 1.8 Setting Expectations

eBPF has a steep learning curve. Here's why:

1. **You're programming the kernel** — Different rules, different constraints, different debugging
2. **The verifier is strict** — It rejects programs that *look* safe but can't be proven safe
3. **Documentation is scattered** — The kernel source is the ultimate reference
4. **Tooling is evolving** — The ecosystem moves fast

But here's the good news:

- **You don't need to be a kernel expert** — eBPF abstracts away most kernel complexity
- **The verifier teaches you** — Its error messages guide you toward correct code
- **The community is active** — Mailing lists, Discord, and GitHub are full of helpful people
- **Rust makes it easier** — The type system catches many issues before the verifier does

By the end of this book, you'll be comfortable reading verifier errors, understanding eBPF architecture, and building real tools.

---

## 1.9 Summary

- **Systems programming** is about working close to the hardware and kernel
- **eBPF** lets you run safe, dynamic code inside the Linux kernel
- **C** is the traditional language for eBPF; **Rust** is the modern alternative
- **libpf-rs** brings Rust's safety and ergonomics to eBPF development
- eBPF programs go through: **compile → load → verify → JIT → attach → run**
- The **verifier** is the most important concept — it guarantees safety

---

## 1.10 Looking Ahead

In the next chapter, we'll dive into **C essentials for eBPF**. Even if you know some C, eBPF uses a specific subset with unique constraints. We'll cover exactly what you need — nothing more, nothing less.

If you're already comfortable with C pointers, structs, and the preprocessor, you can skim Chapter 2 and jump to Chapter 3 (Rust fundamentals). But I recommend at least reading the sections on eBPF-specific C constraints — they'll save you hours of debugging later.

---

*Next: [Chapter 2 — C Essentials for eBPF](./02-c-essentials.md)*
