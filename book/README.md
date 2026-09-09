# Mastering eBPF with Rust, C, and libpf-rs

## A Complete Guide from Beginner to Advanced

---

## About This Book

This book is your comprehensive guide to understanding and mastering eBPF (Extended Berkeley Packet Filter) programming. It uniquely combines three essential technologies:

- **C** — The traditional language for eBPF development and the foundation of the eBPF ecosystem
- **Rust** — The modern systems language bringing safety and expressiveness to eBPF
- **libpf-rs** — The Rust library that makes eBPF development ergonomic and powerful

Whether you're a systems programmer looking to add eBPF to your toolkit, a Rust developer curious about kernel programming, or a C programmer wanting to modernize your eBPF workflow, this book will take you from zero to building production-grade eBPF tools.

---

## What You'll Learn

1. **Systems programming fundamentals** in C and Rust
2. **How eBPF works inside the Linux kernel** — the architecture, verifier, and execution model
3. **Writing eBPF programs in C** using libbpf
4. **Writing eBPF programs in Rust** using libpf-rs and the Aya ecosystem
5. **Building real-world tools** for observability, networking, and security
6. **Advanced patterns** — CO-RE, XDP, LSM, and production deployment

---

## Book Structure

### Part I: Foundations — The Building Blocks

| Chapter | Title | What You'll Learn |
|---------|-------|-------------------|
| 1 | [Introduction to Systems Programming](./chapters/01-introduction.md) | Why eBPF matters, the systems programming landscape, and what this book covers |
| 2 | [C Essentials for eBPF](./chapters/02-c-essentials.md) | C fundamentals tailored for eBPF development — pointers, memory, the preprocessor |
| 3 | [Rust for Systems Programmers](./chapters/03-rust-fundamentals.md) | Rust ownership, lifetimes, traits, and patterns relevant to eBPF |

### Part II: eBPF Theory — Understanding the Machine

| Chapter | Title | What You'll Learn |
|---------|-------|-------------------|
| 4 | [eBPF Architecture](./chapters/04-ebpf-architecture.md) | How eBPF works inside the kernel — VM, registers, execution model |
| 5 | [The eBPF Verifier](./chapters/05-ebpf-verifier.md) | How the verifier ensures safety — the most important concept in eBPF |
| 6 | [eBPF Maps](./chapters/06-ebpf-maps.md) | Sharing data between kernel and userspace — all map types explained |
| 7 | [eBPF Helper Functions](./chapters/07-ebpf-helpers.md) | The syscall-like interface — what helpers are available and how to use them |

### Part III: eBPF Programming with C and libbpf

| Chapter | Title | What You'll Learn |
|---------|-------|-------------------|
| 8 | [Setting Up the Environment](./chapters/08-environment-setup.md) | Toolchain, kernel headers, bpftool, and development workflow |
| 9 | [First eBPF Program: Tracepoints](./chapters/09-first-ebpf-c.md) | Writing your first eBPF program in C with libbpf |
| 10 | [Kprobes and Kretprobes](./chapters/10-kprobes.md) | Dynamic kernel tracing — hooking any kernel function |
| 11 | [XDP — Express Data Path](./chapters/11-xdp.md) | High-performance packet processing at the driver level |
| 12 | [eBPF for Observability](./chapters/12-observability-c.md) | Building monitoring tools — counters, histograms, and exporters |

### Part IV: eBPF Programming with Rust and libpf-rs

| Chapter | Title | What You'll Learn |
|---------|-------|-------------------|
| 13 | [The Rust eBPF Ecosystem](./chapters/13-rust-ecosystem.md) | Aya, libpf-rs, redbpf — understanding the landscape |
| 14 | [Writing eBPF Programs in Rust](./chapters/14-ebpf-rust-basics.md) | First Rust eBPF program — structure, compilation, loading |
| 15 | [Userspace Integration with libpf-rs](./chapters/15-libpf-rs-userspace.md) | The userspace side — loading programs, managing maps, async patterns |
| 16 | [Building a Complete Tool in Rust](./chapters/16-complete-tool-rust.md) | End-to-end: a network monitoring tool from scratch |
| 17 | [Advanced Rust Patterns](./chapters/17-advanced-rust-ebpf.md) | Async eBPF, channels, shared state, and performance optimization |

### Part V: Advanced Topics and Production

| Chapter | Title | What You'll Learn |
|---------|-------|-------------------|
| 18 | [CO-RE: Compile Once, Run Everywhere](./chapters/18-core.md) | Portable eBPF with BTF and CO-RE |
| 19 | [eBPF for Security](./chapters/19-security.md) | LSM hooks, seccomp, and security monitoring |
| 20 | [Performance Tuning](./chapters/20-performance.md) | Optimizing eBPF programs — instructions, maps, batch operations |
| 21 | [Testing and Debugging](./chapters/21-testing-debugging.md) | Unit testing, integration testing, and debugging techniques |
| 22 | [Production Deployment](./chapters/22-production.md) | Lifecycle management, privilege model, and real-world patterns |

---

## How to Use This Book

**If you're new to systems programming:** Start from Chapter 1 and work through sequentially. Each chapter builds on the previous one.

**If you know C but not Rust:** Skim Chapter 2, then focus on Chapter 3 before moving to Part IV.

**if you know Rust but not C:** Read Chapter 2 for C essentials, then proceed to Part II for eBPF theory.

**If you know eBPF but want Rust:** Jump to Part IV (Chapter 13), but read Chapter 5 (the verifier) if you haven't already.

---

## Prerequisites

- A Linux machine or VM (Ubuntu 22.04+ recommended)
- Basic command-line familiarity
- Curiosity about how things work under the hood

All code examples are available in the `examples/` directory and can be run on any modern Linux kernel (5.15+ recommended, 6.1+ ideal).

---

## Code Examples

Every chapter has accompanying code in the `examples/` directory:

```
examples/
├── 02-c-essentials/
├── 03-rust-fundamentals/
├── 09-first-ebpf-c/
├── 10-kprobes/
├── 11-xdp/
├── 14-ebpf-rust-basics/
├── 15-libpf-rs-userspace/
├── 16-complete-tool-rust/
└── ...
```

Each example includes a `Makefile` or `Cargo.toml` and instructions for building and running.

---

## Let's Begin

Ready to dive in? Start with [Chapter 1: Introduction to Systems Programming](./chapters/01-introduction.md).
