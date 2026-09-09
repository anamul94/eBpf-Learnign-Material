# Comprehensive eBPF Learning Book
## From Beginner to Advanced Systems Programming

![eBPF Overview](images/ebpf-overview.svg)

---

## About This Book

This is a **complete, project-based learning resource** for eBPF (Extended Berkeley Packet Filter) programming, taking you from foundational Linux systems concepts through to building production-grade eBPF tools.

**Philosophy:** Learn eBPF by understanding how Linux works underneath, then safely instrumenting it. Each chapter balances theory with hands-on code you can build and run.

**What this book covers:**
- Linux systems programming fundamentals (processes, memory, filesystem, system calls)
- eBPF architecture, verifier, and execution model
- Writing eBPF programs in C using **libbpf** (the standard, no-AYA approach)
- Rust integration with **libbpf-rs** (modern, safe systems programming)
- Building 12+ complete, running projects from simple tracers to XDP firewalls
- Advanced topics: CO-RE, LSM hooks, performance tuning, production deployment

**Prerequisites:**
- Linux machine or VM (Ubuntu 22.04+, kernel 5.8+ with BTF)
- Rust installed via `rustup`
- `clang`, `libbpf-dev`, `bpftool`
- Basic command-line familiarity

**Book structure:** 24 chapters across 4 phases, each with:
- Clear learning objectives
- Complete, annotated code examples
- "Build and run" instructions
- Concept deep-dives ("Why are we using what?")
- Exercises and extensions

---

## Phase Overview

| Phase | Title | Focus | Chapters |
|-------|-------|-------|----------|
| **1** | Linux Systems Programming Fundamentals | How Linux works: processes, memory, filesystem, syscalls | 1-6 |
| **2** | eBPF Fundamentals | eBPF architecture, verifier, maps, program types, attachment | 7-12 |
| **3** | eBPF Programming with C & libbpf | Writing practical eBPF programs, skeleton API, maps, helpers | 13-18 |
| **4** | Advanced Topics & Projects | XDP, LSM, CO-RE, performance, Rust integration, production | 19-24 |

---

## How to Use This Book

### If you're new to systems programming:
> Start from Chapter 1 and work **sequentially**. Each chapter builds on the previous one. Don't skip Phase 1 — you'll need the Linux fundamentals to understand eBPF.

### If you know C but not Linux internals:
> Read Chapters 1-3 quickly, then dive into Phase 2 (eBPF fundamentals). Use Chapters 4-6 as reference when you encounter unfamiliar concepts.

### If you know Linux but not eBPF:
> Start from Chapter 7. The first few chapters will bring you up to speed on eBPF-specific concepts, then move to hands-on programming.

### If you know eBPF but want Rust:
> Phase 1 is still valuable for kernel context. Phase 3 (chapters 13-18) covers libbpf-rs patterns. Phase 4 (chapters 19-24) shows Rust-specific advanced topics.

### General rules for each chapter:
1. **Read** the chapter introduction and learning objectives
2. **Study** the complete, annotated code example
3. **Build** and run the example (follow the instructions)
4. **Modify** it to trace/something different (the exercises)
5. **Explain** why it works (what kernel structures/maps are involved)
6. **Document** your findings

---

## Quick Start — First Program

If you want to jump straight in, here's the minimal workflow:

```bash
# 1. Install dependencies
sudo apt install clang libbpf-dev linux-tools-common bpftool
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# Verify BTF
ls /sys/kernel/btf/vmlinux

# 2. Build and run "Hello Kernel" (Chapter 1)
# Follow the chapter instructions

# 3. Explore the ecosystem
sudo bpftool prog show      # List loaded programs
sudo bpftool map show       # List maps
sudo cat /sys/kernel/debug/tracing/trace_pipe  # Kernel trace output
```

---

## Book Conventions

### Code blocks
Code examples are complete and annotated. Key lines are explained inline.

```c
// This is a typical eBPF map definition
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} my_map SEC(".maps");
```

### Terminal outputs
```bash
$ make
clang ... ok
$ sudo ./my_ebpf_tool
Tracing syscalls... Press Ctrl+C to stop.
```

### "Why are we using what?" sidebars
Each chapter includes sidebars explaining the rationale behind choices (e.g., why use BPF_MAP_TYPE_HASH vs ARRAY, why libbpf-rs over raw FFI, why kprobes over tracepoints).

### Exercises
Each chapter has "Try it yourself" exercises to reinforce learning. Solutions are not provided — the best way to learn eBPF is to break things and fix them.

---

## Additional Resources

- **Kernel source:** `/usr/src/linux/` or download from kernel.org
- **libbpf source:** https://github.com/libbpf/libbpf
- **eBPF tools:** `bpftrace`, `bcc`, `bpfcc-tools`
- **Rust eBPF:** `libbpf-rs`, `aya` (ecosystem reference, not primary focus)
- **Community:** [r/eBPF](https://reddit.com/r/eBPF), [BPF Discord](https://bpf.rocks)

---

## License

This book is free to read and distribute. Code examples are provided under MIT license unless otherwise noted.

*Happy tracing!*

---