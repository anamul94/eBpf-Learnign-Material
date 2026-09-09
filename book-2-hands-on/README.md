# Hands-On eBPF with libbpf-rs

## Learn by Building Real Tools

---

## About This Book

This is a **practical, project-based** book. You learn eBPF by building real tools, not by studying theory.

**What makes this different:**
- Each chapter = one complete project
- Uses **libbpf-rs** (Rust bindings for libbpf)
- Explains **why** we do things, not just how
- Minimal theory, maximum hands-on
- Code you can actually run

**Why libbpf-rs?**
- It's the official Rust wrapper around libbpf (the standard C library)
- Uses the skeleton workflow - less boilerplate
- CO-RE support out of the box
- What most production Rust eBPF tools use

---

## What You'll Build

| Chapter | Project | What You Learn |
|---------|---------|----------------|
| 1 | Hello Kernel | First program, tracepoints, loading |
| 2 | Syscall Counter | Maps, kernel-userspace communication |
| 3 | Process Tracker | Hash maps, ring buffers, events |
| 4 | File Monitor | Kprobes, reading kernel memory |
| 5 | XDP Firewall | Packet parsing, high-speed filtering |
| 6 | Network Monitor | Multiple programs, async processing |
| 7 | Latency Histogram | Measuring distributions, not averages |
| 8 | CPU Profiler | Stack traces, sampling, symbols |
| 9 | Security Monitor | LSM hooks, enforcing policies |
| 10 | Production Tool | Deployment, metrics, operations |

---

## How to Use This Book

**Read sequentially.** Each chapter builds on the previous one.

For each chapter:
1. Read what we're building and why
2. Study the code (every line is explained)
3. Build and run it yourself
4. Do the "Try it yourself" exercises

---

## Prerequisites

- Linux machine or VM (Ubuntu 22.04+ recommended)
- Rust installed (via rustup)
- clang, libbpf-dev, bpftool
- Kernel 5.8+ with BTF support

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt install clang libbpf-dev linux-tools-$(uname -r) bpftool

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Verify BTF is available
ls /sys/kernel/btf/vmlinux
```

---

## Project Structure

Each chapter follows the libbpf-rs skeleton pattern:

```
chapter-xx-name/
├── Cargo.toml          # Dependencies
├── build.rs            # Builds BPF, generates skeleton
├── src/
│   ├── main.rs         # Userspace code (Rust)
│   └── bpf/
│       └── xxx.bpf.c   # Kernel code (C)
```

The `build.rs` uses `libbpf-cargo` to:
1. Compile `.bpf.c` to BPF bytecode
2. Generate a Rust skeleton for easy loading

---

## Let's Begin

Ready to write your first eBPF program? Start with [Chapter 1: Hello Kernel](./chapters/01-hello-kernel.md)
