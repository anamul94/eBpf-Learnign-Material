# Chapter 13: The Rust eBPF Ecosystem

## What This Chapter Covers

- Overview of Rust eBPF libraries
- Aya — the primary Rust eBPF framework
- libpf-rs — Rust bindings for libbpf
- redbpf — an alternative approach
- Cargo-based eBPF development
- Toolchain setup for Rust eBPF
- Choosing the right library

---

## 13.1 The Rust eBPF Landscape

```
┌─────────────────────────────────────────────────────────────┐
│                 RUST eBPF ECOSYSTEM                         │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                    Aya                               │   │
│  │  - Pure Rust eBPF toolchain                          │   │
│  │  - No C dependencies for eBPF compilation            │   │
│  │  - Userspace library for loading/managing            │   │
│  │  - Most active, most feature-complete                │   │
│  └─────────────────────────────────────────────────────┘   │
│                            │                                │
│                            ▼                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                  libpf-rs                             │   │
│  │  - Rust bindings for libbpf (C library)              │   │
│  │  - Uses libbpf for loading, verification             │   │
│  │  - Familiar to C eBPF developers                     │   │
│  │  - Good for existing libbpf projects                 │   │
│  └─────────────────────────────────────────────────────┘   │
│                            │                                │
│                            ▼                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                  redbpf                              │   │
│  │  - Older Rust eBPF library                           │   │
│  │  - Compile-time code generation                      │   │
│  │  - Less active development                           │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 13.2 Aya — Pure Rust eBPF

Aya is the most popular Rust eBPF library. It provides:

1. **aya-bpf** — eBPF program macros and helpers (kernel side)
2. **aya** — Userspace library for loading and managing eBPF programs
3. **aya-tool** — Code generation for types shared between kernel and userspace

### 13.2.1 Aya Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    AYA ARCHITECTURE                         │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  eBPF Program (Rust)                                │   │
│  │  - Uses aya-bpf macros                              │   │
│  │  - Compiled to eBPF bytecode via rustc (bpf target) │   │
│  │  - No C dependencies                                │   │
│  └─────────────────────────────────────────────────────┘   │
│                            │                                │
│                            ▼                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Userspace Loader (Rust)                            │   │
│  │  - Uses aya library                                 │   │
│  │  - Loads programs via bpf() syscall                 │   │
│  │  - Manages maps, programs, links                    │   │
│  │  - Async support (tokio)                            │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 13.2.2 Aya eBPF Program Example

```rust
// ebpf/src/main.rs
use aya_bpf::{
    macros::{map, tracepoint},
    programs::TracePointContext,
    maps::PerfEventArray,
    bindings::pt_regs,
};

#[map]
static EVENTS: PerfEventArray<ProcessEvent> = PerfEventArray::with_max_entries(1024, 0);

#[tracepoint]
pub fn sys_enter_execve(ctx: TracePointContext) -> u32 {
    let event = ProcessEvent {
        pid: bpf_get_current_pid_tgid() >> 32,
        ..Default::default()
    };
    EVENTS.output(&ctx, &event, 0);
    0
}
```

### 13.2.3 Aya Userspace Example

```rust
// src/main.rs
use aya::{
    Bpf,
    programs::{TracePoint, traced},
    maps::perf::AsyncPerfEventArray,
};
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // Load the eBPF program
    let mut bpf = Bpf::load(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/target/bpfel-unknown-none/release/myapp"
    )))?;

    // Get the program
    let program: &mut TracePoint = bpf.program_mut("sys_enter_execve")
        .unwrap()
        .try_into()?;

    // Attach to tracepoint
    program.load()?;
    program.attach("syscalls", "sys_enter_execve")?;

    // Set up perf event array
    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS")?)?;

    // Process events
    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;
        tokio::spawn(async move {
            let mut events = [ProcessEvent::default(); 100];
            while let Ok(events) = buf.read_events(&mut events).await {
                for event in events.iter().take(events) {
                    println!("PID: {}", event.pid);
                }
            }
        });
    }

    signal::ctrl_c().await?;
    Ok(())
}
```

---

## 13.3 libpf-rs — Rust Bindings for libbpf

libpf-rs provides Rust bindings to the C libbpf library. It's ideal when:

- You have existing C eBPF programs you want to load from Rust
- You want to use libbpf's mature loading/verification
- You need features not yet in pure Rust implementations

### 13.3.1 libpf-rs Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  libpf-rs ARCHITECTURE                      │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  eBPF Program (C or Rust)                           │   │
│  │  - Compiled with clang to eBPF bytecode             │   │
│  │  - Standard ELF with BTF                            │   │
│  └─────────────────────────────────────────────────────┘   │
│                            │                                │
│                            ▼                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Userspace Loader (Rust)                            │   │
│  │  - Uses libpf-rs (Rust bindings for libbpf)         │   │
│  │  - Calls libbpf C functions via FFI                 │   │
│  │  - Type-safe wrappers around libbpf API             │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 13.3.2 libpf-rs Example

```rust
// Cargo.toml
// [dependencies]
// libpf-rs = "0.1"  # or latest version
// libbpf-sys = "1"  # FFI bindings

use libpf_rs::{Object, Program, Map};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Open the BPF object file
    let obj = Object::open_file("execve_counter.bpf.o")?;

    // Load into kernel
    obj.load()?;

    // Get a program
    let prog = obj.program("tracepoint__syscalls__sys_enter_execve")
        .ok_or("Program not found")?;

    // Attach to tracepoint
    prog.attach_tracepoint("syscalls", "sys_enter_execve")?;

    // Get a map
    let map = obj.map("execve_count").ok_or("Map not found")?;

    // Read map value
    let key: u32 = 0;
    let value: u64 = map.lookup(&key)?.unwrap_or(0);
    println!("Execve count: {}", value);

    Ok(())
}
```

---

## 13.4 Comparison: Aya vs libpf-rs

| Feature | Aya | libpf-rs |
|---------|-----|----------|
| eBPF compilation | Pure Rust (no clang) | Requires clang |
| Userspace library | Pure Rust | FFI to libbpf C |
| Map types | Typed, compile-time checked | Runtime access |
| Async support | Built-in (tokio) | Manual |
| CO-RE support | Yes (aya-tool) | Yes (via libbpf) |
| Maturity | Active, growing | Stable (wraps libbpf) |
| Learning curve | Moderate | Lower (if you know libbpf) |
| Use case | New projects | Existing C programs |

---

## 13.5 Setting Up Rust eBPF Toolchain

### 13.5.1 Install Rust

```bash
# Install rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Add BPF target
rustup target add bpfel-unknown-none
rustup target add bpfeb-unknown-none  # For big-endian
```

### 13.5.2 Install Required Tools

```bash
# For Aya (pure Rust)
cargo install aya-tool

# For libpf-rs (needs libbpf)
sudo apt install libbpf-dev
```

### 13.5.3 Project Structure (Aya)

```
my-ebpf-tool/
├── Cargo.toml              # Workspace manifest
├── ebpf/                   # eBPF program
│   ├── Cargo.toml
│   └── src/
│       └── main.rs
├── ebpf-common/            # Shared types
│   ├── Cargo.toml
│   └── src/
│       └── lib.rs
└── userspace/              # Userspace loader
    ├── Cargo.toml
    └── src/
        └── main.rs
```

### 13.5.4 Cargo.toml (Workspace)

```toml
# Cargo.toml (root)
[workspace]
members = ["ebpf", "ebpf-common", "userspace"]

[workspace.package]
edition = "2021"
```

```toml
# ebpf/Cargo.toml
[package]
name = "my-ebpf-tool-ebpf"
version.workspace = true
edition.workspace = true

[dependencies]
aya-bpf = { git = "https://github.com/aya-rs/aya" }
aya-log-ebpf = { git = "https://github.com/aya-rs/aya" }

[[bin]]
name = "my-ebpf-tool-ebpf"
path = "src/main.rs"

[profile.dev]
opt-level = 3
debug = false
debug-assertions = false
overflow-checks = false
lto = true
panic = "abort"
incremental = false
codegen-units = 1
rpath = false

[profile.release]
lto = true
panic = "abort"
codegen-units = 1
```

```toml
# userspace/Cargo.toml
[package]
name = "my-ebpf-tool"
version.workspace = true
edition.workspace = true

[dependencies]
aya = { git = "https://github.com/aya-rs/aya", features = ["async_tokio"] }
aya-log = { git = "https://github.com/aya-rs/aya" }
tokio = { version = "1", features = ["full"] }
anyhow = "1"
```

---

## 13.6 Building and Running

### 13.6.1 Build eBPF Program

```bash
# Build eBPF program
cd ebpf
cargo build --target bpfel-unknown-none --release

# Output: target/bpfel-unknown-none/release/my-ebpf-tool-ebpf
```

### 13.6.2 Build Userspace

```bash
# Build userspace (includes eBPF binary)
cd userspace
cargo build --release

# Output: target/release/my-ebpf-tool
```

### 13.6.3 Run

```bash
# Run (requires root)
sudo ./target/release/my-ebpf-tool
```

---

## 13.7 Shared Types with aya-tool

```rust
// ebpf-common/src/lib.rs
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ProcessEvent {
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; 16],
    pub timestamp: u64,
}

// Ensure consistent layout
#[cfg(feature = "user")]
unsafe impl aya::Pod for ProcessEvent {}
```

Generate C headers (optional):
```bash
aya-tool generate process_event > process_event.h
```

---

## 13.8 Summary

- **Aya** is the primary Rust eBPF framework (pure Rust)
- **libpf-rs** provides Rust bindings for libbpf (FFI to C)
- **redbpf** is an older alternative
- Aya uses `aya-bpf` for kernel side, `aya` for userspace
- Shared types use `#[repr(C)]` and `aya-tool`
- Build with `cargo build --target bpfel-unknown-none`

---

## 13.9 Looking Ahead

Chapter 14 covers **writing eBPF programs in Rust** — the actual code patterns and macros you'll use.

---

*Next: [Chapter 14 — Writing eBPF Programs in Rust](./14-ebpf-rust-basics.md)*
