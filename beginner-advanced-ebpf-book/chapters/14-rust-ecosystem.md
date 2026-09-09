# Chapter 14: Rust eBPF Ecosystem

## What This Chapter Covers

- The Rust eBPF landscape: libbpf-rs, Aya, redbpf, and other frameworks
- Writing eBPF programs in Rust using libbpf-rs skeleton API
- Comparing Rust eBPF workflows with C/libbpf
- Memory safety, ownership, and the `unsafe` boundary
- **Why:** Rust brings memory safety and ergonomic tooling to eBPF development. While C remains the dominant language, Rust's growing eBPF ecosystem offers compelling benefits for production observability and security tools.

---

## 14.1 Rust eBPF Framework Landscape

| Framework | Base | Key Features | Maturity |
|-----------|------|--------------|----------|
| **libbpf-rs** | libbpf C library bindings | Full libbpf feature coverage, skeleton workflow, CO-RE support | High (mature) |
| **aya** | Modern Rust framework | Ergonomic API, async support, compile-time checks, BTF integration | Medium-High |
| **redbpf** | Another Rust libbpf binding | Similar to libbpf-rs, different ergonomics | Lower |
| **flamegraph-rs** | eBPF-driven profiling | Parses perf/maps output, generates flame graphs | Niche |
| **bpf-lsm-rs** | LSM security hooks | Rust bindings for LSM hook programs | Early |

### libbpf-rs vs. aya: The Tradeoff

| Aspect | libbpf-rs | Aya |
|--------|-----------|-----|
| **Coverage** | 100% of libbpf features | ~80% (growing rapidly) |
| **Ergonomics** | More verbose, C-like | More Rust idiomatic |
| **CO-RE support** | Full, via vmlinux.h | Good, built-in BTF handling |
| **Async support** | Manual (std::thread, channels) | First-class (async/await) |
| **Learning curve** | Lower (C veterans feel at home) | Moderate (Rust + eBPF concepts) |
| **Production use** | Cilium, many projects | Growing, production-ready |
| **Safety** | Unsafe FFI blocks required | Rust type system catches more |

### Why libbpf-rs was chosen for this book

The `book-2-hands-on` project uses libbpf-rs because:

1. **Complete feature coverage** — every libbpf feature is available
2. **Skeleton workflow** — same pattern as C code, easier comparison
3. **Mature and stable** — used in production (Cilium, others)
4. **CO-RE support** — same BTF-based portability as C
5. **Rust familiarity** — agents already know Rust basics

---

## 14.2 Writing eBPF Programs in Rust (libbpf-rs)

### Project structure

```
chapter-14-hello/
├── Cargo.toml
├── build.rs          # Compiles .bpf.c, generates Rust skeleton
└── src/
    ├── main.rs       # Userspace Rust code
    └── bpf/
        └── main.bpf.c  # Kernel C code (compiled to eBPF)
```

### build.rs (build script)

```rust
use std::env;
use std::path::Path;

fn main() {
    // Tell cargo to re-run if the BPF file changes
    println!("cargo:rerun-if-changed=src/bpf/main.bpf.c");
    
    // Include the BPF object generation
    // This will compile the .bpf.c and generate Rust FFI bindings
    let out_dir = env::var("OUT_DIR").unwrap();
    
    // Use libbpf-cargo to compile and generate skeleton
    // The bpf!() macro and associated types come from this
}
```

### Cargo.toml dependencies

```toml
[package]
name = "chapter-14-hello"
version = "0.1.0"
edition = "2021"

[dependencies]
libbpf = "0.6"
aya Logging and error handling

// In main.rs:
use libbpf::{Program, Map};
use std::signal::{Signal, signal};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup signal handler for Ctrl+C
    signal(Signal::INT, || {});
    signal(Signal::TERM, || {});
    
    // Load the BPF object (compiled .bfel.o)
    let prog = Program::load("target/bpfel-unknown-linux-gnu/debug/chapter-14-hello")?;
    
    // Attach using the link API (modern approach)
    // ... (see Chapter 8 for link patterns)
    
    println!("eBPF program loaded and attached!");
    
    // Keep running until signal
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    
    Ok(())
}
```

### Compiling the BPF program

The `build.rs` handles:
1. `clang -target bpf -c src/bpf/main.bpf.c -o ...` — compile C to bytecode
2. `bpftool gen skeleton ...` — generate Rust skeleton header
3. `cargo:rerun-if-changed` — rebuild on source change

### Rust skeleton generation

libbpf-cargo generates Rust code similar to the C skeleton API:

```rust
// Auto-generated from build.rs
struct XdpProg {
    prog: bpf_rs::Program,
    maps: bpf_rs::Maps,
}

impl XdpProg {
    fn open() -> Result<Self, bpf_rs::Error> {
        // Parse ELF, create maps
        Ok(Self { ... })
    }
    
    fn load(&mut self) -> Result<(), bpf_rs::Error> {
        // Verify, JIT compile, prepare for attach
        Ok(())
    }
    
    fn attach(&mut self) -> Result<(), bpf_rs::Error> {
        // Attach program to hook using link API
        Ok(())
    }
    
    fn detach(&mut self) {
        // Detach and clean up
    }
}
```

### Memory safety in Rust eBPF

Rust's role in eBPF:

| Safety aspect | C approach | Rust approach |
|--------------|-----------|---------------|
| **Map value sizes** | Manual verification | `static_assert_eq!` + compile check |
| **Pointer arithmetic** | Verifier checks + manual | `unsafe` blocks + BTF-checked |
| **Buffer overflows** | Verifier rejects | `Vec`, `ArrayString`, bounds-checked |
| **Memory leaks** | Manual `kfree()` | `Drop` traits, RAII |
| **Concurrent access** | Spinlocks, per-CPU | `Mutex`, `RwLock`, `Perfetto` patterns |

### The `unsafe` boundary

Rust eBPF programs still need `unsafe` for:

1. **FFI to C libbpf functions**: `bpf_map_lookup_elem()`, etc.
2. **Raw pointer operations**: `bpf_probe_read`, struct field access
3. **Helper calls**: `e_call` instructions

However, once behind `unsafe`, the rest of the program can be safe Rust:

```rust
unsafe {
    // FFI call - verified by libbpf
    let result = bpf_map_lookup_elem(map_fd, &key, &value, 0);
    
    // Safe Rust can use the result
    if result == 0 {
        println!("Value: {}", value);
    }
}
```

---

## 14.3 Comparing Rust vs. C eBPF Workflows

| Step | C workflow | Rust (libbpf-rs) workflow |
|------|-----------|---------------------------|
| **Write BPF code** | `.bpf.c` file | Same `.bpf.c` file (shared!) |
| **Compile BPF** | `clang -target bpf` + Makefile | `cargo build` (build.rs handles it) |
| **Generate skeleton** | `bpftool gen skeleton` + C header | `cargo build` (build.rs generates Rust) |
| **Userspace loading** | `libbpf C API` or `bpftool` | `libbpf-rs Rust API` |
| **Attach program** | `bpf_prog_attach()` | `prog.attach_kprobe()` (link API) |
| **Map access** | `skel->maps.map_name` | `skel.maps.map_name` or `Map::new()` |
| **Error handling** | `if (err) { ... }` | `?` operator, `Result` types |
| **Memory management** | Manual, risk of leaks | Rust `Drop`, RAII, fewer leaks |
| **CO-RE support** | `vmlinux.h` + libbpf middleware | Same, via libbpf-rs BTF handling |
| **Async/event loop** | `select()`, `poll()`, loops | `async/await`, `tokio`, `channels` |

### Can I share .bpf.c between C and Rust?

**Yes!** The `.bpf.c` source is language-agnostic. Both C and Rust compile it to the same eBPF bytecode. The difference is in the userspace loader:

```c
// C example (from this book's chapters)
gcc file.c -lbpf -lelf -lz -o file

// Rust example (same .bpf.c source)
cargo build  # build.rs compiles .bpf.c, generates Rust bindings
```

The only difference is the userspace API (C libbpf vs. Rust libbpf-rs), not the kernel code.

---

## 14.4 Example: Rust-based Syscall Counter

Building on the execve_counter from earlier chapters, here's the Rust version using libbpf-rs:

### Cargo.toml

```toml
[package]
name = "execve_counter"
version = "0.1.0"
edition = "2021"

[dependencies]
libbpf = "0.6"
```

### build.rs

```rust
fn main() {
    // Tell cargo to invalidate the build if any of these change
    println!("cargo:rerun-if-changed=src/bpf/execve_counter.bpf.c");
    
    // The libbpf-cargo integration will:
    // 1. Compile .bpf.c to BPF bytecode
    // 2. Generate Rust skeleton for easy loading
    // 3. Set up include paths for vmlinux.h
}
```

### src/main.rs

```rust
use libbpf::{Program, Map};
use std::signal::{Signal, signal};
use std::thread;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup signal handlers for graceful shutdown
    signal(Signal::INT, || {});  // Ctrl+C
    signal(Signal::TERM, || {}); // kill signal
    
    // Load the BPF object (compiled .bpfel-unknown-linux-gnu/debug/execve_counter)
    let mut skel = execve_counter::Skel::open()?;
    
    // Load (verify, JIT compile) the BPF program
    skel.load()?;
    
    // Attach using the link API (modern, automatic cleanup)
    // Find the tracepoint program and attach
    let link = skel.programs.tracepoint__syscalls__sys_enter_execve.attach_tracepoint()?;
    
    println!("Tracing execve calls (Ctrl+C to stop)...");
    
    // Main loop: poll ring buffer for events
    loop {
        // Poll with 100ms timeout
        if let Ok(events) = skel.maps.events.poll() {
            for event in events {
                // Event data is in the ring buffer entry
                // Access fields: event.pid, event.comm, event.count, etc.
                println!("PID={} COMM={} COUNT={}", 
                    event.pid, 
                    String::from_utf8_lossy(&event.comm),
                    event.count);
            }
        }
        
        thread::sleep(Duration::from_millis(100));
    }
}
```

### Running the Rust program

```bash
# Build (compiles .bpf.c + generates Rust skeleton + builds binary)
cargo build --release

# Run (requires root for BPF operations)
sudo ./target/release/execve_counter

# Output:
# PID=1234 COMM=bash COUNT=1
# PID=1235 COMM=ls COUNT=2
# ...
```

### Advantages of Rust version

| Advantage | Detail |
|-----------|--------|
| **No Makefile** | Single `Cargo.toml` + `build.rs` handles everything |
| **Automatic cleanup** | `Drop` traits ensure link detachment on exit |
| **Type safety** | Rust types for map keys/values, fewer bugs |
| **Async support** | `tokio` integration for non-blocking I/O |
| **Cross-compilation** | `cross` or `rustup target add` for different ARCHs |
| **Tooling** | `cargo fmt`, `clippy`, IDE integration |
| **Same .bpf.c** | Share kernel code between C and Rust projects |

---

## 14.5 When to Choose Rust vs. C

| Choose Rust when... | Choose C when... |
|--------------------|-------------------|
| Building long-lived observability tools | Quick prototype / learning eBPF |
| Value memory safety (no leaks) | Want minimal cognitive overhead |
| Using async/await patterns | Prefer simple while loops |
| Integrating with Rust ecosystem (tokio, async-std) | Need maximum libbpf feature coverage |
| Production deployment where reliability matters | Working within existing C codebase |
| Writing tools in organizations already using Rust | Starting eBPF from scratch |

### Adoption path

Many teams start with C (lower learning curve) and migrate critical tools to Rust as they gain expertise. The shared `.bpf.c` source makes migration painless.

---

## 14.6 Summary

| Aspect | C (libbpf) | Rust (libbpf-rs/aya) |
|--------|-----------|----------------------|
| **Language** | C | Rust |
| **Build system** | Makefile + clang | Cargo + build.rs |
| **Skeleton API** | C structs + functions | Rust structs + methods |
| **Attachment** | `bpf_program__attach_*` | Same (link API) + `prog.attach_*` methods |
| **Memory safety** | Manual, risk of leaks | Rust ownership + Drop |
| **Async support** | Manual threading | First-class async/await |
| **CO-RE support** | Via vmlinux.h + libbpf | Same, often more ergonomic |
| **Learning curve** | Lower (C basics) | Moderate (Rust + eBPF) |
| **Production maturity** | High (Cilium, many) | Growing (ay a, redbpf) |
| **Same BPF bytecode** | Yes | Yes (shared .bpf.c) |

---

## 14.7 Looking Ahead

Chapter 15 covers **Advanced Topics** — CO-RE in depth, performance tuning final patterns, testing and debugging eBPF programs, and production deployment lifecycle management. You'll consolidate all the knowledge from this book into production-ready tool building.

*Next: [Chapter 15 — Advanced Topics and Production Deployment](./15-advanced.md)*