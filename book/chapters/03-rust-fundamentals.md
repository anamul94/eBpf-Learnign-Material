# Chapter 3: Rust for Systems Programmers

## What This Chapter Covers

- Rust ownership, borrowing, and lifetimes — the core concepts
- Traits and generics for zero-cost abstractions
- Error handling patterns
- Unsafe Rust — when and why we need it
- Async Rust for userspace eBPF tooling
- How Rust maps to eBPF concepts

---

## 3.1 Why Rust for eBPF?

Rust brings unique advantages to eBPF development:

1. **Memory safety without garbage collection** — Critical for systems code
2. **Type system catches eBPF errors early** — Many verifier rejections become compile errors
3. **Zero-cost abstractions** — Pay only for what you use
4. **Fearless concurrency** — Safe multi-threaded userspace code
5. **Modern tooling** — Cargo, clippy, rustfmt, and excellent IDE support

The Rust eBPF ecosystem (Aya, libpf-rs) leverages these strengths to make eBPF development safer and more productive.

---

## 3.2 Ownership — The Foundation

Rust's ownership system is its defining feature. It enforces three rules:

1. Every value has exactly one **owner**
2. When the owner goes out of scope, the value is **dropped**
3. You can have **one mutable reference** OR **any number of immutable references** (not both)

### 3.2.1 Basic Ownership

```rust
fn main() {
    let s1 = String::from("hello");  // s1 owns the string
    let s2 = s1;                      // s2 now owns it; s1 is invalid

    // println!("{}", s1);            // COMPILE ERROR: s1 was moved
    println!("{}", s2);               // OK: s2 is the owner
}   // s2 goes out of scope, memory is freed
```

**Why this matters for eBPF:** eBPF resources (map handles, program file descriptors) have similar ownership semantics. When you close a map handle, it's gone. Rust's ownership model makes this explicit.

### 3.2.2 Borrowing

Instead of transferring ownership, you can **borrow**:

```rust
fn print_length(s: &String) {  // Borrow: &String is a reference
    println!("Length: {}", s.len());
}   // s goes out of scope, but the String isn't dropped (we don't own it)

fn main() {
    let s = String::from("hello");
    print_length(&s);  // Borrow s
    println!("{}", s); // OK: s is still valid
}
```

### 3.2.3 Mutable Borrowing

```rust
fn append_world(s: &mut String) {  // Mutable borrow
    s.push_str(" world");
}

fn main() {
    let mut s = String::from("hello");
    append_world(&mut s);           // Mutable borrow
    println!("{}", s);              // Prints "hello world"
}
```

**The borrow checker prevents data races:** You can't have a mutable reference while any other reference exists.

---

## 3.3 Lifetimes — Teaching the Compiler About References

Lifetimes ensure references are always valid. The compiler infers most lifetimes, but sometimes you need to annotate them:

```rust
// The compiler can't figure out which input lifetime the output references
fn longest<'a>(x: &'a str, y: &'a str) -> &'a str {
    if x.len() > y.len() { x } else { y }
}

fn main() {
    let s1 = String::from("long string");
    let result;
    {
        let s2 = String::from("xyz");
        result = longest(&s1, &s2);  // result's lifetime is tied to s2's
    }
    // println!("{}", result);  // ERROR: result might reference dropped s2
}
```

**For eBPF:** Lifetimes matter when you're passing references to kernel data. The Rust eBPF libraries use lifetimes to ensure you don't use kernel data after the program has returned.

---

## 3.4 Structs and Traits — Building Abstractions

### 3.4.1 Structs

```rust
#[derive(Debug)]
struct ProcessEvent {
    pid: u32,
    uid: u32,
    comm: [u8; 16],
    timestamp: u64,
}

impl ProcessEvent {
    fn new(pid: u32, uid: u32) -> Self {
        ProcessEvent {
            pid,
            uid,
            comm: [0u8; 16],
            timestamp: 0,
        }
    }
}
```

### 3.4.2 Traits — Rust's Interfaces

```rust
trait Printable {
    fn format(&self) -> String;
}

impl Printable for ProcessEvent {
    fn format(&self) -> String {
        let comm_str = String::from_utf8_lossy(&self.comm);
        format!("[{}] pid={} uid={}", self.timestamp, self.pid, self.uid)
    }
}
```

**For eBPF:** Traits are used extensively in libpf-rs for map access, program types, and async streams. They provide zero-cost polymorphism — no runtime overhead.

---

## 3.5 Enums and Pattern Matching

Rust enums are powerful — they can carry data:

```rust
#[derive(Debug)]
enum Event {
    ProcessExec { pid: u32, comm: String },
    NetworkConnect { src: String, dst: String, port: u16 },
    FileOpen { pid: u32, path: String },
}

fn handle_event(event: Event) {
    match event {
        Event::ProcessExec { pid, comm } => {
            println!("Process {} ({}) executed", pid, comm);
        }
        Event::NetworkConnect { src, dst, port } => {
            println!("Connection from {} to {}:{}", src, dst, port);
        }
        Event::FileOpen { pid, path } => {
            println!("Process {} opened {}", pid, path);
        }
    }
}
```

**For eBPF:** Enums are perfect for representing different event types from different eBPF programs. Pattern matching ensures you handle every case.

---

## 3.6 Error Handling — Result and Option

Rust doesn't have exceptions. Instead, it uses `Result` and `Option`:

```rust
// Option: A value that might be None
fn find_process(pid: u32) -> Option<Process> {
    if pid_exists(pid) {
        Some(Process::new(pid))
    } else {
        None
    }
}

// Result: A value or an error
fn load_program(path: &str) -> Result<Program, BpfError> {
    let file = File::open(path)?;  // ? propagates errors
    let program = parse(file)?;
    Ok(program)
}

// Using them:
fn main() {
    // Option with pattern matching
    match find_process(1234) {
        Some(process) => println!("Found: {:?}", process),
        None => println!("Process not found"),
    }

    // Result with the ? operator
    match load_program("program.o") {
        Ok(prog) => println!("Loaded: {:?}", prog),
        Err(e) => eprintln!("Failed: {}", e),
    }
}
```

**For eBPF:** `bpf_map_lookup_elem` returns a pointer that might be NULL. In Rust, this becomes `Option<&T>`, forcing you to handle the NULL case at compile time.

---

## 3.7 Generics — Type-Safe Reuse

```rust
// Generic map wrapper
struct BpfMap<K, V> {
    fd: RawFd,
    _phantom: PhantomData<(K, V)>,
}

impl<K: Copy, V: Copy> BpfMap<K, V> {
    fn lookup(&self, key: &K) -> Option<V> {
        // ... BPF map lookup
        Some(value)
    }

    fn update(&self, key: &K, value: &V) -> Result<(), BpfError> {
        // ... BPF map update
        Ok(())
    }
}

// Usage:
let counters: BpfMap<u32, u64> = load_map("counters")?;
let process_info: BpfMap<u32, ProcessInfo> = load_map("processes")?;
```

**For eBPF:** Generics let us write type-safe map wrappers. The compiler ensures you don't accidentally use a `u32` key on a `u64` key map.

---

## 3.8 Smart Pointers

### 3.8.1 Box — Heap Allocation

```rust
fn main() {
    let boxed = Box::new(42);
    println!("{}", *boxed);  // Dereference like a pointer
}
```

### 3.8.2 Rc — Reference Counting

```rust
use std::rc::Rc;

fn main() {
    let shared = Rc::new(String::from("shared data"));
    let ref1 = Rc::clone(&shared);
    let ref2 = Rc::clone(&shared);
    println!("Reference count: {}", Rc::strong_count(&shared));  // 3
}
```

### 3.8.3 Arc — Thread-Safe Reference Counting

```rust
use std::sync::Arc;
use std::thread;

fn main() {
    let shared = Arc::new(vec![1, 2, 3]);
    let mut handles = vec![];

    for i in 0..3 {
        let data = Arc::clone(&shared);
        handles.push(thread::spawn(move || {
            println!("Thread {}: {:?}", i, data);
        }));
    }

    for h in handles {
        h.join().unwrap();
    }
}
```

**For eBPF:** `Arc` is used extensively in userspace eBPF tools to share map handles and program references across threads.

---

## 3.9 Iterators and Closures

```rust
fn main() {
    let numbers = vec![1, 2, 3, 4, 5];

    // Iterator with closure
    let sum: i32 = numbers.iter()
        .filter(|&&x| x > 2)       // Closure: keep values > 2
        .map(|&x| x * 2)            // Closure: double each
        .sum();

    println!("Sum: {}", sum);  // 24 (3*2 + 4*2 + 5*2)
}
```

**For eBPF:** Iterators are used in userspace to process events from ring buffers and perf events. Closures capture context elegantly.

---

## 3.10 Unsafe Rust — When We Need It

Rust's safety is opt-in. When you need raw pointers or FFI, use `unsafe`:

```rust
unsafe fn read_kernel_address(addr: u64) -> u64 {
    // Raw pointer dereference — unsafe!
    let ptr = addr as *const u64;
    *ptr
}

fn main() {
    // Safe wrapper around unsafe code
    fn safe_read(addr: u64) -> Option<u64> {
        if addr != 0 && is_valid_address(addr) {
            Some(unsafe { read_kernel_address(addr) })
        } else {
            None
        }
    }
}
```

**For eBPF:** Unsafe is needed for:
- FFI with libbpf C library
- Direct memory access in some eBPF helpers
- Performance-critical paths

The Rust eBPF libraries encapsulate unsafe code behind safe APIs.

---

## 3.11 Async Rust — For Userspace eBPF Tools

Async Rust is essential for eBPF userspace programs that handle multiple event streams:

```rust
use tokio::sync::mpsc;

async fn process_events(mut rx: mpsc::Receiver<Event>) {
    while let Some(event) = rx.recv().await {
        match event {
            Event::ProcessExec { pid, comm } => {
                println!("Process {} executed: {}", pid, comm);
            }
            // ...
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let (tx, rx) = mpsc::channel(1000);

    // Spawn eBPF event producer
    tokio::spawn(async move {
        let bpf = Bpf::load(include_bytes!("program.bpf.o"))?;
        for event in bpf.events() {
            tx.send(event).await.ok();
        }
    });

    // Process events
    process_events(rx).await;

    Ok(())
}
```

**For eBPF:** Async is perfect for:
- Reading from ring buffers without blocking
- Handling multiple eBPF programs concurrently
- Integrating with web servers or gRPC

---

## 3.12 Cargo — The Rust Build System

### 3.2.1 Project Structure

```
my-ebpf-tool/
├── Cargo.toml          # Project manifest
├── Cargo.lock          # Dependency lock file
├── src/
│   ├── main.rs         # Userspace binary
│   └── lib.rs          # Library code (optional)
├── ebpf/
│   └── src/
│       └── main.rs     # eBPF program (compiled separately)
├── build.rs            # Build script (optional)
└── target/             # Build output
```

### 3.12.2 Cargo.toml

```toml
[package]
name = "my-ebpf-tool"
version = "0.1.0"
edition = "2021"

[dependencies]
tokio = { version = "1", features = ["full"] }
aya = "0.13"           # Rust eBPF library
anyhow = "1"           # Error handling
libc = "0.2"           # FFI bindings

[[bin]]
name = "my-tool"
path = "src/main.rs"
```

### 3.12.3 Build Commands

```bash
# Build the project
cargo build

# Build with optimizations
cargo build --release

# Run the project
cargo run

# Check without building
cargo check

# Run tests
cargo test

# Format code
cargo fmt

# Lint
cargo clippy
```

---

## 3.13 How Rust Maps to eBPF Concepts

| eBPF Concept | Rust Equivalent |
|--------------|-----------------|
| eBPF Map | `BpfMap<K, V>` struct with typed access |
| Helper Function | Safe wrapper function (e.g., `bpf_map_lookup_elem`) |
| Program Section | Function with `#[aya::bpf]` attribute |
| Ring Buffer | `async Stream` of events |
| Verifier Error | Compile-time type error (often caught earlier) |
| File Descriptor | `OwnedFd` (automatically closed on drop) |
| Memory Safety | Ownership + borrowing (compile-time guarantees) |

---

## 3.14 A Taste of Rust eBPF

Here's a preview of what Rust eBPF looks like (we'll cover this in detail in Part IV):

```rust
// eBPF program (compiled to eBPF bytecode)
use aya_bpf::{macros::tracepoint, programs::TracePointContext};
use aya_bpf::maps::PerfEventArray;
use aya_bpf::bindings::pt_regs;

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

```rust
// Userspace loader
use aya::{Bpf, programs::TracePoint};
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let mut bpf = Bpf::load(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/target/bpfel-unknown-none/release/program"
    )))?;

    let program: &mut TracePoint = bpf.program_mut("sys_enter_execve").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_execve")?;

    // Process events
    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS")?);
    // ... read events asynchronously

    signal::ctrl_c().await?;
    Ok(())
}
```

---

## 3.15 Summary

- **Ownership** prevents use-after-free and double-free
- **Borrowing** lets you reference data without taking ownership
- **Lifetimes** ensure references are always valid
- **Traits** provide zero-cost polymorphism
- **Enums + pattern matching** handle different event types safely
- **Result/Option** forces explicit error handling
- **Generics** enable type-safe reusable code
- **Async** is essential for userspace eBPF event processing
- **Unsafe** is encapsulated behind safe APIs
- **Cargo** manages builds, dependencies, and tooling

---

## 3.16 Looking Ahead

Now that you have foundations in both C and Rust, we're ready to dive deep into eBPF theory. Chapter 4 will explain how eBPF actually works inside the kernel — the virtual machine, registers, and execution model.

---

*Next: [Chapter 4 — eBPF Architecture](./04-ebpf-architecture.md)*
