# Chapter 15: Userspace Integration with libpf-rs

## What This Chapter Covers

- Loading eBPF programs with libpf-rs
- Managing maps from Rust
- Async event handling with tokio
- Program lifecycle management
- Error handling patterns
- Complete userspace examples

---

## 15.1 libpf-rs Overview

libpf-rs provides Rust bindings for libbpf, the standard C library for eBPF. It gives you:

- **Type-safe wrappers** around libbpf C functions
- **Ergonomic Rust API** for loading, attaching, and managing eBPF programs
- **Map access** with Rust types
- **Async support** for event processing

### 15.1.1 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  libpf-rs ARCHITECTURE                      │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Your Rust Application                              │   │
│  │  - Loads eBPF programs                              │   │
│  │  - Reads/writes maps                                │   │
│  │  - Processes events                                 │   │
│  └─────────────────────────────────────────────────────┘   │
│                            │                                │
│                            ▼                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  libpf-rs (Rust)                                    │   │
│  │  - BpfObject, Program, Map structs                  │   │
│  │  - Safe wrappers around libbpf                      │   │
│  └─────────────────────────────────────────────────────┘   │
│                            │                                │
│                            ▼                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  libbpf (C)                                         │   │
│  │  - bpf() syscall                                    │   │
│  │  - Verification                                     │   │
│  │  - JIT compilation                                  │   │
│  └─────────────────────────────────────────────────────┘   │
│                            │                                │
│                            ▼                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Linux Kernel                                       │   │
│  │  - eBPF VM                                          │   │
│  │  - Verifier                                         │   │
│  │  - Maps                                             │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 15.2 Loading eBPF Programs

### 15.2.1 Basic Loading

```rust
use libpf_rs::Object;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Open the BPF object file
    let obj = Object::open_file("execve_counter.bpf.o")?;

    // Load into kernel (verifies and JIT compiles)
    obj.load()?;

    println!("eBPF program loaded successfully!");
    Ok(())
}
```

### 15.2.2 Finding Programs and Maps

```rust
use libpf_rs::{Object, Program, Map};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let obj = Object::open_file("execve_counter.bpf.o")?;
    obj.load()?;

    // Get a program by name
    let prog = obj.program("tracepoint__syscalls__sys_enter_execve")
        .ok_or("Program not found")?;

    // Get a map by name
    let map = obj.map("execve_count")
        .ok_or("Map not found")?;

    println!("Found program: {:?}", prog.name());
    println!("Found map: {:?}", map.name());

    Ok(())
}
```

---

## 15.3 Attaching Programs

### 15.3.1 Tracepoint Attachment

```rust
use libpf_rs::Program;

fn attach_tracepoint(prog: &Program) -> Result<(), Box<dyn std::error::Error>> {
    // Attach to a tracepoint
    prog.attach_tracepoint("syscalls", "sys_enter_execve")?;
    println!("Attached to tracepoint");
    Ok(())
}
```

### 15.3.2 Kprobe Attachment

```rust
use libpf_rs::Program;

fn attach_kprobe(prog: &Program) -> Result<(), Box<dyn std::error::Error>> {
    // Attach to a kernel function
    prog.attach_kprobe("do_sys_openat2", false)?;  // false = not a kretprobe
    println!("Attached to kprobe");
    Ok(())
}

fn attach_kretprobe(prog: &Program) -> Result<(), Box<dyn std::error::Error>> {
    // Attach to a kernel function return
    prog.attach_kprobe("do_sys_openat2", true)?;  // true = kretprobe
    println!("Attached to kretprobe");
    Ok(())
}
```

### 15.3.3 XDP Attachment

```rust
use libpf_rs::Program;

fn attach_xdp(prog: &Program, ifname: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Attach to network interface
    let ifindex = libc::if_nametoindex(ifname.as_ptr() as *const i8);
    prog.attach_xdp(ifindex as i32)?;
    println!("Attached to XDP on {}", ifname);
    Ok(())
}
```

---

## 15.4 Map Access

### 15.4.1 Reading Maps

```rust
use libpf_rs::Map;

fn read_map(map: &Map) -> Result<(), Box<dyn std::error::Error>> {
    // Lookup by key
    let key: u32 = 0;
    match map.lookup::<u32, u64>(&key)? {
        Some(value) => println!("Value: {}", value),
        None => println!("Key not found"),
    }

    // Get all entries
    for entry in map.iter::<u32, u64>()? {
        let (key, value) = entry?;
        println!("{}: {}", key, value);
    }

    Ok(())
}
```

### 15.4.2 Writing Maps

```rust
use libpf_rs::Map;

fn write_map(map: &Map) -> Result<(), Box<dyn std::error::Error>> {
    // Insert or update
    let key: u32 = 0;
    let value: u64 = 42;
    map.update(&key, &value, libpf_rs::MapFlags::ANY)?;

    // Delete
    map.delete(&key)?;

    Ok(())
}
```

### 15.4.3 Typed Map Wrapper

```rust
use libpf_rs::Map;

struct TypedMap<K: Copy, V: Copy> {
    map: Map,
    _phantom: std::marker::PhantomData<(K, V)>,
}

impl<K: Copy, V: Copy> TypedMap<K, V> {
    fn new(map: Map) -> Self {
        TypedMap {
            map,
            _phantom: std::marker::PhantomData,
        }
    }

    fn get(&self, key: &K) -> Result<Option<V>, Box<dyn std::error::Error>> {
        self.map.lookup(key)
    }

    fn set(&self, key: &K, value: &V) -> Result<(), Box<dyn std::error::Error>> {
        self.map.update(key, value, libpf_rs::MapFlags::ANY)
    }

    fn remove(&self, key: &K) -> Result<(), Box<dyn std::error::Error>> {
        self.map.delete(key)
    }
}

// Usage
let counter_map = TypedMap::<u32, u64>::new(map);
counter_map.set(&0, &42)?;
let value = counter_map.get(&0)?;
```

---

## 15.5 Async Event Handling

### 15.5.1 Ring Buffer with Tokio

```rust
use libpf_rs::Map;
use tokio::sync::mpsc;

async fn process_events(map: Map) -> Result<(), Box<dyn std::error::Error>> {
    let (tx, mut rx) = mpsc::channel(1000);

    // Spawn a task to read from ring buffer
    tokio::spawn(async move {
        loop {
            // Poll for events
            match map.ring_buf_next::<ProcessEvent>() {
                Ok(Some(event)) => {
                    if tx.send(event).await.is_err() {
                        break;
                    }
                }
                Ok(None) => {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
                Err(e) => {
                    eprintln!("Error reading ring buffer: {}", e);
                    break;
                }
            }
        }
    });

    // Process events
    while let Some(event) = rx.recv().await {
        println!("PID: {}, UID: {}", event.pid, event.uid);
    }

    Ok(())
}
```

### 15.5.2 Perf Event Array

```rust
use libpf_rs::Map;
use tokio::task;

async fn process_perf_events(map: Map) -> Result<(), Box<dyn std::error::Error>> {
    let num_cpus = num_cpus::get();

    for cpu_id in 0..num_cpus {
        let map_clone = map.clone();
        task::spawn(async move {
            loop {
                match map_clone.perf_event_read::<ProcessEvent>(cpu_id) {
                    Ok(events) => {
                        for event in events {
                            println!("CPU {}: PID {}", cpu_id, event.pid);
                        }
                    }
                    Err(e) => {
                        eprintln!("Error on CPU {}: {}", cpu_id, e);
                        break;
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        });
    }

    Ok(())
}
```

---

## 15.6 Complete Userspace Example

```rust
// src/main.rs
use libpf_rs::{Object, Program, Map};
use tokio::signal;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Copy)]
#[repr(C)]
struct ProcessEvent {
    pid: u32,
    uid: u32,
    comm: [u8; 16],
    timestamp: u64,
}

struct App {
    object: Object,
    running: Arc<Mutex<bool>>,
}

impl App {
    fn new(bpf_object_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let object = Object::open_file(bpf_object_path)?;
        object.load()?;

        Ok(App {
            object,
            running: Arc::new(Mutex::new(true)),
        })
    }

    fn attach_programs(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Attach tracepoint
        let prog = self.object.program("sys_enter_execve")
            .ok_or("Program not found")?;
        prog.attach_tracepoint("syscalls", "sys_enter_execve")?;

        println!("Attached to tracepoint");
        Ok(())
    }

    async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let events_map = self.object.map("events")
            .ok_or("Events map not found")?;

        let running = self.running.clone();

        // Spawn event processing task
        let handle = tokio::spawn(async move {
            while *running.lock().await {
                match events_map.ring_buf_next::<ProcessEvent>() {
                    Ok(Some(event)) => {
                        let comm = String::from_utf8_lossy(&event.comm);
                        println!(
                            "PID: {}, UID: {}, COMM: {}",
                            event.pid, event.uid, comm
                        );
                    }
                    Ok(None) => {
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    }
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        break;
                    }
                }
            }
        });

        // Wait for Ctrl+C
        signal::ctrl_c().await?;
        println!("\nShutting down...");

        // Stop the event loop
        *self.running.lock().await = false;
        handle.await?;

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = App::new("execve_counter.bpf.o")?;
    app.attach_programs().await?;
    app.run().await?;
    Ok(())
}
```

---

## 15.7 Error Handling Patterns

```rust
use thiserror::Error;

#[derive(Error, Debug)]
enum BpfError {
    #[error("Failed to open BPF object: {0}")]
    OpenError(String),

    #[error("Failed to load BPF program: {0}")]
    LoadError(String),

    #[error("Program not found: {0}")]
    ProgramNotFound(String),

    #[error("Map not found: {0}")]
    MapNotFound(String),

    #[error("Attachment failed: {0}")]
    AttachError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

fn load_and_attach(path: &str) -> Result<(), BpfError> {
    let obj = Object::open_file(path)
        .map_err(|e| BpfError::OpenError(e.to_string()))?;

    obj.load()
        .map_err(|e| BpfError::LoadError(e.to_string()))?;

    let prog = obj.program("my_program")
        .ok_or_else(|| BpfError::ProgramNotFound("my_program".into()))?;

    prog.attach_tracepoint("syscalls", "sys_enter_execve")
        .map_err(|e| BpfError::AttachError(e.to_string()))?;

    Ok(())
}
```

---

## 15.8 Program Lifecycle Management

```rust
use std::sync::atomic::{AtomicBool, Ordering};

struct BpfApp {
    object: Object,
    running: Arc<AtomicBool>,
}

impl BpfApp {
    fn new(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let object = Object::open_file(path)?;
        object.load()?;

        Ok(BpfApp {
            object,
            running: Arc::new(AtomicBool::new(true)),
        })
    }

    fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Attach all programs
        for prog in self.object.programs() {
            println!("Attaching: {}", prog.name());
            // Attach based on program type...
        }
        Ok(())
    }

    fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

// Cleanup on drop
impl Drop for BpfApp {
    fn drop(&mut self) {
        self.stop();
        // Programs are automatically detached when object is dropped
    }
}
```

---

## 15.9 Summary

- **libpf-rs** provides Rust bindings for libbpf
- **Object::open_file** loads the BPF object
- **Program::attach_tracepoint/kprobe/xdp** attaches programs
- **Map::lookup/update/delete** for map access
- **Async** event handling with tokio
- **Error handling** with custom error types
- **Drop trait** for automatic cleanup

---

## 15.10 Looking Ahead

Chapter 16 covers **building a complete eBPF tool in Rust** — an end-to-end network monitoring tool.

---

*Next: [Chapter 16 — Building a Complete Tool in Rust](./16-complete-tool-rust.md)*
