# Chapter 14: Writing eBPF Programs in Rust

## What This Chapter Covers

- Rust eBPF program structure
- Aya macros for maps and programs
- Helper functions in Rust
- Map access patterns
- Event submission
- Complete working examples

---

## 14.1 Rust eBPF Program Structure

```rust
// ebpf/src/main.rs
#![no_std]
#![no_main]

use aya_bpf::{
    macros::{map, tracepoint},
    programs::TracePointContext,
    maps::PerfEventArray,
    bindings::bpf_helper_ids,
};

// Map definition
#[map]
static EVENTS: PerfEventArray<ProcessEvent> = PerfEventArray::with_max_entries(1024, 0);

// Program definition
#[tracepoint]
pub fn sys_enter_execve(ctx: TracePointContext) -> u32 {
    // Program logic
    0
}

// Panic handler (required for no_std)
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
```

---

## 14.2 Map Types in Rust

### 14.2.1 PerfEventArray

```rust
use aya_bpf::maps::PerfEventArray;

#[map]
static EVENTS: PerfEventArray<ProcessEvent> = PerfEventArray::with_max_entries(1024, 0);

// Usage
EVENTS.output(&ctx, &event, 0);
```

### 14.2.2 RingBuf

```rust
use aya_bpf::maps::RingBuf;

#[map]
static EVENTS: RingBuf = RingBuf::with_max_entries(256 * 1024, 0);

// Usage
match EVENTS.reserve::<ProcessEvent>(0) {
    Some(mut event) => {
        event.pid = 1234;
        event.submit(0);
    }
    None => {
        // Buffer full
    }
}
```

### 14.2.3 HashMap

```rust
use aya_bpf::maps::HashMap;

#[map]
static PROCESS_COUNT: HashMap<u32, u64> = HashMap::with_max_entries(10000, 0);

// Usage
match PROCESS_COUNT.get_ptr_mut(&pid) {
    Some(count) => {
        unsafe { *count += 1; }
    }
    None => {
        let init: u64 = 1;
        PROCESS_COUNT.insert(&pid, &init, 0);
    }
}
```

### 14.2.4 Array

```rust
use aya_bpf::maps::Array;

#[map]
static COUNTERS: Array<u64> = Array::with_max_entries(256, 0);

// Usage
let key: u32 = 0;
if let Some(count) = COUNTERS.get(key) {
    unsafe { *count += 1; }
}
```

### 14.2.5 PerCpuArray / PerCpuHashMap

```rust
use aya_bpf::maps::PerCpuArray;

#[map]
static PER_CPU_COUNTERS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

// Usage
let key: u32 = 0;
if let Some(count) = PER_CPU_COUNTERS.get_ptr_mut(key) {
    unsafe { *count += 1; }
}
```

---

## 14.3 Program Types in Rust

### 14.3.1 Tracepoint

```rust
use aya_bpf::macros::tracepoint;
use aya_bpf::programs::TracePointContext;

#[tracepoint]
pub fn sys_enter_execve(ctx: TracePointContext) -> u32 {
    // ctx provides access to tracepoint arguments
    0
}

// With custom naming
#[tracepoint(name = "my_custom_name")]
pub fn sys_enter_execve(ctx: TracePointContext) -> u32 {
    0
}
```

### 14.3.2 KProbe / KRetProbe

```rust
use aya_bpf::macros::{kprobe, kretprobe};
use aya_bpf::programs::ProbeContext;

#[kprobe]
pub fn do_sys_openat2(ctx: ProbeContext) -> u32 {
    // Access registers
    let dfd: i32 = ctx.arg(0).unwrap_or(0);
    0
}

#[kretprobe]
pub fn do_sys_openat2_exit(ctx: ProbeContext) -> u32 {
    let ret: i64 = ctx.ret().unwrap_or(0);
    0
}
```

### 14.3.3 XDP

```rust
use aya_bpf::macros::xdp;
use aya_bpf::programs::XdpContext;

#[xdp]
pub fn xdp_filter(ctx: XdpContext) -> u32 {
    // Access packet data
    let data = ctx.data();
    let data_end = ctx.data_end();
    0 // XDP_PASS
}
```

### 14.3.4 Socket Filter

```rust
use aya_bpf::macros::socket_filter;
use aya_bpf::programs::SkBuffContext;

#[socket_filter]
pub fn socket_filter_prog(ctx: SkBuffContext) -> u64 {
    0 // Pass all packets
}
```

---

## 14.4 Helper Functions in Rust

### 14.4.1 Process Information

```rust
use aya_bpf::helpers::*;

// Get PID/TGID
let pid_tgid = bpf_get_current_pid_tgid();
let pid = (pid_tgid >> 32) as u32;
let tid = pid_tgid as u32;

// Get UID/GID
let uid_gid = bpf_get_current_uid_gid();
let uid = (uid_gid >> 32) as u32;
let gid = uid_gid as u32;

// Get process name
let mut comm = [0u8; 16];
bpf_get_current_comm(&mut comm);

// Get timestamp
let ts = bpf_ktime_get_ns();
```

### 14.4.2 Memory Access

```rust
use aya_bpf::helpers::*;

// Safe memory read
let mut value: u64 = 0;
let ret = bpf_probe_read_user(&mut value, size_of::<u64>() as u32, ptr);

// String read
let mut buffer = [0u8; 256];
let ret = bpf_probe_read_user_str(&mut buffer, buffer.len() as u32, ptr);
```

### 14.4.3 Map Operations

```rust
// Lookup
let value = MAP.get_ptr_mut(&key);

// Insert
MAP.insert(&key, &value, 0);

// Delete
MAP.remove(&key);

// Flags
// BPF_ANY    = 0  // Create or update
// BPF_NOEXIST = 1 // Create only
// BPF_EXIST   = 2 // Update only
// BPF_F_LOCK = 4 // Spin lock
```

---

## 14.5 Complete Example: Process Exec Monitor

### 14.5.1 Shared Types

```rust
// ebpf-common/src/lib.rs
#![no_std]

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ProcessEvent {
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; 16],
    pub timestamp: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ProcessEvent {}
```

### 14.5.2 eBPF Program

```rust
// ebpf/src/main.rs
#![no_std]
#![no_main]

use aya_bpf::{
    macros::{map, tracepoint},
    programs::TracePointContext,
    maps::RingBuf,
    helpers::*,
    bindings::PT_REGS_PARM1,
};

use ebpf_common::ProcessEvent;

#[map]
static EVENTS: RingBuf = RingBuf::with_max_entries(256 * 1024, 0);

#[tracepoint]
pub fn sys_enter_execve(ctx: TracePointContext) -> u32 {
    // Reserve ring buffer space
    let event = match EVENTS.reserve::<ProcessEvent>(0) {
        Some(event) => event,
        None => return 0,
    };

    // Fill event data
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();

    event.pid = (pid_tgid >> 32) as u32;
    event.uid = uid_gid as u32;
    event.timestamp = bpf_ktime_get_ns();

    // Get process name
    let _ = bpf_get_current_comm(&mut event.comm);

    // Submit event
    event.submit(0);

    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
```

### 14.5.3 Userspace Loader

```rust
// userspace/src/main.rs
use aya::{
    Bpf,
    programs::TracePoint,
    maps::ring_buf::RingBuf,
    util::online_cpus,
};
use tokio::signal;
use bytes::BytesMut;

use ebpf_common::ProcessEvent;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // Load eBPF program
    let mut bpf = Bpf::load(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/target/bpfel-unknown-none/release/process-monitor"
    )))?;

    // Get and attach the program
    let program: &mut TracePoint = bpf
        .program_mut("sys_enter_execve")
        .unwrap()
        .try_into()?;

    program.load()?;
    program.attach("syscalls", "sys_enter_execve")?;

    // Set up ring buffer
    let mut ring_buf = RingBuf::try_from(bpf.map("EVENTS")?)?;

    println!("Monitoring process executions... Press Ctrl+C to stop.");
    println!("{:<8} {:<6} {:<6} {:<16}", "TIME", "PID", "UID", "COMM");

    // Process events
    loop {
        tokio::select! {
            event = ring_buf.next() => {
                match event {
                    Some(event) => {
                        let bytes = BytesMut::from(&event[..]);
                        let event = unsafe {
                            &*(bytes.as_ptr() as *const ProcessEvent)
                        };
                        let time = chrono::Local::now().format("%H:%M:%S");
                        let comm = String::from_utf8_lossy(&event.comm);
                        println!(
                            "{:<8} {:<6} {:<6} {:<16}",
                            time, event.pid, event.uid, comm
                        );
                    }
                    None => break,
                }
            }
            _ = signal::ctrl_c() => {
                println!("\nShutting down...");
                break;
            }
        }
    }

    Ok(())
}
```

---

## 14.6 XDP in Rust

```rust
// ebpf/src/main.rs
#![no_std]
#![no_main]

use aya_bpf::{
    macros::{map, xdp},
    programs::XdpContext,
    bindings::xdp_action,
};

#[map]
static BLOCKED_IPS: aya_bpf::maps::HashMap<u32, u8> =
    aya_bpf::maps::HashMap::with_max_entries(10000, 0);

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    // Parse Ethernet header
    let data = ctx.data() as *const u8;
    let data_end = ctx.data_end() as *const u8;

    // Safety check
    if data as usize + 14 > data_end as usize {
        return xdp_action::XDP_DROP;
    }

    let eth = data as *const ethhdr;
    unsafe {
        if (*eth).h_proto != 0x08u16.to_be() {
            return xdp_action::XDP_PASS;
        }
    }

    // Parse IP header
    let ip = unsafe { data.add(14) as *const iphdr };
    if ip as usize + 20 > data_end as usize {
        return xdp_action::XDP_DROP;
    }

    let src_ip = unsafe { (*ip).s_addr };

    // Check blocked IPs
    if BLOCKED_IPS.get(&src_ip).is_some() {
        return xdp_action::XDP_DROP;
    }

    xdp_action::XDP_PASS
}

#[repr(C)]
struct ethhdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: u16,
}

#[repr(C)]
struct iphdr {
    ihl_version: u8,
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    protocol: u8,
    check: u16,
    saddr: u32,
    daddr: u32,
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
```

---

## 14.7 Error Handling in eBPF Rust

```rust
// eBPF has no std, so we use Option and Result from core

// Map lookup returns Option
match MAP.get(&key) {
    Some(value) => { /* use value */ }
    None => { /* key not found */ }
}

// RingBuf reserve returns Option
let mut event = match EVENTS.reserve::<MyEvent>(0) {
    Some(event) => event,
    None => return 0, // Buffer full
};

// Helper functions return i64 (negative = error)
let ret = bpf_probe_read_user(&mut buf, size, ptr);
if ret < 0 {
    // Handle error
    return 0;
}
```

---

## 14.8 Logging in eBPF

```rust
use aya_bpf::helpers::bpf_trace_printk;

// Simple logging (for debugging)
let msg = b"Hello from eBPF!\0";
bpf_trace_printk(msg.as_ptr(), msg.len() as u32);

// With aya-log-ebpf (better)
use aya_log_ebpf::info;

info!(&ctx, "Process {} executed", pid);
info!(&ctx, "Value: {}, Other: {}", value, other);
```

---

## 14.9 Summary

- Rust eBPF programs use `#![no_std]` and `#![no_main]`
- **Maps** are defined with `#[map]` macro
- **Programs** use `#[tracepoint]`, `#[kprobe]`, `#[xdp]`, etc.
- **Helpers** are available via `aya_bpf::helpers`
- **RingBuf** is the preferred event streaming mechanism
- **Shared types** use `#[repr(C)]` and `aya::Pod`

---

## 14.10 Looking Ahead

Chapter 15 covers **userspace integration with libpf-rs** — loading programs, managing maps, and async patterns.

---

*Next: [Chapter 15 — Userspace Integration with libpf-rs](./15-libpf-rs-userspace.md)*
