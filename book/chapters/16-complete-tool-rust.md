# Chapter 16: Building a Complete eBPF Tool in Rust

## What This Chapter Covers

- Designing a complete eBPF tool
- Network monitoring tool architecture
- eBPF programs for packet capture
- Userspace event processing
- CLI interface
- Statistics and reporting
- Full working example

---

## 16.1 What We're Building

A **network monitoring tool** that:
- Captures TCP connection events
- Tracks bytes sent/received per connection
- Reports top talkers
- Exports metrics to stdout

---

## 16.2 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                 NETWORK MONITOR TOOL                        │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  eBPF Programs                                      │   │
│  │  - tcp_connect: Track new connections               │   │
│  │  - tcp_sendmsg: Track outgoing bytes                │   │
│  │  - tcp_recvmsg: Track incoming bytes                │   │
│  │  - tcp_close: Track connection close                │   │
│  └─────────────────────────────────────────────────────┘   │
│                            │                                │
│                            ▼                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  eBPF Maps                                          │   │
│  │  - connections: HashMap<ConnKey, ConnStats>         │   │
│  │  - events: RingBuf<ConnEvent>                       │   │
│  └─────────────────────────────────────────────────────┘   │
│                            │                                │
│                            ▼                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Userspace (Rust)                                   │   │
│  │  - Event processor: Reads ring buffer               │   │
│  │  - Stats aggregator: Reads maps periodically        │   │
│  │  - CLI: User interface                              │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 16.3 Shared Types

```rust
// shared/src/lib.rs
#![no_std]

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ConnKey {
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub pid: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ConnStats {
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub packets_sent: u64,
    pub packets_recv: u64,
    pub start_time: u64,
    pub last_seen: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ConnEvent {
    pub key: ConnKey,
    pub stats: ConnStats,
    pub event_type: u8,  // 0=connect, 1=close, 2=stats
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ConnKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ConnStats {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ConnEvent {}
```

---

## 16.4 eBPF Programs

```rust
// ebpf/src/main.rs
#![no_std]
#![no_main]

use aya_bpf::{
    macros::{kprobe, kretprobe, map},
    programs::ProbeContext,
    maps::{HashMap, RingBuf},
    helpers::*,
    bindings::sock,
};

use shared::{ConnKey, ConnStats, ConnEvent};

#[map]
static CONNECTIONS: HashMap<ConnKey, ConnStats> = HashMap::with_max_entries(10000, 0);

#[map]
static EVENTS: RingBuf = RingBuf::with_max_entries(256 * 1024, 0);

// Helper to get connection key from socket
fn get_conn_key(sk: *const sock) -> Option<ConnKey> {
    let mut key = ConnKey::default();

    // Read socket fields
    let Ok(saddr) = unsafe { bpf_probe_read(&(*sk).__sk_common.skc_rcv_saddr) } else {
        return None;
    };
    let Ok(daddr) = unsafe { bpf_probe_read(&(*sk).__sk_common.skc_daddr) } else {
        return None;
    };
    let Ok(sport) = unsafe { bpf_probe_read(&(*sk).__sk_common.skc_num) } else {
        return None;
    };
    let Ok(dport) = unsafe { bpf_probe_read(&(*sk).__sk_common.skc_dport) } else {
        return None;
    };

    key.saddr = saddr;
    key.daddr = daddr;
    key.sport = sport;
    key.dport = u16::from_be(dport);
    key.pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    Some(key)
}

#[kprobe]
pub fn tcp_v4_connect(ctx: ProbeContext) -> u32 {
    let sk: *const sock = ctx.arg(0).unwrap_or(std::ptr::null());

    let Some(key) = get_conn_key(sk) else { return 0; };

    let now = bpf_ktime_get_ns();
    let stats = ConnStats {
        start_time: now,
        last_seen: now,
        ..Default::default()
    };

    CONNECTIONS.insert(&key, &stats, 0);

    // Emit connect event
    if let Some(event) = EVENTS.reserve::<ConnEvent>(0) {
        event.key = key;
        event.stats = stats;
        event.event_type = 0; // connect
        event.submit(0);
    }

    0
}

#[kprobe]
pub fn tcp_sendmsg_entry(ctx: ProbeContext) -> u32 {
    let sk: *const sock = ctx.arg(0).unwrap_or(std::ptr::null());
    let size: usize = ctx.arg(2).unwrap_or(0);

    let Some(key) = get_conn_key(sk) else { return 0; };

    if let Some(stats) = CONNECTIONS.get_ptr_mut(&key) {
        unsafe {
            (*stats).bytes_sent += size as u64;
            (*stats).packets_sent += 1;
            (*stats).last_seen = bpf_ktime_get_ns();
        }
    }

    0
}

#[kprobe]
pub fn tcp_recvmsg_entry(ctx: ProbeContext) -> u32 {
    let sk: *const sock = ctx.arg(0).unwrap_or(std::ptr::null());
    let size: usize = ctx.arg(2).unwrap_or(0);

    let Some(key) = get_conn_key(sk) else { return 0; };

    if let Some(stats) = CONNECTIONS.get_ptr_mut(&key) {
        unsafe {
            (*stats).bytes_recv += size as u64;
            (*stats).packets_recv += 1;
            (*stats).last_seen = bpf_ktime_get_ns();
        }
    }

    0
}

#[kprobe]
pub fn tcp_close_entry(ctx: ProbeContext) -> u32 {
    let sk: *const sock = ctx.arg(0).unwrap_or(std::ptr::null());

    let Some(key) = get_conn_key(sk) else { return 0; };

    if let Some(stats) = CONNECTIONS.get(&key) {
        // Emit close event
        if let Some(event) = EVENTS.reserve::<ConnEvent>(0) {
            event.key = key;
            event.stats = stats;
            event.event_type = 1; // close
            event.submit(0);
        }
    }

    CONNECTIONS.remove(&key);

    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
```

---

## 16.5 Userspace Application

```rust
// src/main.rs
use aya::{
    Bpf,
    programs::KProbe,
    maps::ring_buf::RingBuf,
    util::online_cpus,
};
use clap::Parser;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration};
use bytes::BytesMut;

use shared::{ConnKey, ConnStats, ConnEvent};

#[derive(Parser)]
#[command(name = "netmon", about = "Network monitoring tool")]
struct Cli {
    /// Refresh interval in seconds
    #[arg(short, long, default_value = "5")]
    interval: u64,

    /// Show only top N connections
    #[arg(short, long, default_value = "10")]
    top: usize,
}

struct NetMonApp {
    bpf: Bpf,
    stats: Arc<RwLock<HashMap<ConnKey, ConnStats>>>,
}

impl NetMonApp {
    fn new() -> Result<Self, anyhow::Error> {
        let mut bpf = Bpf::load(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/target/bpfel-unknown-none/release/netmon"
        )))?;

        // Attach programs
        Self::attach_program(&mut bpf, "tcp_v4_connect", "tcp_v4_connect")?;
        Self::attach_program(&mut bpf, "tcp_sendmsg_entry", "tcp_sendmsg")?;
        Self::attach_program(&mut bpf, "tcp_recvmsg_entry", "tcp_recvmsg")?;
        Self::attach_program(&mut bpf, "tcp_close_entry", "tcp_close")?;

        Ok(NetMonApp {
            bpf,
            stats: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    fn attach_program(bpf: &mut Bpf, name: &str, attach: &str) -> Result<(), anyhow::Error> {
        let program: &mut KProbe = bpf.program_mut(name).unwrap().try_into()?;
        program.load()?;
        program.attach(attach, 0)?;
        println!("Attached: {}", name);
        Ok(())
    }

    async fn process_events(&self) -> Result<(), anyhow::Error> {
        let mut ring_buf = RingBuf::try_from(self.bpf.map("EVENTS")?)?;

        loop {
            match ring_buf.next().await {
                Some(event) => {
                    let bytes = BytesMut::from(&event[..]);
                    let event = unsafe { &*(bytes.as_ptr() as *const ConnEvent) };

                    let mut stats = self.stats.write().await;
                    match event.event_type {
                        0 => {
                            // Connect
                            stats.insert(event.key, event.stats);
                        }
                        1 => {
                            // Close
                            stats.remove(&event.key);
                        }
                        _ => {}
                    }
                }
                None => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    }

    async fn display_stats(&self, top_n: usize) {
        let mut interval = interval(Duration::from_secs(5));

        loop {
            interval.tick().await;

            // Clear screen
            print!("\x1B[2J\x1B[1;1H");

            let stats = self.stats.read().await;

            // Sort by total bytes
            let mut connections: Vec<_> = stats.iter().collect();
            connections.sort_by_key(|(_, s)| -(s.bytes_sent + s.bytes_recv) as i64);

            println!("{:<20} {:<20} {:>12} {:>12} {:>8}",
                     "Source", "Destination", "Sent", "Recv", "PID");
            println!("{}", "-".repeat(80));

            for (key, stats) in connections.iter().take(top_n) {
                let src = format!("{}:{}",
                    ipv4_to_string(key.saddr), key.sport);
                let dst = format!("{}:{}",
                    ipv4_to_string(key.daddr), key.dport);

                println!("{:<20} {:<20} {:>10} {:>10} {:>8}",
                    src, dst,
                    format_bytes(stats.bytes_sent),
                    format_bytes(stats.bytes_recv),
                    key.pid);
            }

            println!("\nTotal connections: {}", stats.len());
        }
    }

    async fn run(&self, cli: Cli) -> Result<(), anyhow::Error> {
        let stats_clone = self.stats.clone();

        // Spawn event processor
        let event_handle = tokio::spawn(async move {
            self.process_events().await
        });

        // Spawn stats display
        let display_handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(cli.interval)).await;
                // Display logic here
            }
        });

        tokio::select! {
            _ = event_handle => {},
            _ = display_handle => {},
            _ = tokio::signal::ctrl_c() => {
                println!("\nShutting down...");
            }
        }

        Ok(())
    }
}

fn ipv4_to_string(addr: u32) -> String {
    format!("{}.{}.{}.{}",
        addr & 0xFF,
        (addr >> 8) & 0xFF,
        (addr >> 16) & 0xFF,
        (addr >> 24) & 0xFF)
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB"];
    let mut size = bytes as f64;
    let mut unit = 0;

    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }

    format!("{:.1}{}", size, UNITS[unit])
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let cli = Cli::parse();

    println!("Network Monitor Starting...");
    println!("Refresh interval: {}s", cli.interval);
    println!("Showing top {} connections", cli.top);

    let app = NetMonApp::new()?;
    app.run(cli).await?;

    Ok(())
}
```

---

## 16.6 Cargo.toml

```toml
[package]
name = "netmon"
version = "0.1.0"
edition = "2021"

[dependencies]
aya = { git = "https://github.com/aya-rs/aya", features = ["async_tokio"] }
aya-log = { git = "https://github.com/aya-rs/aya" }
tokio = { version = "1", features = ["full"] }
clap = { version = "4", features = ["derive"] }
bytes = "1"
anyhow = "1"

shared = { path = "../shared" }

[[bin]]
name = "netmon"
path = "src/main.rs"
```

---

## 16.7 Building and Running

```bash
# Build eBPF program
cd ebpf
cargo build --target bpfel-unknown-none --release

# Build userspace
cd ..
cargo build --release

# Run (requires root)
sudo ./target/release/netmon --interval 5 --top 10
```

---

## 16.8 Summary

- Design tools with **clear separation** of eBPF and userspace
- Use **shared types** with `#[repr(C)]` and `aya::Pod`
- **RingBuf** for event streaming
- **HashMap** for state tracking
- **Tokio** for async event processing
- **Clap** for CLI interfaces

---

## 16.9 Looking Ahead

Chapter 17 covers **advanced Rust patterns** — async eBPF, channels, shared state, and performance optimization.

---

*Next: [Chapter 17 — Advanced Rust Patterns](./17-advanced-rust-ebpf.md)*
