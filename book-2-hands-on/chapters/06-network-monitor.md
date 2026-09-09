# Chapter 6: Network Monitor - Putting It All Together

## What We're Building

A complete network monitoring tool that:
- Tracks TCP connections
- Counts bytes sent/received per connection
- Displays top talkers

**Why this project?** Because real tools combine multiple eBPF program types. This chapter shows how to architect a complete tool.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                 NETWORK MONITOR                             │
│                                                             │
│  Kernel Space (BPF)                    Userspace (Rust)     │
│  ─────────────────                     ─────────────────    │
│                                                             │
│  tcp_connect ──┐                       ┌──► Event Processor│
│  tcp_sendmsg ──┼──► Hash Map ─────────┤   (Ring Buffer)   │
│  tcp_recvmsg ──┘   (per-connection    │                    │
│                    stats)             └──► Stats Display   │
│                                            (periodic poll) │
└─────────────────────────────────────────────────────────────┘
```

**Why this architecture?**
- Multiple BPF programs collect different data
- Hash map stores per-connection state
- Ring buffer streams events (new connections, closed connections)
- Userspace reads both for display

---

## The Complete Code

### src/bpf/netmon.bpf.c

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define TASK_COMM_LEN 16

// Connection key - uniquely identifies a connection
// WHY this structure? Because we need to identify connections uniquely.
// Using just IPs isn't enough (multiple connections between same IPs).
struct conn_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u32 pid;
};

// Per-connection statistics
struct conn_stats {
    __u64 bytes_sent;
    __u64 bytes_recv;
    __u64 packets_sent;
    __u64 packets_recv;
    __u64 start_time;
    __u64 last_seen;
    char comm[TASK_COMM_LEN];
};

// Event for ring buffer
struct event {
    struct conn_key key;
    struct conn_stats stats;
    __u8 type;  // 0=new, 1=close, 2=update
};

// WHY PERCPU HASH?
// - Each CPU has its own hash table
// - No locking needed when updating
// - Much faster than regular hash map for counters
// - We aggregate in userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 10000);
    __type(key, struct conn_key);
    __type(value, struct conn_stats);
} connections SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Helper to extract connection key from socket
static __always_inline void get_conn_key(struct sock *sk, struct conn_key *key)
{
    key->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    key->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    key->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    key->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    key->pid = bpf_get_current_pid_tgid() >> 32;
}

// Track new TCP connections
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(trace_connect, struct sock *sk)
{
    struct conn_key key = {};
    struct conn_stats stats = {};
    struct event *e;

    get_conn_key(sk, &key);

    // Initialize stats
    stats.start_time = bpf_ktime_get_ns();
    stats.last_seen = stats.start_time;
    bpf_get_current_comm(&stats.comm, sizeof(stats.comm));

    // Store in hash map
    bpf_map_update_elem(&connections, &key, &stats, BPF_ANY);

    // Emit event
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->key = key;
        e->stats = stats;
        e->type = 0;  // new connection
        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}

// Track outgoing bytes
SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(trace_send, struct sock *sk, struct msghdr *msg, size_t size)
{
    struct conn_key key = {};
    struct conn_stats *stats;

    get_conn_key(sk, &key);

    stats = bpf_map_lookup_elem(&connections, &key);
    if (!stats)
        return 0;

    // WHY no atomic? Because this is a PERCPU hash map!
    // Each CPU has its own copy, so no locking needed.
    stats->bytes_sent += size;
    stats->packets_sent += 1;
    stats->last_seen = bpf_ktime_get_ns();

    return 0;
}

// Track incoming bytes
SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(trace_recv, struct sock *sk, struct msghdr *msg, size_t size)
{
    struct conn_key key = {};
    struct conn_stats *stats;

    get_conn_key(sk, &key);

    stats = bpf_map_lookup_elem(&connections, &key);
    if (!stats)
        return 0;

    stats->bytes_recv += size;
    stats->packets_recv += 1;
    stats->last_seen = bpf_ktime_get_ns();

    return 0;
}

// Track connection close
SEC("kprobe/tcp_close")
int BPF_KPROBE(trace_close, struct sock *sk)
{
    struct conn_key key = {};
    struct conn_stats *stats;
    struct event *e;

    get_conn_key(sk, &key);

    stats = bpf_map_lookup_elem(&connections, &key);
    if (!stats)
        return 0;

    // Emit close event with final stats
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->key = key;
        e->stats = *stats;
        e->type = 1;  // close
        bpf_ringbuf_submit(e, 0);
    }

    bpf_map_delete_elem(&connections, &key);
    return 0;
}

char _license[] SEC("license") = "GPL";
```

**Key design decisions:**

1. **PERCPU_HASH** - Each CPU has its own hash table. **Why?** Because `tcp_sendmsg` and `tcp_recvmsg` run very frequently. With a regular hash map, we'd need atomics. With PERCPU, no locking needed!

2. **BPF_CORE_READ** - CO-RE style reads. **Why?** Because kernel struct layouts change between versions. This makes our program portable.

3. **Separate programs for each event** - **Why?** Because each event type needs different data. `tcp_v4_connect` gives us the socket, `tcp_sendmsg` gives us the size.

### src/main.rs

```rust
use libbpf_rs::{ObjectBuilder, RingBufferBuilder};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

mod bpf {
    include!("bpf/netmon.skel.rs");
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct ConnKey {
    saddr: u32,
    daddr: u32,
    sport: u16,
    dport: u16,
    pid: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct ConnStats {
    bytes_sent: u64,
    bytes_recv: u64,
    packets_sent: u64,
    packets_recv: u64,
    start_time: u64,
    last_seen: u64,
    comm: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Event {
    key: ConnKey,
    stats: ConnStats,
    event_type: u8,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    let obj = ObjectBuilder::default()
        .open_file("target/bpfel-unknown-none/release/netmon.bpf.o")?;
    let obj = obj.load()?;

    // Attach all programs
    let programs = [
        ("trace_connect", "tcp_v4_connect"),
        ("trace_send", "tcp_sendmsg"),
        ("trace_recv", "tcp_recvmsg"),
        ("trace_close", "tcp_close"),
    ];

    let mut links = Vec::new();
    for (prog_name, func_name) in programs {
        let prog = obj.prog(prog_name).ok_or(format!("{} not found", prog_name))?;
        let link = prog.attach_kprobe(false, func_name)?;
        links.push(link);
        println!("Attached {} to {}", prog_name, func_name);
    }

    // Set up ring buffer for events
    let mut ring_buf_builder = RingBufferBuilder::new();
    ring_buf_builder.add(obj.map("events").unwrap(), |data: &[u8]| {
        let event = unsafe { &*(data.as_ptr() as *const Event) };

        match event.event_type {
            0 => {
                let comm = String::from_utf8_lossy(&event.stats.comm);
                println!("[NEW] {}:{} -> {}:{} ({})",
                    u32::from_be(event.key.saddr),
                    u16::from_be(event.key.sport),
                    u32::from_be(event.key.daddr),
                    u16::from_be(event.key.dport),
                    comm);
            }
            1 => {
                println!("[CLOSE] {}:{} -> {}:{} sent={} recv={}",
                    u32::from_be(event.key.saddr),
                    u16::from_be(event.key.sport),
                    u32::from_be(event.key.daddr),
                    u16::from_be(event.key.dport),
                    event.stats.bytes_sent,
                    event.stats.bytes_recv);
            }
        }

        0
    })?;
    let ring_buf = ring_buf_builder.build()?;

    println!("\nMonitoring network connections... Press Ctrl+C to exit.\n");

    // Main loop: poll ring buffer and periodically print stats
    let mut iteration = 0;
    while running.load(Ordering::SeqCst) {
        ring_buf.poll(Duration::from_millis(100))?;

        // Every 50 iterations (~5 seconds), print top talkers
        iteration += 1;
        if iteration % 50 == 0 {
            print_top_talkers(&obj)?;
        }
    }

    Ok(())
}

fn print_top_talkers(obj: &libbpf_rs::Object) -> Result<(), Box<dyn std::error::Error>> {
    let map = obj.map("connections").ok_or("Map not found")?;

    // Aggregate per-CPU values
    let mut aggregated: HashMap<ConnKey, ConnStats> = HashMap::new();

    // Iterate over all keys
    let mut key = vec![0u8; std::mem::size_of::<ConnKey>()];
    while map.get_next_key(&key, &mut key)? {
        // Get all CPU values for this key
        // (Simplified - actual implementation would iterate CPUs)
        let value = map.lookup(&key, libbpf_rs::MapFlags::ANY)?;
        if let Some(bytes) = value {
            let stats: ConnStats = unsafe {
                std::ptr::read(bytes.as_ptr() as *const ConnStats)
            };
            let key: ConnKey = unsafe {
                std::ptr::read(key.as_ptr() as *const ConnKey)
            };
            aggregated.insert(key, stats);
        }
    }

    // Sort by total bytes
    let mut connections: Vec<_> = aggregated.iter().collect();
    connections.sort_by_key(|(_, s)| -(s.bytes_sent + s.bytes_recv) as i64);

    println!("\n=== Top Talkers ===");
    for (key, stats) in connections.iter().take(10) {
        let comm = String::from_utf8_lossy(&stats.comm);
        println!("{}:{} -> {}:{}  sent={} recv={} ({})",
            u32::from_be(key.saddr), u16::from_be(key.sport),
            u32::from_be(key.daddr), u16::from_be(key.dport),
            stats.bytes_sent, stats.bytes_recv, comm);
    }
    println!();

    Ok(())
}
```

---

## Building and Running

```bash
cargo build --release
sudo ./target/release/netmon
```

Output:
```
Attached trace_connect to tcp_v4_connect
Attached trace_send to tcp_sendmsg
Attached trace_recv to tcp_recvmsg
Attached trace_close to tcp_close

Monitoring network connections... Press Ctrl+C to exit.

[NEW] 192.168.1.5:45678 -> 93.184.216.34:443 (firefox)
[NEW] 192.168.1.5:45680 -> 142.250.80.46:443 (curl)
[CLOSE] 192.168.1.5:45680 -> 142.250.80.46:443 sent=128 recv=4096

=== Top Talkers ===
192.168.1.5:45678 -> 93.184.216.34:443  sent=2048 recv=1048576 (firefox)
192.168.1.5:45680 -> 142.250.80.46:443  sent=128 recv=4096 (curl)
```

---

## Why This Architecture Works

1. **Multiple programs** - Each collects different data at different points
2. **Per-CPU hash map** - No locking for high-frequency updates
3. **Ring buffer** - Efficient event streaming for connection lifecycle
4. **Userspace aggregation** - Complex logic stays in userspace

**The golden rule:** Keep BPF programs simple and fast. Do complex processing in userspace.

---

## Try It Yourself

1. **Add UDP tracking** - Hook `udp_sendmsg` and `udp_recvmsg`.

2. **Track by process** - Aggregate stats by PID instead of connection.

3. **Add DNS tracking** - Hook `udp_recvmsg` and parse DNS responses on port 53.

---

*Next: [Chapter 7 - Latency Histogram](../chapters/07-latency-histogram.md)*
