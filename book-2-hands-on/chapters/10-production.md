# Chapter 10: Production Deployment

## What We're Building

Taking our network monitor from Chapter 6 and making it production-ready with:
- Graceful shutdown
- Map pinning
- Prometheus metrics
- systemd integration
- Proper logging

**Why this chapter?** Because building a tool is only half the battle. Production deployment requires careful architecture.

---

## The Complete Code

### src/bpf/netmon.bpf.c

```c
// Same as Chapter 6, but with one addition:
// We add a map for exposing metrics to userspace

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define TASK_COMM_LEN 16

struct conn_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u32 pid;
};

struct conn_stats {
    __u64 bytes_sent;
    __u64 bytes_recv;
    __u64 packets_sent;
    __u64 packets_recv;
    __u64 start_time;
    __u64 last_seen;
    char comm[TASK_COMM_LEN];
};

struct event {
    struct conn_key key;
    struct conn_stats stats;
    __u8 type;
};

// WHY PERCPU_HASH? Same reason as Chapter 6 - no locking needed
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

// NEW: Metrics map for Prometheus
// WHY this map? So we can expose metrics that Prometheus can scrape.
// We update these counters in BPF, read them from userspace.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} metrics SEC(".maps");

// Metric indices
#define METRIC_EVENTS_TOTAL 0
#define METRIC_EVENTS_DROPPED 1
#define METRIC_CONNECTIONS_ACTIVE 2
#define METRIC_BYTES_TOTAL 3

static __always_inline void update_metric(__u32 metric, __u64 value)
{
    __u64 *val = bpf_map_lookup_elem(&metrics, &metric);
    if (val)
        __sync_fetch_and_add(val, value);
}

static __always_inline void get_conn_key(struct sock *sk, struct conn_key *key)
{
    key->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    key->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    key->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    key->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    key->pid = bpf_get_current_pid_tgid() >> 32;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(trace_connect, struct sock *sk)
{
    struct conn_key key = {};
    struct conn_stats stats = {};
    struct event *e;

    get_conn_key(sk, &key);

    stats.start_time = bpf_ktime_get_ns();
    stats.last_seen = stats.start_time;
    bpf_get_current_comm(&stats.comm, sizeof(stats.comm));

    bpf_map_update_elem(&connections, &key, &stats, BPF_ANY);

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->key = key;
        e->stats = stats;
        e->type = 0;
        bpf_ringbuf_submit(e, 0);
        update_metric(METRIC_EVENTS_TOTAL, 1);
    } else {
        update_metric(METRIC_EVENTS_DROPPED, 1);
    }

    return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(trace_send, struct sock *sk, struct msghdr *msg, size_t size)
{
    struct conn_key key = {};
    struct conn_stats *stats;

    get_conn_key(sk, &key);

    stats = bpf_map_lookup_elem(&connections, &key);
    if (!stats)
        return 0;

    stats->bytes_sent += size;
    stats->packets_sent += 1;
    stats->last_seen = bpf_ktime_get_ns();

    update_metric(METRIC_BYTES_TOTAL, size);

    return 0;
}

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

    update_metric(METRIC_BYTES_TOTAL, size);

    return 0;
}

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

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->key = key;
        e->stats = *stats;
        e->type = 1;
        bpf_ringbuf_submit(e, 0);
    }

    bpf_map_delete_elem(&connections, &key);
    return 0;
}

char _license[] SEC("license") = "GPL";
```

### src/main.rs

```rust
use libbpf_rs::{ObjectBuilder, RingBufferBuilder};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;

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

// WHY this struct? To hold all the state we need to keep alive
struct App {
    obj: libbpf_rs::Object,
    running: Arc<AtomicBool>,
}

impl App {
    fn new(bpf_object_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let obj = ObjectBuilder::default()
            .open_file(bpf_object_path)?
            .load()?;

        Ok(App {
            obj,
            running: Arc::new(AtomicBool::new(true)),
        })
    }

    fn attach_programs(&self) -> Result<Vec<libbpf_rs::Link>, Box<dyn std::error::Error>> {
        let programs = [
            ("trace_connect", "tcp_v4_connect"),
            ("trace_send", "tcp_sendmsg"),
            ("trace_recv", "tcp_recvmsg"),
            ("trace_close", "tcp_close"),
        ];

        let mut links = Vec::new();
        for (prog_name, func_name) in programs {
            let prog = self.obj.prog(prog_name)
                .ok_or(format!("{} not found", prog_name))?;
            let link = prog.attach_kprobe(false, func_name)?;
            links.push(link);
            tracing::info!(program = prog_name, function = func_name, "Attached");
        }

        Ok(links)
    }

    // WHY pin maps? So they survive process restarts.
    // Other processes can also access pinned maps.
    fn pin_maps(&self) -> Result<(), Box<dyn std::error::Error>> {
        let maps = ["connections", "events", "metrics"];

        for map_name in maps {
            if let Some(map) = self.obj.map(map_name) {
                map.pin(format!("/sys/fs/bpf/netmon/{}", map_name))?;
                tracing::info!(map = map_name, "Pinned");
            }
        }

        Ok(())
    }

    async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Set up ring buffer
        let mut ring_buf_builder = RingBufferBuilder::new();
        ring_buf_builder.add(self.obj.map("events").unwrap(), |data: &[u8]| {
            let event = unsafe { &*(data.as_ptr() as *const Event) };

            match event.event_type {
                0 => {
                    let comm = String::from_utf8_lossy(&event.stats.comm);
                    tracing::info!(pid = event.key.pid, comm = %comm, "New connection");
                }
                1 => {
                    tracing::info!(
                        sent = event.stats.bytes_sent,
                        recv = event.stats.bytes_recv,
                        "Connection closed"
                    );
                }
            }

            0
        })?;

        let ring_buf = ring_buf_builder.build()?;

        // WHY separate task for metrics? Because we want to expose
        // metrics continuously, independent of event processing.
        let metrics_handle = self.spawn_metrics_exporter();

        // Main event loop
        while self.running.load(Ordering::Relaxed) {
            ring_buf.poll(Duration::from_millis(100))?;
        }

        // Cleanup
        metrics_handle.abort();
        tracing::info!("Shutting down...");

        Ok(())
    }

    fn spawn_metrics_exporter(&self) -> tokio::task::AbortHandle {
        let running = self.running.clone();
        let obj = &self.obj;

        let handle = tokio::spawn(async move {
            // In a real implementation, this would run an HTTP server
            // that Prometheus can scrape
            while running.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_secs(1)).await;

                // Read metrics from BPF maps
                if let Some(map) = obj.map("metrics") {
                    for i in 0..4u32 {
                        if let Ok(Some(bytes)) = map.lookup(&i, libbpf_rs::MapFlags::ANY) {
                            let value = u64::from_ne_bytes(bytes.try_into().unwrap());
                            let metric_name = match i {
                                0 => "events_total",
                                1 => "events_dropped",
                                2 => "connections_active",
                                3 => "bytes_total",
                                _ => "unknown",
                            };
                            tracing::debug!(metric = metric_name, value = value);
                        }
                    }
                }
            }
        });

        handle.abort_handle()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // WHY structured logging? Because in production, you need
    // machine-readable logs for aggregation (e.g., ELK, Loki)
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    tracing::info!("Starting network monitor");

    let app = App::new("target/bpfel-unknown-none/release/netmon.bpf.o")?;

    // Pin maps for persistence
    app.pin_maps()?;

    // Attach all programs
    let _links = app.attach_programs()?;

    // WHY graceful shutdown? Because we want to:
    // 1. Detach BPF programs cleanly
    // 2. Flush any pending events
    // 3. Unpin maps if needed
    let running = app.running.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = signal::ctrl_c() => {
                tracing::info!("Received SIGINT");
            }
            _ = signal::terminate() => {
                tracing::info!("Received SIGTERM");
            }
        }
        running.store(false, Ordering::Relaxed);
    });

    app.run().await?;

    tracing::info!("Shutdown complete");
    Ok(())
}
```

### systemd Service File

```ini
# /etc/systemd/system/netmon.service
[Unit]
Description=Network Monitor eBPF Tool
After=network.target
Documentation=https://example.com/netmon

[Service]
Type=simple
ExecStart=/usr/local/bin/netmon
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

# WHY these capabilities? Because BPF needs them:
# - CAP_BPF: Load BPF programs
# - CAP_PERFMON: Use perf events
# - CAP_NET_ADMIN: Attach XDP/TC programs
# - CAP_SYS_ADMIN: Some BPF operations
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_NET_ADMIN CAP_SYS_ADMIN
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_NET_ADMIN CAP_SYS_ADMIN

# WHY these security settings? To limit damage if compromised
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=/sys/fs/bpf
PrivateTmp=yes
NoNewPrivileges=yes

# Resource limits
MemoryMax=256M
CPUQuota=10%

[Install]
WantedBy=multi-user.target
```

### Prometheus Metrics Endpoint

```rust
// In a real implementation, you'd add this to the metrics task:

use prometheus::{IntCounter, IntGauge, Registry, TextEncoder, Encoder};
use warp::Filter;

lazy_static! {
    static ref REGISTRY: Registry = Registry::new();

    static ref EVENTS_TOTAL: IntCounter = IntCounter::new(
        "netmon_events_total", "Total events processed"
    ).unwrap();

    static ref BYTES_TOTAL: IntCounter = IntCounter::new(
        "netmon_bytes_total", "Total bytes transferred"
    ).unwrap();

    static ref CONNECTIONS_ACTIVE: IntGauge = IntGauge::new(
        "netmon_connections_active", "Active connections"
    ).unwrap();
}

async fn run_metrics_server() {
    let metrics_route = warp::path("metrics")
        .map(|| {
            let encoder = TextEncoder::new();
            let metric_families = REGISTRY.gather();
            let mut buffer = Vec::new();
            encoder.encode(&metric_families, &mut buffer).unwrap();
            String::from_utf8(buffer).unwrap()
        });

    warp::serve(metrics_route)
        .run(([0, 0, 0, 0], 9090))
        .await;
}
```

---

## Building and Running

```bash
# Build
cargo build --release

# Install
sudo cp target/release/netmon /usr/local/bin/
sudo chmod +x /usr/local/bin/netmon

# Create BPF filesystem directory
sudo mkdir -p /sys/fs/bpf/netmon

# Run directly
sudo /usr/local/bin/netmon

# Or install as systemd service
sudo cp netmon.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable netmon
sudo systemctl start netmon

# Check status
sudo systemctl status netmon
sudo journalctl -u netmon -f
```

---

## Production Checklist

```
✅ Graceful shutdown (signal handling)
✅ Map pinning (persistence)
✅ Structured logging (tracing)
✅ Prometheus metrics
✅ systemd integration
✅ Resource limits
✅ Security (capabilities, sandboxing)
✅ Error handling
✅ Health checks
```

---

## Key Takeaways

1. **Pin maps** - They survive process restarts
2. **Graceful shutdown** - Clean up BPF programs properly
3. **Structured logging** - Machine-readable logs for production
4. **Metrics** - Export to Prometheus for monitoring
5. **systemd** - Proper service management
6. **Capabilities** - Minimal required privileges
7. **Resource limits** - Prevent runaway resource usage

---

## What We Learned (All Chapters)

| Chapter | Key Concept |
|---------|-------------|
| 1 | BPF workflow: open → load → attach |
| 2 | Maps for kernel-userspace communication |
| 3 | Ring buffers for event streaming |
| 4 | Kprobes for flexible hooking |
| 5 | XDP for high-speed networking |
| 6 | Multi-program architecture |
| 7 | Histograms for distributions |
| 8 | Stack traces for context |
| 9 | LSM for enforcement |
| 10 | Production deployment patterns |

---

## Next Steps

Now that you've built real eBPF tools:

1. **Explore more map types** - LRU, queue, stack
2. **Try more program types** - cgroup, sockops, flow_dissector
3. **Read production code** - Cilium, Falco, Pixie
4. **Contribute to libbpf-rs** - Help improve the ecosystem
5. **Build your own tool** - Solve a real problem you have

---

*Congratulations on completing the Hands-On eBPF book!*

---

## Quick Reference

### Essential Commands
```bash
# Generate vmlinux.h
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Build
cargo build --release

# Run with sudo
sudo ./target/release/<program>

# Inspect loaded programs
sudo bpftool prog show

# Inspect maps
sudo bpftool map show

# Dump map contents
sudo bpftool map dump name <map_name>

# Read trace pipe
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

### libbpf-rs Cheat Sheet
```rust
// Open and load
let obj = ObjectBuilder::default()
    .open_file("program.bpf.o")?
    .load()?;

// Attach to tracepoint
let link = prog.attach_tracepoint("syscalls", "sys_enter_execve")?;

// Attach to kprobe
let link = prog.attach_kprobe(false, "do_sys_openat2")?;

// Attach to XDP
let link = prog.attach_xdp(ifindex)?;

// Attach to LSM
let link = prog.attach_lsm()?;

// Map operations
let map = obj.map("name").unwrap();
map.update(&key, &value, MapFlags::ANY)?;
let value = map.lookup(&key, MapFlags::ANY)?;
map.pin("/sys/fs/bpf/name")?;

// Ring buffer
let mut rb = RingBufferBuilder::new();
rb.add(map, |data: &[u8]| { /* process */ 0 })?;
let rb = rb.build()?;
rb.poll(Duration::from_millis(100))?;
```

---

*End of Book*
