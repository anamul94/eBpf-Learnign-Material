# Chapter 22: Production Deployment

## What This Chapter Covers

- eBPF in production environments
- Lifecycle management
- Privilege model and security
- Deployment patterns
- Monitoring eBPF programs
- Troubleshooting production issues
- Real-world case studies

---

## 22.1 Production Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                 PRODUCTION eBPF ARCHITECTURE                │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  eBPF Tool Daemon                                   │   │
│  │  - Loads and manages eBPF programs                  │   │
│  │  - Handles lifecycle (start/stop/upgrade)           │   │
│  │  - Exports metrics and events                       │   │
│  └─────────────────────────────────────────────────────┘   │
│                            │                                │
│                            ▼                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  eBPF Programs                                      │   │
│  │  - Attached to kernel hooks                         │   │
│  │  - Run in kernel space                              │   │
│  │  - Communicate via maps                             │   │
│  └─────────────────────────────────────────────────────┘   │
│                            │                                │
│                            ▼                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Monitoring & Observability                         │   │
│  │  - Prometheus metrics                               │   │
│  │  - Grafana dashboards                               │   │
│  │  - Alerting                                         │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 22.2 Lifecycle Management

### 22.2.1 Starting eBPF Programs

```rust
use std::process::Command;

struct EbpfManager {
    programs: Vec<String>,
}

impl EbpfManager {
    fn load_program(&mut self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let output = Command::new("bpftool")
            .args(&["prog", "load", path, "/sys/fs/bpf/program"])
            .output()?;

        if !output.status.success() {
            return Err(format!(
                "Failed to load: {}",
                String::from_utf8_lossy(&output.stderr)
            ).into());
        }

        self.programs.push(path.to_string());
        Ok(())
    }

    fn attach_tracepoint(&self, prog_fd: i32, category: &str, name: &str) -> Result<(), Box<dyn std::error::Error>> {
        let tp_id = self.get_tracepoint_id(category, name)?;

        let output = Command::new("bpftool")
            .args(&["prog", "attach", &prog_fd.to_string(),
                   "tracepoint", &tp_id.to_string()])
            .output()?;

        if !output.status.success() {
            return Err("Failed to attach".into());
        }

        Ok(())
    }

    fn get_tracepoint_id(&self, category: &str, name: &str) -> Result<i32, Box<dyn std::error::Error>> {
        let format_path = format!(
            "/sys/kernel/debug/tracing/events/{}/{}",
            category, name
        );

        let id_str = std::fs::read_to_string(format_path + "/id")?;
        Ok(id_str.trim().parse()?)
    }
}
```

### 22.2.2 Graceful Shutdown

```rust
use tokio::signal;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

struct ProductionApp {
    bpf: Bpf,
    running: Arc<AtomicBool>,
}

impl ProductionApp {
    async fn run(&self) -> Result<(), anyhow::Error> {
        let running = self.running.clone();

        // Handle signals
        let signal_handle = tokio::spawn(async move {
            tokio::select! {
                _ = signal::ctrl_c() => {
                    println!("Received SIGINT");
                }
                _ = signal::terminate() => {
                    println!("Received SIGTERM");
                }
            }
            running.store(false, Ordering::SeqCst);
        });

        // Main event loop
        while self.running.load(Ordering::Relaxed) {
            // Process events
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        // Cleanup
        signal_handle.await?;
        self.cleanup()?;

        Ok(())
    }

    fn cleanup(&self) -> Result<(), anyhow::Error> {
        // Programs are automatically detached when Bpf is dropped
        println!("Cleaning up eBPF programs");
        Ok(())
    }
}
```

---

## 22.3 Privilege Model

### 22.3.1 Required Capabilities

```rust
use caps::Capability;

fn check_privileges() -> Result<(), Box<dyn std::error::Error>> {
    let caps = caps::read(None, Capability::Effective)?;

    let required = &[
        Capability::CAP_BPF,
        Capability::CAP_PERFMON,
        Capability::CAP_NET_ADMIN,
        Capability::CAP_SYS_ADMIN,
    ];

    for cap in required {
        if !caps.contains(cap) {
            eprintln!("Missing capability: {:?}", cap);
        }
    }

    Ok(())
}
```

### 22.3.2 Setting Capabilities

```bash
# Set capabilities on binary
sudo setcap cap_bpf,cap_perfmon,cap_net_admin,cap_sys_admin+ep /usr/local/bin/my-ebpf-tool

# Verify
getcap /usr/local/bin/my-ebpf-tool
```

### 22.3.3 systemd Service

```ini
# /etc/systemd/system/my-ebpf-tool.service
[Unit]
Description=My eBPF Tool
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/my-ebpf-tool
Restart=on-failure
RestartSec=5

# Privileges
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_NET_ADMIN CAP_SYS_ADMIN
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_NET_ADMIN CAP_SYS_ADMIN

# Security
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=/sys/fs/bpf
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

---

## 22.4 Deployment Patterns

### 22.4.1 DaemonSet (Kubernetes)

```yaml
# daemonset.yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: ebpf-monitor
spec:
  selector:
    matchLabels:
      app: ebpf-monitor
  template:
    metadata:
      labels:
        app: ebpf-monitor
    spec:
      hostNetwork: true
      hostPID: true
      containers:
      - name: ebpf-monitor
        image: my-registry/ebpf-monitor:latest
        securityContext:
          privileged: true
        volumeMounts:
        - name: bpffs
          mountPath: /sys/fs/bpf
        - name: debugfs
          mountPath: /sys/kernel/debug
          readOnly: true
        resources:
          requests:
            memory: "64Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "500m"
      volumes:
      - name: bpffs
        hostPath:
          path: /sys/fs/bpf
      - name: debugfs
        hostPath:
          path: /sys/kernel/debug
```

### 22.4.2 Systemd Timer for Periodic Tasks

```ini
# /etc/systemd/system/ebpf-report.timer
[Unit]
Description=Run eBPF report every 5 minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target

# /etc/systemd/system/ebpf-report.service
[Unit]
Description=Generate eBPF report

[Service]
Type=oneshot
ExecStart=/usr/local/bin/ebpf-report
```

---

## 22.5 Monitoring eBPF Programs

### 22.5.1 Prometheus Metrics

```rust
use prometheus::{IntCounter, IntGauge, Registry, TextEncoder, Encoder};

lazy_static! {
    static ref REGISTRY: Registry = Registry::new();

    static ref EBPF_EVENTS_TOTAL: IntCounter = IntCounter::new(
        "ebpf_events_total", "Total eBPF events"
    ).unwrap();

    static ref EBPF_MAP_ENTRIES: IntGauge = IntGauge::new(
        "ebpf_map_entries", "Number of entries in eBPF map"
    ).unwrap();
}

fn register_metrics() {
    REGISTRY.register(Box::new(EBPF_EVENTS_TOTAL.clone())).unwrap();
    REGISTRY.register(Box::new(EBPF_MAP_ENTRIES.clone())).unwrap();
}

async fn metrics_server() -> Result<(), anyhow::Error> {
    let app = warp::path("metrics")
        .map(|| {
            let encoder = TextEncoder::new();
            let metric_families = REGISTRY.gather();
            let mut buffer = Vec::new();
            encoder.encode(&metric_families, &mut buffer).unwrap();
            String::from_utf8(buffer).unwrap()
        });

    warp::serve(app).run(([0, 0, 0, 0], 9090)).await;
    Ok(())
}
```

### 22.5.2 Health Checks

```rust
use std::time::Instant;

struct HealthStatus {
    last_event: Instant,
    events_processed: u64,
    errors: u64,
}

impl HealthStatus {
    fn is_healthy(&self) -> bool {
        // Healthy if we've seen events recently
        self.last_event.elapsed() < Duration::from_secs(60)
    }
}

async fn health_check(status: Arc<RwLock<HealthStatus>>) -> impl warp::Reply {
    let status = status.read().await;

    if status.is_healthy() {
        warp::reply::with_status("OK", warp::http::StatusCode::OK)
    } else {
        warp::reply::with_status("UNHEALTHY", warp::http::StatusCode::SERVICE_UNAVAILABLE)
    }
}
```

---

## 22.6 Troubleshooting Production Issues

### 22.6.1 Common Production Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| Program won't load | Kernel version mismatch | Use CO-RE, check BTF |
| High CPU usage | Too many events | Add filtering, rate limiting |
| Memory growth | Map not cleaning up | Use LRU maps, periodic cleanup |
| Events lost | Ring buffer full | Increase buffer size, faster processing |
| Permission denied | Missing capabilities | Set proper capabilities |
| Program detached | Interface down | Re-attach on interface up |

### 22.6.2 Diagnostic Script

```bash
#!/bin/bash
# diagnose-ebpf.sh - Diagnose eBPF issues

echo "=== eBPF Diagnostic Report ==="
echo "Date: $(date)"
echo ""

echo "--- Kernel Version ---"
uname -r
echo ""

echo "--- BPF Config ---"
cat /proc/config.gz 2>/dev/null | gunzip | grep CONFIG_BPF || echo "Config not available"
echo ""

echo "--- BPF JIT ---"
sysctl net.core.bpf_jit_enable
echo ""

echo "--- Loaded Programs ---"
sudo bpftool prog show 2>/dev/null || echo "bpftool not available"
echo ""

echo "--- Loaded Maps ---"
sudo bpftool map show 2>/dev/null || echo "bpftool not available"
echo ""

echo "--- BPF Stats ---"
cat /proc/bpf_stats 2>/dev/null || echo "BPF stats not available"
echo ""

echo "--- Recent Kernel Messages ---"
dmesg | grep -i bpf | tail -20
echo ""

echo "=== End of Report ==="
```

---

## 22.7 Real-World Case Studies

### 22.7.1 Cilium — Container Networking

- Uses **XDP** and **TC** for high-performance networking
- **eBPF maps** for service load balancing
- **CO-RE** for portability across kernel versions
- Runs as **DaemonSet** in Kubernetes

### 22.7.2 Falco — Security Monitoring

- Uses **kprobes** and **traceps** for syscall monitoring
- **Ring buffer** for event streaming
- **LSM hooks** for enforcement
- **Rules engine** in userspace

### 22.7.3 Pixie — Application Observability

- Uses **kprobes** for HTTP/gRPC tracing
- **Perf events** for CPU profiling
- **CO-RE** for deployment flexibility
- **In-cluster** data collection

---

## 22.8 Best Practices Summary

### Development
- ✅ Use CO-RE for portability
- ✅ Test on multiple kernel versions
- ✅ Handle all error cases
- ✅ Minimize instruction count

### Deployment
- ✅ Use minimal required capabilities
- ✅ Pin maps for persistence
- ✅ Implement graceful shutdown
- ✅ Monitor resource usage

### Operations
- ✅ Export Prometheus metrics
- ✅ Implement health checks
- ✅ Set up log aggregation
- ✅ Create runbooks for common issues

---

## 22.9 Summary

- **Lifecycle management** for starting/stopping programs
- **Privilege model** with capabilities
- **Deployment patterns**: DaemonSet, systemd
- **Monitoring** with Prometheus metrics
- **Health checks** for reliability
- **Troubleshooting** common production issues

---

## 22.10 Conclusion

You've completed this comprehensive guide to eBPF with Rust, C, and libpf-rs. You now have the knowledge to:

1. **Understand** how eBPF works inside the kernel
2. **Write** eBPF programs in both C and Rust
3. **Use** libpf-rs for userspace integration
4. **Build** production-grade observability and security tools
5. **Deploy** eBPF tools in real-world environments

The eBPF ecosystem continues to evolve rapidly. Keep learning, experimenting, and contributing to this exciting technology.

---

*Congratulations on completing the book!*

---

## Quick Reference

### Essential Commands
```bash
# Generate kernel headers
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Compile eBPF program
clang -target bpf -g -O2 -c program.bpf.c -o program.bpf.o

# Generate skeleton
bpftool gen skeleton program.bpf.o > program.skel.h

# Load and inspect
bpftool prog load program.o /sys/fs/bpf/prog verbose
bpftool prog show
bpftool map show
bpftool prog dump xlated name prog_name
```

### Rust eBPF Build
```bash
# Add BPF target
rustup target add bpfel-unknown-none

# Build eBPF program
cargo build --target bpfel-unknown-none --release

# Build userspace
cargo build --release
```

### Useful Resources
- [eBPF Documentation](https://ebpf.io/)
- [Aya Documentation](https://aya-rs.dev/)
- [libbpf GitHub](https://github.com/libbpf/libbpf)
- [bpftool Man Pages](https://man7.org/linux/man-pages/man8/bpftool.8.html)
- [eBPF Mailing List](https://lore.kernel.org/bpf/)

---

*End of Book*
