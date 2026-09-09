# Chapter 15: Advanced Topics & Production Deployment

## What This Chapter Covers

- Production-grade eBPF tool lifecycle management
- Advanced CO-RE patterns and kernel version compatibility
- Testing strategies, verifier integration, and debugging
- Resource management, privilege separation, and hardening
- **Why:** Building eBPF tools that work in production requires attention to reliability, maintainability, and operational patterns beyond just getting a program to load.

---

## 15.1 Production Tool Lifecycle

### Load → Attach → Run → Update → Detach → Unload

A production eBPF tool follows this lifecycle:

| Phase | Action | Key considerations |
|-------|--------|-------------------|
| **1. Load** | `bpftool prog load` or libbpf `open/load` | Verify dependencies (clang, libbpf, BTF); check `RLIMIT_MEMLOCK`; ensure `CAP_BPF` |
| **2. Attach** | `bpftool prog attach` or link API | Verify hook availability; handle attachment failures gracefully; attach correct program type |
| **3. Run** | Event loop, map polling, signal handling | Keep program loaded; handle SIGINT/SIGTERM; periodic health checks |
| **4. Update** | Map reconfiguration, program replacement | Hot-reload maps without detaching; use BPF_NOEXIST for atomic updates; avoid disrupting traffic |
| **5. Detach** | `bpf_prog_detach` or link drop | Detach before unloading; avoid zombie programs; cleanup FDs |
| **6. Unload** | `bpftool prog unload` | Ensure no other process references the program; clean map FDs |

### Example: Graceful shutdown pattern

```c
#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <libbpf/libbpf.h>

static volatile bool running = 1;

static void sig_handler(int sig)
{
    running = 0;
}

int main(void)
{
    struct bpf_object *obj;
    int err;

    // Signal handling
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Open and load BPF object
    err = bump_memlock_rlimit();
    if (err) {
        fprintf(stderr, "Cannot increase RLIMIT_MEMLOCK: %s\n", strerror(err));
        return 1;
    }

    err = libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    if (err) {
        fprintf(stderr, "Failed to set strict mode: %d\n", err);
        return 1;
    }

    obj = libbpf_object__open("my_tool");
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    err = libbpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        goto out;
    }

    // Attach programs (using link API for auto-cleanup)
    // ... attach programs ...

    // Main loop
    while (running) {
        // Poll maps, process events, etc.
        usleep(100000);  // 100ms
    }

    // Cleanup: link destruction auto-detaches programs
    // (or explicit detach if not using link API)

out:
    libbpf_object__close(obj);
    return 0;
}
```

---

## 15.2 Map Management in Production

### Dynamic map updates

Maps can be updated from userspace while the eBPF program is running:

```c
// Add entry to LRU hash map
int key = 12345;
__u64 value = 999;
bpf_map_update_elem(map_fd, &key, &value, BPF_NOEXIST);

// Update existing entry
bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);

// Remove entry
bpf_map_delete_elem(map_fd, &key);

// Iterate and scan
struct key = 0;
struct key_next;
while (bpf_map_get_next_key(map_fd, &key, &key_next) == 0) {
    // Process key_next
    key = key_next;
}
```

### Map type selection for production

| Map type | Production use case |
|----------|--------------------|
| `HASH` | Counters, per-key data, LRU cache |
| `PERCPU_ARRAY` | Per-CPU statistics, no locking |
| `LRU_HASH` | Cache with automatic eviction, TTL |
| `QUEUE` | FIFO event queue, multi-producer |
| `RINGBUF` | Event streaming to userspace (always paired with poll) |

### Map size guidance

- Start conservative: `max_entries: 256` or `1024`
- Monitor actual usage via `bpftool map dump`
- Increase if "map full" errors appear
- For per-CPU: `max_entries: 1` (the count is per-CPU, not total)

---

## 15.3 Testing eBPF Programs

### Unit testing (host-level)

Since eBPF programs run in kernel, unit testing is done on the userspace side:

```c
// Test that the BPF object loads correctly
void test_load(void) {
    struct bpf_object *obj;
    int err;
    
    obj = libbpf_object__open("program.bpf.o");
    if (!obj) {
        fprintf(stderr, "FAIL: cannot open BPF object\n");
        return;
    }
    
    err = libbpf_object__load(obj);
    if (err) {
        fprintf(stderr, "FAIL: cannot load BPF object: %d\n", err);
        libbpf_object__close(obj);
        return;
    }
    
    printf("PASS: BPF object loaded successfully\n");
    libbpf_object__close(obj);
}
```

### Verifier error testing

```bash
# Test that verifier rejects bad program
sudo bpftool prog load bad_program.bpf.o /sys/fs/bpf/test 2>&1

# Expected output contains verifier rejection reasons
# e.g., "verifier rejected program: unbounded loop"
```

### Integration testing

| Test type | What it verifies |
|-----------|-----------------|
| **Load test** | Program loads on target kernel version |
| **Attach test** | Program attaches to expected hook |
| **Functional test** | Program correctly traces/filters target |
| **Stress test** | Program runs under high event rate without crashes |
| **Unload test** | Program detaches cleanly, no kernel impact |

### Automated testing framework (example)

```bash
#!/bash
# test_ebpf.sh - automated eBPF program testing

set -e

PROGRAM="my_tracer"
KERNEL_VERSION=$(uname -r)

# 1. Build
make -C /path/to/source clean all || { echo "BUILD FAILED"; exit 1; }

# 2. Load program
if sudo bpftool prog load ${PROGRAM}.bpf.o /sys/fs/bpf/${PROGRAM} 2>/dev/null; then
    echo "PASS: Program loaded on kernel ${KERNEL_VERSION}"
else
    echo "FAIL: Program failed to load on kernel ${KERNEL_VERSION}"
    exit 1
fi

# 3. Verify program is running
if sudo bpftool prog show | grep -q "${PROGRAM}"; then
    echo "PASS: Program is attached"
else
    echo "FAIL: Program not found in loaded progs"
    sudo bpftool prog load --remove ${PROGRAM}.bpf.o 2>/dev/null || true
    exit 1
fi

# 4. Run functional test (5 seconds)
timeout 5s sudo ./${PROGRAM} || true

# 5. Unload
sudo bpftool prog unload ${PROGRAM} 2>/dev/null || true

echo "TEST PASSED on kernel ${KERNEL_VERSION}"
```

---

## 15.4 Debugging eBPF Programs

### Verifier logs

The verifier produces detailed error logs when a program is rejected:

```bash
# Load with verbose output
sudo bpftool prog load program.bpf.o /sys/fs/bpf/test verbose

# Or via libbpf
# Logs appear in dmesg
dmesg | grep -i "BPF\|verifier\|prog load"
```

### Common verifier errors and fixes

| Error | Cause | Fix |
|-------|-------|-----|
| `unbounded loop` | `for (;;) {}` or `while(1)` without break | Add bounded counter, use `unroll` pragma, or restructure |
| `potential out-of-bounds access` | Array index not proven within `max_entries` | Use correct key type; verify key space |
| `unsafe pointer arithmetic` | Casting between pointer sizes | Use `bpf_probe_read` family instead |
| `uninitialized variable` | Register used before set | Initialize all registers before use |
| `verifier rejected program (size)` | Too many instructions (>1M) | Refactor into smaller helper functions |
| `function is not available` | Helper/kprobe target doesn't exist on this kernel | Use CO-RE/BTF; check kernel version |

### Debugging tools

| Tool | Purpose |
|------|---------|
| `bpftool prog show --json` | Program info, BTF, loaded state |
| `bpftool map dump name <map>` | Map contents, current values |
| `sudo cat /sys/kernel/debug/tracing/trace_pipe` | Kernel trace output (if using tracepoint prints) |
| `bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h` | Generate BTF for debugging |
| `clang -target bpf -g -c -O2 program.bpf.c -o /dev/null 2>&1` | Compile-check without loading |
| `bpftrace -e 'probe { ... }' 2>&1` | bpftrace alternative for testing |

### Printk for eBPF debugging

```c
// Limited printf for eBPF debugging
// Uses perf buffer or ring buffer to send to userspace
```

bpf_trace_printk is the standard way:

```c
SEC("kprobe/sys_open")
int trace_open(struct pt_regs *ctx)
{
    bpf_trace_printk("open called: comm=%s pid=%d\n",
                     bpf_get_current_comm(),
                     bpf_get_current_pid_tgid() >> 32);
    return 0;
}
```

**Limitation**: `bpf_trace_printk` adds overhead and uses a special debug ring buffer. Use sparingly in production.

### Data-driven debugging

Instead of printk, update a map that userspace can inspect:

```c
// Instead of bpf_trace_printk, update a counter map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} call_count SEC(".maps");

// In the program:
count = bpf_map_lookup_elem(&call_count, &key);
if (count)
    __sync_fetch_and_add(count, 1);
```

Userspace then reads the map via `bpftool map dump` — no runtime overhead for printk.

---

## 15.5 Privilege and Security Hardening

### Capability requirements

| Operation | Required capability |
|-----------|--------------------|
| Load BPF program | `CAP_BPF` (Linux 5.9+) |
| Attach kprobe/kretprobe | `CAP_BPF` + process had `CAP_SYS_PTRACE` historically |
| Attach XDP to interface | `CAP_NET_RAW` + interface must be up |
| Attach LSM hooks | `CAP_BPF` (root typically required) |
| Modify BPF maps | `CAP_BPF` + appropriate map permissions |
| Unload program | `CAP_BPF` + program must not be actively running on other CPUs |

### Running with minimal privileges

```bash
# Create a capability-privileged user
sudo useradd -m -s /usr/sbin/nologger ebpf_user

# Grant only BPF capability
sudo setcap cap_ep+ebpf /path/to/ebpf_tool

# Or use capabilities(7) directly
# setcap cap_bpf+ep /usr/local/bin/my_ebpf_tool
```

### Secure deployment patterns

| Pattern | Description |
|---------|-------------|
| **Sidecar pattern** | Deploy eBPF tool as container sidecar with `CAP_BPF` only |
| **Init script** | Load/attach eBPF programs during container/k8s startup, then drop privileges |
| **Operator pattern** | Single privileged instance manages BPF objects for all workers |
| **Feature flag** | Enable eBPF tracing only when explicitly configured |

### BPF filter and restrict

Some kernels support BPF restrictions via `bpf_set_affinity()` or map filtering, but these are kernel-version-dependent. The safest approach is capability dropping after initialization.

---

## 15.6 Summary

| Area | Key Takeaway |
|------|--------------|
| **Lifecycle** | Load → Attach → Run → Update → Detach → Unload; use link API for auto-cleanup |
| **Map management** | Dynamic updates possible; choose type based on contention pattern; monitor sizes |
| **Testing** | Build → Load → Attach → Functional → Stress → Unload; automate with scripts |
| **Debugging** | Verifier logs are primary source; prefer map-based debugging over printk |
| **Privileges** | `CAP_BPF` is minimum; drop other capabilities after init; use capability-dedicated users |
| **Production readiness** | Test on target kernels; verify map sizes; implement graceful shutdown; monitor overhead |

---

## 15.7 Looking Ahead

Congratulations! You've now completed the comprehensive eBPF learning journey from Linux systems programming fundamentals through advanced eBPF development. Chapter 16 provides a **final consolidated project** that ties together everything you've learned — building a complete production-grade observability tool from scratch.

*Next: [Chapter 16 — Final Project: Production Observability Tool](./16-final-project.md)*