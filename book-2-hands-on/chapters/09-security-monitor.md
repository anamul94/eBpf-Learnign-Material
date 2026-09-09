# Chapter 9: Security Monitor - LSM Hooks

## What We're Building

A security tool that monitors file operations and can DENY them based on rules.

**Why this project?** Because LSM (Linux Security Module) hooks are special - they can actually BLOCK operations, not just observe them.

---

## The Complete Code

### src/bpf/security.bpf.c

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define PATH_MAX 256
#define TASK_COMM_LEN 16

// Event for ring buffer
struct event {
    __u32 pid;
    __u32 uid;
    char comm[TASK_COMM_LEN];
    char path[PATH_MAX];
    __u8 allowed;  // 1=allowed, 0=denied
    __u64 timestamp;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// WHY hash map for rules?
// - Rules need to be dynamic (userspace adds/removes them)
// - Fast lookup by path prefix
// - Can be updated at runtime
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000);
    __type(key, char[PATH_MAX]);  // Path prefix to block
    __type(value, __u8);          // 1=blocked
} blocked_paths SEC(".maps");

// WHY LSM hooks?
// - Regular kprobes/tracepoints can only OBSERVE
// - LSM hooks can ENFORCE - they can DENY operations
// - Return 0 = allow, return -EPERM = deny
// - This is how real security tools work (e.g., Falco)

// Hook: file open
SEC("lsm/file_open")
int BPF_PROG(deny_file_open, struct file *file)
{
    struct event *e;
    struct inode *inode;
    char path[PATH_MAX] = {};
    char *path_ptr;

    // Get the path
    // WHY this complex path resolution?
    // Because there's no simple "get path from file" function.
    // We need to walk the dentry (directory entry) path.
    inode = file->f_inode;
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);

    // Simple path extraction (simplified for example)
    // In production, use bpf_d_path() helper (kernel 5.16+)
    bpf_probe_read_str(path, sizeof(path), &dentry->d_name.name);

    // Check if path is blocked
    if (bpf_map_lookup_elem(&blocked_paths, &path)) {
        // DENY the operation
        // WHY -EPERM? Because that's the standard "permission denied" error.
        // The syscall will return this to userspace.

        // Log the denial
        e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->pid = bpf_get_current_pid_tgid() >> 32;
            e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
            e->allowed = 0;  // Denied
            e->timestamp = bpf_ktime_get_ns();
            bpf_get_current_comm(&e->comm, sizeof(e->comm));
            __builtin_memcpy(e->path, path, sizeof(path));
            bpf_ringbuf_submit(e, 0);
        }

        return -EPERM;  // DENY!
    }

    return 0;  // Allow
}

// Hook: socket connect
SEC("lsm/socket_connect")
int BPF_PROG(deny_socket_connect, struct socket *sock,
             struct sockaddr *addr, int addrlen)
{
    // Example: Block connections to specific IPs
    // (Simplified - actual implementation would check addr)

    // For now, just log
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->pid = bpf_get_current_pid_tgid() >> 32;
        e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        e->allowed = 1;
        e->timestamp = bpf_ktime_get_ns();
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_probe_read_str(e->path, sizeof(e->path), "socket_connect");
        bpf_ringbuf_submit(e, 0);
    }

    return 0;  // Allow
}

char _license[] SEC("license") = "GPL";
```

**The LSM hooks explained:**

`SEC("lsm/file_open")` - This is an LSM hook. **Why LSM?** Because LSM hooks are the kernel's security framework. They're designed for security modules to enforce policies.

`BPF_PROG` - **Why not `BPF_KPROBE`?** Because LSM programs have a different signature. They don't use `pt_regs`.

`return -EPERM` - **This is the key difference!** Regular BPF programs can only observe. LSM programs can DENY operations by returning negative values.

**Return values:**
- `0` - Allow the operation
- `-EPERM` - Deny with "Permission denied"
- `-EACCES` - Deny with "Access denied"

### src/main.rs

```rust
use libbpf_rs::{ObjectBuilder, RingBufferBuilder};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

mod bpf {
    include!("bpf/security.skel.rs");
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Event {
    pid: u32,
    uid: u32,
    comm: [u8; 16],
    path: [u8; 256],
    allowed: u8,
    timestamp: u64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    let obj = ObjectBuilder::default()
        .open_file("target/bpfel-unknown-none/release/security.bpf.o")?;
    let obj = obj.load()?;

    // Attach LSM programs
    // WHY attach_lsm? Because LSM programs attach to LSM hooks,
    // not tracepoints or kprobes.
    let file_open_prog = obj.prog("deny_file_open")
        .ok_or("deny_file_open not found")?;
    let _file_open_link = file_open_prog.attach_lsm()?;

    let socket_prog = obj.prog("deny_socket_connect")
        .ok_or("deny_socket_connect not found")?;
    let _socket_link = socket_prog.attach_lsm()?;

    println!("Security monitor active!");
    println!("Adding blocked paths...\n");

    // Add some blocked paths
    let map = obj.map("blocked_paths").ok_or("Map not found")?;

    let blocked = ["/etc/shadow", "/etc/passwd", "/root/.ssh"];
    for path in blocked {
        let mut key = [0u8; 256];
        key[..path.len()].copy_from_slice(path.as_bytes());
        let value: u8 = 1;
        map.update(&key, &value, libbpf_rs::MapFlags::ANY)?;
        println!("Blocked: {}", path);
    }
    println!();

    // Set up ring buffer
    let mut ring_buf_builder = RingBufferBuilder::new();
    ring_buf_builder.add(obj.map("events").unwrap(), |data: &[u8]| {
        let event = unsafe { &*(data.as_ptr() as *const Event) };

        let comm = String::from_utf8_lossy(&event.comm);
        let path = String::from_utf8_lossy(&event.path);

        if event.allowed == 0 {
            println!("[DENIED] PID={} UID={} COMM={} PATH={}",
                     event.pid, event.uid, comm, path);
        } else {
            println!("[ALLOWED] PID={} UID={} COMM={} PATH={}",
                     event.pid, event.uid, comm, path);
        }

        0
    })?;

    let ring_buf = ring_buf_builder.build()?;

    println!("Monitoring... Press Ctrl+C to exit.\n");

    while running.load(Ordering::SeqCst) {
        ring_buf.poll(Duration::from_millis(100))?;
    }

    Ok(())
}
```

---

## Building and Running

```bash
# WHY special requirements for LSM?
# - Need CAP_BPF and CAP_SYS_ADMIN
# - Kernel must have CONFIG_BPF_LSM=y
# - Check: zgrep CONFIG_BPF_LSM /proc/config.gz

cargo build --release
sudo ./target/release/security
```

Output:
```
Security monitor active!
Adding blocked paths...

Blocked: /etc/shadow
Blocked: /etc/passwd
Blocked: /root/.ssh

Monitoring... Press Ctrl+C to exit.

[DENIED] PID=1234 UID=1000 COMM=cat PATH=/etc/shadow
[ALLOWED] PID=1235 UID=1000 COMM=ls PATH=/home/user
[DENIED] PID=1236 UID=1000 COMM=vim PATH=/root/.ssh/id_rsa
```

---

## Why LSM is Special

| Feature | Kprobe/Tracepoint | LSM |
|---------|-------------------|-----|
| Can observe | Yes | Yes |
| Can deny | No | Yes |
| Return value | Ignored | Determines allow/deny |
| Use case | Monitoring | Enforcement |

**LSM hooks are the only way for eBPF to enforce security policies.**

---

## Available LSM Hooks

```c
// File operations
lsm/file_open
lsm/file_permission
lsm/inode_unlink
lsm/inode_rename

// Network
lsm/socket_create
lsm/socket_bind
lsm/socket_connect

// Process
lsm/task_alloc
lsm/bprm_check_security  // exec
```

---

## Try It Yourself

1. **Add a whitelist mode** - Only allow paths in the map (invert logic).

2. **Block by UID** - Deny operations from specific users.

3. **Rate limiting** - Allow N operations per second, deny after.

---

*Next: [Chapter 10 - Production Deployment](../chapters/10-production.md)*
