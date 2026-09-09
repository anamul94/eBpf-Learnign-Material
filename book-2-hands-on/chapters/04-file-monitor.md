# Chapter 4: File Monitor - Kprobes and Safe Memory Access

## What We're Building

A program that monitors file opens and logs which process opened which file.

**Why this project?** Because:
1. Tracepoints are limited - not every kernel function has one
2. Kprobes let us hook ANY kernel function
3. We need to safely read userspace memory (filenames)

---

## The Complete Code

### src/bpf/filemon.bpf.c

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define PATH_MAX 256
#define TASK_COMM_LEN 16

struct event {
    __u32 pid;
    __u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[PATH_MAX];
    __u64 timestamp;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// WHY KPROBE instead of tracepoint?
// - Not every kernel function has a tracepoint
// - Kprobes can hook ANY non-inline kernel function
// - More flexible, but less stable (function names can change)
//
// WHY do_sys_openat2?
// - This is the kernel function that handles open() syscalls
// - We use the actual kernel function name, not a tracepoint
SEC("kprobe/do_sys_openat2")
int BPF_KPROBE(trace_do_sys_openat2, int dfd, const char *filename,
               struct open_how *how)
{
    struct event *e;

    // Reserve ring buffer space
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    // Get process info
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // WHY bpf_probe_read_user_str?
    // - filename is a pointer to userspace memory
    // - Kernel can't directly access userspace memory (security!)
    // - bpf_probe_read_user_str safely copies it to kernel space
    // - Returns bytes read, or negative on error
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
```

**The kprobe explained:**

`SEC("kprobe/do_sys_openat2")` - Attach to the kernel function `do_sys_openat2`. **Why kprobe?** Because there's no tracepoint for every function. Kprobes work by inserting a breakpoint at the function entry.

`BPF_KPROBE(trace_do_sys_openat2, int dfd, const char *filename, ...)` - This macro makes it easy to access function arguments. **Why a macro?** Because it handles the architecture-specific work of reading arguments from registers.

`bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename)` - **Critical!** This safely copies a string from userspace to kernel space. **Why not just dereference the pointer?** Because:
1. Userspace memory might be paged out
2. The pointer might be invalid
3. Direct access would crash the kernel

### src/main.rs

```rust
use libbpf_rs::{ObjectBuilder, RingBufferBuilder};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

mod bpf {
    include!("bpf/filemon.skel.rs");
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Event {
    pid: u32,
    uid: u32,
    comm: [u8; 16],
    filename: [u8; 256],
    timestamp: u64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    let obj = ObjectBuilder::default()
        .open_file("target/bpfel-unknown-none/release/filemon.bpf.o")?;
    let obj = obj.load()?;

    // WHY attach_kprobe instead of attach_tracepoint?
    // Because we're hooking a kernel function, not a tracepoint.
    // attach_kprobe takes the function name (without the kprobe/ prefix)
    let prog = obj.prog("trace_do_sys_openat2").ok_or("Program not found")?;
    let _link = prog.attach_kprobe(false, "do_sys_openat2")?;
    //                       ^^^^^
    //                       false = kprobe (entry), true = kretprobe (exit)

    let mut ring_buf_builder = RingBufferBuilder::new();
    ring_buf_builder.add(obj.map("events").unwrap(), |data: &[u8]| {
        let event = unsafe { &*(data.as_ptr() as *const Event) };

        let comm = String::from_utf8_lossy(&event.comm);
        let filename = String::from_utf8_lossy(&event.filename);

        println!("PID={} UID={} COMM={} FILE={}",
                 event.pid, event.uid, comm, filename);

        0
    })?;

    let ring_buf = ring_buf_builder.build()?;

    println!("Monitoring file opens... Press Ctrl+C to exit.\n");

    while running.load(Ordering::SeqCst) {
        ring_buf.poll(Duration::from_millis(100))?;
    }

    Ok(())
}
```

**The attachment explained:**

`prog.attach_kprobe(false, "do_sys_openat2")` - Attach to function entry. **Why false?** Because:
- `false` = kprobe (function entry)
- `true` = kretprobe (function exit)

**Why would we want kretprobe?** To measure how long a function took, or to see its return value.

---

## Building and Running

```bash
cargo build --release
sudo ./target/release/filemon
```

Output:
```
Monitoring file opens... Press Ctrl+C to exit.

PID=1234 UID=1000 COMM=cat FILE=/etc/hosts
PID=1235 UID=1000 COMM=ls FILE=/home/user
PID=1236 UID=1000 COMM=gcc FILE=main.c
PID=1236 UID=1000 COMM=gcc FILE=/usr/include/stdio.h
```

---

## Kprobe vs Tracepoint

| Feature | Tracepoint | Kprobe |
|---------|------------|--------|
| Stability | Stable ABI | May break across kernels |
| Coverage | Limited points | Any non-inline function |
| Performance | Slightly faster | Slightly slower (breakpoint) |
| Arguments | Pre-parsed | Raw (need to extract) |
| Use when | Available | No tracepoint exists |

**Rule of thumb:** Use tracepoints when available, kprobes when you need more flexibility.

---

## Safe Memory Access

**Why can't we just dereference userspace pointers?**

```c
// WRONG - will crash or be rejected by verifier
char *filename = (char *)PT_REGS_PARM2(ctx);
bpf_printk("%s\n", filename);  // CRASH!

// RIGHT - use helper to safely copy
char filename[256];
bpf_probe_read_user_str(filename, sizeof(filename), ptr);
```

**The helpers:**
- `bpf_probe_read_kernel(dst, size, src)` - Read kernel memory
- `bpf_probe_read_user(dst, size, src)` - Read userspace memory
- `bpf_probe_read_user_str(dst, size, src)` - Read userspace string

**Why separate kernel/user?** Because they have different address spaces and page tables.

---

## Try It Yourself

1. **Measure open() latency** - Use both kprobe and kretprobe:
   ```c
   // Store entry time in hash map
   SEC("kprobe/do_sys_openat2")
   int BPF_KPROBE(trace_entry, int dfd, const char *filename, ...) {
       __u64 pid = bpf_get_current_pid_tgid();
       __u64 ts = bpf_ktime_get_ns();
       bpf_map_update_elem(&start, &pid, &ts, BPF_ANY);
       return 0;
   }

   // Calculate duration on exit
   SEC("kretprobe/do_sys_openat2")
   int BPF_KRETPROBE(trace_exit, int ret) {
       __u64 pid = bpf_get_current_pid_tgid();
       __u64 *start = bpf_map_lookup_elem(&start, &pid);
       if (start) {
           __u64 duration = bpf_ktime_get_ns() - *start;
           // Report duration...
       }
       return 0;
   }
   ```

2. **Filter by filename** - Only report opens of specific files:
   ```c
   // After reading filename
   if (filename[0] != '/' || filename[1] != 'e')  // Not /etc/...
       return 0;
   ```

3. **Track per-file open counts** - Use a hash map with filename as key.

---

## Common Mistakes

**"Function not found"** - The kernel function name might differ across versions. Check with:
```bash
sudo cat /proc/kallsyms | grep do_sys_open
```

**Verifier rejects your program** - Usually means you're accessing memory unsafely. Always use `bpf_probe_read_*`.

**Reading garbage strings** - Make sure your buffer is large enough and null-terminated.

**Kprobe doesn't fire** - The function might be inlined. Try a different function or use tracepoints.

---

*Next: [Chapter 5 - XDP Firewall](../chapters/05-xdp-firewall.md)*
