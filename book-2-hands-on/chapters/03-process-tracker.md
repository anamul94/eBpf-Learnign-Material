# Chapter 3: Process Tracker - Hash Maps and Ring Buffers

## What We're Building

A program that tracks process executions and streams events (PID, UID, process name) to userspace in real-time.

**Why this project?** Because real tools need to:
1. Track multiple entities (hash map)
2. Stream events efficiently (ring buffer)

This chapter introduces the two most important map types.

---

## The Complete Code

### src/bpf/process.bpf.c

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16

// This struct will be shared between kernel and userspace.
// Why #[repr(C)] in Rust? Because C and Rust have different struct layouts.
// repr(C) makes Rust use the same layout as C.
struct event {
    __u32 pid;
    __u32 uid;
    char comm[TASK_COMM_LEN];
    __u64 timestamp;
};

// WHY RING BUFFER?
// - We want to stream events to userspace as they happen
// - Ring buffer is designed for this: producer (kernel) writes,
//   consumer (userspace) reads
// - It handles backpressure: if userspace is slow, old events get overwritten
// - More efficient than perf buffer (no per-CPU allocation)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  // 256 KB ring buffer
} events SEC(".maps");

SEC("tp/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;

    // Reserve space in the ring buffer
    // Why reserve first? Because we need memory to write the event.
    // If buffer is full, this returns NULL.
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;  // Buffer full, skip this event

    // Fill the event
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Submit the event
    // Why separate reserve and submit? Because reserve might fail (buffer full).
    // If we can't reserve, we just skip the event.
    bpf_ringbuf_submit(e, 0);

    return 0;
}

char _license[] SEC("license") = "GPL";
```

**The ring buffer explained:**

`bpf_ringbuf_reserve(&events, sizeof(*e), 0)` - Reserve space for our event. **Why reserve?** Because we need a place to write the data. Returns NULL if buffer is full.

`bpf_ringbuf_submit(e, 0)` - Make the event available to userspace. **Why not write directly?** Because reserve/submit lets us skip events if the buffer is full, rather than blocking.

**Why 256 KB?** Big enough to handle bursts, small enough to not waste memory. Ring buffers are power-of-2 sized.

### src/main.rs

```rust
use libbpf_rs::{ObjectBuilder, RingBufferBuilder};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

mod bpf {
    include!("bpf/process.skel.rs");
}

// Must match the C struct exactly!
// Why repr(C)? So Rust uses the same memory layout as C.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct Event {
    pid: u32,
    uid: u32,
    comm: [u8; 16],
    timestamp: u64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    // Open and load
    let obj = ObjectBuilder::default()
        .open_file("target/bpfel-unknown-none/release/process.bpf.o")?;
    let obj = obj.load()?;

    // Attach program
    let prog = obj.prog("trace_execve").ok_or("Program not found")?;
    let _link = prog.attach_tracepoint("syscalls", "sys_enter_execve")?;

    // Set up ring buffer
    // Why RingBufferBuilder? Because it handles the callback-based API
    // that libbpf uses for ring buffers.
    let mut ring_buf_builder = RingBufferBuilder::new();

    // Add our map and a callback for when events arrive
    ring_buf_builder.add(obj.map("events").unwrap(), |data: &[u8]| {
        // This callback runs for each event
        // Why unsafe? Because we're interpreting raw bytes as a struct.
        let event = unsafe { &*(data.as_ptr() as *const Event) };

        let comm = String::from_utf8_lossy(&event.comm);
        println!("PID={} UID={} COMM={}", event.pid, event.uid, comm);

        0  // Return 0 to continue
    })?;

    let ring_buf = ring_buf_builder.build()?;

    println!("Tracking process executions... Press Ctrl+C to exit.\n");

    // Poll the ring buffer
    while running.load(Ordering::SeqCst) {
        // Poll with 100ms timeout
        ring_buf.poll(Duration::from_millis(100))?;
    }

    Ok(())
}
```

**The userspace code explained:**

`#[repr(C)]` - **Critical!** This makes Rust use C's struct layout. Without this, the kernel data won't match our struct.

`RingBufferBuilder` - Sets up callbacks for ring buffer events. **Why callbacks?** Because libbpf uses a poll-based model - we provide a function to call when data arrives.

`ring_buf.poll(...)` - Check for new events. **Why poll?** Because ring buffer is non-blocking. We poll in a loop to process events as they arrive.

---

## Building and Running

```bash
cargo build --release
sudo ./target/release/process
```

Output:
```
Tracking process executions... Press Ctrl+C to exit.

PID=1234 UID=1000 COMM=bash
PID=1235 UID=1000 COMM=ls
PID=1236 UID=1000 COMM=cat
PID=1237 UID=1000 COMM=gcc
```

---

## Why Two Map Types?

In this chapter we used:
1. **Ring buffer** - For streaming events
2. (We'll add hash maps next for state)

**When to use which:**

| Use Case | Map Type | Why |
|----------|----------|-----|
| Stream events to userspace | Ring buffer | Efficient, handles backpressure |
| Store state per-entity | HashMap | Flexible keys, dynamic |
| Simple counters | Array | Fastest, fixed size |
| Per-CPU counters | PerCpuArray/Hash | No locking |

---

## Ring Buffer vs Perf Buffer

| Feature | Ring Buffer | Perf Buffer |
|---------|-------------|-------------|
| Memory | Shared ring | Per-CPU buffers |
| Ordering | FIFO | Per-CPU ordering |
| Overwrite | Old events lost | Can drop if full |
| API | Simple reserve/submit | More complex |
| Kernel | 5.8+ | 4.1+ |

**Why ring buffer is usually better:** Simpler API, shared memory, better for most use cases.

---

## Try It Yourself

1. **Add a hash map for process counts** - Track how many times each process has been executed:
   ```c
   struct {
       __uint(type, BPF_MAP_TYPE_HASH);
       __uint(max_entries, 10000);
       __type(key, __u32);      // PID
       __type(value, __u64);    // Count
   } process_counts SEC(".maps");
   ```

2. **Filter by UID** - Only trace processes from your UID:
   ```c
   __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   if (uid != 1000)  // Change to your UID
       return 0;
   ```

3. **Add the filename** - Read the filename from `ctx->args[0]`:
   ```c
   const char *filename = (const char *)ctx->args[0];
   // Note: You'd need a bigger event struct to include filename
   ```

---

## Common Mistakes

**Struct layout mismatch** - If your Rust struct doesn't match the C struct exactly, you'll get garbage data. Always use `#[repr(C)]`.

**Forgetting to poll** - If you don't call `ring_buf.poll()`, you'll never see events.

**Buffer too small** - If you see events getting dropped, increase `max_entries`.

**Not handling NULL from reserve** - If the buffer is full, `bpf_ringbuf_reserve` returns NULL. Always check.

---

*Next: [Chapter 4 - File Monitor with Kprobes](../chapters/04-file-monitor.md)*
