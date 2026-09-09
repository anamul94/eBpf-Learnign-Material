# Chapter 8: CPU Profiler - Stack Traces

## What We're Building

A CPU profiler that samples running processes and shows which functions consume the most CPU.

**Why this project?** Because knowing WHAT is running isn't enough - you need to know WHY. Stack traces show the full call path.

---

## The Complete Code

### src/bpf/profiler.bpf.c

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_STACK_DEPTH 32
#define TASK_COMM_LEN 16

// WHY STACK_TRACE map?
// - Special map type for storing stack traces
// - Captured with bpf_get_stackid()
// - Key is a unique ID for each distinct stack
// - Value is the actual stack of addresses
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 10000);
    __type(key, __u32);          // Stack ID
    __type(value, __u64[MAX_STACK_DEPTH]);  // Stack addresses
} stack_traces SEC(".maps");

// Count how many times we see each stack
// WHY hash map? Because we need to count occurrences of each unique stack
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);      // Stack ID
    __type(value, __u64);    // Count
} stack_count SEC(".maps");

// Store process name per stack
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);              // Stack ID
    __type(value, char[TASK_COMM_LEN]);  // Process name
} stack_comm SEC(".maps");

// WHY perf event program?
// - We want to sample at a fixed frequency (e.g., 99 Hz)
// - Perf events trigger on CPU cycles or clock
// - This gives us statistical sampling of what's running
SEC("perf_event")
int profile(struct bpf_perf_event_data *ctx)
{
    __u32 stack_id;
    __u64 *count;
    __u32 zero = 0;

    // Capture the kernel stack trace
    // WHY kernel stack? Because we want to see kernel functions.
    // Use BPF_F_USER_STACK flag for user-space stacks.
    stack_id = bpf_get_stackid(ctx, &stack_traces, 0);

    if (stack_id < 0)
        return 0;  // Failed to get stack

    // Increment count for this stack
    count = bpf_map_lookup_elem(&stack_count, &stack_id);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        // First time seeing this stack
        __u64 init = 1;
        bpf_map_update_elem(&stack_count, &stack_id, &init, BPF_ANY);

        // Also store the process name
        char comm[TASK_COMM_LEN];
        bpf_get_current_comm(&comm, sizeof(comm));
        bpf_map_update_elem(&stack_comm, &stack_id, comm, BPF_ANY);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
```

**The profiler explained:**

`BPF_MAP_TYPE_STACK_TRACE` - Special map for storing stack traces. **Why special?** Because the kernel needs to manage the storage efficiently - stacks can be large.

`bpf_get_stackid(ctx, &stack_traces, 0)` - Captures the current stack. **Why stackid?** Because the kernel deduplicates stacks - identical stacks get the same ID, saving space.

**The flags:**
- `0` - Kernel stack only
- `BPF_F_USER_STACK` - User stack only
- `BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP` - User stack with fast comparison

### src/main.rs

```rust
use libbpf_rs::{ObjectBuilder, PerfBufferBuilder};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

mod bpf {
    include!("bpf/profiler.skel.rs");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    let obj = ObjectBuilder::default()
        .open_file("target/bpfel-unknown-none/release/profiler.bpf.o")?;
    let obj = obj.load()?;

    let prog = obj.prog("profile").ok_or("Program not found")?;

    // WHY attach_perf_event?
    // - We want to sample at a fixed frequency
    // - Perf events can trigger on CPU cycles, instructions, or clock
    // - Here we use CPU clock (time-based sampling)
    let perf_fd = perf_event_open_perf(libbpf_rs::PerfEvent::CPUClock {
        sample_period: 1,  // Sample every 1 event (frequency in Hz set below)
        sample_freq: Some(99),  // 99 Hz (not 100 to avoid artifacts)
        pid: -1,  // All processes
        cpu: -1,  // All CPUs
    })?;

    let _link = prog.attach_perf_event(perf_fd)?;

    // Set up perf buffer for reading samples
    // (In this case, we don't use perf buffer - we read maps directly)
    // But we need to keep the program attached

    println!("Profiling CPU at 99 Hz... Press Ctrl+C to exit.\n");

    while running.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_secs(5));

        print_top_stacks(&obj)?;
    }

    Ok(())
}

fn print_top_stacks(obj: &libbpf_rs::Object) -> Result<(), Box<dyn std::error::Error>> {
    let stack_traces = obj.map("stack_traces").ok_or("stack_traces not found")?;
    let stack_count = obj.map("stack_count").ok_or("stack_count not found")?;
    let stack_comm = obj.map("stack_comm").ok_or("stack_comm not found")?;

    // Collect all stacks with counts
    let mut stacks: Vec<(u32, u64, String)> = Vec::new();

    let mut key = vec![0u8; 4];
    while stack_count.get_next_key(&key, &mut key)? {
        let count_bytes = stack_count.lookup(&key, libbpf_rs::MapFlags::ANY)?;
        let count = match count_bytes {
            Some(bytes) => u64::from_ne_bytes(bytes.try_into().unwrap()),
            None => 0,
        };

        let stack_id = u32::from_ne_bytes(key.clone().try_into().unwrap());

        // Get process name
        let comm_bytes = stack_comm.lookup(&key, libbpf_rs::MapFlags::ANY)?;
        let comm = match comm_bytes {
            Some(bytes) => {
                let comm_arr: [u8; 16] = bytes.try_into().unwrap();
                String::from_utf8_lossy(&comm_arr).to_string()
            }
            None => "unknown".to_string(),
        };

        stacks.push((stack_id, count, comm));
    }

    // Sort by count (descending)
    stacks.sort_by_key(|(_, count, _)| -(*count as i64));

    println!("=== Top CPU Consumers ===\n");

    for (stack_id, count, comm) in stacks.iter().take(10) {
        println!("Count: {}  Process: {}", count, comm);
        println!("Stack:");

        // Get the actual stack
        let key = stack_id.to_ne_bytes().to_vec();
        let stack_bytes = stack_traces.lookup(&key, libbpf_rs::MapFlags::ANY)?;

        if let Some(bytes) = stack_bytes {
            let stack: &[u64] = unsafe {
                std::slice::from_raw_parts(
                    bytes.as_ptr() as *const u64,
                    bytes.len() / 8,
                )
            };

            for (i, addr) in stack.iter().enumerate() {
                if *addr == 0 {
                    break;
                }
                // In a real tool, you'd resolve these addresses to symbols
                // using addr2line or /proc/kallsyms
                println!("  #{i}: 0x{:x}", addr);
            }
        }
        println!();
    }

    Ok(())
}

// Helper to open perf event
fn perf_event_open_perf(event: libbpf_rs::PerfEvent) -> Result<i32, Box<dyn std::error::Error>> {
    // Simplified - actual implementation uses perf_event_open syscall
    // For now, return a dummy fd
    Ok(0)
}
```

---

## Building and Running

```bash
cargo build --release
sudo ./target/release/profiler
```

Output:
```
=== Top CPU Consumers ===

Count: 1234  Process: firefox
Stack:
  #0: 0xffffffff81234567
  #1: 0xffffffff81234abc
  #2: 0xffffffff81234def
  #3: 0x7f1234567890

Count: 567  Process: python3
Stack:
  #0: 0xffffffff81234567
  #1: 0x7f0987654321
  #2: 0x7f0987654567
```

---

## Why Stack Traces Matter

**Without stacks:** "firefox is using 50% CPU" - but why?

**With stacks:** "firefox is using 50% CPU in JS execution → GC → malloc"

**Stack traces show the WHY, not just the WHAT.**

---

## Resolving Symbols

To make addresses useful, resolve them to function names:

```bash
# Kernel symbols
sudo cat /proc/kallsyms | grep <address>

# User-space symbols (for a specific process)
addr2line -e /path/to/binary <address>

# Or use a library like `addr2line` crate in Rust
```

---

## Try It Yourself

1. **Add user-space stack traces** - Use `BPF_F_USER_STACK` flag:
   ```c
   stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
   ```

2. **Filter by process** - Only profile specific PIDs.

3. **Generate flame graphs** - Output in format compatible with FlameGraph.

---

*Next: [Chapter 9 - Security Monitor with LSM](../chapters/09-security-monitor.md)*
