# Chapter 2: Syscall Counter - Your First Map

## What We're Building

A program that counts how many times `execve` is called and prints the count every 5 seconds.

**Why this project?** Because maps are how kernel and userspace communicate. Without maps, BPF programs can only print messages. With maps, they can store data we can read later.

---

## The Complete Code

### src/bpf/counter.bpf.c

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// This is a map. Think of it as a key-value store that both
// kernel (BPF program) and userspace (Rust) can access.
//
// Why BPF_MAP_TYPE_ARRAY?
// - We only need one counter (key is always 0)
// - Array is the fastest map type (direct index, no hashing)
// - Perfect for single-value counters
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);      // Only 1 entry (key=0)
    __type(key, __u32);          // Key type
    __type(value, __u64);        // Value type (64-bit counter)
} counter SEC(".maps");          // SEC(".marks") puts it in the maps section

SEC("tp/syscalls/sys_enter_execve")
int count_execve(struct trace_event_raw_sys_enter *ctx)
{
    __u32 key = 0;
    __u64 *val;

    // Look up the counter
    // Why check for NULL? Because the key might not exist yet.
    val = bpf_map_lookup_elem(&counter, &key);
    if (!val)
        return 0;  // Key not found, skip

    // Increment the counter
    // Why __sync_fetch_and_add? Because it's atomic.
    // Multiple CPUs might call this simultaneously.
    __sync_fetch_and_add(val, 1);

    return 0;
}

char _license[] SEC("license") = "GPL";
```

**The map declaration explained:**

`__uint(type, BPF_MAP_TYPE_ARRAY)` - What kind of map. **Why ARRAY?** Because we have exactly one entry, and arrays have O(1) lookup with no hashing overhead.

`__uint(max_entries, 1)` - Maximum entries. We only need one counter.

`__type(key, __u32)` - Key type. We use key=0 always since there's only one entry.

`__type(value, __u64)` - Value type. 64-bit so the counter won't overflow quickly.

`SEC(".maps")` - Tells the compiler to put this in the maps section. libbpf looks here to create maps.

**The program explained:**

`bpf_map_lookup_elem(&counter, &key)` - Find the value for key=0. Returns a pointer so we can modify it in-place. **Why a pointer?** Because BPF programs run in kernel space - we modify the actual map value directly.

`__sync_fetch_and_add(val, 1)` - Atomically add 1. **Why atomic?** Because multiple CPUs might execute this program simultaneously for different processes. Without atomic, we'd lose counts.

### src/main.rs

```rust
use libbpf_rs::ObjectBuilder;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

mod bpf {
    include!("bpf/counter.skel.rs");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    // Open and load
    let obj = ObjectBuilder::default()
        .open_file("target/bpfel-unknown-none/release/counter.bpf.o")?;
    let obj = obj.load()?;

    // Attach the program
    let prog = obj.prog("count_execve").ok_or("Program not found")?;
    let _link = prog.attach_tracepoint("syscalls", "sys_enter_execve")?;

    println!("Counting execve calls... Press Ctrl+C to exit.\n");

    // Every 5 seconds, read the counter from the map
    while running.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_secs(5));

        // Get the map by name
        let map = obj.map("counter").ok_or("Map not found")?;

        // Read the value for key 0
        let key: u32 = 0;
        let value = map.lookup(&key, libbpf_rs::MapFlags::ANY)?;

        match value {
            Some(bytes) => {
                // Convert bytes to u64
                let count = u64::from_ne_bytes(bytes.try_into().unwrap());
                println!("execve called {} times in last 5 seconds", count);
            }
            None => {
                println!("No data yet");
            }
        }
    }

    Ok(())
}
```

**The userspace code explained:**

`obj.map("counter")` - Get a handle to our map by name. **Why by name?** Because the skeleton knows the names from our BPF code.

`map.lookup(&key, ...)` - Read the value for key=0. Returns `Option<Vec<u8>>`. **Why bytes?** Because maps store raw bytes - we need to interpret them.

`u64::from_ne_bytes(...)` - Convert the bytes back to a u64. **Why from_ne_bytes?** Because the kernel stores values in native byte order.

---

## Building and Running

```bash
cargo build --release
sudo ./target/release/counter
```

Output:
```
Counting execve calls... Press Ctrl+C to exit.

execve called 12 times in last 5 seconds
execve called 8 times in last 5 seconds
execve called 45 times in last 5 seconds
```

---

## Why Maps Matter

Without maps, BPF can only:
- Print messages (bpf_printk)
- Drop/allow packets (XDP)

With maps, BPF can:
- Store state across program invocations
- Communicate with userspace
- Share data between different BPF programs
- Make decisions based on history

**Maps are the primary communication channel between kernel and userspace.**

---

## Map Types Cheat Sheet

| Map Type | When to Use | Why |
|----------|-------------|-----|
| `BPF_MAP_TYPE_ARRAY` | Fixed-size lookup tables | Fastest, O(1) by index |
| `BPF_MAP_TYPE_HASH` | Dynamic key-value store | Flexible keys, grows as needed |
| `BPF_MAP_TYPE_PERCPU_ARRAY/Hash` | Per-CPU counters | No locking needed |
| `BPF_MAP_TYPE_RINGBUF` | Streaming events | Efficient producer-consumer |
| `BPF_MAP_TYPE_LRU_HASH` | Caches | Auto-evicts old entries |

---

## Try It Yourself

1. **Count a different syscall** - Change to `sys_enter_read` to count read calls.

2. **Count per-PID** - Use a hash map with PID as key:
   ```c
   struct {
       __uint(type, BPF_MAP_TYPE_HASH);
       __uint(max_entries, 10000);
       __type(key, __u32);      // PID
       __type(value, __u64);    // Count
   } pid_count SEC(".maps");
   ```

3. **Use a per-CPU array** - No need for atomics:
   ```c
   struct {
       __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
       __uint(max_entries, 1);
       __type(key, __u32);
       __type(value, __u64);
   } counter SEC(".maps");
   ```
   Then just do `*val += 1` (no atomic needed!).

---

## Common Mistakes

**"Map not found"** - Make sure the map name in `obj.map("counter")` matches the name in your C code.

**Wrong byte size** - If your value type changes, you must update both the C and Rust sides.

**Forgetting NULL check** - `bpf_map_lookup_elem` returns NULL if key doesn't exist. Always check.

**Not using atomics** - Without `__sync_fetch_and_add`, you'll lose counts on multi-core systems.

---

*Next: [Chapter 3 - Process Tracker](../chapters/03-process-tracker.md)*
