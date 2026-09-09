# Chapter 7: Latency Histogram - Measuring Distributions

## What We're Building

A program that measures block I/O latency and displays it as a histogram.

**Why this project?** Because averages lie. A histogram shows the full distribution - you can see if most requests are fast but some are very slow (tail latency).

---

## The Complete Code

### src/bpf/hist.bpf.c

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// WHY logarithmic buckets?
// - Latency spans nanoseconds to seconds (huge range)
// - Linear buckets would waste space on unused ranges
// - Logarithmic buckets give good resolution at all scales
// - Each bucket covers 2x the range of the previous
#define MAX_SLOTS 32

// WHY ARRAY map for histogram?
// - Fixed number of buckets (known at compile time)
// - Array is fastest map type (direct index)
// - Perfect for histograms where bucket count is fixed
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_SLOTS);
    __type(key, __u32);      // Bucket index
    __type(value, __u64);    // Count
} hist SEC(".maps");

// Store entry timestamps
// WHY hash map? Because we need to track multiple in-flight requests
// (different requests can be pending simultaneously)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u64);      // Request address (unique per request)
    __type(value, __u64);    // Entry timestamp
} start SEC(".maps");

// Calculate log2 bucket for a value
// WHY log2? Because we want buckets that double in size:
// Bucket 0: 1-2 ns
// Bucket 1: 2-4 ns
// Bucket 2: 4-8 ns
// Bucket 3: 8-16 ns
// etc.
static __always_inline __u32 log2l(__u64 val)
{
    __u32 bucket = 0;
    while (val > 1) {
        val >>= 1;
        bucket++;
    }
    return bucket;
}

SEC("kprobe/blk_mq_start_request")
int BPF_KPROBE(trace_start, struct request *req)
{
    __u64 ts = bpf_ktime_get_ns();

    // Store entry time, keyed by request address
    // WHY request address? Because it's unique per request
    // and available in both start and end probes
    bpf_map_update_elem(&start, &req, &ts, BPF_ANY);
    return 0;
}

SEC("kprobe/blk_mq_end_request")
int BPF_KPROBE(trace_end, struct request *req)
{
    __u64 *start_ts;
    __u64 duration, bucket, *count;

    // Look up entry time
    start_ts = bpf_map_lookup_elem(&start, &req);
    if (!start_ts)
        return 0;  // We missed the start (map was full)

    // Calculate duration
    duration = bpf_ktime_get_ns() - *start_ts;

    // Clean up
    bpf_map_delete_elem(&start, &req);

    // Convert to microseconds for better readability
    duration /= 1000;

    // Find the bucket
    bucket = log2l(duration);
    if (bucket >= MAX_SLOTS)
        bucket = MAX_SLOTS - 1;

    // Increment the bucket counter
    count = bpf_map_lookup_elem(&hist, &bucket);
    if (count)
        __sync_fetch_and_add(count, 1);

    return 0;
}

char _license[] SEC("license") = "GPL";
```

**The histogram explained:**

`log2l()` - Calculates which bucket a value belongs to. **Why log2?** Because we want exponentially-sized buckets. This gives us good resolution at both small and large values.

`BPF_MAP_TYPE_ARRAY` - **Why array?** Because we have a fixed number of buckets (32). Arrays have O(1) lookup by index - perfect for histograms.

`start` map - Stores entry timestamps. **Why?** Because we need to match start and end events. We use the request pointer as key since it's unique per request.

### src/main.rs

```rust
use libbpf_rs::ObjectBuilder;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

mod bpf {
    include!("bpf/hist.skel.rs");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    let obj = ObjectBuilder::default()
        .open_file("target/bpfel-unknown-none/release/hist.bpf.o")?;
    let obj = obj.load()?;

    // Attach programs
    let start_prog = obj.prog("trace_start").ok_or("trace_start not found")?;
    let _start_link = start_prog.attach_kprobe(false, "blk_mq_start_request")?;

    let end_prog = obj.prog("trace_end").ok_or("trace_end not found")?;
    let _end_link = end_prog.attach_kprobe(false, "blk_mq_end_request")?;

    println!("Measuring block I/O latency... Press Ctrl+C to exit.\n");

    let map = obj.map("hist").ok_or("Map not found")?;

    while running.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_secs(5));

        // Print histogram
        println!("Block I/O Latency Histogram:");
        println!("{:>12} {:>10}  {}", "Latency (us)", "Count", "Distribution");
        println!("{:>12} {:>10}  {}", "------------", "-----", "------------");

        for bucket in 0..32u32 {
            let value = map.lookup(&bucket, libbpf_rs::MapFlags::ANY)?;
            let count = match value {
                Some(bytes) => u64::from_ne_bytes(bytes.try_into().unwrap()),
                None => 0,
            };

            if count > 0 {
                // Calculate latency range for this bucket
                let low = (1u64 << bucket) / 1000;  // Convert ns to us
                let high = (1u64 << (bucket + 1)) / 1000;

                // Simple ASCII bar
                let bar_len = (count as usize).min(50);
                let bar = "█".repeat(bar_len);

                println!("{:>5} - {:<5} {:>10}  {}", low, high, count, bar);
            }
        }
        println!();
    }

    Ok(())
}
```

---

## Building and Running

```bash
cargo build --release
sudo ./target/release/hist
```

Output:
```
Block I/O Latency Histogram:
  Latency (us)      Count  Distribution
  ------------      -----  ------------
    1 - 2                5  █
    2 - 4               12  ██
    4 - 8               45  █████████
    8 - 16              89  ██████████████████
   16 - 32              67  █████████████
   32 - 64              23  ████
   64 - 128              8  █
  128 - 256              3
  256 - 512              2
 512 - 1024              1
```

**What this tells us:** Most I/O completes in 8-32 microseconds, but there's a long tail - some requests take over 500 microseconds.

---

## Why Histograms Beat Averages

**Average latency:** 45 microseconds (looks fine!)

**Histogram reveals:**
- 80% of requests: < 32 us (fast)
- 15% of requests: 32-128 us (slow)
- 5% of requests: > 128 us (very slow!)

**The average hides the tail.** If you only look at averages, you miss the slow requests that hurt user experience.

---

## Logarithmic Buckets Explained

```
Bucket 0:     1 - 2 us
Bucket 1:     2 - 4 us
Bucket 2:     4 - 8 us
Bucket 3:     8 - 16 us
Bucket 4:    16 - 32 us
Bucket 5:    32 - 64 us
Bucket 6:    64 - 128 us
Bucket 7:   128 - 256 us
Bucket 8:   256 - 512 us
Bucket 9:   512 - 1024 us
Bucket 10: 1024 - 2048 us
...
```

**Why logarithmic?**
- Linear buckets (0-100, 100-200, ...) waste space on empty ranges
- Logarithmic buckets give equal resolution at all scales
- Each bucket covers 2x the range of the previous

---

## Try It Yourself

1. **Measure read vs write latency separately** - Use two histograms:
   ```c
   // Check if it's a read or write
   if (req->cmd_flags & REQ_WRITE)
       bucket += MAX_SLOTS;  // Use upper half for writes
   ```

2. **Track by process** - Use a hash map of histograms (one per PID).

3. **Add a max latency tracker** - Keep track of the slowest request.

---

*Next: [Chapter 8 - CPU Profiler](../chapters/08-cpu-profiler.md)*
