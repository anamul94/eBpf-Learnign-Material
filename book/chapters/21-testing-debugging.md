# Chapter 21: Testing and Debugging eBPF Programs

## What This Chapter Covers

- Unit testing eBPF programs
- Integration testing strategies
- Debugging with bpf_printk
- Using bpftool for debugging
- Verifier log analysis
- Common bugs and solutions
- Continuous integration for eBPF

---

## 21.1 Testing Challenges

eBPF programs are hard to test because:
1. They run in kernel space (crash the kernel if buggy)
2. They require specific kernel versions
3. They interact with kernel internals
4. Traditional testing frameworks don't apply

**Solutions:**
- **Unit testing** with mock BPF helpers
- **Integration testing** on real/simulated kernels
- **Static analysis** with verifier
- **Runtime monitoring** with bpftool

---

## 21.2 Unit Testing with Mock Helpers

### 21.2.1 Rust Unit Tests

```rust
// tests/unit_tests.rs
#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    // Mock BPF map for testing
    struct MockMap<K, V> {
        data: HashMap<K, V>,
    }

    impl<K: Eq + std::hash::Hash + Copy, V: Copy> MockMap<K, V> {
        fn new() -> Self {
            MockMap { data: HashMap::new() }
        }

        fn lookup(&self, key: &K) -> Option<&V> {
            self.data.get(key)
        }

        fn insert(&mut self, key: K, value: V) {
            self.data.insert(key, value);
        }

        fn remove(&mut self, key: &K) {
            self.data.remove(key);
        }
    }

    #[test]
    fn test_counter_increment() {
        let mut counter = MockMap::<u32, u64>::new();

        // Simulate BPF program logic
        let key = 0;
        let val = counter.lookup(&key).unwrap_or(&0);
        counter.insert(key, val + 1);

        assert_eq!(*counter.lookup(&key).unwrap(), 1);
    }

    #[test]
    fn test_connection_tracking() {
        let mut connections = MockMap::<ConnKey, ConnStats>::new();

        let key = ConnKey {
            saddr: 0x0100007f,
            daddr: 0x01000080,
            sport: 8080,
            dport: 443,
            pid: 1234,
        };

        let stats = ConnStats {
            bytes_sent: 1000,
            bytes_recv: 2000,
            ..Default::default()
        };

        connections.insert(key, stats);
        assert_eq!(connections.lookup(&key).unwrap().bytes_sent, 1000);
    }
}
```

---

## 21.3 Integration Testing

### 21.3.1 Testing with Real eBPF Loading

```rust
// tests/integration_tests.rs
use aya::Bpf;
use std::fs;

const TEST_PROGRAM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/target/bpfel-unknown-none/release/test-program"
));

#[test]
fn test_program_loads() {
    let result = Bpf::load(TEST_PROGRAM);
    assert!(result.is_ok(), "Failed to load BPF program");
}

#[test]
fn test_program_attaches() {
    let mut bpf = Bpf::load(TEST_PROGRAM).expect("Failed to load");

    let program = bpf.program_mut("test_program");
    assert!(program.is_some(), "Program not found");

    let program = program.unwrap();
    let result = program.load();
    assert!(result.is_ok(), "Failed to load program");
}

#[test]
fn test_map_operations() -> Result<(), anyhow::Error> {
    let bpf = Bpf::load(TEST_PROGRAM)?;

    // Test map access
    let map = bpf.map("test_map").ok_or("Map not found")?;
    // Perform map operations...

    Ok(())
}
```

### 21.3.2 VM-Based Testing

```yaml
# .github/workflows/test.yml
name: eBPF Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y clang llvm libelf-dev linux-headers-$(uname -r)

      - name: Install Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
          target: bpfel-unknown-none

      - name: Build eBPF program
        run: cd ebpf && cargo build --target bpfel-unknown-none --release

      - name: Run unit tests
        run: cargo test

      - name: Run integration tests (requires sudo)
        run: |
          sudo -E cargo test --test integration_tests -- --ignored
```

---

## 21.4 Debugging with bpf_printk

### 21.4.1 C Debugging

```c
// Debug with bpf_printk
SEC("kprobe/do_sys_open")
int trace_open(struct pt_regs *ctx) {
    const char *filename = (const char *)PT_REGS_PARM2(ctx);

    // Print debug message
    bpf_printk("do_sys_open called: filename=%p\n", filename);

    char name[64];
    bpf_probe_read_user_str(name, sizeof(name), filename);
    bpf_printk("filename=%s\n", name);

    return 0;
}
```

### 21.4.2 Rust Debugging

```rust
use aya_log_ebpf::info;
use aya_bpf::programs::ProbeContext;

#[kprobe]
pub fn do_sys_open(ctx: ProbeContext) -> u32 {
    let filename: *const u8 = ctx.arg(1).unwrap_or(std::ptr::null());

    info!(&ctx, "do_sys_open called: filename={:x}", filename as usize);

    // Read and log filename
    let mut name = [0u8; 64];
    let ret = unsafe { bpf_probe_read_user_str(&mut name, name.len() as u32, filename) };
    if ret > 0 {
        info!(&ctx, "filename={}", core::str::from_utf8(&name));
    }

    0
}
```

### 21.4.3 Reading Debug Output

```bash
# Read bpf_printk output
sudo cat /sys/kernel/debug/tracing/trace_pipe

# Clear the buffer
sudo echo > /sys/kernel/debug/tracing/trace

# Enable tracing
sudo echo 1 > /sys/kernel/debug/tracing/tracing_on
```

---

## 21.5 Debugging with bpftool

### 21.5.1 Inspect Loaded Programs

```bash
# List all loaded programs
sudo bpftool prog show

# Show detailed program info
sudo bpftool prog show id 42 --json

# Dump program instructions
sudo bpftool prog dump xlated id 42

# Dump JIT-compiled code
sudo bpftool prog dump jited id 42

# Show verifier log for a program
sudo bpftool prog load program.o /sys/fs/bpf/test verbose
```

### 21.5.2 Inspect Maps

```bash
# List all maps
sudo bpftool map show

# Show map details
sudo bpftool map show id 10 --json

# Dump map contents
sudo bpftool map dump id 10

# Lookup specific key
sudo bpftool map lookup id 10 key 0x00 0x00 0x00 0x00

# Update map entry
sudo bpftool map update id 10 key 0x00 0x00 0x00 0x00 value 0x01
```

### 21.5.3 Inspect BTF

```bash
# Show BTF types for a program
sudo bpftool btf dump prog id 42

# Show kernel BTF types
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format raw | head -100

# Show kernel BTF for a specific type
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c | grep "struct task_struct"
```

---

## 21.6 Verifier Log Analysis

### 21.6.1 Understanding Verifier Errors

```bash
# Load with verbose output
sudo bpftool prog load program.o /sys/fs/bpf/test verbose 2>&1

# Example output:
# 0: (b7) r1 = 1
# 1: (15) if r1 == 0x0 goto pc+2
# 2: (b7) r0 = 0
# 3: (95) exit
# 4: (79) r2 = *(u64 *)(r1 + 0)
# invalid access to map value, value_size=8 off=0 size=8
# R0 type=inv expected=map_value
```

### 21.6.2 Common Verifier Issues

```c
// Issue 1: Missing NULL check
__u64 *val = bpf_map_lookup_elem(&map, &key);
// *val += 1;  // ERROR: val might be NULL

// Fix:
if (val)
    *val += 1;

// Issue 2: Uninitialized register
__u32 x;
// if (x == 42) {}  // ERROR: x not initialized

// Fix:
__u32 x = 0;

// Issue 3: Out of bounds access
struct event e;
// e.data[256] = 0;  // ERROR: beyond struct size

// Fix:
// e.data[255] = 0;  // Within bounds
```

---

## 21.7 Debugging Tips

### 21.7.1 Start Simple

```c
// Start with minimal program
SEC("xdp")
int minimal(struct xdp_md *ctx) {
    bpf_printk("XDP program triggered\n");
    return XDP_PASS;
}

// Verify it loads and runs
// Then add complexity incrementally
```

### 21.7.2 Use Conditional Debugging

```c
#ifdef DEBUG
    #define bpf_debug(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
    #define bpf_debug(fmt, ...)
#endif

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    bpf_debug("Processing packet\n");
    // ... actual logic ...
    return XDP_PASS;
}
```

### 21.7.3 Test with Known Inputs

```bash
# Generate test traffic
ping -c 10 192.168.1.1

# Monitor eBPF output
sudo cat /sys/kernel/debug/tracing/trace_pipe &

# Run test
sudo ./my_ebpf_tool
```

---

## 21.8 Common Bugs and Solutions

| Bug | Cause | Solution |
|-----|-------|----------|
| "R0 type=inv expected=map_value" | Missing NULL check | Add NULL check before dereference |
| "invalid access to map value" | Out of bounds access | Check offset < value_size |
| "back-edge from insn X to Y" | Unbounded loop | Add constant loop bound |
| "BPF program is too large" | Too many instructions | Use tail calls or simplify |
| "helper call is not allowed" | Wrong helper for program type | Check helper availability |
| "Permission denied" | Missing capabilities | Run as root or add capabilities |
| Program doesn't trigger | Wrong attachment point | Verify tracepoint/kprobe name |

---

## 21.9 Summary

- **Unit testing** with mock BPF helpers
- **Integration testing** on real kernels
- **bpf_printk** for runtime debugging
- **bpftool** for inspection and analysis
- **Verifier log** for understanding errors
- **Start simple** and add complexity incrementally

---

## 21.10 Looking Ahead

Chapter 22 covers **production deployment** — lifecycle management, privilege model, and real-world patterns.

---

*Next: [Chapter 22 — Production Deployment](./22-production.md)*
