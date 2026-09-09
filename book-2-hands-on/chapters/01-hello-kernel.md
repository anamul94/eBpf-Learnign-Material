# Chapter 1: Hello Kernel!

## What We're Building

A minimal eBPF program that prints "Hello!" every time any process runs `execve()` (which happens whenever you run a command).

**Why start here?** Because the simplest working program teaches us the complete workflow without distractions.

---

## The Complete Code

### Project Structure

```
chapter-01-hello/
├── Cargo.toml
├── build.rs
└── src/
    ├── main.rs
    └── bpf/
        └── hello.bpf.c
```

### Cargo.toml

```toml
[package]
name = "hello"
version = "0.1.0"
edition = "2021"

[dependencies]
libbpf-rs = "0.24"    # The Rust wrapper around libbpf
libc = "0.2"           # For C types
ctrlc = "3"            # For handling Ctrl+C

[build-dependencies]
libbpf-cargo = "0.24"  # Build-time BPF compilation
```

**Why these dependencies?**
- `libbpf-rs` - Safe Rust API for loading BPF programs
- `libbpf-cargo` - Compiles our C code to BPF bytecode at build time
- `ctrlc` - Lets us cleanly exit and detach the BPF program

### build.rs

```rust
use libbpf_cargo::SkeletonBuilder;

fn main() {
    SkeletonBuilder::new()
        .source("src/bpf/hello.bpf.c")
        .build_and_generate("./src/bpf/hello.skel.rs")
        .unwrap();
}
```

**Why do we need a build script?**
1. It compiles `hello.bpf.c` to BPF bytecode (using clang)
2. It generates a Rust "skeleton" file that makes loading easy

The skeleton is auto-generated Rust code that knows about our BPF programs and maps. Without it, we'd have to manually find and load everything.

### src/bpf/hello.bpf.c (Kernel Code)

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("tp/syscalls/sys_enter_execve")
int hello(struct trace_event_raw_sys_enter *ctx)
{
    bpf_printk("Hello from eBPF! execve was called\n");
    return 0;
}

char _license[] SEC("license") = "GPL";
```

**Line by line:**

`#include "vmlinux.h"` - This gives us kernel type definitions. We generate it from the running kernel with `bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h`. **Why?** So we can use kernel structs like `trace_event_raw_sys_enter`.

`#include <bpf/bpf_helpers.h>` - This gives us helper functions like `bpf_printk`. **Why?** Because BPF programs can't call normal C library functions - they can only use kernel-provided helpers.

`SEC("tp/syscalls/sys_enter_execve")` - This tells libbpf where to attach. **Why tracepoints?** Because they're stable - the kernel developers promise not to change them. The format is `tp/category/name`.

`int hello(...)` - This is our program function. It gets called every time the tracepoint fires. The `ctx` parameter contains the tracepoint data (syscall arguments in this case).

`bpf_printk(...)` - Like `printf`, but output goes to `/sys/kernel/debug/tracing/trace_pipe`. **Why not regular printf?** Because there's no stdout in kernel space!

`return 0` - Must return 0 to indicate success.

`char _license[] SEC("license") = "GPL"` - **Required!** Some kernel helpers are only available to GPL programs. Without this, the verifier rejects your program.

### src/main.rs (Userspace Code)

```rust
use libbpf_rs::ObjectBuilder;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

// Include the auto-generated skeleton
mod bpf {
    include!("bpf/hello.skel.rs");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set up Ctrl+C handler for clean exit
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    // Open the BPF object file
    let obj = ObjectBuilder::default()
        .open_file("target/bpfel-unknown-none/release/hello.bpf.o")?;

    // Load into kernel (verifier runs here)
    let obj = obj.load()?;

    // Get our program and attach it
    let prog = obj.prog("hello").ok_or("Program not found")?;
    let _link = prog.attach_tracepoint("syscalls", "sys_enter_execve")?;

    println!("eBPF program loaded! Press Ctrl+C to exit.");
    println!("Run in another terminal:");
    println!("  sudo cat /sys/kernel/debug/tracing/trace_pipe");

    // Keep running until Ctrl+C
    while running.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(100));
    }

    println!("\nDetaching...");
    // _link drops here, automatically detaching the program

    Ok(())
}
```

**Why this flow?**

1. **Open** - Read the BPF object file (the compiled bytecode)
2. **Load** - Submit to kernel. The verifier checks safety here. If your program is unsafe, you get an error.
3. **Attach** - Connect the program to the tracepoint. Only now does it start running.
4. **Keep alive** - If main() exits, the program detaches. We loop until Ctrl+C.

**Why `_link`?** The `attach_*` methods return a `Link` object. When it drops (goes out of scope), the program detaches. We use `_link` to keep it alive. The `_` prefix means "we know it's unused" - but we need it alive!

---

## Building and Running

```bash
# Generate vmlinux.h (do this once)
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Build the project
cargo build --release

# Run (needs root for BPF)
sudo ./target/release/hello
```

In another terminal, watch the output:
```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

Now run some commands - you'll see "Hello from eBPF!" messages!

---

## What We Learned

1. **BPF programs are written in C** (`.bpf.c` files)
2. **Userspace loaders are written in Rust** (using libbpf-rs)
3. **build.rs** compiles BPF and generates skeletons
4. **Tracepoints** are stable kernel hooks
5. **bpf_printk** is how we debug BPF programs
6. **The license declaration is required**
7. **We must keep the program alive** to keep it attached

---

## Try It Yourself

1. **Change the tracepoint** - Try `sys_enter_openat` instead of `sys_enter_execve`. What happens?

2. **Print the PID** - Use `bpf_get_current_pid_tgid()` to print which process called execve:
   ```c
   __u32 pid = bpf_get_current_pid_tgid() >> 32;
   bpf_printk("Hello from PID %d\n", pid);
   ```

3. **Print the filename** - The filename is in `ctx->args[0]`:
   ```c
   const char *filename = (const char *)ctx->args[0];
   char fname[64];
   bpf_probe_read_user_str(fname, sizeof(fname), filename);
   bpf_printk("Process %d is running: %s\n", pid, fname);
   ```

---

## Common Mistakes

**"Program not found"** - Make sure the function name in `obj.prog("hello")` matches your C function name.

**"Permission denied"** - BPF needs root or capabilities. Use `sudo`.

**"Failed to load"** - Check the verifier log. Usually means you forgot a NULL check or accessed memory unsafely.

**No output** - Make sure you're reading from `trace_pipe` in another terminal. Also check that tracing is enabled: `echo 1 | sudo tee /sys/kernel/debug/tracing/tracing_on`

---

*Next: [Chapter 2 - Syscall Counter](../chapters/02-syscall-counter.md)*
