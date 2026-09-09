# Chapter 8: eBPF Links & Advanced Attachment

## What This Chapter Covers

- The modern eBPF link API for program attachment and lifecycle management
- How links differ from the older `bpftool`/`libbpf` imperative approach
- Reference counting, automatic cleanup, and error handling
- **Why:** The link API is the recommended way to attach eBPF programs in modern libbpf and Aya-based development. It provides safety guarantees (automatic detachment on close) and a cleaner code pattern than manual `bpftool` commands.

---

## 8.1 Links vs. Imperative Attachment

### Old approach (bpftool / libbpf imperative)

```c
// Manual program management
skel = bpf_object__open_file("prog.o");
bpf_object__load(skel);

// Manual attach (returns FD, must track separately)
prog = bpf_object__find_program_by_title(skel, "sys_enter_execve");
err = bpf_prog_attach(prog->fd, BPF_PROG_TYPE_TRACEPOINT,
                       "syscalls", "sys_enter_execve");
// Manual detach
err = bpf_prog_detach(prog->fd, BPF_PROG_TYPE_TRACEPOINT,
                       "syscalls", "sys_enter_execve");
```

**Problems:**
- Manual FD management (easy to leak FDs)
- No automatic cleanup on process exit
- Error-prone sequence (attach, then forget to detach)
- Hard to integrate with RAII patterns in Rust/C++

### New link approach

```c
// Automatic lifecycle management
struct bpf_link *link;
struct bpf_program *prog = bpf_object__find_program_by_title(skel, "sys_enter_execve");

// Attach returns a link object that owns the reference
link = bpf_program__attach_kprobe(prog, NULL, "do_sys_open");
if (!link) {
    // Attachment failed
    return -errno;
}

// When link goes out of scope (or is freed), it auto-detaches
// No need for explicit bpf_prog_detach()
```

**Advantages:**
- RAII-style resource management
- Automatic detach on close/free
- Integrated error handling
- Works with `bpf_link__destroy()` for explicit cleanup
- Better integration with C++ and Rust

---

## 8.2 Link Types

Different program types use different link creation functions:

| Program Type | Attach Function | Link Object |
|--------------|----------------|-------------|
| **Kprobe** | `bpf_program__attach_kprobe` | `struct bpf_link *` |
| **Kretprobe** | `bpf_program__attach_kretprobe` | `struct bpf_link *` |
| **Tracepoint** | `bpf_program__attach_tracepoint` | `struct bpf_link *` |
| **XDP** | `bpf_program__attach_xdp` | `struct bpf_link *` |
| **cgroup/skb** | `bpf_program__attach_cgroup_skb` | `struct bpf_link *` |
| **LSM** | `bpf_program__attach_lsm` | `struct bpf_link *` |
| **TC (qdisc)** | `bpf_program__attach_tc` | `struct bpf_link *` |

### Link attachment flow (generic)

```c
// 1. Find the program in the BPF object
struct bpf_program *prog = bpf_object__find_program_by_title(skel, "program_name");
if (!prog) {
    fprintf(stderr, "Program not found\n");
    return 1;
}

// 2. Attach using the appropriate helper
struct bpf_link *link = bpf_program__attach_kprobe(prog, NULL, "function_name");
if (!link) {
    fprintf(stderr, "Failed to attach kprobe\n");
    return 1;
}

// 3. Use the program - it's now attached
// ... 

// 4. When done, the link auto-detaches when freed
// Or explicitly:
bpf_link__destroy(link);
```

---

## 8.3 Link Reference Counting

Links use reference counting, similar to other kernel objects:

```c
// Increment reference count (acquire)
void bpf_link__ref(struct bpf_link *link);

// Decrement reference count, auto-detach when 0
void bpf_link__unref(struct bpf_link *link);

// Get the current reference count (debugging)
int bpf_link__refcount(struct bpf_link *link);
```

### Typical pattern: link lives with program

```c
// Both program and link are in the same scope
// When the link is destroyed, the program is automatically detached
// When the program is freed, the link is automatically destroyed

struct bpf_program *prog = ...;
struct bpf_link *link = bpf_program__attach_kprobe(prog, ...);

// Later:
// Destroying link first detaches the program
bpf_link__destroy(link);
// Now we can safely free the program
bpf_program__free(prog);
```

---

## 8.4 Error Handling with Links

The link API returns NULL on failure, with the error code available via:

```c
// Get last error from link
int err = bpf_link__fd(link);  // or use bpf_link__error()
```

Or more commonly, just check the return value:

```c
struct bpf_link *link = bpf_program__attach_kprobe(prog, ...);
if (!link) {
    // Attachment failed
    int err = -bpf_link__fd(link);  // May not be meaningful
    fprintf(stderr, "Attach failed\n");
    return 1;
}
```

Common failure reasons:
- Program type mismatch (attaching kprobe to tracepoint-compatible program)
- Function address not found (kprobe target doesn't exist in current kernel)
- Resource limits (too many programs attached)
- Insufficient permissions (root required)

---

## 8.5 Program Detachment and Detaching

### Explicit detachment

```c
// Explicitly detach before destroying
bpf_link__destroy(link);
// link is now NULL/destroyed; program is detached
```

### Automatic detachment

```c
// When link FD is closed (process exit, close FD)
// Kernel automatically detaches the program
// No resource leak
```

### Detaching all programs from a BPF object

```c
// Iterate over all programs and detach
struct bpf_program *prog;
bpf_object__for_each_program(prog, skel) {
    struct bpf_link *link = bpf_program__get_link(prog);
    if (link)
        bpf_link__destroy(link);
}
```

---

## 8.6 Example: Complete Program with Links

Here's a complete example showing the link pattern:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "execve_counter.h"  // Includes map definitions + skeleton header

static volatile bool running = true;

static void sig_handler(int sig)
{
    running = false;
}

int main(int argc, char **argv)
{
    struct execve_counter_bpf *skel;
    int err;

    // Set up signal handling
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Open and load the BPF skeleton
    skel = execve_counter_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = execve_counter_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    // Attach using the link API (modern approach)
    // Find the tracepoint program and attach
    struct bpf_program *prog = bpf_object__find_program_by_title(skel, "tracepoint__syscalls__sys_enter_execve");
    if (!prog) {
        fprintf(stderr, "Program not found\n");
        err = 1;
        goto cleanup;
    }

    // Attach using the link API
    struct bpf_link *link = bpf_program__attach_tracepoint(prog, NULL);
    if (!link) {
        fprintf(stderr, "Failed to attach tracepoint\n");
        err = 1;
        goto cleanup;
    }

    printf("Tracing execve calls... Press Ctrl+C to stop.\n");

    // Main loop - just wait for Ctrl+C
    while (running) {
        // We could poll maps here, but for this simple example
        // we just keep the program loaded and attached
        usleep(100000);  // 100ms
    }

    // Link will auto-detach when freed, but let's be explicit
bpf_link__destroy(link);

cleanup:
    execve_counter_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}
```

**Key differences from the old skeleton API:**

| Old approach | New link approach |
|--------------|-------------------|
| `execve_counter_bpf__attach(skel)` | `bpf_program__attach_tracepoint(prog)` |
| Manual detach on cleanup | Auto-destroy link → auto-detach |
| `skel->maps.execve_count` via FD | Direct map access via `skel->maps.execve_count` |
| Manual `bpf_tool` commands | No `bpftool` needed for attach/detach |

---

## 8.7 Links in Rust (libbpf-rs / Aya)

In Rust, the link pattern is even more idiomatic:

```rust
use libbpf_rs::*;

fn main() -> Result<(), LibbpfError> {
    // Open BPF object
    let obj = BPFObject::open_file("program.bpf.o", &Default::default())?;
    
    // Find and attach program
    let prog = obj.find_program("tracepoint__syscalls__sys_enter_execve")?;
    let link = prog.attach_tracepoint(None)?;
    
    println!("Program attached successfully!");
    
    // Link is automatically detached when it goes out of scope
    // or when explicitly dropped
    
    Ok(())
}
```

**Benefits in Rust:**
- The `Link` type implements `Drop` trait for automatic cleanup
- Compile-time checking of attachment compatibility
- Integrated with Rust's ownership model
- No raw FD management needed

---

## 8.8 When to Use Each Approach

| Scenario | Recommended approach |
|----------|---------------------|
| **Learning / prototyping** | Old skeleton API (easier to understand start) |
| **Production tools** | Link API (safer, automatic cleanup) |
| **Rust eBPF development** | Link API (idiomatic Rust, RAII) |
| **C legacy codebase** | Can use either; link API if rewriting |
| **Maximum compatibility** (old kernels) | Skeleton API (link API requires newer libbpf) |

### libbpf version requirements

| libbpf version | Link API support |
|----------------|-----------------|
| < 0.5 | Not available |
| 0.5 - 0.10 | Limited support |
| >= 0.11 | Full link API support |
| Latest (1.0+) | Recommended, stable |

---

## 8.9 Summary

| Aspect | Old approach | Link API |
|--------|-------------|----------|
| **Attachment** | `bpf_prog_attach()` | `bpf_program__attach_*()` |
| **Detachment** | `bpf_prog_detach()` | Automatic on link drop + `bpf_link__destroy()` |
| **Resource mgmt** | Manual FD tracking | RAII, reference counting |
| **Error handling** | Return codes, goto cleanup | NULL return + error introspection |
| **Rust integration** | Possible but verbose | Native, idiomatic |
| **Best for** | Learning, simple tools | Production, Rust, C++ |

---

## 8.10 Looking Ahead

Chapter 9 returns to **practical eBPF programming** — we'll write a complete, production-ready syscall counter using everything learned so far: maps, ring buffers, the link API, and proper userspace integration. This chapter ties together the theory of earlier chapters with a working tool you can run immediately.

*Next: [Chapter 9 — First Complete eBPF Program: Syscall Counter](./09-syscall-counter.md)*