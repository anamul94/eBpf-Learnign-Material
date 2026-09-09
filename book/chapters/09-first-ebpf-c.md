# Chapter 9: First eBPF Program — Tracepoints in C

## What This Chapter Covers

- Writing a complete eBPF program from scratch
- Understanding tracepoints
- Using libbpf skeleton API
- Building and running the program
- Reading data from userspace
- A complete, working example

---

## 9.1 What We're Building

We'll create a program that counts how many times `execve` is called (i.e., how many new processes are started). This teaches:

- Tracepoint attachment
- Map operations (kernel side)
- Ring buffer events (kernel → userspace)
- Userspace loading and event handling

---

## 9.2 The Complete Program

### 9.2.1 Shared Header (execve_counter.h)

```c
// execve_counter.h
#ifndef __EXECVE_COUNTER_H
#define __EXECVE_COUNTER_H

#define TASK_COMM_LEN 16
#define MAX_EVENTS 1024

struct event {
    __u32 pid;
    __u32 uid;
    char comm[TASK_COMM_LEN];
    __u64 timestamp;
    __u64 count;
};

#endif /* __EXECVE_COUNTER_H */
```

### 9.2.2 eBPF Program (execve_counter.bpf.c)

```c
// execve_counter.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "execve_counter.h"

// Map: counter for total execve calls
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} execve_count SEC(".maps");

// Map: ring buffer for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  // 256 KB
} events SEC(".maps");

// Tracepoint: sys_enter_execve
SEC("tp/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
    __u32 key = 0;
    __u64 *count;
    struct event *e;

    // Increment counter
    count = bpf_map_lookup_elem(&execve_count, &key);
    if (count)
        __sync_fetch_and_add(count, 1);

    // Reserve ring buffer space
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;  // Buffer full — skip

    // Fill event data
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Get current count value
    if (count)
        e->count = *count;
    else
        e->count = 0;

    // Submit event
    bpf_ringbuf_submit(e, 0);

    return 0;
}

// Required license (GPL needed for some helpers)
char _license[] SEC("license") = "GPL";
```

### 9.2.3 Userspace Loader (execve_counter.c)

```c
// execve_counter.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "execve_counter.skel.h"  // Generated skeleton
#include "execve_counter.h"

static volatile bool running = true;

static void sig_handler(int sig)
{
    running = false;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    time_t t;
    struct tm *tm;
    char ts[32];

    t = time(NULL);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    printf("%s %-6d %-6d %-16s count=%llu\n",
           ts, e->pid, e->uid, e->comm, e->count);

    return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}

int bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    return setrlimit(RLIMIT_MEMLOCK, &rlim_new);
}

int main(int argc, char **argv)
{
    struct execve_counter_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    // Set up libbpf logging
    libbpf_set_print(libbpf_print_fn);

    // Bump RLIMIT_MEMLOCK for older kernels
    err = bump_memlock_rlimit();
    if (err) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK: %s\n", strerror(errno));
        return 1;
    }

    // Set up signal handler
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Open and load the BPF program
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

    // Attach the tracepoint
    err = execve_counter_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    // Set up ring buffer polling
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = 1;
        goto cleanup;
    }

    printf("Tracing execve calls... Press Ctrl+C to stop.\n");
    printf("%-8s %-6s %-6s %-16s %s\n", "TIME", "PID", "UID", "COMM", "COUNT");

    // Main loop
    while (running) {
        err = ring_buffer__poll(rb, 100);  // 100ms timeout
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    execve_counter_bpf__destroy(skel);

    return err < 0 ? -err : 0;
}
```

### 9.2.4 Makefile

```makefile
# Makefile
APP = execve_counter
CLANG = clang
CC = gcc
BPFTOOL = bpftool

CFLAGS = -g -O2 -Wall
BPF_CFLAGS = -target bpf -g -O2 -Wall

ARCH = $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

.PHONY: all clean

all: $(APP)

# Generate vmlinux.h
vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# Compile eBPF program
$(APP).bpf.o: $(APP).bpf.c vmlinux.h $(APP).h
	$(CLANG) $(BPF_CFLAGS) -I. -D__TARGET_ARCH_$(ARCH) -c $< -o $@

# Generate skeleton
$(APP).skel.h: $(APP).bpf.o
	$(BPFTOOL) gen skeleton $< > $@

# Compile userspace program
$(APP): $(APP).c $(APP).skel.h $(APP).h
	$(CC) $(CFLAGS) -I. $< -lbpf -lelf -lz -o $@

clean:
	rm -f $(APP) $(APP).bpf.o $(APP).skel.h vmlinux.h
```

---

## 9.3 Building and Running

```bash
# Build
make

# Run (requires root)
sudo ./execve_counter

# Output:
# Tracing execve calls... Press Ctrl+C to stop.
# TIME     PID    UID    COMM             COUNT
# 14:23:01 1234   1000   bash             1
# 14:23:01 1235   1000   ls               2
# 14:23:02 1236   1000   cat              3
# ...
```

---

## 9.4 Understanding the Code

### 9.4.1 The Tracepoint Section

```c
SEC("tp/syscalls/sys_enter_execve")
```

This tells libbpf to attach the program to the `sys_enter_execve` tracepoint. The format is:
- `tp/` — tracepoint
- `syscalls/` — tracepoint category
- `sys_enter_execve` — tracepoint name

### 9.4.2 The Context Structure

```c
struct trace_event_raw_sys_enter *ctx
```

The context contains the syscall arguments. For `sys_enter_execve`:
```c
struct trace_event_raw_sys_enter {
    __u64 unused;
    __u32 nr;           // Syscall number (59 for execve)
    __u32 flags;
    __u64 args[6];      // Syscall arguments
};
```

### 9.4.3 The Counter Map

```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} execve_count SEC(".maps");
```

- `BPF_MAP_TYPE_ARRAY` — Fixed-size array
- `max_entries: 1` — Single entry (key always 0)
- `__u64` value — 64-bit counter

### 9.4.4 The Ring Buffer

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");
```

- `BPF_MAP_TYPE_RINGBUF` — Modern event streaming
- `256 * 1024` — 256 KB ring buffer

### 9.4.5 The Skeleton API

```c
// Open (parse ELF, create maps)
skel = execve_counter_bpf__open();

// Load (verify, JIT, attach maps)
execve_counter_bpf__load(skel);

// Attach (attach programs to hooks)
execve_counter_bpf__attach(skel);

// Access maps
skel->maps.execve_count;
skel->maps.events;

// Access programs
skel->progs.tracepoint__syscalls__sys_enter_execve;

// Cleanup
execve_counter_bpf__destroy(skel);
```

---

## 9.5 Inspecting the Running Program

```bash
# List loaded programs
sudo bpftool prog show

# Output:
# 42: tracepoint  name tracepoint__syscalls__sys_enter_execve  tag abc123  ...

# Show program info
sudo bpftool prog show id 42 --json

# List maps
sudo bpftool map show

# Dump map contents
sudo bpftool map dump name execve_count

# Show verifier log
sudo bpftool prog load execve_counter.bpf.o /sys/fs/bpf/test verbose

# Monitor trace output
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

---

## 9.6 Extending the Program

### 9.6.1 Filter by PID

```c
// Add to config map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} config SEC(".maps");

SEC("tp/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
    __u32 key = 0;
    __u32 *target_pid;

    // Check if we should filter
    target_pid = bpf_map_lookup_elem(&config, &key);
    if (target_pid && *target_pid) {
        __u32 pid = bpf_get_current_pid_tgid() >> 32;
        if (pid != *target_pid)
            return 0;  // Skip this process
    }

    // ... rest of the program
}
```

### 9.6.2 Track Multiple Syscalls

```c
// Add more tracepoints
SEC("tp/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    // Similar implementation
}

SEC("tp/syscalls/sys_enter_read")
int trace_read(struct trace_event_raw_sys_enter *ctx) {
    // Similar implementation
}
```

---

## 9.7 Common Mistakes

### Mistake 1: Forgetting the License

```c
// WRONG: Missing license
// Some helpers require GPL license

// CORRECT: Always include
char _license[] SEC("license") = "GPL";
```

### Mistake 2: Not Checking Map Lookup

```c
// WRONG: Dereferencing without check
__u64 *count = bpf_map_lookup_elem(&map, &key);
*count += 1;  // Might be NULL!

// CORRECT: Check first
__u64 *count = bpf_map_lookup_elem(&map, &key);
if (count)
    *count += 1;
```

### Mistake 3: Stack Overflow

```c
// WRONG: Large stack allocation
struct event e;  // If event is large, this exceeds 512 bytes

// CORRECT: Use ring buffer
struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
```

---

## 9.8 Summary

- **Tracepoints** are stable kernel hooks for tracing
- **libbpf skeleton API** provides clean userspace loading
- **Ring buffers** are the preferred way to stream events
- Always **check map lookup return values**
- Always **include a license** declaration
- Use **bpftool** for inspection and debugging

---

## 9.9 Looking Ahead

Chapter 10 covers **kprobes and kretprobes** — dynamic tracing that lets you hook any kernel function, not just tracepoints.

---

*Next: [Chapter 10 — Kprobes and Kretprobes](./10-kprobes.md)*
