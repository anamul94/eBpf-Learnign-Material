# Chapter 12: eBPF for Observability — Building Monitoring Tools

## What This Chapter Covers

- Observability with eBPF
- Counters and histograms
- Latency measurement
- Stack traces
- Exporting metrics to Prometheus
- Building a complete monitoring tool

---

## 12.1 Why eBPF for Observability?

Traditional observability tools require:
- **Kernel modules** (risky, hard to deploy)
- **User-space polling** (high overhead)
- **Application instrumentation** (modifies code)

eBPF observability:
- **Zero overhead** when not attached
- **No code changes** to applications
- **Safe** (verified by kernel)
- **Dynamic** (attach/detach at runtime)

---

## 12.2 Counters — Simple Event Counting

```c
// counter.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Per-CPU counter for maximum performance
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} syscall_count SEC(".maps");

SEC("tp/syscalls/sys_enter_read")
int count_read(struct trace_event_raw_sys_enter *ctx)
{
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&syscall_count, &key);
    if (count)
        __sync_fetch_and_add(count, 1);
    return 0;
}

char _license[] SEC("license") = "GPL";
```

---

## 12.3 Histograms — Distribution Measurement

```c
// histogram.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_SLOTS 256

// Histogram map: 256 slots for logarithmic buckets
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_SLOTS);
    __type(key, __u32);
    __type(value, __u64);
} latency_hist SEC(".maps");

// Calculate log2 bucket for a value
static __always_inline __u32 log2(__u64 val)
{
    __u32 bucket = 0;
    while (val > 1) {
        val >>= 1;
        bucket++;
    }
    return bucket;
}

// Store entry timestamps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u64);
    __type(value, __u64);
} start_times SEC(".maps");

SEC("kprobe/blk_mq_start_request")
int BPF_KPROBE(trace_blk_start, struct request *req)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_times, &pid_tgid, &ts, BPF_ANY);
    return 0;
}

SEC("kprobe/blk_mq_end_request")
int BPF_KPROBE(trace_blk_end, struct request *req)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *start_ts = bpf_map_lookup_elem(&start_times, &pid_tgid);
    if (!start_ts)
        return 0;

    __u64 duration = bpf_ktime_get_ns() - *start_ts;
    bpf_map_delete_elem(&start_times, &pid_tgid);

    // Convert to microseconds and find bucket
    __u64 us = duration / 1000;
    __u32 bucket = log2(us);
    if (bucket >= MAX_SLOTS)
        bucket = MAX_SLOTS - 1;

    __u64 *count = bpf_map_lookup_elem(&latency_hist, &bucket);
    if (count)
        __sync_fetch_and_add(count, 1);

    return 0;
}

char _license[] SEC("license") = "GPL";
```

---

## 12.4 Stack Traces — Finding the "Why"

```c
// stack_trace.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_STACK_DEPTH 32

// Map: store stack traces
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 10000);
    __type(key, __u32);     // Stack ID
} stack_traces SEC(".maps");

// Map: count stack traces
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);     // Stack ID
    __type(value, __u64);   // Count
} stack_count SEC(".maps");

SEC("kprobe/vfs_read")
int BPF_KPROBE(trace_read, struct file *file, char *buf, size_t count, loff_t *pos)
{
    // Capture kernel stack trace
    __u32 stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);

    if (stack_id < 0)
        return 0;

    // Increment count for this stack
    __u64 *cnt = bpf_map_lookup_elem(&stack_count, &stack_id);
    if (cnt) {
        __sync_fetch_and_add(cnt, 1);
    } else {
        __u64 init = 1;
        bpf_map_update_elem(&stack_count, &stack_id, &init, BPF_ANY);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
```

---

## 12.5 Userspace: Reading and Displaying Data

```c
// monitor.c (userspace)
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <syms.h>

#include "monitor.skel.h"

static volatile bool running = true;

void sig_handler(int sig)
{
    running = false;
}

// Print histogram
void print_histogram(struct bpf_map *map, const char *title)
{
    int fd = bpf_map__fd(map);
    __u32 key, next_key;
    int n_cpus = libbpf_num_possible_cpus();

    printf("\n%s\n", title);
    printf("%-15s %s\n", "Latency (us)", "Count");
    printf("%-15s %s\n", "------------", "-----");

    key = -1;
    while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
        key = next_key;
        __u64 values[n_cpus];
        __u64 total = 0;

        if (bpf_map_lookup_elem(fd, &key, values) == 0) {
            for (int cpu = 0; cpu < n_cpus; cpu++)
                total += values[cpu];
        }

        // Convert bucket to latency range
        __u64 low = (1ULL << key) / 1000;
        __u64 high = (1ULL << (key + 1)) / 1000;

        if (total > 0)
            printf("%5llu - %5llu: %llu\n", low, high, total);
    }
}

// Print stack traces
void print_stack_traces(struct bpf_map *stacks, struct bpf_map *counts)
{
    int stacks_fd = bpf_map__fd(stacks);
    int counts_fd = bpf_map__fd(counts);
    __u32 key, next_key;

    printf("\nTop Stack Traces\n");
    printf("%-10s %s\n", "Count", "Stack");
    printf("%-10s %s\n", "-----", "-----");

    // Simple: just print first 10
    int printed = 0;
    key = -1;
    while (bpf_map_get_next_key(counts_fd, &key, &next_key) == 0 && printed < 10) {
        key = next_key;
        __u64 count;
        if (bpf_map_lookup_elem(counts_fd, &key, &count) == 0 && count > 0) {
            printf("%-10llu ", count);

            // Resolve stack
            __u64 ip[MAX_STACK_DEPTH];
            if (bpf_map_lookup_elem(stacks_fd, &key, ip) == 0) {
                for (int i = 0; i < MAX_STACK_DEPTH && ip[i]; i++) {
                    struct symbol *sym = resolve_symbol(ip[i]);
                    if (sym)
                        printf("%s ", sym->name);
                }
            }
            printf("\n");
            printed++;
        }
    }
}

int main(int argc, char **argv)
{
    struct monitor_bpf *skel;
    int err;

    signal(SIGINT, sig_handler);

    skel = monitor_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load BPF program\n");
        return 1;
    }

    err = monitor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach: %d\n", err);
        goto cleanup;
    }

    printf("Monitoring... Press Ctrl+C to stop.\n");

    while (running) {
        sleep(5);
        print_histogram(skel->maps.latency_hist, "Block I/O Latency Histogram");
    }

cleanup:
    monitor_bpf__destroy(skel);
    return err;
}
```

---

## 12.6 Prometheus Exporter

```c
// prometheus_export.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <microhttpd.h>
#include <bpf/libbpf.h>

#include "monitor.skel.h"

#define PORT 9400

static struct monitor_bpf *skl;

// HTTP handler for /metrics
static int handle_metrics(void *cls, struct MHD_Connection *connection,
                          const char *url, const char *method,
                          const char *version, const char **upload_data,
                          size_t *upload_data_size, void **con_cls)
{
    char response[4096];
    int pos = 0;

    // Prometheus format
    pos += snprintf(response + pos, sizeof(response) - pos,
                    "# HELP ebpf_syscall_total Total syscalls\n");
    pos += snprintf(response + pos, sizeof(response) - pos,
                    "# TYPE ebpf_syscall_total counter\n");

    // Read counter from map
    __u32 key = 0;
    int n_cpus = libbpf_num_possible_cpus();
    __u64 values[n_cpus];
    bpf_map_lookup_elem(bpf_map__fd(skel->maps.syscall_count), &key, values);

    __u64 total = 0;
    for (int cpu = 0; cpu < n_cpus; cpu++)
        total += values[cpu];

    pos += snprintf(response + pos, sizeof(response) - pos,
                    "ebpf_syscall_total %llu\n", total);

    // Send response
    struct MHD_Response *resp = MHD_create_response_from_buffer(
        pos, response, MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(resp, "Content-Type", "text/plain");
    int ret = MHD_queue_response(connection, MHD_HTTP_OK, resp);
    MHD_destroy_response(resp);
    return ret;
}

int main(int argc, char **argv)
{
    // Load BPF
    skl = monitor_bpf__open_and_load();
    if (!skl) return 1;
    monitor_bpf__attach(skl);

    // Start HTTP server
    struct MHD_Daemon *daemon = MHD_start_daemon(
        MHD_USE_THREAD_PER_CONNECTION, PORT, NULL, NULL,
        &handle_metrics, NULL, MHD_OPTION_END);

    if (!daemon) return 1;

    printf("Prometheus exporter running on http://localhost:%d/metrics\n", PORT);
    printf("Press Ctrl+C to stop.\n");

    while (1) sleep(3600);

    MHD_stop_daemon(daemon);
    monitor_bpf__destroy(skl);
    return 0;
}
```

---

## 12.7 Summary

- **Counters** use per-CPU maps for lock-free counting
- **Histograms** use logarithmic buckets for distribution measurement
- **Stack traces** help identify the source of events
- **Prometheus exporters** expose eBPF metrics to monitoring systems
- Userspace reads maps periodically or streams via ring buffer

---

## 12.8 Looking Ahead

Now we move to **Part IV: eBPF with Rust and libpf-rs**. Chapter 13 introduces the Rust eBPF ecosystem.

---

*Next: [Chapter 13 — The Rust eBPF Ecosystem](./13-rust-ecosystem.md)*
