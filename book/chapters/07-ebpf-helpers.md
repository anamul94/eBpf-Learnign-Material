# Chapter 7: eBPF Helper Functions — The Kernel Interface

## What This Chapter Covers

- What helper functions are and how they work
- Communication helpers (maps, ring buffer)
- Kernel information helpers
- Packet and network helpers
- Process and task helpers
- Memory access helpers
- Debugging helpers
- Helper function availability by program type

---

## 7.1 What Are Helper Functions?

Helper functions are the **syscalls of eBPF** — they're the only way eBPF programs can interact with the kernel. They provide:

1. **Map access** — Read/write maps
2. **Information retrieval** — Get process info, timestamps, etc.
3. **Data transfer** — Send data to userspace
4. **Packet manipulation** — Modify network packets
5. **Memory access** — Safely read kernel memory

Each helper is identified by a number and has a fixed signature. The verifier tracks helper calls to ensure correct usage.

---

## 7.2 Helper Function Categories

### 7.2.1 Map Access Helpers

```c
// Core map operations
void *bpf_map_lookup_elem(struct bpf_map *map, const void *key);
long bpf_map_update_elem(struct bpf_map *map, const void *key,
                         const void *value, __u64 flags);
long bpf_map_delete_elem(struct bpf_map *map, const void *key);
long bpf_map_get_next_key(struct bpf_map *map, const void *key,
                          void *next_key);
void *bpf_map_lookup_and_delete_elem(struct bpf_map *map, const void *key);

// Push/pop/peek for queue/stack maps
long bpf_map_push_elem(struct bpf_map *map, const void *value, __u64 flags);
long bpf_map_pop_elem(struct bpf_map *map, void *value);
long bpf_map_peek_elem(struct bpf_map *map, void *value);
```

### 7.2.2 Communication Helpers

```c
// Ring buffer (preferred for event streaming)
void *bpf_ringbuf_reserve(struct bpf_map *map, __u64 size, __u64 flags);
void bpf_ringbuf_submit(void *data, __u64 flags);
void bpf_ringbuf_discard(void *data, __u64 flags);
long bpf_ringbuf_output(struct bpf_map *map, void *data, __u64 size,
                        __u64 flags);

// Perf event array (legacy)
long bpf_perf_event_output(struct pt_regs *ctx, struct bpf_map *map,
                           __u64 flags, void *data, __u64 size);

// Trace printk (debugging only)
long bpf_trace_printk(const char *fmt, __u32 fmt_size, ...);

// Modern printk replacement
long bpf_printk(const char *fmt, ...);  // Variadic, verifier handles specially
```

### 7.2.3 Kernel Information Helpers

```c
// Time
__u64 bpf_ktime_get_ns(void);           // Monotonic time in nanoseconds
__u64 bpf_ktime_get_boot_ns(void);      // Boot time (includes suspend)
__u64 bpf_jiffies64(void);              // Jiffies

// CPU
__u32 bpf_get_smp_processor_id(void);   // Current CPU number

// Process/Task
__u64 bpf_get_current_pid_tgid(void);   // Returns (tgid << 32) | pid
__u64 bpf_get_current_uid_gid(void);    // Returns (uid << 32) | gid
__u32 bpf_get_current_pid(void);        // Current PID (simplified)
void bpf_get_current_comm(void *buf, __u32 size);  // Process name
__u64 bpf_get_current_cgroup_id(void);  // Cgroup ID

// Task struct access
struct task_struct *bpf_get_current_task(void);
struct task_struct *bpf_task_from_pid(__u32 pid);
```

### 7.2.4 Memory Access Helpers

```c
// Safe memory reading (handles faults gracefully)
long bpf_probe_read(void *dst, __u32 size, const void *src);
long bpf_probe_read_user(void *dst, __u32 size, const void *src);
long bpf_probe_read_kernel(void *dst, __u32 size, const void *src);
long bpf_probe_read_str(void *dst, __u32 size, const void *src);
long bpf_probe_read_user_str(void *dst, __u32 size, const void *src);
long bpf_probe_read_kernel_str(void *dst, __u32 size, const void *src);

// CO-RE memory access (uses BTF)
long bpf_core_read(void *dst, __u32 size, const void *src);
long bpf_core_read_str(void *dst, __u32 size, const void *src);
```

### 7.2.5 Packet and Network Helpers

```c
// Packet access
void *bpf_xdp_load_bytes(struct xdp_md *ctx, __u32 offset, void *buf, __u32 len);
void *bpf_skb_load_bytes(struct sk_buff *skb, __u32 offset, void *buf, __u32 len);

// Packet modification (XDP)
long bpf_xdp_adjust_head(struct xdp_md *ctx, int delta);
long bpf_xdp_adjust_tail(struct xdp_md *ctx, int delta);
long bpf_xdp_adjust_meta(struct xdp_md *ctx, int delta);

// Checksum
long bpf_csum_diff(__be32 *from, __u32 from_size, __be32 *to,
                   __u32 to_size, __u32 seed);
long bpf_csum_update(struct sk_buff *skb, __u16 csum);

// Socket lookup
struct sock *bpf_sk_lookup_tcp(struct sk_buff *skb, struct bpf_sock_tuple *tuple,
                               __u32 tuple_size, __u64 netns, __u64 flags);
struct sock *bpf_sk_lookup_udp(struct sk_buff *skb, struct bpf_sock_tuple *tuple,
                               __u32 tuple_size, __u64 netns, __u64 flags);

// Socket redirect
long bpf_sk_redirect_map(struct sk_buff *skb, struct bpf_map *map,
                         __u32 key, __u64 flags);
long bpf_sock_map_update(struct bpf_sock *sk, struct bpf_map *map,
                         void *key, __u64 flags);
```

### 7.2.6 Tail Call and Program Helpers

```c
// Tail call
long bpf_tail_call(void *ctx, struct bpf_map *map, __u32 index);

// Get current program's attachment point
__u32 bpf_get_attach_ctx(void *ctx, void *buf, __u32 size);

// Fentry/fexit (BPF trampoline)
// These are special — they're attached via BPF trampoline, not direct calls
```

### 7.2.7 Debugging Helpers

```c
// Print to kernel trace buffer
long bpf_trace_printk(const char *fmt, __u32 fmt_size, ...);
long bpf_printk(const char *fmt, ...);  // Modern version

// Send signal
long bpf_send_signal(__u32 sig);

// Overwrite return value (for kretprobe)
long bpf_override_return(struct pt_regs *regs, __u64 rc);
```

---

## 7.3 Helper Function Availability by Program Type

Not all helpers are available to all program types. The verifier enforces this:

### 7.3.1 Tracing Programs (kprobe, tracepoint, etc.)

```c
// Available:
bpf_map_lookup_elem, bpf_map_update_elem, bpf_map_delete_elem
bpf_probe_read, bpf_probe_read_str
bpf_ktime_get_ns
bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_get_current_comm
bpf_perf_event_output, bpf_ringbuf_reserve, bpf_ringbuf_submit
bpf_trace_printk, bpf_printk
bpf_tail_call
bpf_get_smp_processor_id

// NOT available:
bpf_xdp_adjust_head  (XDP only)
bpf_sk_lookup_tcp    (network only)
```

### 7.3.2 XDP Programs

```c
// Available:
bpf_map_lookup_elem, bpf_map_update_elem
bpf_xdp_load_bytes
bpf_xdp_adjust_head, bpf_xdp_adjust_tail, bpf_xdp_adjust_meta
bpf_csum_diff
bpf_redirect, bpf_redirect_map
bpf_xdp_output (perf event)
bpf_ktime_get_ns
bpf_tail_call

// NOT available:
bpf_get_current_pid_tgid  (no current task in XDP)
bpf_probe_read            (no arbitrary memory access)
```

### 7.3.3 Socket/Cgroup Programs

```c
// Available:
bpf_map_lookup_elem, bpf_map_update_elem
bpf_skb_load_bytes
bpf_sk_lookup_tcp, bpf_sk_lookup_udp
bpf_sk_redirect_map
bpf_sock_map_update
bpf_get_current_uid_gid, bpf_get_current_cgroup_id
bpf_get_current_pid_tgid
```

---

## 7.4 CO-RE Helpers — Portable Kernel Access

CO-RE (Compile Once, Run Everywhere) helpers use BTF to access kernel fields portably:

```c
// Instead of direct field access (breaks across kernel versions):
// pid_t pid = task->pid;  // BAD: offset may change

// Use BPF_CORE_READ (portable):
pid_t pid = BPF_CORE_READ(task, pid);  // GOOD: uses BTF

// Nested access:
__u64 inode = BPF_CORE_READ(task, mm, exe_file, f_inode, i_ino);

// With type casting:
struct task_struct *task = (struct task_struct *)bpf_get_current_task();
pid_t pid = BPF_CORE_READ((struct task_struct *)task, pid);
```

### 7.4.1 CO-RE Read Macros

```c
// Direct read
BPF_CORE_READ(dst, field)

// Read with pointer
BPF_CORE_READ_INTO(dst, src, field)

// Read from pointer
BPF_CORE_READ_USER_INTO(dst, src, field)  // For user memory

// Field existence check
bpf_core_field_exists(struct task_struct, field)

// Field size check
bpf_core_field_size(struct task_struct, field)
```

---

## 7.5 Practical Helper Usage Examples

### 7.5.1 Getting Process Information

```c
SEC("tp/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    // Get PID and TGID
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;      // TGID (process ID)
    __u32 tid = pid_tgid & 0xFFFFFFFF;  // PID (thread ID)

    // Get UID and GID
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 uid = uid_gid >> 32;
    __u32 gid = uid_gid & 0xFFFFFFFF;

    // Get process name
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    // Get timestamp
    __u64 ts = bpf_ktime_get_ns();

    bpf_printk("execve: pid=%d uid=%d comm=%s\n", pid, uid, comm);
    return 0;
}
```

### 7.5.2 Reading Kernel Memory Safely

```c
SEC("kprobe/do_sys_open")
int trace_open(struct pt_regs *ctx) {
    // Get filename from second argument
    const char *filename = (const char *)PT_REGS_PARM2(ctx);

    // Safe read (handles faults)
    char name[64];
    long ret = bpf_probe_read_user_str(name, sizeof(name), filename);
    if (ret < 0) {
        bpf_printk("Failed to read filename: %ld\n", ret);
        return 0;
    }

    bpf_printk("open: %s\n", name);
    return 0;
}
```

### 7.5.3 Packet Parsing in XDP

```c
SEC("xdp")
int xdp_parser(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    // Only handle IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;

    // Only handle TCP
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // Parse TCP header
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return XDP_DROP;

    __u16 dst_port = bpf_ntohs(tcp->dest);
    bpf_printk("TCP packet to port %d\n", dst_port);

    return XDP_PASS;
}
```

### 7.5.4 Using Ring Buffer

```c
struct event {
    __u32 pid;
    __u32 uid;
    char comm[16];
    __u64 timestamp;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tp/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    // Reserve space
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;  // Buffer full

    // Fill event
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Submit
    bpf_ringbuf_submit(e, 0);
    return 0;
}
```

---

## 7.6 Helper Function Return Values

Most helpers return a status code or pointer:

```c
// Map lookup returns pointer or NULL
void *val = bpf_map_lookup_elem(&map, &key);
if (!val) {
    // Key not found
}

// Update/delete return 0 on success, negative on error
long ret = bpf_map_update_elem(&map, &key, &val, BPF_ANY);
if (ret < 0) {
    // Error: check errno
}

// Probe read returns 0 on success, negative on error
long ret = bpf_probe_read(dst, size, src);
if (ret < 0) {
    // Read failed (invalid address)
}
```

---

## 7.7 Helper Function Stability

Helper functions are **stable** — once added, they don't change. This is a kernel ABI guarantee:

- New helpers are added in kernel releases
- Existing helpers never change signature
- Programs compiled against older helpers work on newer kernels

This is why eBPF programs can be portable across kernel versions (especially with CO-RE).

---

## 7.8 Summary

- **Helper functions** are the only way eBPF programs interact with the kernel
- Categories: **map access**, **communication**, **info retrieval**, **packet manipulation**, **memory access**
- Not all helpers are available to all **program types**
- **CO-RE helpers** provide portable kernel field access
- Helpers return **pointers or status codes** — always check for errors
- Helper functions are **stable** across kernel versions

---

## 7.9 Looking Ahead

Now that you understand eBPF theory, we're ready to start coding! Chapter 8 covers **setting up the development environment** — the toolchain, kernel headers, and tools you need.

---

*Next: [Chapter 8 — Setting Up the Environment](./08-environment-setup.md)*
