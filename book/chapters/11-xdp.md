# Chapter 11: XDP — Express Data Path

## What This Chapter Covers

- What XDP is and why it's fast
- XDP program structure
- Packet parsing and modification
- XDP actions (pass, drop, redirect, abort)
- XDP vs TC vs iptables
- Practical examples: firewall, load balancer, DDoS protection

---

## 11.1 What is XDP?

XDP (eXpress Data Path) is the **fastest networking layer** in Linux. It runs eBPF programs directly in the network driver, **before the kernel allocates an sk_buff** (socket buffer).

```
┌─────────────────────────────────────────────────────────────┐
│                    NETWORK STACK LAYERS                     │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  XDP (eBPF)  ◀── EARLIEST POINT (driver level)     │   │
│  │  - Runs in driver, before sk_buff allocation        │   │
│  │  - ~10 million packets/second per core              │   │
│  └─────────────────────────────────────────────────────┘   │
│                            │                                │
│                            ▼                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  TC (Traffic Control)                               │   │
│  │  - After sk_buff allocation                         │   │
│  │  - ~1-2 million packets/second per core             │   │
│  └─────────────────────────────────────────────────────┘   │
│                            │                                │
│                            ▼                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Netfilter (iptables/nftables)                      │   │
│  │  - Higher in the stack                              │   │
│  │  - ~500K-1M packets/second per core                 │   │
│  └─────────────────────────────────────────────────────┘   │
│                            │                                │
│                            ▼                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Socket Layer                                       │   │
│  │  - Application receives data                        │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Why XDP is fast:**
1. No sk_buff allocation (saves ~200 cycles)
2. Runs in driver poll mode (batch processing)
3. Runs before the kernel network stack
4. Can drop packets before they consume resources

---

## 11.2 XDP Program Structure

```c
// xdp_example.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// XDP context structure
// struct xdp_md {
//     __u32 data;         // Start of packet data
//     __u32 data_end;     // End of packet data
//     __u32 data_meta;    // Metadata pointer
//     __u32 ingress_ifindex;  // Input interface index
//     __u32 rx_queue_index;   // RX queue index
// };

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Packet processing here...

    return XDP_PASS;  // Default action
}

char _license[] SEC("license") = "GPL";
```

---

## 11.3 XDP Actions

| Action | Description | Use Case |
|--------|-------------|----------|
| `XDP_PASS` | Pass to kernel network stack | Normal packet processing |
| `XDP_DROP` | Drop packet silently | Firewall, DDoS protection |
| `XDP_TX` | Transmit back on same interface | Load balancer, reflector |
| `XDP_REDIRECT` | Forward to another interface or CPU | Routing, load balancing |
| `XDP_ABORTED` | Drop with error trace | Debugging |

---

## 11.4 Packet Parsing

### 11.4.1 Ethernet Header

```c
struct ethhdr {
    __u8 h_dest[6];      // Destination MAC
    __u8 h_source[6];    // Source MAC
    __u16 h_proto;       // EtherType (IPv4, IPv6, etc.)
};
```

### 11.4.2 IP Header

```c
struct iphdr {
    __u8 ihl:4;          // Header length
    __u8 version:4;      // IP version
    __u8 tos;            // Type of service
    __u16 tot_len;       // Total length
    __u16 id;            // Identification
    __u16 frag_off;      // Fragment offset
    __u8 ttl;            // Time to live
    __u8 protocol;       // Protocol (TCP, UDP, etc.)
    __u16 check;         // Checksum
    __u32 saddr;         // Source IP
    __u32 daddr;         // Destination IP
};
```

### 11.4.3 TCP Header

```c
struct tcphdr {
    __u16 source;        // Source port
    __u16 dest;          // Destination port
    __u32 seq;           // Sequence number
    __u32 ack_seq;       // Acknowledgment number
    __u8 res1:4;
    __u8 doff:4;         // Data offset (header length)
    __u8 flags;          // TCP flags
    __u16 window;        // Window size
    __u16 check;         // Checksum
    __u16 urg_ptr;       // Urgent pointer
};
```

### 11.4.4 Complete Parser

```c
SEC("xdp")
int xdp_parser(struct xdp_md *ctx)
{
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
    __u16 src_port = bpf_ntohs(tcp->source);

    bpf_printk("TCP %pI4:%d -> %pI4:%d\n",
               &ip->saddr, src_port, &ip->daddr, dst_port);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

---

## 11.5 XDP Firewall Example

```c
// xdp_firewall.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Map: blocked IP addresses
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);     // IP address
    __type(value, __u8);    // Dummy value (just checking existence)
} blocked_ips SEC(".maps");

// Map: blocked ports
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000);
    __type(key, __u16);     // Port number
    __type(value, __u8);
} blocked_ports SEC(".maps");

// Map: packet counters
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

enum stats_idx {
    STAT_TOTAL = 0,
    STAT_PASSED,
    STAT_DROPPED_IP,
    STAT_DROPPED_PORT,
};

static __always_inline void update_stat(__u32 idx)
{
    __u64 *val = bpf_map_lookup_elem(&stats, &idx);
    if (val)
        __sync_fetch_and_add(val, 1);
}

SEC("xdp")
int xdp_firewall(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    update_stat(STAT_TOTAL);

    // Parse Ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    // Only IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        goto pass;

    // Parse IP
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;

    // Check blocked IPs
    __u8 *blocked = bpf_map_lookup_elem(&blocked_ips, &ip->saddr);
    if (blocked) {
        update_stat(STAT_DROPPED_IP);
        return XDP_DROP;
    }

    // Only TCP/UDP
    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
        goto pass;

    // Get destination port
    __u16 dst_port = 0;
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return XDP_DROP;
        dst_port = bpf_ntohs(tcp->dest);
    } else {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return XDP_DROP;
        dst_port = bpf_ntohs(udp->dest);
    }

    // Check blocked ports
    blocked = bpf_map_lookup_elem(&blocked_ports, &dst_port);
    if (blocked) {
        update_stat(STAT_DROPPED_PORT);
        return XDP_DROP;
    }

pass:
    update_stat(STAT_PASSED);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

---

## 11.6 XDP Redirect Example

```c
// xdp_redirect.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Map: interface index to redirect to
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u32);
} tx_port SEC(".maps");

// Map: CPU map for XPS (eXmit Packet Steering)
struct {
    __uint(type, BPF_MAP_TYPE_CPUMAP);
    __uint(max_entries, 128);
    __type(key, __u32);
    __type(value, __u32);
} cpu_map SEC(".maps");

SEC("xdp")
int xdp_redirect(struct xdp_md *ctx)
{
    // Simple: redirect to another interface
    return bpf_redirect_map(&tx_port, 1, XDP_DROP);
}

SEC("xdp")
int xdp_cpu_redirect(struct xdp_md *ctx)
{
    // Distribute across CPUs based on flow
    __u32 cpu = bpf_get_smp_processor_id();
    return bpf_redirect_map(&cpu_map, cpu, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
```

---

## 11.7 Userspace: Managing XDP

```c
// xdp_firewall.c (userspace)
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "xdp_firewall.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
    struct xdp_firewall_bpf *skel;
    int err;
    int ifindex = if_nametoindex("eth0");  // Your interface

    libbpf_set_print(libbpf_print_fn);

    // Open and load
    skel = xdp_firewall_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load BPF program\n");
        return 1;
    }

    // Attach XDP to interface
    err = bpf_xdp_attach(ifindex, bpf_program__fd(skel->progs.xdp_firewall),
                         XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
    if (err) {
        fprintf(stderr, "Failed to attach XDP: %d\n", err);
        goto cleanup;
    }

    printf("XDP firewall attached to eth0\n");
    printf("Adding blocked IP: 192.168.1.100\n");

    // Add a blocked IP
    __u32 blocked_ip = 0xC0A80164;  // 192.168.1.100
    __u8 dummy = 1;
    bpf_map_update_elem(bpf_map__fd(skel->maps.blocked_ips),
                        &blocked_ip, &dummy, BPF_ANY);

    printf("Press Ctrl+C to detach...\n");
    while (1) {
        sleep(1);

        // Print stats
        for (__u32 i = 0; i < 4; i++) {
            __u64 values[libbpf_num_possible_cpus()];
            __u64 total = 0;
            int n_cpus = libbpf_num_possible_cpus();
            bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats), &i, values);
            for (int cpu = 0; cpu < n_cpus; cpu++)
                total += values[cpu];

            const char *names[] = {"total", "passed", "drop_ip", "drop_port"};
            if (total > 0)
                printf("%s: %llu\n", names[i], total);
        }
        printf("---\n");
    }

cleanup:
    bpf_xdp_detach(ifindex, XDP_FLAGS_UPDATE_IF_NOEXIST);
    xdp_firewall_bpf__destroy(skel);
    return err;
}
```

---

## 11.8 XDP vs TC vs iptables

| Feature | XDP | TC | iptables |
|---------|-----|----|----------|
| Layer | Driver (before sk_buff) | After sk_buff | After sk_buff |
| Performance | ~10M pps/core | ~1-2M pps/core | ~500K pps/core |
| Modification | Full packet | Full packet | Limited |
| State | Stateless | Can be stateful | Stateful |
| Complexity | Medium | High | Low |
| Use case | DDoS, routing, LB | QoS, shaping | General firewall |

---

## 11.9 Summary

- **XDP** runs eBPF programs at the driver level for maximum performance
- Actions: **PASS, DROP, TX, REDIRECT, ABORTED**
- Must **bounds-check** every packet access
- Use **bpf_htons/bpf_ntohs** for byte order conversion
- **XDP_REDIRECT** enables packet forwarding between interfaces/CPUs
- Much faster than TC or iptables for packet processing

---

## 11.10 Looking Ahead

Chapter 12 covers **eBPF for observability** — building monitoring tools with counters, histograms, and exporters.

---

*Next: [Chapter 12 — eBPF for Observability](./12-observability-c.md)*
