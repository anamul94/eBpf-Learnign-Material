# Chapter 5: XDP Firewall - High-Speed Packet Filtering

## What We're Building

A firewall that blocks traffic from specific IP addresses at the network driver level - before the kernel even processes the packet.

**Why this project?** Because XDP is the fastest networking layer in Linux. It's why eBPF revolutionized networking.

---

## The Complete Code

### src/bpf/xdp.bpf.c

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// WHY these structs? Because XDP gives us raw packet data.
// There's no sk_buff yet - we parse everything manually.
struct ethhdr {
    __u8 h_dest[6];
    __u8 h_source[6];
    __u16 h_proto;
};

struct iphdr {
    __u8 ihl:4, version:4;
    __u8 tos;
    __u16 tot_len;
    __u16 id;
    __u16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __u16 check;
    __u32 saddr;
    __u32 daddr;
};

// WHY hash map for blocked IPs?
// - We need fast lookups (O(1))
// - The list can change at runtime (userspace updates it)
// - Hash maps are perfect for this
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);      // IP address
    __type(value, __u8);     // Just checking existence
} blocked_ips SEC(".maps");

// WHY XDP program?
// - Runs at the network driver level (earliest possible point)
// - Before kernel allocates sk_buff (saves ~200 cycles per packet)
// - Can process ~10 million packets/second per core
SEC("xdp")
int xdp_firewall(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // WHY bounds checking?
    // - The verifier requires it
    // - Packet might be malformed
    // - Without this, verifier rejects your program
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;  // Packet too small

    // Only handle IPv4
    // WHY bpf_htons? Because network byte order is big-endian,
    // but x86 is little-endian. We need to convert.
    if (eth->h_proto != bpf_htons(0x0800))
        return XDP_PASS;  // Not IPv4, let kernel handle it

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;  // Packet too small

    // Check if source IP is blocked
    // WHY lookup before dropping? Because most packets are NOT blocked.
    // We want fast path for allowed packets.
    if (bpf_map_lookup_elem(&blocked_ips, &ip->saddr))
        return XDP_DROP;  // Blocked!

    return XDP_PASS;  // Allowed
}

char _license[] SEC("license") = "GPL";
```

**The XDP program explained:**

`SEC("xdp")` - This is an XDP program. **Why XDP?** Because it runs in the network driver, before the kernel network stack. This is the fastest place to process packets.

`struct xdp_md *ctx` - The XDP metadata. Contains:
- `ctx->data` - Start of packet data
- `ctx->data_end` - End of packet data

**Why no sk_buff?** Because XDP runs before the kernel allocates one. This is why it's fast!

`if ((void *)(eth + 1) > data_end)` - **Critical bounds check!** The verifier requires every memory access to be checked. **Why?** Because packets can be malformed or truncated.

`bpf_htons(0x0800)` - Convert to network byte order. **Why?** Because x86 is little-endian but network protocols are big-endian.

**Return values:**
- `XDP_PASS` - Let the kernel process the packet normally
- `XDP_DROP` - Drop the packet immediately
- `XDP_TX` - Send back out the same interface
- `XDP_REDIRECT` - Forward to another interface/CPU

### src/main.rs

```rust
use libbpf_rs::ObjectBuilder;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

mod bpf {
    include!("bpf/xdp.skel.rs");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    let obj = ObjectBuilder::default()
        .open_file("target/bpfel-unknown-none/release/xdp.bpf.o")?;
    let obj = obj.load()?;

    let prog = obj.prog("xdp_firewall").ok_or("Program not found")?;

    // WHY attach_xdp? Because XDP programs attach to network interfaces,
    // not tracepoints or kprobes.
    // We need the interface index (ifindex).
    let iface = "eth0";  // Change to your interface
    let ifindex = unsafe {
        libc::if_nametoindex(iface.as_ptr() as *const i8)
    } as u32;

    // Attach with flags
    // WHY XDP_FLAGS_UPDATE_IF_NOEXIST? So we don't replace an existing
    // XDP program if one is already attached.
    let _link = prog.attach_xdp(ifindex)?;

    println!("XDP firewall attached to {}", iface);
    println!("Adding some blocked IPs...\n");

    // Add some IPs to block
    let map = obj.map("blocked_ips").ok_or("Map not found")?;

    // Block 192.168.1.100 (0xC0A80164 in network order)
    let blocked_ip: u32 = 0x6401A8C0;  // 192.168.1.100 in little-endian
    let value: u8 = 1;
    map.update(&blocked_ip, &value, libbpf_rs::MapFlags::ANY)?;

    println!("Blocked 192.168.1.100");
    println!("Press Ctrl+C to exit.\n");

    while running.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    println!("Detaching XDP program...");
    // _link drops here, detaching the program

    Ok(())
}
```

**The attachment explained:**

`prog.attach_xdp(ifindex)` - Attach to a network interface. **Why ifindex?** Because interfaces are identified by number, not name.

**Why XDP is fast:**
1. Runs in driver context (no kernel network stack overhead)
2. No sk_buff allocation
3. Batch processing (driver polls multiple packets at once)
4. Can drop packets before they consume resources

---

## Building and Running

```bash
# Find your interface
ip link show

# Build
cargo build --release

# Run (needs root)
sudo ./target/release/xdp

# Test - try pinging a blocked IP
ping 192.168.1.100  # Should fail if that IP is on your network
```

---

## XDP vs TC vs iptables

| Feature | XDP | TC | iptables |
|---------|-----|----|----------|
| Layer | Driver (before sk_buff) | After sk_buff | After sk_buff |
| Speed | ~10M pps/core | ~1-2M pps/core | ~500K pps/core |
| Modification | Full packet | Full packet | Limited |
| Use case | DDoS, routing, LB | QoS, shaping | General firewall |

**When to use XDP:** When you need maximum packet processing speed.

---

## XDP Return Values

| Value | Meaning | Use Case |
|-------|---------|----------|
| `XDP_PASS` | Let kernel handle | Normal packets |
| `XDP_DROP` | Drop silently | Blocked packets |
| `XDP_TX` | Send back same interface | Reflectors |
| `XDP_REDIRECT` | Forward to another interface/CPU | Load balancing |

---

## Try It Yourself

1. **Block by destination port** - Parse TCP/UDP headers:
   ```c
   if (ip->protocol == IPPROTO_TCP) {
       struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
       if ((void *)(tcp + 1) > data_end)
           return XDP_DROP;
       __u16 dport = bpf_ntohs(tcp->dest);
       if (dport == 22)  // Block SSH
           return XDP_DROP;
   }
   ```

2. **Rate limiting** - Use a per-CPU array to track packet counts per IP.

3. **Whitelist mode** - Only allow IPs in the map (invert the logic).

---

## Common Mistakes

**"Invalid argument" on attach** - Check that your interface name is correct and exists.

**Verifier rejects bounds checks** - Every packet access must be checked. The pattern is always:
```c
if ((void *)(ptr + 1) > data_end)
    return XDP_DROP;
```

**Wrong byte order** - Network protocols use big-endian. Use `bpf_htons`/`bpf_ntohs` for 16-bit values, `bpf_htonl`/`bpf_ntohl` for 32-bit.

**Program doesn't fire** - Make sure your interface supports XDP. Most do, but some drivers don't.

---

*Next: [Chapter 6 - Network Monitor](../chapters/06-network-monitor.md)*
