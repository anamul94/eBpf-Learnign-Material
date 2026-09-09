# Chapter 11: eBPF Security

## What This Chapter Covers

- Using eBPF for security monitoring and enforcement
- Linux Security Module (LSM) hooks for intercepting kernel operations
- Building security tools that can observe and modify kernel behavior
- Sandboxing and verifier-enforced safety for eBPF programs
- **Why:** eBPF is increasingly used in security contexts (Cilium, Falco, Pixie). Understanding how to write secure eBPF programs and how kernel security modules work is essential for building production-grade tools.

---

## 11.1 eBPF in the Security Stack

eBPF has become a cornerstone of modern cloud-native security. Its position in the kernel makes it ideal for:

| Use case | eBPF advantage |
|----------|----------------|
| **Container security** | Observe all container syscalls without modifying applications |
| **Runtime protection** | Detect and block malicious behavior in real-time |
| **Network security** | XDP-based packet filtering, encryption enforcement |
| **Audit & compliance** | Complete syscall-level audit trail |
| **Intrusion detection** | Pattern matching on kernel behavior |

### Why eBPF over traditional approaches

| Approach | eBPF advantage |
|----------|----------------|
| **Kernel modules** | No reboot needed; can load/unload at runtime |
| **iptables/nftables** | Packet-level vs. system-call-level observability |
| **System-call filters (seccomp)** | eBPF can observe before the filter decision |
| **Auditd** | eBPF has lower overhead (JIT compiled, no userspace mediation) |
| **Endpoint AV** | eBPF can run at kernel entry, before user-space malware actions |

---

## 11.2 LSM Security Hooks

Linux Security Modules (LSM) provide a framework for security hooks throughout the kernel. Over 40 hook points exist, from fork/exec to file operations to network packets.

### Common LSM Hooks Available to eBPF

| Hook | When fires | eBPF program type | Typical use |
|------|------------|-------------------|-------------|
| `lsm/bpf` | eBPF-specific hook | `lsm` | General-purpose security |
| `security_file_open` | File open | `lsm` | File access monitoring |
| `security_file_rename` | File rename | `lsm` | Prevent unauthorized moves |
| `security_socket_create` | Socket creation | `lsm` / `socket_filter` | Network security |
| `security_socket_connect` | Socket connect | `lsm` | Block suspicious connections |
| `security_task_create` | Process creation | `lsm` | Container escape detection |
| `security_binder_set_attrs` | Binder IPC | `lsm` | Android security |
| `security_module_load` | Kernel module load | `lsm` | Rootkit detection |

### Loading an LSM program

```bash
# Load the BPF program; it auto-attaches to all available LSM hooks
sudo bpftool prog load lsm_prog.o /sys/fs/bpf/lsm_prog

# The program receives notifications for every hooked operation
# Can allow/deny based on its logic
```

### LSM program structure

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("lsm/file_open")
int trace_file_open(struct file *filp)
{
    // filp->f_path.dentry->d_name.name: filename string
    // current->pid, current->comm: process info
    
    // Example: block opening of sensitive files
    // if (strstr(filename, "/etc/shadow"))
    //     return 1;  // Deny (return non-zero)
    
    // Example: log all file opens
    // bpf_trace_printk("open: %s by PID %d\\n", filename, current->pid);
    
    return 0;  // Allow (return 0)
}

char _license[] SEC("license") = "GPL";
```

### Return value semantics

- **Return 0**: Allow the operation (default, continue normally)
- **Return non-zero**: Deny the operation (kernel will return error to caller)

### Multiple LSMs

Kernel can have multiple LSMs loaded simultaneously (common: AppArmor + SELinux, or just Landlock). eBPF programs attach to every available hook, and each can independently allow/deny.

---

## 11.3 Building a File-Monitoring Security Tool

### Objective

Create an eBPF program that monitors file operations and blocks access to sensitive files (e.g., /etc/shadow, private keys).

### Approach

1. **kprobe** on `do_sys_open` (syscall entry) or **lsm** hook on `security_file_open`
2. **Check filename** against a blocklist
3. **Return non-zero** to deny access
4. **Log allowed operations** to a map or ring buffer

### eBPF Program (security_monitor.bpf.c)

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Blocklist map: keys are filename hash values, values are 1 (blocked)
// Using LRU hash map for dynamic blocklist
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u64);
} blocklist SEC(".maps");

// Populate blocklist at load time or via userspace
// Example: bpftool map update name blocklist key 0x...

SEC("lsm/file_open")
int security_file_open(struct file *filp)
{
    const char *filename;
    __u32 hash;
    __u64 *action;
    
    // Extract filename from file struct
    // filp->f_path.dentry->d_name.name contains the filename
    // Use bpf_probe_read_user to read user-space filename if needed
    
    // Simple hash of filename for map lookup
    // In practice, use a more robust hash (Jenkins, xxhash)
    hash = bpf_lru_hash_key_from_filename(filp);  // hypothetical helper
    
    // Look up in blocklist
    action = bpf_map_lookup_elem(&blocklist, &hash);
    if (action && *action)
        return 1;  // Deny: file is on blocklist
    
    // Log allowed operation to ring buffer (optional)
    // ... or just let it pass through
    
    return 0;  // Allow
}
```

### Userspace: Managing the Blocklist

```bash
# Add entries to the blocklist map
sudo bpftool map update elem blocklist \
    key 0x5a3f1e21 value 1  # hash of "/etc/shadow"

# Remove an entry
sudo bpftool map update delete_elem blocklist key 0x5a3f1e21

# List current blocklist entries
sudo bpftool map dump name blocklist
```

### Populating the blocklist dynamically

```c
// Userspace program can update the map via bpf() syscall
// Or via libbpf:
// int fd = bpf_map__fd(skel->maps.blocklist);
// bpf_map_update_elem(fd, &key, &value, BPF_NOEXIST);

// Or mount a debugfs interface that writes to the map
// Or use a sidecar process that listens on a Unix socket
```

---

## 11.4 Securing the eBPF Program Itself

### Verifier Safety

The eBPF verifier is the first line of defense:

| Verifier check | What it prevents |
|----------------|------------------|
| **No infinite loops** | Program can't hang kernel |
| **Bounds checking** | No memory corruption |
| **Initialization checks** | Use of uninitialized data |
| **Helper restrictions** | Only safe helpers allowed |
| **Instruction limit** | Program size bounded |

### Defense-in-Depth Patterns

| Pattern | Description |
|----------|-------------|
| **Principle of least privilege** | eBPF program only does one thing (e.g., just monitor, not modify) |
| **Explicit return values** | Always return 0 (allow) or specific error (deny); never fall through |
| **Map validation** | Check map lookup returns before dereferencing |
| **Defensive copying** | Use `bpf_probe_read_user` for any data from userspace |
| **Minimum permissions** | Load eBPF with least privilege needed (cap_bpf, capped) |

### Privilege Requirements

| Action | Required capability |
|--------|---------------------|
| Load eBPF program | `CAP_BPF` (since Linux 5.9) |
| Attach to kprobe/kretprobe | `CAP_BPF` + process had `CAP_SYS_PTRACE` historically |
| Attach XDP to interface | `CAP_NET_RAW` + interface up |
| Attach LSM hooks | `CAP_BPF` + root usually required |
| Modify kernel maps | `CAP_BPF` + appropriate map type permissions |

---

## 11.5 Security-Evasive Patterns to Avoid

| Anti-pattern | Why it's bad | Better alternative |
|--------------|--------------|--------------------|
| **Running unverified eBPF** | Could crash kernel if verifier bugs exist | Always use verified libbpf/clang pipeline |
| **Overly broad kprobes** | Too many probes, high overhead | Use tracepoints when available; filter by function name |
| **Not checking map lookups** | NULL dereference, verifier rejection | Always: `if (ret == 0) { ... }` |
| **Hardcoding kernel addresses** | Breaks on kernel update | Use BTF/CO-RE, kprobe symbols via vmlinux |
| **Missing license GPL** | Verifier rejection for some helpers | Always: `char _license[] SEC("license") = "GPL";` |

---

## 11.6 Summary

| Security Aspect | Key Takeaway |
|-----------------|--------------|
| **LSM hooks** | eBPF can intercept file, socket, process operations |
| **Return values** | 0 = allow, non-zero = deny |
| **Blocklist/map** | Dynamic configuration of what to filter |
| **Verifier** | First security layer; guarantees program safety |
| **Privileges** | `CAP_BPF` needed for load/attach |
| **Best practice** | Minimal privilege, defensive copying, explicit returns |

---

## 11.7 Looking Ahead

Chapter 12 covers **Performance Tuning** — optimizing eBPF programs for low overhead, efficient map operations, and production-scale data collection. You'll learn how to make eBPF tools that add minimal overhead to the system they're observing.

*Next: [Chapter 12 — Performance Tuning](./12-performance.md)*