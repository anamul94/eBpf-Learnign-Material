# Chapter 8: Setting Up the eBPF Development Environment

## What This Chapter Covers

- Required tools and packages
- Kernel configuration for eBPF
- Installing libbpf and bpftool
- Generating vmlinux.h
- Building your first eBPF project
- Debugging tools and workflows

---

## 8.1 Required Tools

### 8.1.1 Essential Packages

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y \
    build-essential \
    clang \
    llvm \
    libelf-dev \
    zlib1g-dev \
    libbfd-dev \
    libcap-dev \
    linux-tools-$(uname -r) \
    linux-headers-$(uname -r) \
    bpftool

# Fedora/RHEL
sudo dnf install -y \
    clang \
    llvm \
    elfutils-libelf-devel \
    zlib-devel \
    binutils-devel \
    libcap-devel \
    kernel-devel \
    kernel-headers \
    bpftool

# Arch Linux
sudo pacman -S \
    base-devel \
    clang \
    llvm \
    libelf \
    zlib \
    binutils \
    libcap \
    linux-tools \
    linux-headers \
    bpftool
```

### 8.1.2 Verify Installation

```bash
# Check Clang supports eBPF target
clang --version
# Should show version 12+ (14+ recommended)

# Check bpftool
bpftool version
# Should show version matching your kernel

# Check kernel config
cat /proc/config.gz | gunzip | grep CONFIG_BPF
# Or: zgrep CONFIG_BPF /boot/config-$(uname -r)
```

---

## 8.2 Kernel Configuration

eBPF requires certain kernel options to be enabled:

```bash
# Check if eBPF is enabled
cat /proc/config.gz | grep -E "CONFIG_BPF|CONFIG_DEBUG_INFO"

# Required options:
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_HAVE_EBPF_JIT=y

# For tracing:
CONFIG_KPROBES=y
CONFIG_UPROBES=y
CONFIG_TRACEPOINTS=y

# For BTF (CO-RE):
CONFIG_DEBUG_INFO_BTF=y

# For XDP:
CONFIG_XDP=y

# For LSM:
CONFIG_BPF_LSM=y
CONFIG_DEBUG_INFO_BTF=y
```

Most modern distributions have these enabled by default. If you need to check:

```bash
# Quick check
sysctl net.core.bpf_jit_enable
# Should return 1

# Check BTF
ls /sys/kernel/btf/vmlinux
# Should exist
```

---

## 8.3 Installing libbpf

libbpf is the standard C library for loading and interacting with eBPF programs.

### 8.3.1 From Source (Recommended)

```bash
# Clone libbpf
git clone --recurse-submodules https://github.com/libbpf/libbpf.git
cd libbpf/src

# Build
make -j$(nproc)

# Install
sudo make install

# Update library cache
sudo ldconfig
```

### 8.3.2 From Package Manager

```bash
# Ubuntu 22.04+
sudo apt install libbpf-dev

# Fedora
sudo dnf install libbpf-devel
```

### 8.3.3 Verify Installation

```bash
# Check headers
ls /usr/include/bpf/
# Should show: bpf.h, libbpf.h, btf.h, etc.

# Check library
ls /usr/lib*/libbpf.*
# Should show: libbpf.so, libbpf.a
```

---

## 8.4 Installing bpftool

bpftool is the essential utility for inspecting and managing eBPF objects.

### 8.4.1 From Source

```bash
git clone --recurse-submodules https://github.com/libbpf/bpftool.git
cd bpftool/src

make -j$(nproc)
sudo make install
```

### 8.4.2 Verify

```bash
bpftool --version
bpftool prog show          # List loaded programs
bpftool map show           # List loaded maps
bpftool btf show           # List BTF types
```

---

## 8.5 Generating vmlinux.h

`vmlinux.h` contains all kernel type definitions — essential for CO-RE:

```bash
# Generate from running kernel
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# This creates a ~5MB header with ALL kernel types
wc -l vmlinux.h
# Typically 100,000+ lines
```

**What's in vmlinux.h:**
- All `struct` definitions from the kernel
- All `typedef` definitions
- All `enum` definitions
- All `union` definitions

**Why you need it:**
- CO-RE programs use `BPF_CORE_READ` which needs type info
- Without it, you'd need to manually define every kernel struct

---

## 8.6 Project Structure

A typical eBPF C project:

```
my-ebpf-project/
├── Makefile
├── vmlinux.h              # Generated kernel headers
├── common.h               # Shared definitions
├── myprog.bpf.c           # eBPF program (kernel side)
├── myprog.c               # Userspace loader
└── myprog.h               # Shared between kernel and userspace
```

### 8.6.1 Common Header (myprog.h)

```c
// myprog.h - shared between kernel and userspace
#ifndef __MYPROG_H
#define __MYPROG_H

#define MAX_COMM_LEN 16
#define MAX_EVENTS 1024

struct event {
    __u32 pid;
    __u32 uid;
    char comm[MAX_COMM_LEN];
    __u64 timestamp;
};

#endif /* __MYPROG_H */
```

### 8.6.2 Makefile

```makefile
# Makefile for eBPF project

APP = myprog

# Tools
CLANG = clang
LLC = llvm-strip
BPFTOOL = bpftool

# Flags
CFLAGS = -g -O2 -Wall
BPF_CFLAGS = -target bpf -g -O2 -Wall

# Paths
LIBBPF_DIR = /usr/include/bpf
ARCH = $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Targets
all: $(APP)

# Generate vmlinux.h (if not present)
vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# Compile eBPF program
$(APP).bpf.o: $(APP).bpf.c vmlinux.h common.h
	$(CLANG) $(BPF_CFLAGS) -I. -I$(LIBBPF_DIR) -D__TARGET_ARCH_$(ARCH) \
		-c $< -o $@

# Generate skeleton
$(APP).skel.h: $(APP).bpf.o
	$(BPFTOOL) gen skeleton $< > $@

# Compile userspace program
$(APP): $(APP).c $(APP).skel.h common.h
	$(CC) $(CFLAGS) -I. -I$(LIBBPF_DIR) $< -lbpf -lelf -lz -o $@

clean:
	rm -f $(APP) $(APP).bpf.o $(APP).skel.h vmlinux.h

.PHONY: all clean
```

---

## 8.7 Building and Running

### 8.7.1 Build

```bash
# Build everything
make

# This produces:
# - myprog.bpf.o (eBPF object file)
# - myprog.skel.h (skeleton header)
# - myprog (userspace binary)
```

### 8.7.2 Run

```bash
# Run (requires root for most eBPF operations)
sudo ./myprog

# Or with capabilities
sudo setcap cap_bpf,cap_perfmon,cap_net_admin,cap_sys_admin+ep ./myprog
./myprog
```

### 8.7.3 Inspect

```bash
# List loaded programs
sudo bpftool prog show

# List loaded maps
sudo bpftool map show

# Dump program bytecode
sudo bpftool prog dump xlated name myprog

# Dump JIT-compiled code
sudo bpftool prog dump jited name myprog

# Show map contents
sudo bpftool map dump name events
```

---

## 8.8 Debugging Tools

### 8.8.1 bpf_trace_printk / bpf_printk

```c
// In eBPF program
bpf_printk("Hello from eBPF! pid=%d\n", pid);

// Read output
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

### 8.8.2 bpftool Debug

```bash
# Show program info
sudo bpftool prog show id 42

# Show map info
sudo bpftool map show id 10

# Show verifier log
sudo bpftool prog load program.o /sys/fs/bpf/prog verbose

# Show BTF info
sudo bpftool btf dump prog id 42
```

### 8.8.3 perf Debug

```bash
# Trace eBPF events
sudo perf trace -e 'bpf:*'

# Record eBPF activity
sudo perf record -e 'bpf:bpf_prog_load' -a
```

---

## 8.9 Development Workflow

```
┌─────────────────────────────────────────────────────────────┐
│                 eBPF DEVELOPMENT WORKFLOW                   │
│                                                             │
│  1. Write eBPF C code                                       │
│     └─▶ Edit myprog.bpf.c                                  │
│                                                             │
│  2. Compile to eBPF bytecode                                │
│     └─▶ clang -target bpf -O2 -g -c myprog.bpf.c          │
│                                                             │
│  3. Fix verifier errors                                     │
│     └─▶ bpftool prog load myprog.bpf.o verbose             │
│     └─▶ Read error, fix code, recompile                    │
│                                                             │
│  4. Generate skeleton                                       │
│     └─▶ bpftool gen skeleton myprog.bpf.o > myprog.skel.h  │
│                                                             │
│  5. Write userspace code                                    │
│     └─▶ Edit myprog.c (uses skeleton API)                  │
│                                                             │
│  6. Build userspace                                         │
│     └─▶ gcc myprog.c -lbpf -o myprog                       │
│                                                             │
│  7. Test                                                    │
│     └─▶ sudo ./myprog                                      │
│     └─▶ Check output, verify behavior                      │
│                                                             │
│  8. Debug                                                   │
│     └─▶ bpftool, bpf_printk, /sys/kernel/debug/tracing     │
│                                                             │
│  9. Iterate                                                 │
│     └─▶ Go back to step 1                                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 8.10 Common Issues and Solutions

### Issue: "vmlinux.h not found"

```bash
# Generate it
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Or install kernel headers
sudo apt install linux-headers-$(uname -r)
```

### Issue: "bpf() syscall not supported"

```bash
# Check kernel config
cat /proc/config.gz | gunzip | grep CONFIG_BPF_SYSCALL

# If not enabled, you need a different kernel
```

### Issue: "Permission denied"

```bash
# Most eBPF operations require root or capabilities
sudo ./myprog

# Or set capabilities
sudo setcap cap_bpf,cap_perfmon,cap_sys_admin+ep ./myprog
```

### Issue: "Failed to load program: Invalid argument"

```bash
# Get verbose error
bpftool prog load program.o /sys/fs/bpf/prog verbose

# Common causes:
# - Missing license declaration
# - Verifier rejection
# - Wrong program type
```

---

## 8.11 Summary

- Install **clang, llvm, libbpf-dev, bpftool**
- Verify **kernel config** has eBPF enabled
- Generate **vmlinux.h** for CO-RE
- Use **libbpf skeleton API** for clean userspace code
- Debug with **bpftool** and **bpf_printk**
- Most operations require **root or capabilities**

---

## 8.12 Looking Ahead

Now that your environment is ready, Chapter 9 walks through writing your **first complete eBPF program** in C — a syscall tracer that counts process executions.

---

*Next: [Chapter 9 — First eBPF Program: Tracepoints](./09-first-ebpf-c.md)*
