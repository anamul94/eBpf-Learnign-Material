# AGENTS: eBPF Learning Repository

## Overview
This repository contains two eBPF learning books in Markdown format:
- `book/`: Comprehensive guide covering C + Rust eBPF from beginner to advanced (22 chapters)
- `book-2-hands-on/`: Practical, project-based eBPF with libbpf-rs (10 chapters, hands-on tools)

Agents should expect Markdown files with code blocks, Makefiles, and build instructions for Linux eBPF development.

## Directory Structure

```
/home/suhayl/Learning/eBPF/
├── book/                  # Comprehensive C+Rust eBPF guide
│   ├── chapters/          # 22 markdown chapters (01-22)
│   ├── examples/          # Code examples per chapter
│   ├── images/            # Diagram assets
│   └── README.md          # Book overview
├── book-2-hands-on/       # Practical libbpf-rs projects
│   ├── chapters/          # 10 markdown chapters (01-10)
│   ├── src/               # Rust source (main.rs, bpf/ subdir)
│   ├── Cargo.toml         # Dependencies + build.rs for skeleton generation
│   └── README.md          # Project overview
├── .commandcode/          # opencode permission settings
└── beginner-advanced-ebpf-book/  # New comprehensive book in progress
```

## Key Conventions

### Markdown code blocks
Code blocks are complete and annotated. Key lines are explained inline. When editing, preserve the explanation style.

### Build systems
- **book chapters**: Makefiles with `clang` for BPF compilation, `bpftool` for skeleton generation
- **book-2-hands-on**: `Cargo.toml` uses `libbpf-cargo`, `build.rs` generates Rust skeletons from `.bpf.c` files

### Common Makefile targets
```makefile
# Generate vmlinux.h (needed for BPF compilation)
vmlinux.h:
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

# Compile eBPF program
chapter.bpf.o: chapter.bpf.c vmlinux.h
    clang -target bpf -g -O2 -I. -c $< -o $@

# Generate skeleton
chapter.skel.h: chapter.bpf.o
    bpftool gen skeleton $< > $@

# Build userspace
chapter: chapter.c chapter.skel.h
    gcc -I. $< -lbpf -lelf -lz -o chapter
```

### Prerequisites (always check first)
```bash
# Install dependencies
sudo apt install clang libbpf-dev linux-tools-common bpftool

# Verify BTF available
ls /sys/kernel/btf/vmlinux

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## Working with Chapters

### Single chapter workflow
1. `cd /home/suhayl/Learning/eBPF/book-2-hands-on` or `book/`
2. Read the chapter README for what's built
3. Follow "Building and Running" instructions
4. Code is in `src/` (book-2-hands-on) or chapter file (book)
5. Makefiles are at the chapter root or parent level

### When adding a new chapter
- Place markdown in `chapters/` directory
- Follow naming: `NN-chapter-name.md` (two-digit prefix for ordering)
- Include: project description, complete code, build instructions, "understanding" section, exercises
- Update the book's README chapter table if applicable

## eBPF-Specific Guidance

### Verifier errors
When eBPF programs fail to load, the verifier log is key:
```bash
sudo bpftool prog load program.bpf.o /sys/fs/bpf/test 2>&1
# Or view in dmesg
dmesg | tail -20
```

### Common patterns to preserve
- Always include `char _license[] SEC("license") = "GPL";`
- Check map lookup return values before dereferencing
- Use `bpf_probe_read` family for kernel memory access
- Include `vmlinux.h` generated from `bpftool btf dump`

### Rust + eBPF notes
- `book-2-hands-on` uses `libbpf-rs` (libbpf-cargo integration)
- `build.rs` compiles `.bpf.c` and generates `bpf` module skeleton
- `main.rs` uses the generated skeleton for loading/attaching
- AYA is not the primary focus; libbpf-rs is the preferred Rust approach in this repo

## What to Avoid

- **Don't** add unnecessary comments to code examples (the style here is self-documenting code + chapter explanations)
- **Don't** change the Makefile/chapter pattern without understanding the libbpf-cargo workflow
- **Don't** skip the BTF/vmlinux.h generation step - it's needed for clang to compile BPF targets
- **Don't** assume kernel features (always check `ls /sys/kernel/btf/vmlinux` first)

## High-Value Sources for Investigation

1. `book-2-hands-on/README.md` - project structure and chapter overview
2. `book/README.md` - comprehensive book overview and chapter map
3. `book-2-hands-on/chapters/01-hello-kernel.md` - minimal working example pattern
4. `book/chapters/09-first-ebpf-c.md` - complete eBPF program with skeleton API
5. `.commandcode/settings.json` - opencode permission boundaries

## Testing & Verification

- Build and run is the primary "test" - the chapters produce working eBPF tools
- Verify programs load: `sudo bpftool prog show`
- Check map contents: `sudo bpftool map dump name map_name`
- Monitor kernel traces: `sudo cat /sys/kernel/debug/tracing/trace_pipe`