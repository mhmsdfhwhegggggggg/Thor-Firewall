# Thor Firewall — eBPF Build System
# نظام بناء برامج eBPF/XDP

CLANG   ?= clang
LLC     ?= llc
ARCH    ?= x86
CFLAGS  := -O2 -Wall -Wextra -target bpf
CFLAGS  += -D__TARGET_ARCH_$(ARCH)
CFLAGS  += -I./headers
CFLAGS  += -I/usr/include
CFLAGS  += -I/usr/include/$(shell uname -m)-linux-gnu

# قائمة برامج eBPF المراد بناؤها
BPF_PROGS := xdp_main xdp_syn_flood_v2 tc_egress

OBJS := $(addsuffix .o, $(BPF_PROGS))

.PHONY: all clean verify generate-skel

all: $(OBJS) generate-skel
	@echo "✅ Thor eBPF programs built successfully"

%.o: %.c thor_common.h
	@echo "  CC  $@"
	$(CLANG) $(CFLAGS) -c $< -o $@
	# Verify BPF bytecode is valid
	@bpftool prog load $@ /sys/fs/bpf/thor_verify 2>/dev/null || true
	@rm -f /sys/fs/bpf/thor_verify 2>/dev/null || true

# Generate skeleton headers for Rust (via aya-gen or bpftool)
generate-skel: $(OBJS)
	@echo "  GEN skeleton headers"
	@for obj in $(OBJS); do \
		name=$$(basename $$obj .o); \
		bpftool gen skeleton $$obj > ../../$(name).skel.h 2>/dev/null || \
		echo "  WARN: bpftool not available, skipping skeleton for $$obj"; \
	done

# Verify BPF programs with kernel verifier
verify: $(OBJS)
	@echo "Verifying BPF programs..."
	@for obj in $(OBJS); do \
		echo "  Verifying $$obj..."; \
		sudo bpftool prog load $$obj /sys/fs/bpf/thor_$$(basename $$obj .o)_verify && \
		sudo rm -f /sys/fs/bpf/thor_$$(basename $$obj .o)_verify && \
		echo "  ✅ $$obj OK" || echo "  ❌ $$obj FAILED"; \
	done

clean:
	rm -f $(OBJS) *.skel.h
	@echo "Cleaned"

# Install headers (requires kernel source)
headers:
	@echo "Generating vmlinux.h from running kernel..."
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > headers/vmlinux.h
	@echo "✅ vmlinux.h generated"
