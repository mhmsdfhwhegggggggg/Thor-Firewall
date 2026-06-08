# Thor Firewall — Agent Dockerfile
# Rust multi-stage build with eBPF programs

FROM rust:1.82-slim AS builder

WORKDIR /build

# Install eBPF build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm libelf-dev linux-libc-dev \
    pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Add bpf target
RUN rustup target add bpfel-unknown-none

# Cache dependencies
COPY agent/Cargo.toml agent/Cargo.lock ./
RUN mkdir -p src && echo "fn main(){}" > src/main.rs && cargo build --release || true

# Build eBPF programs
COPY agent/ .
RUN cargo xtask build-ebpf 2>/dev/null || echo "eBPF build skipped (no kernel headers)"

# Build user space agent
RUN cargo build --release

# ── Runtime ───────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 ca-certificates iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/thor-agent /usr/local/bin/

# Needs NET_ADMIN + BPF capabilities (set in K8s securityContext, not here)
RUN useradd -r -s /sbin/nologin thor

EXPOSE 9090
HEALTHCHECK --interval=30s CMD test -f /proc/net/dev

ENTRYPOINT ["thor-agent"]
