#!/usr/bin/env bash
# Thor Firewall — eBPF Build Script
# Builds eBPF programs either natively or via Docker
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="${ROOT_DIR}/target/ebpf"

log()  { echo -e "\033[1;34m[BUILD]\033[0m $*"; }
ok()   { echo -e "\033[1;32m[  OK ]\033[0m $*"; }
warn() { echo -e "\033[1;33m[ WARN]\033[0m $*"; }
fail() { echo -e "\033[1;31m[ FAIL]\033[0m $*"; exit 1; }

log "Thor eBPF Build Script"
log "Output: ${OUT_DIR}"
mkdir -p "${OUT_DIR}"

# Try native build first
if command -v clang &>/dev/null && command -v llvm-strip &>/dev/null; then
    log "Native build (clang found)"
    CLANG_VER=$(clang --version | head -1)
    log "  ${CLANG_VER}"
    (cd "${ROOT_DIR}" && cargo xtask build-ebpf --release)
    ok "Native build succeeded"
    exit 0
fi

# Fallback: Docker build
if command -v docker &>/dev/null; then
    warn "clang/llvm not found — using Docker builder"
    IMAGE="thor-ebpf-builder:latest"
    
    # Build image if not present
    if ! docker image inspect "${IMAGE}" &>/dev/null 2>&1; then
        log "Building Docker image ${IMAGE}..."
        docker build -f "${ROOT_DIR}/docker/Dockerfile.ebpf" -t "${IMAGE}" "${ROOT_DIR}"
        ok "Docker image built"
    fi
    
    log "Running eBPF build in Docker..."
    docker run --rm \
        -v "${ROOT_DIR}:/work" \
        -w /work \
        "${IMAGE}" \
        cargo xtask build-ebpf --release
    ok "Docker build succeeded"
    exit 0
fi

fail "Neither clang nor docker found. Install one of:
  - clang + llvm:  apt-get install clang llvm
  - Docker:        https://docs.docker.com/engine/install/"
