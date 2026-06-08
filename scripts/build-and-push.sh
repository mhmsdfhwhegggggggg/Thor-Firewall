#!/usr/bin/env bash
# Thor Firewall — Build & Push Docker images to GHCR
# الاستخدام: ./scripts/build-and-push.sh [--tag v1.2.3] [--push]
#
# يبني الـ images التالية:
#   ghcr.io/OWNER/thor-control-plane:TAG
#   ghcr.io/OWNER/thor-dashboard:TAG
#   ghcr.io/OWNER/thor-agent:TAG
#   ghcr.io/OWNER/thor-ml-inference:TAG
#
# SPDX-License-Identifier: MIT

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
REGISTRY="${REGISTRY:-ghcr.io}"
OWNER="${GITHUB_REPOSITORY_OWNER:-mhmsdfhwhegggggggg}"
TAG="${TAG:-$(git describe --tags --always --dirty 2>/dev/null || echo 'dev')}"
PUSH="${PUSH:-false}"
PLATFORM="${PLATFORM:-linux/amd64,linux/arm64}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log()  { echo -e "${BLUE}[$(date +%H:%M:%S)]${NC} $*"; }
ok()   { echo -e "${GREEN}✅${NC} $*"; }
warn() { echo -e "${YELLOW}⚠️ ${NC} $*"; }
fail() { echo -e "${RED}❌${NC} $*"; exit 1; }

# ── Parse args ────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case $1 in
    --tag)     TAG="$2"; shift 2 ;;
    --push)    PUSH=true; shift ;;
    --owner)   OWNER="$2"; shift 2 ;;
    --platform) PLATFORM="$2"; shift 2 ;;
    *) fail "Unknown argument: $1" ;;
  esac
done

log "Building Thor Firewall images"
log "Registry: ${REGISTRY}/${OWNER}"
log "Tag: ${TAG}"
log "Push: ${PUSH}"
log "Platform: ${PLATFORM}"

# ── Check prerequisites ───────────────────────────────────────────────────────
command -v docker >/dev/null 2>&1 || fail "docker not found"
docker buildx version >/dev/null 2>&1 || fail "docker buildx not available"

if [[ "${PUSH}" == "true" ]]; then
  [[ -z "${GITHUB_TOKEN:-}" ]] && fail "GITHUB_TOKEN not set — required for pushing to GHCR"
  echo "${GITHUB_TOKEN}" | docker login "${REGISTRY}" -u "${OWNER}" --password-stdin
  ok "Logged in to ${REGISTRY}"
fi

# ── Build function ────────────────────────────────────────────────────────────
build_image() {
  local name="$1"; local context="$2"; local dockerfile="$3"
  local full_tag="${REGISTRY}/${OWNER}/${name}:${TAG}"
  local latest_tag="${REGISTRY}/${OWNER}/${name}:latest"

  log "Building ${name}..."
  local build_args=(
    "buildx" "build"
    "--platform" "${PLATFORM}"
    "--file"     "${dockerfile}"
    "--tag"      "${full_tag}"
    "--tag"      "${latest_tag}"
    "--label"    "org.opencontainers.image.created=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    "--label"    "org.opencontainers.image.revision=$(git rev-parse HEAD 2>/dev/null || echo unknown)"
    "--label"    "org.opencontainers.image.version=${TAG}"
    "--label"    "org.opencontainers.image.source=https://github.com/${OWNER}/Thor-Firewall"
    "--cache-from" "type=gha"
    "--cache-to"   "type=gha,mode=max"
  )

  [[ "${PUSH}" == "true" ]] && build_args+=("--push") || build_args+=("--load")
  build_args+=("${context}")

  docker "${build_args[@]}"
  ok "Built ${full_tag}"
}

# ── Build all images ──────────────────────────────────────────────────────────
build_image "thor-control-plane"  "."           "control-plane/Dockerfile"
build_image "thor-dashboard"      "."           "dashboard/Dockerfile"
build_image "thor-agent"          "agent"       "agent/Dockerfile"
build_image "thor-ml-inference"   "ml"          "ml/Dockerfile"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
ok "All images built successfully!"
echo ""
echo "Images:"
echo "  ${REGISTRY}/${OWNER}/thor-control-plane:${TAG}"
echo "  ${REGISTRY}/${OWNER}/thor-dashboard:${TAG}"
echo "  ${REGISTRY}/${OWNER}/thor-agent:${TAG}"
echo "  ${REGISTRY}/${OWNER}/thor-ml-inference:${TAG}"
echo ""
if [[ "${PUSH}" != "true" ]]; then
  warn "Images built locally only. Use --push to push to ${REGISTRY}"
fi
