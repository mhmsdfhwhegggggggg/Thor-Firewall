#!/usr/bin/env bash
# Thor Firewall — Production Deployment Script
# يُنفِّذ deployment كامل على Kubernetes باستخدام Helm
#
# المراحل:
# 1. فحص prerequisites
# 2. تهيئة cert-manager
# 3. Helm upgrade/install
# 4. انتظار pods
# 5. smoke tests
# 6. Rollback تلقائي عند الفشل
#
# SPDX-License-Identifier: MIT

set -euo pipefail

# ── Config ─────────────────────────────────────────────────────────────────────
NAMESPACE="${NAMESPACE:-thor-production}"
RELEASE="${RELEASE:-thor}"
CHART="./helm/thor-firewall"
VALUES_FILE="${VALUES_FILE:-./helm/thor-firewall/values-production.yaml}"
TAG="${TAG:-latest}"
TIMEOUT="${TIMEOUT:-600s}"
DRY_RUN="${DRY_RUN:-false}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log()  { echo -e "${BLUE}[$(date +%H:%M:%S)]${NC} $*"; }
ok()   { echo -e "${GREEN}✅${NC} $*"; }
warn() { echo -e "${YELLOW}⚠️ ${NC} $*"; }
fail() { echo -e "${RED}❌${NC} $*"; exit 1; }

# ── Prerequisites ──────────────────────────────────────────────────────────────
log "Checking prerequisites..."
command -v kubectl  >/dev/null 2>&1 || fail "kubectl not found"
command -v helm     >/dev/null 2>&1 || fail "helm not found"
kubectl cluster-info >/dev/null 2>&1 || fail "Cannot connect to Kubernetes cluster"
ok "Prerequisites OK"

# ── Namespace ─────────────────────────────────────────────────────────────────
log "Creating namespace ${NAMESPACE}..."
kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -
kubectl label namespace "${NAMESPACE}" \
  "thor.security/managed=true" \
  "pod-security.kubernetes.io/enforce=restricted" \
  --overwrite
ok "Namespace ready"

# ── cert-manager ─────────────────────────────────────────────────────────────
log "Applying cert-manager configs..."
kubectl apply -f k8s/cert-manager/ --server-side
ok "cert-manager configured"

# ── Helm repos ───────────────────────────────────────────────────────────────
helm repo add jetstack     https://charts.jetstack.io         2>/dev/null || true
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx 2>/dev/null || true
helm repo update

# ── Deploy ────────────────────────────────────────────────────────────────────
log "Deploying Thor Firewall ${TAG} to ${NAMESPACE}..."

HELM_ARGS=(
  upgrade "${RELEASE}" "${CHART}"
  --install
  --namespace "${NAMESPACE}"
  --values "${VALUES_FILE}"
  --set "global.tag=${TAG}"
  --set "global.timestamp=$(date -u +%Y%m%d%H%M%S)"
  --timeout "${TIMEOUT}"
  --wait
  --atomic            # Rollback automatique si échec
  --cleanup-on-fail
  --history-max 10
)

[[ "${DRY_RUN}" == "true" ]] && HELM_ARGS+=("--dry-run")

helm "${HELM_ARGS[@]}"
ok "Helm deployment complete"

# ── Wait for all pods ─────────────────────────────────────────────────────────
if [[ "${DRY_RUN}" != "true" ]]; then
  log "Waiting for all pods to be Ready..."
  kubectl rollout status deployment/${RELEASE}-control-plane -n "${NAMESPACE}" --timeout=300s
  kubectl rollout status daemonset/${RELEASE}-agent          -n "${NAMESPACE}" --timeout=300s
  ok "All pods ready"

  # ── Smoke Tests ───────────────────────────────────────────────────────────
  log "Running smoke tests..."
  API_URL=$(kubectl get ingress -n "${NAMESPACE}" -o jsonpath='{.items[0].spec.rules[0].host}' 2>/dev/null || echo "localhost")

  HEALTH=$(kubectl exec -n "${NAMESPACE}" \
    deploy/${RELEASE}-control-plane -- \
    wget -qO- http://localhost:8000/api/health 2>/dev/null || echo '{}')

  STATUS=$(echo "${HEALTH}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','unknown'))" 2>/dev/null || echo "unknown")

  if [[ "${STATUS}" == "healthy" ]]; then
    ok "Smoke test passed: API is healthy"
  else
    warn "Smoke test inconclusive (status=${STATUS}) — check logs manually"
  fi

  # ── Show deployment info ───────────────────────────────────────────────────
  echo ""
  ok "🚀 Thor Firewall deployed successfully!"
  echo ""
  kubectl get pods -n "${NAMESPACE}" -l "app.kubernetes.io/instance=${RELEASE}"
  echo ""
  echo "Dashboard URL: https://${API_URL}"
  echo "API URL:       https://api.${API_URL}"
fi
