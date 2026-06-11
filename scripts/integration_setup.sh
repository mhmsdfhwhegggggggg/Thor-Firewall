#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Thor Firewall — Integration Setup Script
# تشغيل: bash scripts/integration_setup.sh [--profile full|endpoint|all]
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

PROFILE="${1:---profile}"
PROFILE_VALUE="${2:-core}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILES="-f $ROOT_DIR/docker-compose.yml -f $ROOT_DIR/docker-compose.integrations.yml"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# ── 0. Prerequisites check ───────────────────────────────────────────────────
info "Checking prerequisites..."
for cmd in docker curl jq; do
  if ! command -v "$cmd" &>/dev/null; then
    error "$cmd is required but not installed. Aborting."
    exit 1
  fi
done
DOCKER_COMPOSE_VERSION=$(docker compose version 2>/dev/null || true)
if [[ -z "$DOCKER_COMPOSE_VERSION" ]]; then
  error "Docker Compose v2 plugin required. Run: apt install docker-compose-plugin"
  exit 1
fi
success "All prerequisites found."

# ── 1. Load .env ─────────────────────────────────────────────────────────────
if [[ -f "$ROOT_DIR/.env" ]]; then
  info "Loading .env file..."
  set -a; source "$ROOT_DIR/.env"; set +a
else
  warn ".env not found. Copying from .env.example..."
  cp "$ROOT_DIR/.env.example" "$ROOT_DIR/.env" 2>/dev/null || true
  warn "Please review .env and re-run this script."
fi

# ── 2. Pull images ────────────────────────────────────────────────────────────
info "Pulling all Docker images (this may take several minutes)..."
docker compose $COMPOSE_FILES pull --quiet || warn "Some images couldn't be pulled — continuing anyway."
success "Images ready."

# ── 3. Start core services (databases, redis, kafka) ────────────────────────
info "Starting core infrastructure services..."
docker compose $COMPOSE_FILES up -d \
  clickhouse redis timescaledb zookeeper kafka keycloak-db keycloak
info "Waiting 20s for databases to become healthy..."
sleep 20

# ── 4. Start security stack ───────────────────────────────────────────────────
info "Starting security integration services..."
docker compose $COMPOSE_FILES \
  --profile integration \
  up -d \
  elasticsearch kibana logstash \
  wazuh-manager wazuh-indexer wazuh-dashboard \
  suricata \
  thehive thehive-db \
  shuffle-backend shuffle-frontend shuffle-orborus \
  misp misp-db \
  ossec-hids \
  coraza-waf
info "Waiting 40s for security services to start..."
sleep 40

# ── 5. Start observability + ML ──────────────────────────────────────────────
info "Starting observability and ML services..."
docker compose $COMPOSE_FILES up -d \
  prometheus grafana loki tempo \
  mlflow ml-inference bentoml
sleep 10

# ── 6. Start application layer ───────────────────────────────────────────────
info "Starting control-plane and dashboard..."
docker compose $COMPOSE_FILES up -d control-plane dashboard
sleep 15

# ── 7. Health checks ──────────────────────────────────────────────────────────
info "Running health checks..."
declare -A HEALTH_URLS=(
  ["ClickHouse"]="http://localhost:8123/ping"
  ["Kibana"]="http://localhost:5601/api/status"
  ["Wazuh API"]="https://localhost:55000/"
  ["TheHive"]="http://localhost:9000/api/v1/status"
  ["Shuffle"]="http://localhost:3001/api/v1/health"
  ["Control Plane"]="http://localhost:8000/api/health"
  ["Grafana"]="http://localhost:3001/api/health"
)
ALL_HEALTHY=true
for service in "${!HEALTH_URLS[@]}"; do
  URL="${HEALTH_URLS[$service]}"
  HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "$URL" 2>/dev/null || echo "000")
  if [[ "$HTTP_CODE" =~ ^(200|204|301|302)$ ]]; then
    success "$service is UP (HTTP $HTTP_CODE)"
  else
    warn "$service may not be ready yet (HTTP $HTTP_CODE) — URL: $URL"
    ALL_HEALTHY=false
  fi
done

# ── 8. Create default users ───────────────────────────────────────────────────
info "Creating default Wazuh integration user for TheHive..."
sleep 5
# Create TheHive API user via curl
TH_RESPONSE=$(curl -s -X POST "http://localhost:9000/api/v1/user" \
  -H "Content-Type: application/json" \
  -u "admin@thehive.local:secret" \
  -d '{"login":"wazuh@thor.local","name":"Wazuh Integration","password":"WazuhThor2024!","profile":"analyst"}' 2>/dev/null || echo '{}')
TH_LOGIN=$(echo "$TH_RESPONSE" | jq -r '.login // "failed"' 2>/dev/null || echo "failed")
if [[ "$TH_LOGIN" != "failed" && "$TH_LOGIN" != "null" ]]; then
  success "TheHive user 'wazuh@thor.local' created."
else
  warn "Couldn't auto-create TheHive user (may already exist or service not ready yet)."
fi

# ── 9. Configure Wazuh → TheHive integration ─────────────────────────────────
info "Injecting Wazuh custom integration config for TheHive..."
WAZUH_CONTAINER=$(docker ps --filter "name=thor-wazuh" --format "{{.Names}}" | head -1)
if [[ -n "$WAZUH_CONTAINER" ]]; then
  docker exec "$WAZUH_CONTAINER" bash -c '
    cat > /var/ossec/integrations/custom-thehive << '"'"'INTEGRATION_EOF'"'"'
#!/usr/bin/env python3
import sys, json, urllib.request, ssl
alert = json.loads(sys.stdin.read())
thehive_url = "http://thehive:9000/api/v1/alert"
auth = "wazuh@thor.local:WazuhThor2024!"
payload = {
  "type": "wazuh",
  "source": "wazuh",
  "sourceRef": alert.get("id",""),
  "title": alert.get("rule",{}).get("description","Wazuh Alert"),
  "description": json.dumps(alert, indent=2),
  "severity": min(4, int(alert.get("rule",{}).get("level",1))),
  "tags": ["wazuh", "automated"]
}
import base64
creds = base64.b64encode(auth.encode()).decode()
req = urllib.request.Request(thehive_url, json.dumps(payload).encode(),
  {"Content-Type":"application/json","Authorization":f"Basic {creds}"})
try:
  urllib.request.urlopen(req, context=ssl.create_default_context())
  print("Alert sent to TheHive")
except Exception as e:
  print(f"Error: {e}", file=sys.stderr)
INTEGRATION_EOF
    chmod 750 /var/ossec/integrations/custom-thehive
    chown root:wazuh /var/ossec/integrations/custom-thehive
  ' && success "Wazuh→TheHive integration script deployed." || warn "Couldn'"'"'t inject integration script."
fi

# ── 10. Summary ───────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Thor Firewall — Integration Stack Ready${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo "  Service         │ URL"
echo "  ────────────────┼───────────────────────────────"
echo "  Kibana          │ http://localhost:5601"
echo "  Wazuh Dashboard │ https://localhost:443"
echo "  TheHive         │ http://localhost:9000"
echo "  Shuffle         │ http://localhost:3001"
echo "  MISP            │ http://localhost:8081"
echo "  Grafana         │ http://localhost:3001"
echo "  Control Plane   │ http://localhost:8000"
echo "  Dashboard       │ http://localhost:3002"
echo ""
if $ALL_HEALTHY; then
  echo -e "  Status: ${GREEN}All services healthy ✓${NC}"
else
  echo -e "  Status: ${YELLOW}Some services still warming up — re-check in 2 min${NC}"
fi
echo ""
echo "  Logs: docker compose logs -f [service-name]"
echo "  Stop: docker compose $COMPOSE_FILES down"
echo ""
