#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Thor Firewall — Integration Setup Script v2.0
# الاستخدام: sudo bash scripts/integration_setup.sh
# المتطلبات: Ubuntu 20.04+ | 16GB RAM | 100GB Disk | صلاحيات root
# ═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail
IFS=$'\n\t'

# ─── Constants ────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
LOG_FILE="/var/log/thor_integration.log"
ENV_FILE="$ROOT_DIR/.env"
ENV_EXAMPLE="$ROOT_DIR/.env.example"
COMPOSE_BASE="$ROOT_DIR/docker-compose.yml"
COMPOSE_INT="$ROOT_DIR/docker-compose.integrations.yml"
COMPOSE_CMD="docker compose -f $COMPOSE_BASE -f $COMPOSE_INT --profile integration"
MIN_RAM_MB=8192
MIN_DISK_GB=40

# ─── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

# ─── Logging ──────────────────────────────────────────────────────────────────
exec > >(tee -a "$LOG_FILE") 2>&1
log()     { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${BLUE}[INFO]${NC}  $*"; }
ok()      { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${YELLOW}[WARN]${NC}  $*"; }
err()     { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${RED}[ERROR]${NC} $*" >&2; }
step()    { echo -e "\n${BOLD}${CYAN}━━━ $* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }
die()     { err "$*"; exit 1; }

# ─── Root check ───────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "Run as root: sudo bash $0"

echo ""
echo -e "${BOLD}${CYAN}"
echo "  ████████╗██╗  ██╗ ██████╗ ██████╗      ███████╗██╗   ██╗██╗      "
echo "     ██╔══╝██║  ██║██╔═══██╗██╔══██╗     ██╔════╝██║   ██║██║      "
echo "     ██║   ███████║██║   ██║██████╔╝     █████╗  ██║   ██║██║      "
echo "     ██║   ██╔══██║██║   ██║██╔══██╗     ██╔══╝  ╚██╗ ██╔╝██║      "
echo "     ██║   ██║  ██║╚██████╔╝██║  ██║     ██║      ╚████╔╝ ███████╗ "
echo "     ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝     ╚═╝       ╚═══╝  ╚══════╝ "
echo -e "${NC}"
echo -e "  ${BOLD}Thor Firewall — Integration Setup v2.0${NC}"
echo -e "  Log: $LOG_FILE"
echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 1 — System Prerequisites
# ═══════════════════════════════════════════════════════════════════════════════
step "STEP 1: Checking System Requirements"

# OS check
if ! grep -qiE "(ubuntu|debian)" /etc/os-release 2>/dev/null; then
  warn "Unsupported OS — script tested on Ubuntu 20.04+. Continuing anyway."
fi

# RAM check
RAM_MB=$(awk '/MemTotal/ {printf "%.0f", $2/1024}' /proc/meminfo)
if [[ $RAM_MB -lt $MIN_RAM_MB ]]; then
  warn "RAM: ${RAM_MB}MB detected. Minimum recommended: ${MIN_RAM_MB}MB."
  warn "Elasticsearch and Wazuh Indexer may crash. Consider upgrading."
else
  ok "RAM: ${RAM_MB}MB — sufficient."
fi

# Disk check
DISK_GB=$(df -BG "$ROOT_DIR" | awk 'NR==2 {gsub("G",""); print $4}')
if [[ $DISK_GB -lt $MIN_DISK_GB ]]; then
  warn "Free disk: ${DISK_GB}GB. Minimum recommended: ${MIN_DISK_GB}GB."
else
  ok "Disk: ${DISK_GB}GB free — sufficient."
fi

# vm.max_map_count for Elasticsearch
CURRENT_MAP=$(sysctl -n vm.max_map_count)
if [[ $CURRENT_MAP -lt 262144 ]]; then
  log "Setting vm.max_map_count=262144 (required by Elasticsearch)..."
  sysctl -w vm.max_map_count=262144
  echo "vm.max_map_count=262144" >> /etc/sysctl.conf
  ok "vm.max_map_count set to 262144."
else
  ok "vm.max_map_count=$CURRENT_MAP — OK."
fi

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 2 — Install Docker & Docker Compose
# ═══════════════════════════════════════════════════════════════════════════════
step "STEP 2: Installing Docker & Docker Compose"

install_docker() {
  log "Installing Docker CE..."
  apt-get update -qq
  apt-get install -y -qq ca-certificates curl gnupg lsb-release
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
    gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
    https://download.docker.com/linux/ubuntu \
    $(lsb_release -cs) stable" | \
    tee /etc/apt/sources.list.d/docker.list > /dev/null
  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io \
    docker-buildx-plugin docker-compose-plugin
  systemctl enable docker --now
  ok "Docker CE installed: $(docker --version)"
}

if ! command -v docker &>/dev/null; then
  install_docker
else
  ok "Docker already installed: $(docker --version)"
fi

if ! docker compose version &>/dev/null; then
  log "Installing docker-compose-plugin..."
  apt-get install -y -qq docker-compose-plugin
  ok "Docker Compose plugin installed."
else
  ok "Docker Compose available: $(docker compose version)"
fi

# Install helper tools
log "Installing helper tools (curl, jq, net-tools)..."
apt-get install -y -qq curl jq net-tools nmap hping3 2>/dev/null || \
  apt-get install -y -qq curl jq net-tools nmap 2>/dev/null || true
ok "Helper tools ready."

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 3 — Environment Setup
# ═══════════════════════════════════════════════════════════════════════════════
step "STEP 3: Setting Up Environment Variables"

if [[ ! -f "$ENV_FILE" ]]; then
  if [[ -f "$ENV_EXAMPLE" ]]; then
    cp "$ENV_EXAMPLE" "$ENV_FILE"
    ok "Created .env from .env.example"
  else
    log "Creating .env with secure defaults..."
    cat > "$ENV_FILE" << 'ENVEOF'
# Thor Firewall — Auto-generated .env
CLICKHOUSE_PASSWORD=thor_dev_password
TIMESCALEDB_PASSWORD=thor_ts_dev_password
KEYCLOAK_DB_PASSWORD=keycloak_dev_pass
KEYCLOAK_ADMIN_PASSWORD=Admin2024!
KEYCLOAK_HOSTNAME=localhost
ELASTIC_PASSWORD=ElasticThor2024!
KIBANA_SYSTEM_PASSWORD=KibanaThor2024!
KIBANA_ENCRYPTION_KEY=changethisto32charsecretkey1234
WAZUH_API_PASSWORD=MyS3cr37P450r.*-
WAZUH_INDEXER_PASSWORD=SecretPassword
THEHIVE_SECRET=thor_thehive_secret_change_me
THEHIVE_DB_PASSWORD=thehive_pass
MISP_DB_ROOT_PASSWORD=misp_root_dev
MISP_DB_PASSWORD=misp_dev_password
MISP_ADMIN_EMAIL=admin@thor.local
MISP_ADMIN_PASSWORD=MispAdmin2024!
JWT_SECRET=dev_secret_change_in_prod
AUDIT_HMAC_SECRET=hmac_dev_change_in_prod_32b!!
ENVIRONMENT=development
VITE_API_URL=http://localhost:8000
ML_DEVICE=cpu
GRAFANA_ADMIN_USER=admin
GRAFANA_PASSWORD=GrafanaThor2024!
SURICATA_INTERFACE=eth0
HOME_NET=[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]
ENVEOF
    ok "Created .env with default values."
  fi
else
  ok ".env already exists — using existing values."
fi

# Load env vars
set -a; source "$ENV_FILE"; set +a
ok "Environment variables loaded."

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 4 — Generate Logstash Pipelines
# ═══════════════════════════════════════════════════════════════════════════════
step "STEP 4: Creating Logstash Pipeline Configs"

mkdir -p "$ROOT_DIR/configs/logstash/pipeline"

# Wazuh → Elasticsearch + TheHive forwarder
cat > "$ROOT_DIR/configs/logstash/pipeline/wazuh.conf" << 'LOGSTASH_EOF'
input {
  tcp {
    port => 5045
    codec => json_lines
    tags  => ["wazuh"]
  }
}
filter {
  if "wazuh" in [tags] {
    date {
      match    => ["timestamp", "ISO8601"]
      target   => "@timestamp"
      timezone => "UTC"
    }
    mutate {
      add_field => { "thor_source" => "wazuh" }
      add_field => { "[@metadata][es_index]" => "wazuh-alerts-%{+YYYY.MM.dd}" }
    }
    # Extract severity for TheHive routing
    if [rule][level] {
      mutate { add_field => { "[@metadata][alert_level]" => "%{[rule][level]}" } }
    }
  }
}
output {
  if "wazuh" in [tags] {
    elasticsearch {
      hosts    => ["http://elasticsearch:9200"]
      user     => "elastic"
      password => "${ELASTIC_PASSWORD}"
      index    => "%{[@metadata][es_index]}"
      action   => "index"
    }
    # Forward high-severity alerts (level >= 7) to TheHive via HTTP
    if [@metadata][alert_level] and [@metadata][alert_level] >= "7" {
      http {
        url              => "http://thehive:9000/api/v1/alert"
        http_method      => "post"
        content_type     => "application/json"
        headers          => { "Authorization" => "Bearer ${THEHIVE_API_KEY}" }
        format           => "json"
        mapping          => {
          "type"      => "wazuh"
          "source"    => "wazuh-logstash"
          "sourceRef" => "%{[id]}"
          "title"     => "%{[rule][description]}"
          "severity"  => 2
          "tags"      => ["wazuh", "automated", "level-%{[rule][level]}"]
          "description" => "Rule: %{[rule][description]}\nAgent: %{[agent][name]}\nLevel: %{[rule][level]}\nTimestamp: %{[timestamp]}"
        }
      }
    }
  }
}
LOGSTASH_EOF

# Suricata EVE → Elasticsearch
cat > "$ROOT_DIR/configs/logstash/pipeline/suricata.conf" << 'SURICATA_PIPE_EOF'
input {
  file {
    path  => "/var/log/suricata/eve.json"
    codec => json
    tags  => ["suricata"]
    sincedb_path => "/usr/share/logstash/data/.sincedb_suricata"
    start_position => "beginning"
  }
}
filter {
  if "suricata" in [tags] {
    date {
      match    => ["timestamp", "ISO8601"]
      target   => "@timestamp"
      timezone => "UTC"
    }
    mutate {
      add_field => { "thor_source" => "suricata" }
    }
    if [event_type] == "alert" {
      mutate {
        add_field => { "[@metadata][es_index]" => "suricata-alerts-%{+YYYY.MM.dd}" }
        add_tag   => ["suricata_alert"]
      }
    } else {
      mutate {
        add_field => { "[@metadata][es_index]" => "suricata-events-%{+YYYY.MM.dd}" }
      }
    }
  }
}
output {
  if "suricata" in [tags] {
    elasticsearch {
      hosts    => ["http://elasticsearch:9200"]
      user     => "elastic"
      password => "${ELASTIC_PASSWORD}"
      index    => "%{[@metadata][es_index]}"
    }
    # Forward Suricata alerts with severity >= 1 to TheHive
    if "suricata_alert" in [tags] {
      http {
        url          => "http://thehive:9000/api/v1/alert"
        http_method  => "post"
        content_type => "application/json"
        headers      => { "Authorization" => "Bearer ${THEHIVE_API_KEY}" }
        format       => "json"
        mapping      => {
          "type"      => "suricata"
          "source"    => "suricata-nids"
          "sourceRef" => "%{[flow_id]}"
          "title"     => "Suricata: %{[alert][signature]}"
          "severity"  => 2
          "tags"      => ["suricata", "nids", "%{[alert][category]}"]
          "description" => "Signature: %{[alert][signature]}\nSrc: %{[src_ip]}:%{[src_port]}\nDst: %{[dest_ip]}:%{[dest_port]}\nProto: %{[proto]}"
        }
      }
    }
  }
}
SURICATA_PIPE_EOF

# Logstash main config
cat > "$ROOT_DIR/configs/logstash/logstash.yml" << 'LS_YML_EOF'
http.host: "0.0.0.0"
xpack.monitoring.enabled: false
pipeline.workers: 2
pipeline.batch.size: 125
pipeline.batch.delay: 50
path.config: /usr/share/logstash/pipeline
LS_YML_EOF

ok "Logstash pipeline configs created."

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 5 — Generate Shuffle IP-Block Playbook
# ═══════════════════════════════════════════════════════════════════════════════
step "STEP 5: Creating Shuffle IP-Block Playbook"

mkdir -p "$ROOT_DIR/configs/shuffle"
cat > "$ROOT_DIR/configs/shuffle/ip_block_workflow.json" << 'SHUFFLE_EOF'
{
  "id": "thor-ip-block-workflow",
  "name": "Thor — Auto IP Block on Alert",
  "description": "يستقبل تنبيهاً من TheHive أو Wazuh ويحظر IP المصدر تلقائياً عبر iptables + Coraza WAF",
  "tags": ["thor", "auto-response", "ip-block"],
  "triggers": [
    {
      "id": "webhook-trigger",
      "app_name": "Webhook",
      "name": "TheHive Alert Received",
      "description": "استقبال تنبيه جديد من TheHive",
      "type": "WEBHOOK",
      "status": "running",
      "parameters": [
        { "name": "url_suffix", "value": "/thor-ip-block" }
      ]
    }
  ],
  "actions": [
    {
      "id": "extract-ip",
      "app_name": "Shuffle Tools",
      "app_version": "1.2.0",
      "name": "Extract Source IP",
      "label": "استخراج IP المصدر",
      "description": "استخراج عنوان IP من بيانات التنبيه",
      "parameters": [
        {
          "name": "input_data",
          "value": "$exec"
        },
        {
          "name": "regex",
          "value": "\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b"
        }
      ]
    },
    {
      "id": "check-whitelist",
      "app_name": "Shuffle Tools",
      "app_version": "1.2.0",
      "name": "Check IP Whitelist",
      "label": "التحقق من القائمة البيضاء",
      "description": "تجاهل IPs المحلية والمقيّدة",
      "parameters": [
        {
          "name": "input_data",
          "value": "$extract-ip"
        },
        {
          "name": "check",
          "value": "not in [\"127.0.0.1\", \"0.0.0.0\", \"192.168.1.1\"]"
        }
      ]
    },
    {
      "id": "block-with-iptables",
      "app_name": "SSH",
      "app_version": "1.0.0",
      "name": "Block IP via iptables (60 min)",
      "label": "حظر IP مؤقت 60 دقيقة",
      "description": "حظر IP المصدر عبر iptables لمدة 60 دقيقة",
      "parameters": [
        {
          "name": "host",
          "value": "${FIREWALL_HOST:-localhost}"
        },
        {
          "name": "command",
          "value": "iptables -I INPUT -s $check-whitelist -j DROP -m comment --comment 'thor-auto-block' && echo 'Blocked $check-whitelist for 60min' && (sleep 3600 && iptables -D INPUT -s $check-whitelist -j DROP -m comment --comment 'thor-auto-block') &"
        }
      ]
    },
    {
      "id": "notify-thehive",
      "app_name": "TheHive",
      "app_version": "1.0.0",
      "name": "Update TheHive Case",
      "label": "تحديث الحادثة في TheHive",
      "description": "إضافة ملاحظة للحادثة بأن IP تم حظره",
      "parameters": [
        {
          "name": "apikey",
          "value": "${THEHIVE_API_KEY}"
        },
        {
          "name": "url",
          "value": "http://thehive:9000"
        },
        {
          "name": "note",
          "value": "✅ AUTO-RESPONSE: IP $check-whitelist blocked via iptables for 60 minutes at $(date '+%Y-%m-%d %H:%M:%S'). Action taken by Thor Shuffle playbook."
        }
      ]
    }
  ],
  "start": "extract-ip",
  "execution_argument": ""
}
SHUFFLE_EOF

ok "Shuffle IP-block playbook created."

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 6 — Start Services
# ═══════════════════════════════════════════════════════════════════════════════
step "STEP 6: Starting Docker Services"

cd "$ROOT_DIR"

# Pull images first
log "Pulling Docker images (this may take 5-15 minutes on first run)..."
$COMPOSE_CMD pull --quiet 2>&1 | tail -5 || warn "Some images failed to pull — will use cached/build."

# Start databases first
log "Starting databases and core infrastructure..."
$COMPOSE_CMD up -d \
  clickhouse redis timescaledb \
  keycloak-db keycloak \
  zookeeper kafka
log "Waiting 30s for databases to initialize..."
sleep 30

# Start Elasticsearch first (Kibana depends on it)
log "Starting Elasticsearch..."
$COMPOSE_CMD up -d elasticsearch
log "Waiting up to 90s for Elasticsearch to be ready..."
for i in $(seq 1 18); do
  HTTP=$(curl -su "elastic:${ELASTIC_PASSWORD:-ElasticThor2024!}" \
    "http://localhost:9200/_cluster/health" -o /dev/null -w "%{http_code}" 2>/dev/null || echo 000)
  if [[ "$HTTP" == "200" ]]; then
    ok "Elasticsearch is ready (attempt $i)."
    break
  fi
  log "  attempt $i/18 — HTTP $HTTP — waiting 5s..."
  sleep 5
done

# Set Kibana system password in Elasticsearch
log "Setting Kibana system user password in Elasticsearch..."
curl -s -X POST "http://localhost:9200/_security/user/kibana_system/_password" \
  -su "elastic:${ELASTIC_PASSWORD:-ElasticThor2024!}" \
  -H "Content-Type: application/json" \
  -d "{\"password\":\"${KIBANA_SYSTEM_PASSWORD:-KibanaThor2024!}\"}" > /dev/null && \
  ok "Kibana system password set." || warn "Could not set Kibana system password."

# Create wazuh-alerts index template
log "Creating Elasticsearch index templates..."
curl -s -X PUT "http://localhost:9200/_index_template/wazuh-alerts" \
  -su "elastic:${ELASTIC_PASSWORD:-ElasticThor2024!}" \
  -H "Content-Type: application/json" \
  -d '{"index_patterns":["wazuh-alerts-*"],"template":{"settings":{"number_of_shards":1,"number_of_replicas":0}}}' \
  > /dev/null && ok "Index template wazuh-alerts-* created."
curl -s -X PUT "http://localhost:9200/_index_template/suricata" \
  -su "elastic:${ELASTIC_PASSWORD:-ElasticThor2024!}" \
  -H "Content-Type: application/json" \
  -d '{"index_patterns":["suricata-*"],"template":{"settings":{"number_of_shards":1,"number_of_replicas":0}}}' \
  > /dev/null && ok "Index template suricata-* created."

# Start remaining security stack
log "Starting security services (Kibana, Wazuh, TheHive, Shuffle, Suricata, OSSEC, Coraza)..."
$COMPOSE_CMD up -d \
  kibana logstash \
  wazuh-manager \
  thehive-db thehive \
  shuffle-database shuffle-backend shuffle-frontend shuffle-orborus \
  misp-db misp \
  ossec-hids \
  coraza-waf
log "Waiting 60s for security services to warm up..."
sleep 60

# Start observability
log "Starting observability stack (Prometheus, Grafana, Loki)..."
$COMPOSE_CMD up -d prometheus grafana loki

# Start application
log "Starting control-plane and dashboard..."
$COMPOSE_CMD up -d control-plane dashboard
sleep 20

ok "All services started."

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 7 — Health Checks
# ═══════════════════════════════════════════════════════════════════════════════
step "STEP 7: Running Health Checks"

wait_for_http() {
  local name="$1" url="$2" user="${3:-}" pass="${4:-}" max="${5:-24}"
  log "Waiting for $name at $url ..."
  for i in $(seq 1 $max); do
    local HTTP
    if [[ -n "$user" ]]; then
      HTTP=$(curl -sk -u "$user:$pass" "$url" -o /dev/null -w "%{http_code}" --max-time 5 2>/dev/null || echo 000)
    else
      HTTP=$(curl -sk "$url" -o /dev/null -w "%{http_code}" --max-time 5 2>/dev/null || echo 000)
    fi
    if [[ "$HTTP" =~ ^(200|201|204|302)$ ]]; then
      ok "$name ready — HTTP $HTTP (attempt $i/$max)"
      return 0
    fi
    log "  $name: attempt $i/$max — HTTP $HTTP"
    sleep 5
  done
  warn "$name did not become healthy after $((max*5))s — continuing anyway."
  return 1
}

wait_for_http "Elasticsearch" "http://localhost:9200" "elastic" "${ELASTIC_PASSWORD:-ElasticThor2024!}"
wait_for_http "Kibana"        "http://localhost:5601/api/status" "elastic" "${ELASTIC_PASSWORD:-ElasticThor2024!}"
wait_for_http "TheHive"       "http://localhost:9000/api/v1/status"
wait_for_http "Shuffle"       "http://localhost:3001"
wait_for_http "Grafana"       "http://localhost:3001/api/health" "admin" "${GRAFANA_PASSWORD:-GrafanaThor2024!}" 12

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 8 — Configure Users via API
# ═══════════════════════════════════════════════════════════════════════════════
step "STEP 8: Configuring Users via API"

# ── TheHive: create wazuh integration user ─────────────────────────────────
log "Creating TheHive integration user (wazuh@thor.local)..."
TH_RESPONSE=$(curl -s -X POST "http://localhost:9000/api/v1/user" \
  -H "Content-Type: application/json" \
  -H "X-Organisation: admin" \
  --user "admin@thehive.local:secret" \
  -d '{
    "login":    "wazuh@thor.local",
    "name":     "Wazuh Integration",
    "password": "WazuhThor2024!",
    "profile":  "analyst",
    "roles":    ["read","write","alert"]
  }' 2>/dev/null || echo '{}')

TH_USER=$(echo "$TH_RESPONSE" | jq -r '.login // .message // "unknown"' 2>/dev/null || echo "unknown")
if [[ "$TH_USER" == "wazuh@thor.local" ]]; then
  ok "TheHive user 'wazuh@thor.local' created."
else
  warn "TheHive user creation returned: $TH_USER (may already exist)."
fi

# ── TheHive: get or create API key ─────────────────────────────────────────
log "Generating TheHive API key for wazuh user..."
TH_APIKEY=$(curl -s -X GET "http://localhost:9000/api/v1/user/wazuh@thor.local/key" \
  --user "admin@thehive.local:secret" \
  -H "X-Organisation: admin" 2>/dev/null | jq -r '.key // ""' 2>/dev/null || echo "")

if [[ -z "$TH_APIKEY" ]]; then
  TH_APIKEY=$(curl -s -X POST "http://localhost:9000/api/v1/user/wazuh@thor.local/key/renew" \
    --user "admin@thehive.local:secret" \
    -H "X-Organisation: admin" 2>/dev/null | jq -r '.key // ""' 2>/dev/null || echo "")
fi

if [[ -n "$TH_APIKEY" && "$TH_APIKEY" != "null" ]]; then
  ok "TheHive API key obtained."
  # Update .env with the API key
  if grep -q "^THEHIVE_API_KEY=" "$ENV_FILE"; then
    sed -i "s|^THEHIVE_API_KEY=.*|THEHIVE_API_KEY=$TH_APIKEY|" "$ENV_FILE"
  else
    echo "THEHIVE_API_KEY=$TH_APIKEY" >> "$ENV_FILE"
  fi
  export THEHIVE_API_KEY="$TH_APIKEY"
else
  warn "Could not get TheHive API key — THEHIVE_API_KEY will be empty."
fi

# ── Wazuh: inject custom-thehive integration script ────────────────────────
log "Injecting Wazuh → TheHive custom integration script..."
WAZUH_CONTAINER=$(docker ps --filter "name=thor-wazuh" --format "{{.Names}}" | head -1 || echo "")
if [[ -n "$WAZUH_CONTAINER" ]]; then
  docker exec "$WAZUH_CONTAINER" bash -c "
cat > /var/ossec/integrations/custom-thehive << 'PEOF'
#!/usr/bin/env python3
import sys, json, urllib.request, urllib.error, ssl, os
alert_file = sys.argv[1]
with open(alert_file) as f:
    alert = json.load(f)
api_key = os.environ.get('THEHIVE_API_KEY', '${TH_APIKEY}')
url     = 'http://thehive:9000/api/v1/alert'
level   = int(alert.get('rule', {}).get('level', 0))
if level < 7:
    sys.exit(0)
payload = {
    'type':      'wazuh',
    'source':    'wazuh',
    'sourceRef': str(alert.get('id', 'unknown')),
    'title':     alert.get('rule', {}).get('description', 'Wazuh Alert'),
    'severity':  min(4, max(1, level // 3)),
    'tags':      ['wazuh', 'automated', 'level-' + str(level)],
    'description': json.dumps(alert, indent=2)
}
req = urllib.request.Request(
    url, json.dumps(payload).encode(),
    {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + api_key}
)
try:
    urllib.request.urlopen(req, context=ssl._create_unverified_context())
    print('Alert forwarded to TheHive')
except urllib.error.HTTPError as e:
    body = e.read().decode()
    print(f'TheHive HTTP error {e.code}: {body}', file=sys.stderr)
    sys.exit(1)
except Exception as e:
    print(f'Error: {e}', file=sys.stderr)
    sys.exit(1)
PEOF
chmod 750 /var/ossec/integrations/custom-thehive
chown root:wazuh /var/ossec/integrations/custom-thehive
# Patch ossec.conf to enable integration if not already present
if ! grep -q 'custom-thehive' /var/ossec/etc/ossec.conf; then
    sed -i '/<\/ossec_config>/i \\  <integration>\n    <name>custom-thehive<\/name>\n    <level>7<\/level>\n    <alert_format>json<\/alert_format>\n  <\/integration>' \
      /var/ossec/etc/ossec.conf
fi
/var/ossec/bin/wazuh-control restart 2>/dev/null || true
echo 'Wazuh integration patched.'
" && ok "Wazuh → TheHive integration script deployed." || \
  warn "Could not inject Wazuh integration script."
fi

# ── Shuffle: import IP-block workflow ──────────────────────────────────────
log "Importing Shuffle IP-block playbook..."
SHUFFLE_KEY=$(curl -s -X POST "http://localhost:3001/api/v1/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password"}' 2>/dev/null | \
  jq -r '.success // ""' 2>/dev/null || echo "")
if [[ "$SHUFFLE_KEY" == "true" ]]; then
  ok "Shuffle login successful."
  curl -s -X POST "http://localhost:3001/api/v1/workflows/import" \
    -H "Authorization: Bearer $SHUFFLE_KEY" \
    -F "file=@$ROOT_DIR/configs/shuffle/ip_block_workflow.json" \
    > /dev/null 2>&1 && ok "Shuffle workflow imported." || \
    warn "Could not import Shuffle workflow automatically — import manually via UI."
else
  warn "Shuffle API not ready yet — import workflow manually: configs/shuffle/ip_block_workflow.json"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 9 — Verify Running Containers
# ═══════════════════════════════════════════════════════════════════════════════
step "STEP 9: Container Status"

echo ""
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | \
  grep -E "thor|NAME" | sort
echo ""

RUNNING=$(docker ps --filter "name=thor" --format "{{.Names}}" | wc -l)
ok "$RUNNING Thor containers running."

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 10 — Final Summary
# ═══════════════════════════════════════════════════════════════════════════════
step "STEP 10: Setup Complete — Access URLs"

HOST_IP=$(hostname -I | awk '{print $1}')

echo ""
echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}  ✅  Thor Firewall Integration Stack — Ready!${NC}"
echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BOLD}Service             URL                                  Credentials${NC}"
echo    "  ─────────────────────────────────────────────────────────────────────"
echo -e "  Kibana              http://$HOST_IP:5601             elastic / ${ELASTIC_PASSWORD:-ElasticThor2024!}"
echo -e "  Wazuh Dashboard     https://$HOST_IP:443             admin / ${WAZUH_API_PASSWORD:-MyS3cr37P450r.*-}"
echo -e "  TheHive             http://$HOST_IP:9000             admin@thehive.local / secret"
echo -e "  Shuffle (SOAR)      http://$HOST_IP:3001             admin / password"
echo -e "  MISP                http://$HOST_IP:8081             ${MISP_ADMIN_EMAIL:-admin@thor.local} / ${MISP_ADMIN_PASSWORD:-MispAdmin2024!}"
echo -e "  Grafana             http://$HOST_IP:3001/grafana      ${GRAFANA_ADMIN_USER:-admin} / ${GRAFANA_PASSWORD:-GrafanaThor2024!}"
echo -e "  Control Plane API   http://$HOST_IP:8000/api/docs     —"
echo -e "  Dashboard           http://$HOST_IP:3002              —"
echo -e "  Elasticsearch       http://$HOST_IP:9200              elastic / ${ELASTIC_PASSWORD:-ElasticThor2024!}"
echo ""
echo -e "  ${BOLD}Test Integration:${NC}"
echo -e "  ${CYAN}# Generate test alert (run on same machine or another host):${NC}"
echo -e "  nmap -sS $HOST_IP"
echo -e "  ${CYAN}# Then check TheHive for new alert:${NC}"
echo -e "  curl -s http://localhost:9000/api/v1/alert -H 'Authorization: Bearer \$THEHIVE_API_KEY' | jq '.total'"
echo ""
echo -e "  ${BOLD}Logs:${NC}   tail -f $LOG_FILE"
echo -e "  ${BOLD}Stop:${NC}   docker compose -f docker-compose.yml -f docker-compose.integrations.yml --profile integration down"
echo ""
echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}"
