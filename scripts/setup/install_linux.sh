#!/usr/bin/env bash
# Thor Firewall — Linux Installation Script
# سكريبت تثبيت نظام Thor على Linux
#
# الاستخدام: sudo bash install_linux.sh
# المتطلبات: Ubuntu 22.04+ أو Debian 12+

set -euo pipefail

THOR_VERSION="0.1.0"
THOR_USER="thor"
THOR_DIR="/opt/thor"
THOR_CONFIG="/etc/thor"
THOR_LOGS="/var/log/thor"

# ألوان
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║          ⚡ Thor Firewall v${THOR_VERSION} — Linux Installer          ║"
echo "║         Next-Generation Firewall powered by eBPF + AI        ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ── التحقق من صلاحيات root ──────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "يجب تشغيل هذا السكريبت كـ root (sudo bash install_linux.sh)"

# ── التحقق من إصدار kernel ──────────────────────────────────────────────
KERNEL_VERSION=$(uname -r | cut -d. -f1-2)
KERNEL_MAJOR=$(echo "$KERNEL_VERSION" | cut -d. -f1)
KERNEL_MINOR=$(echo "$KERNEL_VERSION" | cut -d. -f2)

if [[ $KERNEL_MAJOR -lt 5 || ($KERNEL_MAJOR -eq 5 && $KERNEL_MINOR -lt 15) ]]; then
    error "يتطلب Thor Firewall kernel >= 5.15 (الحالي: $(uname -r))"
fi
success "Kernel version: $(uname -r) ✓"

# ── تثبيت المتطلبات ──────────────────────────────────────────────────────
info "Installing dependencies..."
apt-get update -qq

apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-$(uname -r) \
    libssl-dev \
    pkg-config \
    curl \
    git \
    redis-server \
    ca-certificates \
    systemd

success "Dependencies installed"

# ── تثبيت Rust ──────────────────────────────────────────────────────────
if ! command -v cargo &> /dev/null; then
    info "Installing Rust toolchain..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
    source "$HOME/.cargo/env"
    success "Rust installed: $(rustc --version)"
else
    success "Rust already installed: $(rustc --version)"
fi

# ── إنشاء المستخدم ──────────────────────────────────────────────────────
if ! id "$THOR_USER" &>/dev/null; then
    useradd -r -s /bin/false -u 1001 "$THOR_USER"
    success "Created user: $THOR_USER"
fi

# ── إنشاء الدلائل ──────────────────────────────────────────────────────
mkdir -p "$THOR_DIR" "$THOR_CONFIG" "$THOR_LOGS"
chown -R "$THOR_USER:$THOR_USER" "$THOR_LOGS"
success "Directories created"

# ── بناء العميل ──────────────────────────────────────────────────────────
info "Building thor-agent (this may take a few minutes)..."
cargo build --release --package thor-agent 2>&1 | grep -E "(Compiling|Finished|error)" || true

if [[ -f "target/release/thor-agent" ]]; then
    install -m 0755 target/release/thor-agent /usr/local/bin/thor-agent
    success "thor-agent installed to /usr/local/bin/thor-agent"
else
    error "Build failed — check errors above"
fi

# ── إعداد الملفات ──────────────────────────────────────────────────────
if [[ ! -f "$THOR_CONFIG/agent.toml" ]]; then
    cp configs/agent.default.toml "$THOR_CONFIG/agent.toml"
    success "Default config installed to $THOR_CONFIG/agent.toml"
fi

# ── إعداد systemd ──────────────────────────────────────────────────────
cat > /etc/systemd/system/thor-agent.service << EOF
[Unit]
Description=Thor Firewall Agent — Next-Generation Firewall
Documentation=https://github.com/mhmsdfhwhegggggggg/Thor-Firewall
After=network.target redis.service
Wants=redis.service

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/thor-agent --config /etc/thor/agent.toml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=thor-agent

# Security hardening
NoNewPrivileges=false
ProtectSystem=full
ProtectHome=true
ReadWritePaths=/var/log/thor /var/lib/thor

# Required for eBPF
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_BPF CAP_PERFMON

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
success "systemd service created"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    ✅ Installation Complete                   ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Next steps:"
echo "  1. Edit config:    nano $THOR_CONFIG/agent.toml"
echo "  2. Start service:  systemctl start thor-agent"
echo "  3. Enable on boot: systemctl enable thor-agent"
echo "  4. View logs:      journalctl -u thor-agent -f"
echo ""
