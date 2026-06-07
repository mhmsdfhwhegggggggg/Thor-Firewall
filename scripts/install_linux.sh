#!/bin/bash
# Thor Firewall - Linux Installer
# يثبت كل ما تحتاجه البيئة: Rust، eBPF، LLVM، وأدوات الشبكة

set -e  # توقف عند أي خطأ

echo "🛡️  Thor Firewall - Linux Installation Script"
echo "=============================================="

# 1. تحديث الحزم
echo "[1/6] Updating system packages..."
sudo apt update -y && sudo apt upgrade -y

# 2. تثبيت أدوات البناء الأساسية
echo "[2/6] Installing build essentials..."
sudo apt install -y build-essential git curl wget

# 3. تثبيت Rust (إذا لم يكن موجودًا)
if ! command -v cargo &> /dev/null; then
    echo "[3/6] Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
else
    echo "[3/6] Rust already installed."
fi

# 4. تثبيت eBPF dependencies
echo "[4/6] Installing eBPF toolchain..."
sudo apt install -y clang llvm libbpf-dev linux-tools-common linux-tools-$(uname -r)

# 5. تثبيت Python والتبعيات لـ control-plane
echo "[5/6] Installing Python packages for control-plane..."
sudo apt install -y python3-pip python3-venv
sudo mkdir -p /opt/thor
sudo python3 -m venv /opt/thor/venv
source /opt/thor/venv/bin/activate
pip install --upgrade pip
pip install flask numpy pandas scikit-learn torch

# 6. بناء مشروع Rust
echo "[6/6] Building Thor Agent..."
# Assuming we are in the project root
cargo build --release

echo "✅ Installation complete!"
echo "Run Thor Agent with: sudo ./target/release/thor-agent"
