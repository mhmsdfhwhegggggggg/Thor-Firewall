#!/usr/bin/env bash
# Thor Firewall — Download CICIDS2017 Dataset
# Source: Canadian Institute for Cybersecurity
# URL: https://www.unb.ca/cic/datasets/ids-2017.html
#
# Files (7 CSVs, ~450MB total):
#   Monday-WorkingHours.pcap_ISCX.csv        (~70MB)  — Normal traffic
#   Tuesday-WorkingHours.pcap_ISCX.csv       (~69MB)  — FTP-Patator, SSH-Patator
#   Wednesday-WorkingHours.pcap_ISCX.csv     (~72MB)  — DoS/DDoS
#   Thursday-WorkingHours-Morning.pcap_ISCX.csv (~36MB) — Web Attacks
#   Thursday-WorkingHours-Afternoon.pcap_ISCX.csv (~46MB) — Infiltration
#   Friday-WorkingHours-Morning.pcap_ISCX.csv    (~29MB)  — Bot
#   Friday-WorkingHours-Afternoon.pcap_ISCX.csv  (~61MB)  — PortScan, DDoS

set -euo pipefail

DATA_DIR="${1:-./data/CICIDS2017}"
mkdir -p "${DATA_DIR}"

echo "Downloading CICIDS2017 to ${DATA_DIR} ..."
echo "Note: Files are hosted by the University of New Brunswick."
echo "Direct download requires registration at:"
echo "  https://www.unb.ca/cic/datasets/ids-2017.html"
echo ""
echo "Alternative: Use the Kaggle mirror:"
echo "  kaggle datasets download -d cicdataset/cicids2017"
echo "  unzip cicids2017.zip -d ${DATA_DIR}"
echo ""
echo "Or use CIC's Google Drive link (if available):"
echo "  https://drive.google.com/drive/folders/1HnL-nwgMx6J0Y5tDzMOLmFIYEEjTntqH"
echo ""

# If kaggle CLI available, try automatic download
if command -v kaggle &>/dev/null; then
    echo "Kaggle CLI found — attempting download..."
    kaggle datasets download -d cicdataset/cicids2017 -p "${DATA_DIR}" --unzip
    echo "Download complete: ${DATA_DIR}"
else
    echo "Kaggle CLI not found. Manual download required."
    echo "After downloading, place CSV files in: ${DATA_DIR}"
    echo "Then run: python -m ml.training.train_marl --data-dir ${DATA_DIR}"
fi
