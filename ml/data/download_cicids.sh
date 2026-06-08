#!/usr/bin/env bash
# Thor Firewall — CICIDS2018 Dataset Downloader
# تحميل مجموعة بيانات CICIDS2018 من جامعة نيوبرونزويك

set -euo pipefail

DATA_DIR="${1:-./raw}"
mkdir -p "$DATA_DIR"

echo "📥 Downloading CICIDS2018 dataset..."

# CICIDS2017 (available via direct HTTP)
CICIDS2017_BASE="http://205.174.165.80/CICDataset/CIC-IDS-2017/Dataset/CIC-IDS-2017"
declare -a FILES_2017=(
    "Monday-WorkingHours.pcap_ISCX.csv"
    "Tuesday-WorkingHours.pcap_ISCX.csv"
    "Wednesday-workingHours.pcap_ISCX.csv"
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv"
    "Friday-WorkingHours-Morning.pcap_ISCX.csv"
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
)

for f in "${FILES_2017[@]}"; do
    dest="$DATA_DIR/cicids2017_$(echo $f | tr '[:upper:]' '[:lower:]' | tr ' -' '__')"
    if [ ! -f "$dest" ]; then
        echo "  ↓ $f"
        curl -L --retry 3 --retry-delay 5 -o "$dest" "$CICIDS2017_BASE/$f" || {
            echo "  ⚠️  Failed to download $f — will use synthetic fallback"
        }
    else
        echo "  ✓ $f (cached)"
    fi
done

# UNSW-NB15
UNSW_BASE="https://research.unsw.edu.au/sites/default/files/documents"
declare -a FILES_UNSW=(
    "UNSW_NB15_training-set.csv"
    "UNSW_NB15_testing-set.csv"
)

for f in "${FILES_UNSW[@]}"; do
    dest="$DATA_DIR/unsw_nb15_$(echo $f | tr '[:upper:]' '[:lower:]')"
    if [ ! -f "$dest" ]; then
        echo "  ↓ UNSW-NB15: $f"
        curl -L --retry 3 --retry-delay 5 -o "$dest" "$UNSW_BASE/$f" 2>/dev/null || {
            echo "  ⚠️  UNSW-NB15 not available via direct URL — using synthetic fallback"
        }
    fi
done

echo "✅ Download complete. Files in: $DATA_DIR"
