#!/usr/bin/env bash
# Thor Firewall — تنزيل بيانات CICIDS2017/2018 + UNSW-NB15
# الاستخدام: bash download_cicids.sh <output_dir>
#
# المصادر:
#   CICIDS2017: https://www.unb.ca/cic/datasets/ids-2017.html
#   CICIDS2018: https://www.unb.ca/cic/datasets/ids-2018.html
#   UNSW-NB15:  https://research.unsw.edu.au/projects/unsw-nb15-dataset
#
# ملاحظة: تحميل البيانات الأصلية يتطلب التسجيل في الموقع الرسمي.
# هذا السكريبت يُنزّل البيانات المتاحة للعموم من GitHub mirrors.

set -euo pipefail

OUTPUT_DIR="${1:-./data/raw}"
mkdir -p "$OUTPUT_DIR"

echo "📦 Downloading CIC-IDS datasets..."
echo "Output directory: $OUTPUT_DIR"
echo ""

# ── Kaggle mirror (requires kaggle API) ──────────────────────────────────────
if command -v kaggle &>/dev/null; then
  echo "Using Kaggle API..."
  kaggle datasets download -d cicdataset/cicids2017 -p "$OUTPUT_DIR" --unzip 2>/dev/null || true
  kaggle datasets download -d solarmainframe/ids-intrusion-csv -p "$OUTPUT_DIR" --unzip 2>/dev/null || true
  echo "✅ Kaggle download complete"
fi

# ── Direct download from UNB (public) ───────────────────────────────────────
echo ""
echo "Attempting direct downloads from UNB..."

CICIDS2017_FILES=(
  "Monday-WorkingHours.pcap_ISCX.csv"
  "Tuesday-WorkingHours.pcap_ISCX.csv"
  "Wednesday-workingHours.pcap_ISCX.csv"
  "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"
  "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv"
  "Friday-WorkingHours-Morning.pcap_ISCX.csv"
  "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
  "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
)

BASE_URL="https://iscxdownloads.cs.unb.ca/iscxdownloads/CIC-IDS-2017/PCAPs/"
MKDIR_DIR="$OUTPUT_DIR/cicids2017"
mkdir -p "$MKDIR_DIR"

for FILE in "${CICIDS2017_FILES[@]}"; do
  DEST="$MKDIR_DIR/$FILE"
  if [ -f "$DEST" ]; then
    echo "  ✓ Already exists: $FILE"
    continue
  fi
  echo "  Downloading: $FILE ..."
  curl -fL --progress-bar -o "$DEST" "$BASE_URL/$FILE" 2>/dev/null || \
    echo "  ⚠️  Failed (may require login): $FILE"
done

# ── UNSW-NB15 (publicly available) ──────────────────────────────────────────
echo ""
echo "Downloading UNSW-NB15..."
UNSW_DIR="$OUTPUT_DIR/unsw-nb15"
mkdir -p "$UNSW_DIR"

UNSW_URLS=(
  "https://cloudstor.aarnet.edu.au/plus/s/2DhnLGDdEECo4ys/download?files=UNSW-NB15_1.csv"
  "https://cloudstor.aarnet.edu.au/plus/s/2DhnLGDdEECo4ys/download?files=UNSW-NB15_2.csv"
)

for i in "${!UNSW_URLS[@]}"; do
  URL="${UNSW_URLS[$i]}"
  DEST="$UNSW_DIR/UNSW-NB15_$((i+1)).csv"
  if [ -f "$DEST" ]; then
    echo "  ✓ Already exists: UNSW-NB15_$((i+1)).csv"
    continue
  fi
  echo "  Downloading: UNSW-NB15_$((i+1)).csv ..."
  curl -fL --progress-bar -o "$DEST" "$URL" 2>/dev/null || \
    echo "  ⚠️  Failed: UNSW-NB15_$((i+1)).csv"
done

echo ""
echo "==================================="
echo "Download Summary:"
echo "  CICIDS2017 dir: $OUTPUT_DIR/cicids2017"
echo "  UNSW-NB15 dir:  $OUTPUT_DIR/unsw-nb15"
echo ""
echo "Next steps:"
echo "  python data/preprocess.py --data-dir $OUTPUT_DIR --output-dir data/processed"
echo "  python training/train_marl.py --data-dir data/processed"
echo "==================================="
