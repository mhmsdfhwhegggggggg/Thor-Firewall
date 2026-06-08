"""
Thor Firewall — CICIDS2018 Preprocessing Pipeline
خط معالجة بيانات CICIDS2017/2018 وUNSW-NB15

المراحل:
1. تنظيف البيانات (NaN, Inf, duplicates)
2. استخلاص الخصائص (50 feature)
3. ترميز التسميات (8 فئات هجمات)
4. تطبيع StandardScaler
5. تقسيم Train/Val/Test (70/15/15)
6. حفظ numpy arrays + scaler

SPDX-License-Identifier: MIT
"""
from __future__ import annotations
import argparse, logging, os
from pathlib import Path
from typing import Optional, Tuple

import numpy as np
import pandas as pd

logger = logging.getLogger("thor.ml.preprocess")

# ── Label mapping ──────────────────────────────────────────────────────────────
ATTACK_LABELS = {
    "BENIGN": 0, "DoS Hulk": 1, "PortScan": 2, "DDoS": 3,
    "DoS GoldenEye": 4, "FTP-Patator": 5, "SSH-Patator": 6,
    "DoS slowloris": 7, "DoS Slowhttptest": 7, "Bot": 7,
    "Web Attack – Brute Force": 2, "Web Attack – XSS": 2,
    "Web Attack – Sql Injection": 2, "Infiltration": 7,
    "Heartbleed": 7, "Normal": 0,
}

# الـ 50 features المستخدمة من CICIDS2018
CICIDS_FEATURES = [
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Min",
    "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min",
    "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
    "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std",
    "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total",
    "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
    "Fwd Header Length", "Bwd Header Length",
    "Fwd Packets/s", "Bwd Packets/s",
    "Min Packet Length", "Max Packet Length",
    "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count",
    "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
    "CWE Flag Count", "ECE Flag Count",
]


def load_csv_files(data_dir: Path) -> pd.DataFrame:
    """تحميل جميع ملفات CSV في المجلد"""
    csv_files = list(data_dir.glob("**/*.csv"))
    if not csv_files:
        logger.warning("No CSV files found in %s — generating synthetic data", data_dir)
        return _generate_synthetic_data(n_samples=100_000)

    dfs = []
    for f in csv_files:
        try:
            df = pd.read_csv(f, low_memory=False, encoding="latin-1")
            df.columns = df.columns.str.strip()
            dfs.append(df)
            logger.info("Loaded: %s (%d rows)", f.name, len(df))
        except Exception as e:
            logger.warning("Failed to load %s: %s", f.name, e)

    return pd.concat(dfs, ignore_index=True) if dfs else _generate_synthetic_data()


def _generate_synthetic_data(n_samples: int = 50_000) -> pd.DataFrame:
    """بيانات اصطناعية للاختبار"""
    rng = np.random.default_rng(42)
    data = {}
    for feat in CICIDS_FEATURES:
        data[feat] = rng.exponential(scale=1000.0, size=n_samples).astype(np.float32)

    labels = rng.choice(
        list(ATTACK_LABELS.keys()),
        size=n_samples,
        p=[0.70, 0.05, 0.05, 0.05, 0.03, 0.03, 0.03, 0.03,
           0.01, 0.01, 0.01, 0.00, 0.00, 0.00, 0.00, 0.00],
    )
    data["Label"] = labels
    return pd.DataFrame(data)


def clean_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """تنظيف البيانات"""
    original_len = len(df)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(subset=[c for c in CICIDS_FEATURES if c in df.columns], inplace=True)
    df.drop_duplicates(inplace=True)
    df = df[(df.select_dtypes(include=[np.number]) < 1e15).all(axis=1)]
    logger.info("Cleaned: %d → %d rows (removed %d)", original_len, len(df), original_len - len(df))
    return df


def extract_features(df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
    """استخلاص X, y"""
    available = [c for c in CICIDS_FEATURES if c in df.columns]
    X = df[available].values.astype(np.float32)

    if "Label" in df.columns:
        y = df["Label"].map(ATTACK_LABELS).fillna(7).values.astype(np.int64)
    else:
        y = np.zeros(len(X), dtype=np.int64)

    logger.info("Features: %d samples × %d features | Classes: %s",
                len(X), X.shape[1], dict(zip(*np.unique(y, return_counts=True))))
    return X, y


def normalize_and_split(
    X: np.ndarray, y: np.ndarray, output_dir: Path, seed: int = 42
) -> None:
    """تطبيع وتقسيم وحفظ"""
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import train_test_split
    import joblib

    X_tv, X_test, y_tv, y_test = train_test_split(X, y, test_size=0.15, random_state=seed, stratify=y)
    X_train, X_val, y_train, y_val = train_test_split(X_tv, y_tv, test_size=0.176, random_state=seed, stratify=y_tv)

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train).astype(np.float32)
    X_val   = scaler.transform(X_val).astype(np.float32)
    X_test  = scaler.transform(X_test).astype(np.float32)

    output_dir.mkdir(parents=True, exist_ok=True)
    np.save(output_dir / "X_train.npy", X_train)
    np.save(output_dir / "X_val.npy",   X_val)
    np.save(output_dir / "X_test.npy",  X_test)
    np.save(output_dir / "y_train.npy", y_train)
    np.save(output_dir / "y_val.npy",   y_val)
    np.save(output_dir / "y_test.npy",  y_test)
    joblib.dump(scaler, output_dir / "scaler.pkl")

    logger.info("Saved: train=%d | val=%d | test=%d", len(X_train), len(X_val), len(X_test))
    logger.info("Class distribution (train): %s", dict(zip(*np.unique(y_train, return_counts=True))))


def run_pipeline(data_dir: str, output_dir: str) -> None:
    data_path   = Path(data_dir)
    output_path = Path(output_dir)

    df = load_csv_files(data_path)
    df = clean_dataframe(df)
    X, y = extract_features(df)
    normalize_and_split(X, y, output_path)

    logger.info("✅ Preprocessing complete — data saved to %s", output_path)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="Thor CICIDS2018 Preprocessing Pipeline")
    parser.add_argument("--data-dir",   default="./data/raw",       help="Directory containing CSV files")
    parser.add_argument("--output-dir", default="./data/processed", help="Output directory for numpy arrays")
    args = parser.parse_args()
    run_pipeline(args.data_dir, args.output_dir)
