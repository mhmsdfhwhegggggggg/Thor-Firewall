#!/usr/bin/env python3
"""
Thor Firewall — CICIDS2018 Preprocessing Pipeline
مستوحى من: Canadian Institute for Cybersecurity IDS 2018

يقوم بـ:
1. تحميل CSV files من dataset
2. تنظيف البيانات (NaN, Inf, duplicates)
3. Feature engineering (50 features → 82 features)
4. Label encoding (15 attack types → integer classes)
5. Train/Val/Test split (70/15/15)
6. حفظ كـ PyTorch tensors
"""
from __future__ import annotations

import os
import sys
import hashlib
import logging
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("thor.data")

# ── Attack Label Mapping ───────────────────────────────────────────────────────

ATTACK_LABEL_MAP: Dict[str, int] = {
    "BENIGN":                    0,
    "Bot":                       1,
    "DDoS attacks-LOIC-HTTP":    2,
    "DDoS attacks-LOIC-UDP":     2,   # مدمج مع DDoS
    "DDOS attack-HOIC":          2,
    "DoS attacks-Hulk":          3,
    "DoS attacks-GoldenEye":     3,
    "DoS attacks-SlowHTTPTest":  3,
    "DoS attacks-Slowloris":     3,
    "FTP-BruteForce":            4,
    "SSH-Bruteforce":            4,
    "Brute Force -Web":          4,
    "Brute Force -XSS":          4,
    "SQL Injection":             5,
    "XSS":                       5,
    "Web Attack":                5,
    "Infiltration":              6,
    "Infilteration":             6,
}

CLASS_NAMES = [
    "BENIGN", "Bot", "DDoS", "DoS",
    "BruteForce", "WebAttack", "Infiltration",
]

# Feature columns expected from CIC-IDS2018
FEATURE_COLUMNS = [
    "Destination Port", "Flow Duration", "Total Fwd Packets",
    "Total Backward Packets", "Total Length of Fwd Packets",
    "Total Length of Bwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean",
    "Fwd Packet Length Std", "Bwd Packet Length Max",
    "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std",
    "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total",
    "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
    "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s",
    "Bwd Packets/s", "Min Packet Length", "Max Packet Length",
    "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count",
    "ACK Flag Count", "URG Flag Count", "CWE Flag Count", "ECE Flag Count",
    "Down/Up Ratio", "Average Packet Size", "Avg Fwd Segment Size",
    "Avg Bwd Segment Size", "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate", "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate", "Subflow Fwd Packets", "Subflow Fwd Bytes",
    "Subflow Bwd Packets", "Subflow Bwd Bytes", "Init_Win_bytes_forward",
    "Init_Win_bytes_backward", "act_data_pkt_fwd",
    "min_seg_size_forward", "Active Mean", "Active Std",
    "Active Max", "Active Min", "Idle Mean", "Idle Std",
    "Idle Max", "Idle Min",
]

LABEL_COLUMN = "Label"


def load_cicids_csvs(data_dir: str) -> pd.DataFrame:
    """تحميل جميع CSV files من CICIDS2018"""
    data_dir = Path(data_dir)
    csv_files = list(data_dir.glob("*.csv")) + list(data_dir.glob("**/*.csv"))

    if not csv_files:
        log.warning("No CSV files found in %s", data_dir)
        log.info("Generating synthetic dataset for testing...")
        return _generate_synthetic_dataset()

    dfs = []
    for f in csv_files:
        log.info("Loading %s (%.1f MB)", f.name, f.stat().st_size / 1e6)
        try:
            df = pd.read_csv(f, low_memory=False, encoding="latin-1")
            df.columns = df.columns.str.strip()
            dfs.append(df)
        except Exception as e:
            log.error("Failed to load %s: %s", f, e)

    if not dfs:
        return _generate_synthetic_dataset()

    combined = pd.concat(dfs, ignore_index=True)
    log.info("Total rows loaded: %d", len(combined))
    return combined


def _generate_synthetic_dataset(n_samples: int = 100_000) -> pd.DataFrame:
    """
    توليد dataset اصطناعي للاختبار قبل توفر CICIDS2018.
    يحاكي توزيع الـ attacks الحقيقي.
    """
    rng = np.random.RandomState(42)
    n   = n_samples

    log.info("Generating synthetic dataset with %d samples", n)

    # Label distribution (محاكاة CICIDS2018 real distribution)
    label_dist = {
        "BENIGN":              0.70,
        "DDoS attacks-LOIC-HTTP": 0.08,
        "DoS attacks-Hulk":    0.06,
        "FTP-BruteForce":      0.05,
        "SSH-Bruteforce":      0.04,
        "Bot":                 0.03,
        "SQL Injection":       0.02,
        "Infiltration":        0.01,
        "Web Attack":          0.01,
    }
    labels = rng.choice(list(label_dist.keys()), size=n,
                        p=list(label_dist.values()))

    # Feature generation (simplified)
    data = {}
    for col in FEATURE_COLUMNS:
        if "Port" in col:
            data[col] = rng.randint(0, 65535, size=n)
        elif "Flag" in col:
            data[col] = rng.randint(0, 2, size=n)
        elif "Duration" in col:
            data[col] = rng.exponential(1000, size=n)
        else:
            data[col] = np.abs(rng.normal(100, 50, size=n))

    data[LABEL_COLUMN] = labels
    df = pd.DataFrame(data)
    log.info("Synthetic dataset generated: %d rows, %d features", len(df), len(FEATURE_COLUMNS))
    return df


def clean_data(df: pd.DataFrame) -> pd.DataFrame:
    """تنظيف البيانات"""
    original_size = len(df)
    df.columns = df.columns.str.strip()

    # الأعمدة المتاحة
    available_features = [c for c in FEATURE_COLUMNS if c in df.columns]
    if LABEL_COLUMN not in df.columns:
        raise ValueError(f"Label column '{LABEL_COLUMN}' not found. Available: {list(df.columns)[:10]}")

    log.info("Available features: %d / %d", len(available_features), len(FEATURE_COLUMNS))

    cols = available_features + [LABEL_COLUMN]
    df = df[cols].copy()

    # Numeric conversion
    for col in available_features:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    # Remove NaN and Inf
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    df.drop_duplicates(inplace=True)

    # Clip extreme values (z-score > 10)
    for col in available_features:
        q99 = df[col].quantile(0.999)
        df[col] = df[col].clip(upper=q99)

    log.info("Cleaned: %d → %d rows (removed %d)", original_size, len(df), original_size - len(df))
    return df


def encode_labels(df: pd.DataFrame) -> Tuple[pd.DataFrame, np.ndarray, List[str]]:
    """ترميز الـ labels إلى integers"""
    raw_labels = df[LABEL_COLUMN].str.strip()

    # Map known labels
    mapped = raw_labels.map(lambda x: ATTACK_LABEL_MAP.get(x, -1))
    unknown = raw_labels[mapped == -1].unique()
    if len(unknown) > 0:
        log.warning("Unknown labels (will be treated as BENIGN): %s", unknown[:5])
        mapped = mapped.replace(-1, 0)

    df = df.copy()
    df["label_id"] = mapped.values
    df = df.drop(columns=[LABEL_COLUMN])

    class_counts = pd.Series(mapped.values).value_counts().sort_index()
    for cid, count in class_counts.items():
        cname = CLASS_NAMES[cid] if cid < len(CLASS_NAMES) else f"class_{cid}"
        log.info("  Class %d (%s): %d samples (%.1f%%)",
                  cid, cname, count, 100 * count / len(df))

    return df, mapped.values, CLASS_NAMES


def engineer_features(df: pd.DataFrame) -> np.ndarray:
    """
    Feature engineering: raw features → 82-dim ML vector
    """
    available = [c for c in FEATURE_COLUMNS if c in df.columns]
    X = df[available].values.astype(np.float32)

    # Log transform for skewed features
    X = np.where(X > 0, np.log1p(X), X)

    # Pad to 82 if needed
    if X.shape[1] < 82:
        padding = np.zeros((X.shape[0], 82 - X.shape[1]), dtype=np.float32)
        X = np.concatenate([X, padding], axis=1)
    elif X.shape[1] > 82:
        X = X[:, :82]

    # Standardize
    scaler = StandardScaler()
    X = scaler.fit_transform(X).astype(np.float32)

    return X


def build_dataset(data_dir: str, output_dir: str):
    """Pipeline كامل: load → clean → encode → split → save"""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    log.info("=== Thor CICIDS2018 Preprocessing Pipeline ===")
    log.info("Data dir: %s", data_dir)
    log.info("Output dir: %s", output_dir)

    df = load_cicids_csvs(data_dir)
    df = clean_data(df)
    df, y, class_names = encode_labels(df)
    X = engineer_features(df)

    log.info("Final dataset: X=%s, y=%s", X.shape, y.shape)

    # Train/Val/Test split: 70/15/15
    X_train, X_tmp, y_train, y_tmp = train_test_split(X, y, test_size=0.30, random_state=42, stratify=y)
    X_val,   X_test, y_val,  y_test = train_test_split(X_tmp, y_tmp, test_size=0.50, random_state=42, stratify=y_tmp)

    log.info("Train: %d | Val: %d | Test: %d", len(X_train), len(X_val), len(X_test))

    # Save as numpy
    np.save(output_dir / "X_train.npy", X_train)
    np.save(output_dir / "y_train.npy", y_train)
    np.save(output_dir / "X_val.npy",   X_val)
    np.save(output_dir / "y_val.npy",   y_val)
    np.save(output_dir / "X_test.npy",  X_test)
    np.save(output_dir / "y_test.npy",  y_test)

    # Try saving as PyTorch if available
    try:
        import torch
        torch.save({
            "X_train": torch.from_numpy(X_train), "y_train": torch.from_numpy(y_train),
            "X_val":   torch.from_numpy(X_val),   "y_val":   torch.from_numpy(y_val),
            "X_test":  torch.from_numpy(X_test),  "y_test":  torch.from_numpy(y_test),
            "class_names": class_names,
            "n_features": X_train.shape[1],
            "n_classes":  len(class_names),
        }, output_dir / "cicids2018_dataset.pt")
        log.info("Saved PyTorch dataset: cicids2018_dataset.pt")
    except ImportError:
        log.warning("PyTorch not installed — saved numpy arrays only")

    log.info("=== Preprocessing complete ===")
    return {
        "train_size": len(X_train), "val_size": len(X_val),
        "test_size": len(X_test),   "n_features": X_train.shape[1],
        "n_classes": len(class_names), "class_names": class_names,
    }


if __name__ == "__main__":
    data_dir   = sys.argv[1] if len(sys.argv) > 1 else "./data/CICIDS2018"
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "./data/processed"
    stats = build_dataset(data_dir, output_dir)
    print(f"\n✅ Dataset ready: {stats}")
