"""
Thor Firewall — Dataset Loader
==============================
يدعم مجموعات البيانات الحقيقية لتدريب نماذج الكشف عن التهديدات:

  1. CICIDS2017 — Canadian Institute for Cybersecurity
     https://www.unb.ca/cic/datasets/ids-2017.html
     8 فئات: BENIGN, DoS, PortScan, DDoS, Brute Force, Infiltration, Bot, Web Attack

  2. CICIDS2018 — CIC-IDS2018 (أحدث وأشمل)
     https://www.unb.ca/cic/datasets/ids-2018.html
     
  3. NSL-KDD — classic intrusion detection benchmark
     https://www.unb.ca/cic/datasets/nsl.html

  4. UNSW-NB15 — University of New South Wales
     https://research.unsw.edu.au/projects/unsw-nb15-dataset

  5. CIC-DDoS2019 — DDoS attacks
     https://www.unb.ca/cic/datasets/ddos-2019.html

  6. Thor Live — تدفقات حية من XDP ring buffer (production)

الاستخدام:
    loader = DatasetLoader("./data/CICIDS2017/")
    X_train, X_val, X_test, y_train, y_val, y_test = loader.load_split()
"""

from __future__ import annotations

import hashlib
import logging
import os
import pickle
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, RobustScaler

logger = logging.getLogger("thor.data.loader")

# ─── Label Mappings ───────────────────────────────────────────────────────────

# CICIDS2017/2018 → Thor internal class IDs
CICIDS_LABEL_MAP: Dict[str, int] = {
    "BENIGN":             0,
    "Benign":             0,
    "LEGITIMATE":         0,
    # DoS
    "DoS slowloris":      1,
    "DoS Slowloris":      1,
    "DoS Slowhttptest":   1,
    "DoS slowhttptest":   1,
    "DoS Hulk":           1,
    "DoS GoldenEye":      1,
    "DoS goldeneye":      1,
    "DoS":                1,
    # DDoS
    "DDoS":               2,
    "DDOS":               2,
    "DDoS UDP":           2,
    "DDoS TCP":           2,
    "DDoS HTTP":          2,
    # Port Scan
    "PortScan":           3,
    "Port Scan":          3,
    "Portscan":           3,
    # Brute Force
    "FTP-Patator":        4,
    "SSH-Patator":        4,
    "Brute Force":        4,
    "FTP-BruteForce":     4,
    "SSH-Bruteforce":     4,
    # Web Attack
    "Web Attack \x96 Brute Force": 5,
    "Web Attack – Brute Force":    5,
    "Web Attack \x96 XSS":         5,
    "Web Attack – XSS":            5,
    "Web Attack \x96 Sql Injection": 5,
    "Web Attack – Sql Injection":  5,
    "XSS":                5,
    "SQL Injection":      5,
    # Bot / C2
    "Bot":                6,
    "Botnet":             6,
    # Infiltration / APT
    "Infiltration":       7,
    "Infiltration - Droppers": 7,
    # C2 Communication
    "TFTP":               6,
    # Other
    "Heartbleed":         7,
}

CLASS_NAMES = [
    "BENIGN", "DoS", "DDoS", "PortScan",
    "BruteForce", "WebAttack", "Bot/C2", "Infiltration"
]
N_CLASSES = len(CLASS_NAMES)

# ─── Feature columns expected (CICIDS format) ────────────────────────────────
# Based on real CICFlowMeter output columns
CICIDS_FEATURE_COLS = [
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
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count",
    "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
    "CWE Flag Count", "ECE Flag Count", "Down/Up Ratio",
    "Average Packet Size", "Avg Fwd Segment Size",
    "Avg Bwd Segment Size", "Fwd Header Length.1",
    "Subflow Fwd Packets", "Subflow Fwd Bytes",
    "Subflow Bwd Packets", "Subflow Bwd Bytes",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward",
    "act_data_pkt_fwd", "min_seg_size_forward",
    "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
]
INPUT_DIM = len(CICIDS_FEATURE_COLS)  # 72 features from CICFlowMeter


class DatasetLoader:
    """
    Loader for CIC-IDS datasets.
    
    Expected directory structure:
        data/
          CICIDS2017/
            Monday-WorkingHours.pcap_ISCX.csv
            Tuesday-WorkingHours.pcap_ISCX.csv
            ...
          CICIDS2018/
            02-14-2018.csv
            02-15-2018.csv
            ...
    """

    def __init__(
        self,
        data_dir: str,
        dataset: str = "CICIDS2017",
        cache_dir: str = "/tmp/thor_cache",
        val_ratio: float = 0.1,
        test_ratio: float = 0.1,
        random_state: int = 42,
    ):
        self.data_dir    = Path(data_dir)
        self.dataset     = dataset
        self.cache_dir   = Path(cache_dir)
        self.val_ratio   = val_ratio
        self.test_ratio  = test_ratio
        self.random_state = random_state
        self.scaler      = RobustScaler()
        self.label_enc   = LabelEncoder()
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    # ── Public API ─────────────────────────────────────────────────────────────

    def load_split(self) -> Tuple[
        np.ndarray, np.ndarray, np.ndarray,
        np.ndarray, np.ndarray, np.ndarray
    ]:
        """
        Load, preprocess and split dataset.
        Returns: X_train, X_val, X_test, y_train, y_val, y_test
        """
        cache_key = self._cache_key()
        cache_file = self.cache_dir / f"{cache_key}.pkl"

        if cache_file.exists():
            logger.info("Loading from cache: %s", cache_file)
            with open(cache_file, "rb") as f:
                data = pickle.load(f)
            return data

        logger.info("Loading %s from %s ...", self.dataset, self.data_dir)
        X, y = self._load_raw()
        X, y = self._preprocess(X, y)

        # Split: train / val / test
        X_tv, X_test, y_tv, y_test = train_test_split(
            X, y, test_size=self.test_ratio,
            random_state=self.random_state, stratify=y
        )
        X_train, X_val, y_train, y_val = train_test_split(
            X_tv, y_tv,
            test_size=self.val_ratio / (1 - self.test_ratio),
            random_state=self.random_state, stratify=y_tv
        )

        result = (X_train, X_val, X_test, y_train, y_val, y_test)
        with open(cache_file, "wb") as f:
            pickle.dump(result, f, protocol=pickle.HIGHEST_PROTOCOL)

        self._log_stats(y_train, y_val, y_test)
        return result

    # ── Internal ───────────────────────────────────────────────────────────────

    def _load_raw(self) -> Tuple[np.ndarray, np.ndarray]:
        csv_files = list(self.data_dir.glob("*.csv"))
        if not csv_files:
            raise FileNotFoundError(
                f"No CSV files in {self.data_dir}\n"
                f"Download CICIDS2017 from:\n"
                f"  https://www.unb.ca/cic/datasets/ids-2017.html\n"
                f"Or CICIDS2018 from:\n"
                f"  https://www.unb.ca/cic/datasets/ids-2018.html"
            )

        dfs = []
        for csv_file in sorted(csv_files):
            logger.info("Reading %s ...", csv_file.name)
            try:
                df = pd.read_csv(csv_file, low_memory=False)
                df.columns = df.columns.str.strip()
                dfs.append(df)
            except Exception as e:
                logger.warning("Failed to read %s: %s", csv_file.name, e)

        if not dfs:
            raise ValueError("No valid CSV files loaded")

        df_all = pd.concat(dfs, ignore_index=True)
        logger.info("Loaded %d rows total", len(df_all))

        # Find label column
        label_col = None
        for candidate in [" Label", "Label", "label", "class", "Class"]:
            if candidate in df_all.columns:
                label_col = candidate
                break
        if label_col is None:
            raise ValueError(f"No label column found. Columns: {df_all.columns.tolist()[:10]}")

        # Map labels to int
        df_all["_label"] = (
            df_all[label_col]
            .str.strip()
            .map(CICIDS_LABEL_MAP)
            .fillna(7)
            .astype(int)
        )

        # Select feature columns (only those present)
        feat_cols = [c for c in CICIDS_FEATURE_COLS if c in df_all.columns]
        if len(feat_cols) < 20:
            # Fallback: use all numeric columns except label
            feat_cols = [
                c for c in df_all.select_dtypes(include=np.number).columns
                if c not in ["_label"]
            ]
        logger.info("Using %d features", len(feat_cols))

        X = df_all[feat_cols].values.astype(np.float32)
        y = df_all["_label"].values.astype(np.int64)
        return X, y

    def _preprocess(self, X: np.ndarray, y: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        # Replace inf/nan
        X = np.nan_to_num(X, nan=0.0, posinf=1e9, neginf=-1e9)
        X = np.clip(X, -1e9, 1e9)

        # Remove rows where all features are zero
        mask = ~np.all(X == 0, axis=1)
        X, y = X[mask], y[mask]

        # Scale
        X = self.scaler.fit_transform(X)
        X = np.clip(X, -10, 10).astype(np.float32)

        return X, y

    def _cache_key(self) -> str:
        key = f"{self.dataset}_{self.data_dir}_{self.val_ratio}_{self.test_ratio}"
        return hashlib.md5(key.encode()).hexdigest()[:16]

    def _log_stats(self, y_train, y_val, y_test):
        total = len(y_train) + len(y_val) + len(y_test)
        logger.info("Dataset split — total: %d", total)
        logger.info("  train: %d (%.1f%%)", len(y_train), 100*len(y_train)/total)
        logger.info("  val:   %d (%.1f%%)", len(y_val),   100*len(y_val)/total)
        logger.info("  test:  %d (%.1f%%)", len(y_test),  100*len(y_test)/total)
        for cls_id, cls_name in enumerate(CLASS_NAMES):
            count = int((y_train == cls_id).sum() + (y_val == cls_id).sum() + (y_test == cls_id).sum())
            if count > 0:
                logger.info("  [%d] %-15s : %d (%.2f%%)", cls_id, cls_name, count, 100*count/total)
