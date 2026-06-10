"""
Thor Firewall — Feature Engineering Pipeline
=============================================
يحوّل الحزم الخام أو تدفقات CICFlowMeter إلى متجهات ميزات
جاهزة لإدخالها في نموذج MARL/GNN.

المصدران:
  A) CICIDS CSVs    → CICFlowMeter features (72 cols) → 82 features
  B) XDP RingBuffer → Live packet metadata            → 82 features

الميزات الـ 82:
  [0:16]   Flow metadata (ports, protocol, duration, flags)
  [16:32]  Packet length statistics (min/max/mean/std fwd+bwd)
  [32:48]  Inter-arrival time stats (IAT fwd+bwd)
  [48:56]  TCP flag counts (SYN/ACK/FIN/RST/PSH/URG/ECE/CWE)
  [56:64]  Flow rate features (bytes/s, pkt/s, pps ratio)
  [64:72]  Window/segment sizes
  [72:78]  Temporal context (hour, day, weekend, rolling stats)
  [78:82]  Threat intelligence enrichment (TI score, geo risk, etc.)
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import List, Optional
import numpy as np

FEATURE_DIM = 82

# ─── Feature names (for interpretability / SHAP) ─────────────────────────────
FEATURE_NAMES: List[str] = [
    # [0:16] Flow metadata
    "dst_port_norm",        # dest port / 65535
    "protocol_tcp",         # 1 if TCP
    "protocol_udp",         # 1 if UDP
    "protocol_icmp",        # 1 if ICMP
    "flow_duration_log",    # log(duration_ms + 1)
    "total_fwd_pkts",       # log(fwd_pkt_count + 1)
    "total_bwd_pkts",       # log(bwd_pkt_count + 1)
    "total_fwd_bytes_log",  # log(fwd_bytes + 1)
    "total_bwd_bytes_log",  # log(bwd_bytes + 1)
    "bwd_fwd_pkt_ratio",    # bwd / (fwd + 1)
    "bwd_fwd_byte_ratio",   # bwd_bytes / (fwd_bytes + 1)
    "is_well_known_port",   # dst_port < 1024
    "is_ephemeral_port",    # dst_port > 49152
    "is_internal_src",      # RFC1918
    "is_internal_dst",      # RFC1918
    "is_broadcast",         # dst = x.x.x.255

    # [16:32] Packet length statistics
    "fwd_pkt_len_max_log",
    "fwd_pkt_len_min_log",
    "fwd_pkt_len_mean",
    "fwd_pkt_len_std",
    "bwd_pkt_len_max_log",
    "bwd_pkt_len_min_log",
    "bwd_pkt_len_mean",
    "bwd_pkt_len_std",
    "pkt_len_max_log",
    "pkt_len_min_log",
    "pkt_len_mean",
    "pkt_len_std",
    "pkt_len_variance_log",
    "avg_fwd_seg_size",
    "avg_bwd_seg_size",
    "avg_pkt_size",

    # [32:48] Inter-arrival time (IAT)
    "flow_iat_mean_log",
    "flow_iat_std_log",
    "flow_iat_max_log",
    "flow_iat_min_log",
    "fwd_iat_total_log",
    "fwd_iat_mean_log",
    "fwd_iat_std_log",
    "fwd_iat_max_log",
    "fwd_iat_min_log",
    "bwd_iat_total_log",
    "bwd_iat_mean_log",
    "bwd_iat_std_log",
    "bwd_iat_max_log",
    "bwd_iat_min_log",
    "active_mean_log",
    "idle_mean_log",

    # [48:56] TCP flags
    "flag_fin",
    "flag_syn",
    "flag_rst",
    "flag_psh",
    "flag_ack",
    "flag_urg",
    "flag_ece",
    "flag_cwe",

    # [56:64] Flow rate
    "flow_bytes_per_sec_log",
    "flow_pkts_per_sec_log",
    "fwd_pkts_per_sec_log",
    "bwd_pkts_per_sec_log",
    "down_up_ratio",
    "subflow_fwd_pkts_log",
    "subflow_bwd_pkts_log",
    "subflow_fwd_bytes_log",

    # [64:72] Window & segment
    "init_win_fwd_log",
    "init_win_bwd_log",
    "act_data_pkt_fwd_log",
    "min_seg_size_fwd",
    "header_len_fwd_log",
    "header_len_bwd_log",
    "fwd_psh_flags",
    "bwd_psh_flags",

    # [72:78] Temporal context
    "hour_sin",             # sin(2π * hour / 24)
    "hour_cos",             # cos(2π * hour / 24)
    "day_of_week_sin",      # sin(2π * dow / 7)
    "day_of_week_cos",      # cos(2π * dow / 7)
    "is_business_hours",    # 09:00-17:00 Mon-Fri
    "is_weekend",

    # [78:82] Threat intelligence
    "ti_risk_score",        # from Redis TI cache [0,1]
    "geo_risk",             # country risk score [0,1]
    "port_abuse_score",     # known bad port [0,1]
    "recent_block_rate",    # how often src was blocked recently [0,1]
]

assert len(FEATURE_NAMES) == FEATURE_DIM, f"Expected {FEATURE_DIM} features, got {len(FEATURE_NAMES)}"


@dataclass
class RawFlow:
    """Represents a single network flow from XDP ring buffer or CICIDS CSV."""
    # Network
    src_ip:        int   = 0       # IPv4 as uint32
    dst_ip:        int   = 0
    src_port:      int   = 0
    dst_port:      int   = 0
    protocol:      int   = 6       # TCP=6, UDP=17, ICMP=1

    # Packet counts
    fwd_pkt_count: int   = 0
    bwd_pkt_count: int   = 0
    fwd_bytes:     int   = 0
    bwd_bytes:     int   = 0

    # Timing (microseconds)
    duration_us:   int   = 0
    timestamp:     float = field(default_factory=time.time)

    # TCP flags (cumulative ORed over flow)
    tcp_flags:     int   = 0       # bitmask: FIN=1 SYN=2 RST=4 PSH=8 ACK=16 URG=32

    # Packet lengths
    fwd_pkt_len_max:  float = 0.0
    fwd_pkt_len_min:  float = 0.0
    fwd_pkt_len_mean: float = 0.0
    fwd_pkt_len_std:  float = 0.0
    bwd_pkt_len_max:  float = 0.0
    bwd_pkt_len_min:  float = 0.0
    bwd_pkt_len_mean: float = 0.0
    bwd_pkt_len_std:  float = 0.0

    # IAT (inter-arrival times in microseconds)
    flow_iat_mean: float = 0.0
    flow_iat_std:  float = 0.0
    flow_iat_max:  float = 0.0
    flow_iat_min:  float = 0.0
    fwd_iat_total: float = 0.0
    bwd_iat_total: float = 0.0

    # Window sizes
    init_win_fwd:  int   = 0
    init_win_bwd:  int   = 0

    # TI enrichment (injected from Redis)
    ti_risk:       float = 0.0
    geo_risk:      float = 0.0
    port_abuse:    float = 0.0
    recent_block:  float = 0.0


def _safe_log(x: float) -> float:
    return math.log(max(x, 0) + 1.0)


def _is_rfc1918(ip_int: int) -> bool:
    """Check if uint32 IPv4 is RFC1918 private."""
    b = [(ip_int >> (24 - 8*i)) & 0xFF for i in range(4)]
    return (b[0] == 10 or
            (b[0] == 172 and 16 <= b[1] <= 31) or
            (b[0] == 192 and b[1] == 168))


def extract_features(flow: RawFlow) -> np.ndarray:
    """
    Convert a RawFlow into the 82-dimensional feature vector.
    Returns float32 numpy array of shape (82,).
    """
    f = np.zeros(FEATURE_DIM, dtype=np.float32)
    dt = flow.duration_us / 1e6 if flow.duration_us > 0 else 1.0  # seconds

    # ── [0:16] Flow metadata ──────────────────────────────────────────────────
    f[0]  = flow.dst_port / 65535.0
    f[1]  = float(flow.protocol == 6)
    f[2]  = float(flow.protocol == 17)
    f[3]  = float(flow.protocol == 1)
    f[4]  = _safe_log(flow.duration_us / 1000.0)  # ms
    f[5]  = _safe_log(flow.fwd_pkt_count)
    f[6]  = _safe_log(flow.bwd_pkt_count)
    f[7]  = _safe_log(flow.fwd_bytes)
    f[8]  = _safe_log(flow.bwd_bytes)
    f[9]  = flow.bwd_pkt_count / max(flow.fwd_pkt_count, 1)
    f[10] = flow.bwd_bytes / max(flow.fwd_bytes, 1)
    f[11] = float(flow.dst_port < 1024)
    f[12] = float(flow.dst_port > 49152)
    f[13] = float(_is_rfc1918(flow.src_ip))
    f[14] = float(_is_rfc1918(flow.dst_ip))
    f[15] = float((flow.dst_ip & 0xFF) == 255)

    # ── [16:32] Packet length stats ───────────────────────────────────────────
    f[16] = _safe_log(flow.fwd_pkt_len_max)
    f[17] = _safe_log(flow.fwd_pkt_len_min)
    f[18] = flow.fwd_pkt_len_mean / 1514.0
    f[19] = flow.fwd_pkt_len_std / 1514.0
    f[20] = _safe_log(flow.bwd_pkt_len_max)
    f[21] = _safe_log(flow.bwd_pkt_len_min)
    f[22] = flow.bwd_pkt_len_mean / 1514.0
    f[23] = flow.bwd_pkt_len_std / 1514.0
    total_bytes = flow.fwd_bytes + flow.bwd_bytes
    total_pkts  = max(flow.fwd_pkt_count + flow.bwd_pkt_count, 1)
    avg_pkt = total_bytes / total_pkts
    f[24] = _safe_log(max(flow.fwd_pkt_len_max, flow.bwd_pkt_len_max))
    f[25] = _safe_log(max(min(flow.fwd_pkt_len_min, flow.bwd_pkt_len_min), 0))
    f[26] = avg_pkt / 1514.0
    f[27] = 0.0   # std needs raw data; set 0 for live flows
    f[28] = 0.0   # variance
    f[29] = flow.fwd_pkt_len_mean / 1514.0  # avg fwd seg
    f[30] = flow.bwd_pkt_len_mean / 1514.0  # avg bwd seg
    f[31] = avg_pkt / 1514.0

    # ── [32:48] IAT ───────────────────────────────────────────────────────────
    f[32] = _safe_log(flow.flow_iat_mean)
    f[33] = _safe_log(flow.flow_iat_std)
    f[34] = _safe_log(flow.flow_iat_max)
    f[35] = _safe_log(flow.flow_iat_min)
    f[36] = _safe_log(flow.fwd_iat_total)
    f[37] = _safe_log(flow.fwd_iat_total / max(flow.fwd_pkt_count, 1))
    f[38] = 0.0
    f[39] = 0.0
    f[40] = 0.0
    f[41] = _safe_log(flow.bwd_iat_total)
    f[42] = _safe_log(flow.bwd_iat_total / max(flow.bwd_pkt_count, 1))
    f[43] = 0.0
    f[44] = 0.0
    f[45] = 0.0
    f[46] = 0.0   # active mean
    f[47] = 0.0   # idle mean

    # ── [48:56] TCP flags ─────────────────────────────────────────────────────
    flags = flow.tcp_flags
    f[48] = float(bool(flags & 0x01))  # FIN
    f[49] = float(bool(flags & 0x02))  # SYN
    f[50] = float(bool(flags & 0x04))  # RST
    f[51] = float(bool(flags & 0x08))  # PSH
    f[52] = float(bool(flags & 0x10))  # ACK
    f[53] = float(bool(flags & 0x20))  # URG
    f[54] = float(bool(flags & 0x40))  # ECE
    f[55] = float(bool(flags & 0x80))  # CWE

    # ── [56:64] Flow rate ─────────────────────────────────────────────────────
    f[56] = _safe_log(total_bytes / dt)
    f[57] = _safe_log(total_pkts / dt)
    f[58] = _safe_log(flow.fwd_pkt_count / dt)
    f[59] = _safe_log(flow.bwd_pkt_count / dt)
    f[60] = flow.bwd_bytes / max(flow.fwd_bytes, 1)   # down/up ratio
    f[61] = _safe_log(flow.fwd_pkt_count)
    f[62] = _safe_log(flow.bwd_pkt_count)
    f[63] = _safe_log(flow.fwd_bytes)

    # ── [64:72] Window & segment ──────────────────────────────────────────────
    f[64] = _safe_log(flow.init_win_fwd) / 16.0
    f[65] = _safe_log(flow.init_win_bwd) / 16.0
    f[66] = _safe_log(flow.fwd_pkt_count)
    f[67] = 0.0   # min_seg_size_fwd
    f[68] = 0.0   # header_len_fwd
    f[69] = 0.0   # header_len_bwd
    f[70] = float(bool(flags & 0x08))   # fwd psh
    f[71] = 0.0   # bwd psh

    # ── [72:78] Temporal context ──────────────────────────────────────────────
    import datetime
    dt_obj = datetime.datetime.fromtimestamp(flow.timestamp)
    hour   = dt_obj.hour
    dow    = dt_obj.weekday()
    f[72] = math.sin(2 * math.pi * hour / 24.0)
    f[73] = math.cos(2 * math.pi * hour / 24.0)
    f[74] = math.sin(2 * math.pi * dow / 7.0)
    f[75] = math.cos(2 * math.pi * dow / 7.0)
    f[76] = float(9 <= hour <= 17 and dow < 5)
    f[77] = float(dow >= 5)

    # ── [78:82] Threat intelligence ───────────────────────────────────────────
    f[78] = float(np.clip(flow.ti_risk,    0, 1))
    f[79] = float(np.clip(flow.geo_risk,   0, 1))
    f[80] = float(np.clip(flow.port_abuse, 0, 1))
    f[81] = float(np.clip(flow.recent_block, 0, 1))

    return np.clip(f, -10.0, 10.0)


def from_cicids_row(row: dict) -> np.ndarray:
    """
    Convert a CICIDS CSV row (dict) to 82-dim feature vector.
    Used during dataset loading for training.
    """
    def g(name, default=0.0):
        return float(row.get(name, row.get(" " + name, default)) or default)

    flow = RawFlow(
        dst_port       = int(g("Destination Port")),
        protocol       = int(g("Protocol", 6)),
        fwd_pkt_count  = int(g("Total Fwd Packets")),
        bwd_pkt_count  = int(g("Total Backward Packets")),
        fwd_bytes      = int(g("Total Length of Fwd Packets")),
        bwd_bytes      = int(g("Total Length of Bwd Packets")),
        duration_us    = int(g("Flow Duration")),
        fwd_pkt_len_max  = g("Fwd Packet Length Max"),
        fwd_pkt_len_min  = g("Fwd Packet Length Min"),
        fwd_pkt_len_mean = g("Fwd Packet Length Mean"),
        fwd_pkt_len_std  = g("Fwd Packet Length Std"),
        bwd_pkt_len_max  = g("Bwd Packet Length Max"),
        bwd_pkt_len_min  = g("Bwd Packet Length Min"),
        bwd_pkt_len_mean = g("Bwd Packet Length Mean"),
        bwd_pkt_len_std  = g("Bwd Packet Length Std"),
        flow_iat_mean  = g("Flow IAT Mean"),
        flow_iat_std   = g("Flow IAT Std"),
        flow_iat_max   = g("Flow IAT Max"),
        flow_iat_min   = g("Flow IAT Min"),
        fwd_iat_total  = g("Fwd IAT Total"),
        bwd_iat_total  = g("Bwd IAT Total"),
        init_win_fwd   = int(g("Init_Win_bytes_forward")),
        init_win_bwd   = int(g("Init_Win_bytes_backward")),
        tcp_flags      = (
            int(g("FIN Flag Count") > 0) * 0x01 |
            int(g("SYN Flag Count") > 0) * 0x02 |
            int(g("RST Flag Count") > 0) * 0x04 |
            int(g("PSH Flag Count") > 0) * 0x08 |
            int(g("ACK Flag Count") > 0) * 0x10 |
            int(g("URG Flag Count") > 0) * 0x20
        ),
    )
    return extract_features(flow)
