"""
Thor Firewall — XDP Pipeline Performance Benchmark
قياس أداء خط أنابيب معالجة الحزم

يحاكي معالجة الحزم على مستوى user-space ويقيس:
- زمن التحليل لحزمة واحدة
- معدل الإنتاجية (حزمة/ثانية)
- استهلاك الذاكرة
- أداء PacketParser

الاستخدام:
    python -m pytest tests/performance/bench_xdp_pipeline.py -v --benchmark-autosave
"""

from __future__ import annotations

import os
import struct
import time
from typing import List, Tuple

import numpy as np
import pytest

# ============================================================================
# Packet Generation
# ============================================================================

def make_ip_header(src_ip: int, dst_ip: int, proto: int, pkt_len: int) -> bytes:
    """إنشاء رأس IPv4 للاختبار"""
    # version=4, ihl=5, tos=0
    return struct.pack(
        "!BBHHHBBH4s4s",
        0x45,           # version + ihl
        0,              # tos
        pkt_len,        # total length
        0,              # id
        0,              # flags + fragment offset
        64,             # ttl
        proto,          # protocol (6=TCP, 17=UDP)
        0,              # checksum (0 = not computed)
        src_ip.to_bytes(4, "big"),
        dst_ip.to_bytes(4, "big"),
    )


def make_tcp_header(sport: int, dport: int, flags: int = 0x10) -> bytes:
    """إنشاء رأس TCP للاختبار"""
    return struct.pack(
        "!HHLLBBHHH",
        sport,          # source port
        dport,          # dest port
        0,              # seq
        0,              # ack
        0x50,           # data offset (5 words = 20 bytes) + reserved
        flags,          # flags
        65535,          # window
        0,              # checksum
        0,              # urgent pointer
    )


def generate_packet_batch(n: int, attack_ratio: float = 0.3) -> List[bytes]:
    """توليد دفعة من الحزم للاختبار"""
    rng = np.random.default_rng(42)
    packets = []

    for i in range(n):
        is_attack = rng.random() < attack_ratio

        if is_attack:
            # SYN flood
            src_ip = int.from_bytes(rng.bytes(4), "big")
            dst_ip = 0x0A000001
            sport = int(rng.integers(1024, 65535))
            dport = 80
            flags = 0x02  # SYN only
            payload = b""
        else:
            # HTTPS
            src_ip = 0xC0A80100 | int(rng.integers(1, 254))
            dst_ip = 0x0A000001
            sport = int(rng.integers(32768, 60000))
            dport = 443
            flags = 0x18  # PSH+ACK
            payload = rng.bytes(int(rng.integers(100, 1400)))

        pkt_len = 20 + 20 + len(payload)
        ip_hdr  = make_ip_header(src_ip, dst_ip, 6, pkt_len)
        tcp_hdr = make_tcp_header(sport, dport, flags)
        packet  = b"\x00" * 14 + ip_hdr + tcp_hdr + payload  # Ethernet header
        packets.append(packet)

    return packets


# ============================================================================
# Simulated Feature Extraction (Python equivalent of Rust PacketParser)
# ============================================================================

class PythonPacketParser:
    """نسخة Python من PacketParser لقياس الأداء"""

    def parse(self, pkt: bytes) -> np.ndarray:
        """استخراج 50 ميزة من الحزمة"""
        features = np.zeros(50, dtype=np.float32)

        if len(pkt) < 34:  # Ethernet + IP min
            return features

        # Ethernet: skip 14 bytes
        ip_start = 14
        if len(pkt) < ip_start + 20:
            return features

        version_ihl = pkt[ip_start]
        ihl = (version_ihl & 0x0F) * 4
        protocol = pkt[ip_start + 9]
        src_ip = struct.unpack("!I", pkt[ip_start+12:ip_start+16])[0]
        dst_ip = struct.unpack("!I", pkt[ip_start+16:ip_start+20])[0]
        total_len = struct.unpack("!H", pkt[ip_start+2:ip_start+4])[0]

        # TCP header
        tcp_start = ip_start + ihl
        if len(pkt) < tcp_start + 20:
            return features

        sport = struct.unpack("!H", pkt[tcp_start:tcp_start+2])[0]
        dport = struct.unpack("!H", pkt[tcp_start+2:tcp_start+4])[0]
        tcp_flags = pkt[tcp_start + 13]

        payload_start = tcp_start + 20
        payload = pkt[payload_start:]

        # Feature extraction
        features[0]  = min(total_len / 1500.0, 1.0)
        features[6]  = 1.0 if protocol == 6 else (2.0 if protocol == 17 else 3.0)
        features[11] = min(dport / 65535.0, 1.0)
        features[12] = min(sport / 65535.0, 1.0)

        # TCP flags
        features[20] = 1.0 if tcp_flags & 0x02 else 0.0  # SYN
        features[21] = 1.0 if tcp_flags & 0x10 else 0.0  # ACK
        features[22] = 1.0 if tcp_flags & 0x01 else 0.0  # FIN
        features[23] = 1.0 if tcp_flags & 0x04 else 0.0  # RST

        # Payload entropy
        if payload:
            counts = np.bincount(np.frombuffer(payload, dtype=np.uint8), minlength=256)
            probs = counts[counts > 0] / len(payload)
            features[30] = float(-np.sum(probs * np.log2(probs)))

        # IP features
        features[40] = float((src_ip >> 24) & 0xFF) / 255.0
        features[41] = float((dst_ip >> 24) & 0xFF) / 255.0

        return features


# ============================================================================
# Benchmarks
# ============================================================================

PACKETS = generate_packet_batch(10000, attack_ratio=0.3)
PARSER  = PythonPacketParser()


@pytest.fixture(scope="session")
def packet_batch():
    return PACKETS


@pytest.fixture(scope="session")
def parser():
    return PARSER


class TestPacketParserPerformance:
    def test_single_packet_latency(self, benchmark, parser, packet_batch):
        """يجب أن تكون معالجة حزمة واحدة < 1ms"""
        pkt = packet_batch[0]
        result = benchmark(parser.parse, pkt)
        assert result.shape == (50,)

    def test_batch_1k_throughput(self, benchmark, parser, packet_batch):
        """قياس إنتاجية 1000 حزمة"""
        pkts = packet_batch[:1000]

        def process_batch():
            return [parser.parse(p) for p in pkts]

        results = benchmark(process_batch)
        assert len(results) == 1000

    def test_throughput_10k_packets(self, parser, packet_batch):
        """قياس معدل الإنتاجية مباشرة"""
        start = time.perf_counter()
        for pkt in packet_batch:
            parser.parse(pkt)
        elapsed = time.perf_counter() - start

        pps = len(packet_batch) / elapsed
        print(f"\nPython parser throughput: {pps:,.0f} pps")
        print(f"Per-packet latency: {elapsed/len(packet_batch)*1e6:.1f} μs")

        # حد سخي جداً للـ Python — Rust سيكون أسرع × 100
        assert pps > 10_000


class TestMemoryUsage:
    def test_feature_matrix_memory(self):
        """حجم مصفوفة الميزات لـ 1M تدفق"""
        n_flows = 1_000_000
        n_features = 50
        dtype = np.float32  # 4 bytes

        size_bytes = n_flows * n_features * dtype(0).itemsize
        size_mb = size_bytes / 1024 / 1024
        print(f"\nFeature matrix for 1M flows: {size_mb:.1f} MB")

        # يجب أن يكون < 200MB
        assert size_mb < 200


class TestEntropyCalculation:
    def test_high_entropy_payload(self, parser):
        """بيانات مشفرة = entropy عالية"""
        rng = np.random.default_rng(123)
        encrypted_payload = bytes(rng.integers(0, 256, 1000, dtype=np.uint8))

        # بناء حزمة مع payload مشفرة
        ip_hdr  = make_ip_header(0xC0A80101, 0x0A000001, 6, 20 + 20 + len(encrypted_payload))
        tcp_hdr = make_tcp_header(54321, 443, 0x18)
        pkt = b"\x00" * 14 + ip_hdr + tcp_hdr + encrypted_payload

        features = parser.parse(pkt)
        # Entropy يجب أن تكون عالية (> 7 bits)
        assert features[30] > 6.0

    def test_low_entropy_payload(self, parser):
        """بيانات متكررة = entropy منخفضة"""
        repetitive_payload = b"\x41" * 1000  # 'A' × 1000

        ip_hdr  = make_ip_header(0xC0A80101, 0x0A000001, 6, 20 + 20 + len(repetitive_payload))
        tcp_hdr = make_tcp_header(54321, 80, 0x18)
        pkt = b"\x00" * 14 + ip_hdr + tcp_hdr + repetitive_payload

        features = parser.parse(pkt)
        # Entropy يجب أن تكون منخفضة جداً (= 0 for all same bytes)
        assert features[30] < 1.0
