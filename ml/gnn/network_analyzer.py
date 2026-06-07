"""
Thor Firewall — Graph Neural Network (GNN) Network Analyzer
محلل الشبكة باستخدام الشبكات العصبية البيانية

يبني رسماً بيانياً للشبكة ويُصنّف:
- العقد (Nodes): الأجهزة — خبيثة أو حميدة
- الحواف (Edges): الاتصالات — طبيعية أو مشبوهة

النماذج المستخدمة: GraphSAGE + Graph Attention Network (GAT)

المرجع: "Detecting Network Intrusions Using Graph Neural Networks"
"""

from __future__ import annotations

import torch
import torch.nn as nn
import torch.nn.functional as F
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
import numpy as np

# نحاول الاستيراد - torch_geometric مطلوبة
try:
    from torch_geometric.nn import SAGEConv, GATv2Conv, global_mean_pool
    from torch_geometric.data import Data, Batch
    TORCH_GEOMETRIC_AVAILABLE = True
except ImportError:
    TORCH_GEOMETRIC_AVAILABLE = False
    # Fallback implementation without torch_geometric
    class SAGEConv(nn.Module):
        def __init__(self, in_channels, out_channels):
            super().__init__()
            self.linear = nn.Linear(in_channels * 2, out_channels)
        def forward(self, x, edge_index):
            row, col = edge_index
            agg = torch.zeros_like(x)
            agg.index_add_(0, row, x[col])
            return self.linear(torch.cat([x, agg], dim=-1))


# ============================================================================
# Configuration
# ============================================================================

@dataclass
class GNNConfig:
    """إعدادات محلل GNN"""
    # ميزات العقدة (الجهاز): عنوان IP، عدد الاتصالات، معدل البيانات، إلخ
    node_feature_dim: int = 32
    # ميزات الحافة (الاتصال): مدة الاتصال، كمية البيانات، إلخ
    edge_feature_dim: int = 16
    # بُعد التضمين الداخلي
    hidden_dim: int = 128
    # بُعد التضمين الناتج (يُرسل إلى MARL)
    embedding_dim: int = 32
    # عدد طبقات GNN
    num_layers: int = 3
    # رؤوس Attention في GAT
    num_attention_heads: int = 4
    # معدل Dropout
    dropout: float = 0.2
    # معدل التعلم
    learning_rate: float = 1e-3
    # الجهاز
    device: str = "cuda" if torch.cuda.is_available() else "cpu"


# ============================================================================
# Node Feature Extractor
# ============================================================================

class NodeFeatureExtractor:
    """
    يستخرج ميزات الجهاز من بيانات التدفق
    يُحدَّث كل 10 ثوانٍ لتوفير snapshot دقيق
    """

    def __init__(self):
        # إحصاءات لكل IP
        self._node_stats: Dict[str, Dict] = {}

    def update(self, src_ip: str, dst_ip: str, flow_stats: dict):
        """تحديث إحصاءات عقدة بناءً على تدفق جديد"""
        for ip in [src_ip, dst_ip]:
            if ip not in self._node_stats:
                self._node_stats[ip] = {
                    "total_flows": 0,
                    "inbound_bytes": 0,
                    "outbound_bytes": 0,
                    "unique_destinations": set(),
                    "unique_ports": set(),
                    "failed_connections": 0,
                    "syn_count": 0,
                    "first_seen": flow_stats.get("timestamp", 0),
                    "last_seen": flow_stats.get("timestamp", 0),
                }

            stats = self._node_stats[ip]
            stats["total_flows"] += 1
            stats["last_seen"] = flow_stats.get("timestamp", 0)

            if ip == src_ip:
                stats["outbound_bytes"] += flow_stats.get("bytes", 0)
                stats["unique_destinations"].add(dst_ip)
                stats["unique_ports"].add(flow_stats.get("dst_port", 0))

    def get_node_features(self, ip: str) -> np.ndarray:
        """استخراج متجه ميزات لجهاز معين (32 ميزة)"""
        features = np.zeros(32, dtype=np.float32)

        if ip not in self._node_stats:
            return features

        stats = self._node_stats[ip]
        features[0] = min(stats["total_flows"] / 1000.0, 1.0)
        features[1] = min(stats["inbound_bytes"] / 1e9, 1.0)
        features[2] = min(stats["outbound_bytes"] / 1e9, 1.0)
        features[3] = min(len(stats["unique_destinations"]) / 100.0, 1.0)
        features[4] = min(len(stats["unique_ports"]) / 1000.0, 1.0)
        features[5] = min(stats["failed_connections"] / 100.0, 1.0)
        features[6] = min(stats["syn_count"] / 1000.0, 1.0)

        # نسبة الاتصالات الفاشلة
        total = stats["total_flows"]
        if total > 0:
            features[7] = stats["failed_connections"] / total

        return features

    def get_all_nodes(self) -> List[str]:
        return list(self._node_stats.keys())


# ============================================================================
# GNN Model (GraphSAGE + GAT)
# ============================================================================

class ThorGNN(nn.Module):
    """
    شبكة GNN لتحليل الشبكة ككل

    البنية:
    1. GraphSAGE لاستخراج ميزات الجوار
    2. GAT لتعلم أوزان الانتباه
    3. طبقة تصنيف نهائية
    """

    def __init__(self, config: GNNConfig):
        super().__init__()
        self.config = config

        # ترميز المدخلات
        self.node_encoder = nn.Sequential(
            nn.Linear(config.node_feature_dim, config.hidden_dim),
            nn.LayerNorm(config.hidden_dim),
            nn.GELU(),
        )

        # طبقات GraphSAGE
        self.sage_layers = nn.ModuleList()
        for i in range(config.num_layers - 1):
            in_dim = config.hidden_dim
            out_dim = config.hidden_dim
            self.sage_layers.append(SAGEConv(in_dim, out_dim))

        # طبقة GAT النهائية (مع attention)
        if TORCH_GEOMETRIC_AVAILABLE:
            self.gat_layer = GATv2Conv(
                config.hidden_dim,
                config.embedding_dim,
                heads=config.num_attention_heads,
                concat=False,
                dropout=config.dropout,
            )
        else:
            self.gat_layer = nn.Linear(config.hidden_dim, config.embedding_dim)

        # رأس التصنيف: خبيث (1) أو حميد (0)
        self.classifier = nn.Sequential(
            nn.Linear(config.embedding_dim, 64),
            nn.GELU(),
            nn.Dropout(config.dropout),
            nn.Linear(64, 2),  # [benign, malicious]
        )

        # رأس تسجيل المخاطر (regression)
        self.risk_scorer = nn.Sequential(
            nn.Linear(config.embedding_dim, 32),
            nn.GELU(),
            nn.Linear(32, 1),
            nn.Sigmoid(),  # إخراج [0, 1]
        )

        self.dropout = nn.Dropout(config.dropout)

    def forward(
        self,
        node_features: torch.Tensor,  # [N, node_feature_dim]
        edge_index: torch.Tensor,      # [2, E]
    ) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Returns:
            embeddings: [N, embedding_dim] — تضمين كل عقدة
            class_logits: [N, 2] — تصنيف خبيث/حميد
            risk_scores: [N, 1] — نقاط الخطر [0, 1]
        """
        # ترميز المدخلات
        x = self.node_encoder(node_features)

        # طبقات GraphSAGE
        for sage_layer in self.sage_layers:
            x_new = sage_layer(x, edge_index)
            x = F.gelu(x_new) + x  # skip connection
            x = self.dropout(x)

        # طبقة GAT
        if TORCH_GEOMETRIC_AVAILABLE:
            embeddings = self.gat_layer(x, edge_index)
        else:
            embeddings = self.gat_layer(x)
        embeddings = F.gelu(embeddings)

        class_logits = self.classifier(embeddings)
        risk_scores = self.risk_scorer(embeddings)

        return embeddings, class_logits, risk_scores


# ============================================================================
# Network Graph Builder
# ============================================================================

class NetworkGraphBuilder:
    """
    يبني الرسم البياني للشبكة من بيانات التدفق
    يُحدَّث في الزمن الحقيقي مع كل تدفق جديد
    """

    def __init__(self, config: GNNConfig):
        self.config = config
        self.device = torch.device(config.device)
        self.feature_extractor = NodeFeatureExtractor()
        self.model = ThorGNN(config).to(self.device)

        self._ip_to_idx: Dict[str, int] = {}
        self._edges: List[Tuple[int, int]] = []

    def update_flow(self, src_ip: str, dst_ip: str, flow_stats: dict):
        """تحديث الرسم البياني بتدفق جديد"""
        self.feature_extractor.update(src_ip, dst_ip, flow_stats)

        # إضافة عقد جديدة
        for ip in [src_ip, dst_ip]:
            if ip not in self._ip_to_idx:
                self._ip_to_idx[ip] = len(self._ip_to_idx)

        # إضافة حافة
        edge = (self._ip_to_idx[src_ip], self._ip_to_idx[dst_ip])
        self._edges.append(edge)

        # الحفاظ على حجم معقول للرسم البياني
        if len(self._edges) > 100_000:
            self._edges = self._edges[-50_000:]

    @torch.no_grad()
    def get_node_embedding(self, ip: str) -> Optional[np.ndarray]:
        """
        الحصول على تضمين GNN لجهاز معين
        يُستخدم كمدخل إضافي لـ MARL
        """
        if ip not in self._ip_to_idx or len(self._ip_to_idx) < 2:
            return np.zeros(self.config.embedding_dim, dtype=np.float32)

        # بناء tensor الرسم البياني
        all_ips = self.feature_extractor.get_all_nodes()
        node_features = np.stack([
            self.feature_extractor.get_node_features(ip_)
            for ip_ in all_ips
        ])

        x = torch.FloatTensor(node_features).to(self.device)

        if not self._edges:
            return np.zeros(self.config.embedding_dim, dtype=np.float32)

        edge_index = torch.LongTensor(self._edges).T.to(self.device)

        # تشغيل GNN
        embeddings, _, risk_scores = self.model(x, edge_index)

        # استرجاع تضمين الجهاز المطلوب
        node_idx = self._ip_to_idx.get(ip)
        if node_idx is not None and node_idx < len(all_ips):
            idx_in_all = all_ips.index(ip) if ip in all_ips else None
            if idx_in_all is not None:
                return embeddings[idx_in_all].cpu().numpy()

        return np.zeros(self.config.embedding_dim, dtype=np.float32)

    @torch.no_grad()
    def analyze_network(self) -> Dict[str, float]:
        """
        تحليل الشبكة كاملة وإرجاع قائمة بالأجهزة المشبوهة
        """
        if len(self._ip_to_idx) < 2 or not self._edges:
            return {}

        all_ips = self.feature_extractor.get_all_nodes()
        node_features = np.stack([
            self.feature_extractor.get_node_features(ip)
            for ip in all_ips
        ])

        x = torch.FloatTensor(node_features).to(self.device)
        edge_index = torch.LongTensor(self._edges[-10000:]).T.to(self.device)

        _, class_logits, risk_scores = self.model(x, edge_index)

        probs = F.softmax(class_logits, dim=-1)
        malicious_probs = probs[:, 1].cpu().numpy()

        return {
            ip: float(malicious_probs[i])
            for i, ip in enumerate(all_ips)
            if malicious_probs[i] > 0.3
        }
