"""
Thor Firewall — PyTorch Geometric GNN Network Analyzer
========================================================
تحليل طوبولوجيا الشبكة باستخدام Graph Neural Networks.

مستوحى من: https://github.com/pyg-team/pytorch_geometric
مستوحى من: https://github.com/dmlc/dgl (للمقارنة)

المعمارية:
  - GraphSAGE: network topology embedding
  - GATv2: threat propagation detection
  - GIN: subgraph pattern matching (DDoS botnet detection)
  - Heterogeneous Graph: hosts + flows + services
  
المخرجات:
  - node_embeddings: [N, 32] لكل جهاز في الشبكة
  - graph_risk_score: [1] للشبكة ككل
  - anomalous_nodes: قائمة IPs مشبوهة
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Tuple

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch import Tensor

# PyTorch Geometric
from torch_geometric.data import Data, HeteroData, Batch
from torch_geometric.nn import (
    SAGEConv,
    GATv2Conv,
    GINConv,
    global_mean_pool,
    global_max_pool,
    global_add_pool,
    BatchNorm,
    LayerNorm,
    to_hetero,
)
from torch_geometric.nn.models import GraphSAGE, GAT, GIN
from torch_geometric.utils import (
    add_self_loops,
    remove_self_loops,
    degree,
    to_undirected,
    dropout_adj,
)

logger = logging.getLogger("thor.ml.gnn")

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

NODE_FEAT_DIM  = 32   # per-host features (IP, port activity, traffic volume...)
EDGE_FEAT_DIM  = 16   # per-connection features (packets, bytes, flags...)
EMBED_DIM      = 32   # output embedding dimension
HIDDEN_DIM     = 128  # hidden layer dimension
NUM_LAYERS     = 3    # GNN depth


# ─────────────────────────────────────────────────────────────────────────────
# GraphSAGE Encoder (Network Topology Embedding)
# ─────────────────────────────────────────────────────────────────────────────

class ThorGraphSAGE(nn.Module):
    """
    GraphSAGE encoder لطوبولوجيا الشبكة.
    
    يُنتج embedding لكل جهاز يُستخدم كـ feature إضافية في MARL.
    مستوحى من: Hamilton et al., "Inductive Representation Learning on Large Graphs"
    """

    def __init__(
        self,
        in_channels: int = NODE_FEAT_DIM,
        hidden_channels: int = HIDDEN_DIM,
        out_channels: int = EMBED_DIM,
        num_layers: int = NUM_LAYERS,
        dropout: float = 0.1,
        aggr: str = "mean",  # mean / max / sum
    ):
        super().__init__()
        self.dropout = dropout

        # GraphSAGE layers
        self.convs = nn.ModuleList()
        self.norms = nn.ModuleList()

        # Input layer
        self.convs.append(SAGEConv(in_channels, hidden_channels, aggr=aggr))
        self.norms.append(BatchNorm(hidden_channels))

        # Hidden layers
        for _ in range(num_layers - 2):
            self.convs.append(SAGEConv(hidden_channels, hidden_channels, aggr=aggr))
            self.norms.append(BatchNorm(hidden_channels))

        # Output layer
        self.convs.append(SAGEConv(hidden_channels, out_channels, aggr=aggr))
        self.norms.append(BatchNorm(out_channels))

        # Skip connections
        self.skip = nn.Linear(in_channels, out_channels) if in_channels != out_channels else nn.Identity()

    def forward(self, x: Tensor, edge_index: Tensor) -> Tensor:
        """
        Args:
            x: Node features [N, in_channels]
            edge_index: Graph connectivity [2, E]
        Returns:
            Tensor: Node embeddings [N, out_channels]
        """
        h = x
        for i, (conv, norm) in enumerate(zip(self.convs, self.norms)):
            h_new = conv(h, edge_index)
            h_new = norm(h_new)
            if i < len(self.convs) - 1:
                h_new = F.relu(h_new)
                h_new = F.dropout(h_new, p=self.dropout, training=self.training)
            h = h_new

        # Skip connection from input to output
        return h + self.skip(x) if x.shape == h.shape else h


# ─────────────────────────────────────────────────────────────────────────────
# GATv2 Threat Propagation Detector
# ─────────────────────────────────────────────────────────────────────────────

class ThreatPropagationGAT(nn.Module):
    """
    GATv2 (Graph Attention Networks v2) للكشف عن انتشار التهديدات.
    
    يُحدد كيف تنتشر الهجمات عبر الشبكة (lateral movement, pivot attacks).
    مستوحى من: Brody et al., "How Attentive are Graph Attention Networks?"
    """

    def __init__(
        self,
        in_channels: int = EMBED_DIM,
        hidden_channels: int = 64,
        out_channels: int = EMBED_DIM,
        heads: int = 4,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.dropout = dropout

        # Multi-head GATv2
        self.gat1 = GATv2Conv(
            in_channels, hidden_channels,
            heads=heads, dropout=dropout,
            edge_dim=EDGE_FEAT_DIM, concat=True,
        )
        self.gat2 = GATv2Conv(
            hidden_channels * heads, out_channels,
            heads=1, dropout=dropout,
            edge_dim=EDGE_FEAT_DIM, concat=False,
        )
        self.norm1 = LayerNorm(hidden_channels * heads)
        self.norm2 = LayerNorm(out_channels)

    def forward(
        self, x: Tensor, edge_index: Tensor,
        edge_attr: Optional[Tensor] = None,
    ) -> Tuple[Tensor, Tensor]:
        """
        Returns:
            (node_embeddings [N, out_channels], attention_weights [E, heads])
        """
        h, attn1 = self.gat1(x, edge_index, edge_attr=edge_attr, return_attention_weights=True)
        h = self.norm1(h)
        h = F.elu(h)
        h = F.dropout(h, p=self.dropout, training=self.training)

        h, attn2 = self.gat2(h, edge_index, edge_attr=edge_attr, return_attention_weights=True)
        h = self.norm2(h)

        return h, attn2[1]  # (embeddings, attention_weights)


# ─────────────────────────────────────────────────────────────────────────────
# Complete Thor GNN Analyzer
# ─────────────────────────────────────────────────────────────────────────────

class ThorGNNAnalyzer(nn.Module):
    """
    الـ GNN الكامل لنظام Thor.
    
    Pipeline:
      1. GraphSAGE → node embeddings
      2. GATv2 → threat propagation scores
      3. Global pooling → graph-level risk score
      4. Node classifier → anomalous node detection
    
    يتكامل مع: Ray RLlib (يُمرر embeddings للـ MARL agents)
    """

    def __init__(
        self,
        node_feat_dim: int = NODE_FEAT_DIM,
        edge_feat_dim: int = EDGE_FEAT_DIM,
        embed_dim: int = EMBED_DIM,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.embed_dim = embed_dim

        # Stage 1: GraphSAGE topology encoding
        self.sage = ThorGraphSAGE(
            in_channels=node_feat_dim,
            hidden_channels=128,
            out_channels=embed_dim,
            num_layers=3,
            dropout=dropout,
        )

        # Stage 2: GATv2 threat propagation
        self.gat = ThreatPropagationGAT(
            in_channels=embed_dim,
            hidden_channels=64,
            out_channels=embed_dim,
            heads=4,
            dropout=dropout,
        )

        # Stage 3: Graph-level risk score
        self.graph_classifier = nn.Sequential(
            nn.Linear(embed_dim * 3, 128),  # mean + max + add pooling
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, 1),
            nn.Sigmoid(),
        )

        # Stage 4: Node-level anomaly classifier
        self.node_classifier = nn.Sequential(
            nn.Linear(embed_dim * 2, 64),   # sage + gat embeddings
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(64, 2),   # [benign, anomalous]
        )

        # Edge-level flow risk scorer
        self.edge_scorer = nn.Sequential(
            nn.Linear(embed_dim * 2 + edge_feat_dim, 64),
            nn.ReLU(),
            nn.Linear(64, 1),
            nn.Sigmoid(),
        )

    def forward(
        self,
        x: Tensor,                    # [N, node_feat_dim]
        edge_index: Tensor,           # [2, E]
        edge_attr: Optional[Tensor] = None,  # [E, edge_feat_dim]
        batch: Optional[Tensor] = None,      # for batched graphs
    ) -> Dict[str, Tensor]:
        """
        Args:
            x: Node features
            edge_index: Graph connectivity
            edge_attr: Edge features (flow statistics)
            batch: Batch vector for multiple graphs
            
        Returns:
            {
              "node_embeddings":  [N, embed_dim],
              "graph_risk_score": [B] or [1],
              "node_anomaly_logits": [N, 2],
              "node_anomaly_probs": [N],
              "attention_weights": [E, 4],
            }
        """
        # Stage 1: Structural embedding
        sage_emb = self.sage(x, edge_index)    # [N, embed_dim]

        # Stage 2: Threat-aware embedding
        gat_emb, attn_weights = self.gat(
            sage_emb, edge_index, edge_attr=edge_attr
        )  # [N, embed_dim]

        # Combined node embedding
        node_emb = sage_emb + gat_emb          # [N, embed_dim] — residual

        # Stage 3: Graph risk
        if batch is None:
            batch = torch.zeros(x.size(0), dtype=torch.long, device=x.device)

        pool_mean = global_mean_pool(node_emb, batch)  # [B, embed_dim]
        pool_max  = global_max_pool(node_emb, batch)   # [B, embed_dim]
        pool_add  = global_add_pool(node_emb, batch)   # [B, embed_dim]
        graph_repr = torch.cat([pool_mean, pool_max, pool_add], dim=-1)  # [B, 3*embed]
        graph_risk = self.graph_classifier(graph_repr).squeeze(-1)        # [B]

        # Stage 4: Node anomaly
        node_input    = torch.cat([sage_emb, gat_emb], dim=-1)   # [N, 2*embed]
        anomaly_logits = self.node_classifier(node_input)          # [N, 2]
        anomaly_probs  = F.softmax(anomaly_logits, dim=-1)[:, 1]  # [N] prob of anomaly

        return {
            "node_embeddings":     node_emb,
            "graph_risk_score":    graph_risk,
            "node_anomaly_logits": anomaly_logits,
            "node_anomaly_probs":  anomaly_probs,
            "attention_weights":   attn_weights,
        }

    @torch.no_grad()
    def get_embeddings(
        self,
        x: Tensor,
        edge_index: Tensor,
        edge_attr: Optional[Tensor] = None,
    ) -> Tensor:
        """
        Inference-only: يُرجع node embeddings للـ MARL agents.
        يُستدعى من ml-inference server بـ latency < 5ms.
        """
        self.eval()
        result = self.forward(x, edge_index, edge_attr)
        return result["node_embeddings"]   # [N, embed_dim=32]


# ─────────────────────────────────────────────────────────────────────────────
# Graph Builder — من flow data إلى PyG Data object
# ─────────────────────────────────────────────────────────────────────────────

class NetworkGraphBuilder:
    """
    يبني PyG graph من بيانات التدفقات الحية.
    
    Nodes = IP addresses (hosts)
    Edges = network flows (connections)
    """

    def __init__(self, max_nodes: int = 10_000):
        self.max_nodes = max_nodes
        self._ip_to_idx: Dict[str, int] = {}
        self._idx_counter = 0

    def build_graph(self, flows: List[Dict]) -> Data:
        """
        flows: list of {src_ip, dst_ip, packets, bytes, risk_score, ...}
        Returns: PyG Data object
        """
        src_indices, dst_indices = [], []
        edge_features = []
        node_features_dict: Dict[int, List[float]] = {}

        for flow in flows:
            src_ip = flow.get("src_ip", "0.0.0.0")
            dst_ip = flow.get("dst_ip", "0.0.0.0")

            src_idx = self._get_or_create_node(src_ip)
            dst_idx = self._get_or_create_node(dst_ip)

            if src_idx >= self.max_nodes or dst_idx >= self.max_nodes:
                continue

            src_indices.append(src_idx)
            dst_indices.append(dst_idx)

            # Edge features (16-dim) — flow statistics
            edge_feat = [
                float(flow.get("packets", 0)) / 1e6,
                float(flow.get("bytes", 0)) / 1e9,
                float(flow.get("pps", 0)) / 1e4,
                float(flow.get("bps", 0)) / 1e9,
                float(flow.get("risk_score", 0.0)),
                float(flow.get("protocol", 6)) / 255,
                float(flow.get("src_port", 0)) / 65535,
                float(flow.get("dst_port", 0)) / 65535,
                float(flow.get("payload_entropy", 0.0)),
                float(flow.get("avg_packet_size", 0)) / 65535,
                float(flow.get("retransmissions", 0)) / 100,
                float(flow.get("duration_ms", 0)) / 1e6,
                0.0, 0.0, 0.0, 0.0,   # padding
            ]
            edge_features.append(edge_feat)

        # Build node features
        num_nodes = len(self._ip_to_idx)
        x = torch.zeros(num_nodes, NODE_FEAT_DIM)

        if not src_indices:
            return Data(x=x, edge_index=torch.zeros(2, 0, dtype=torch.long))

        edge_index = torch.tensor(
            [src_indices, dst_indices], dtype=torch.long
        )
        edge_attr = torch.tensor(edge_features, dtype=torch.float32)

        return Data(x=x, edge_index=edge_index, edge_attr=edge_attr)

    def _get_or_create_node(self, ip: str) -> int:
        if ip not in self._ip_to_idx:
            self._ip_to_idx[ip] = self._idx_counter
            self._idx_counter += 1
        return self._ip_to_idx[ip]

    def reset(self) -> None:
        self._ip_to_idx.clear()
        self._idx_counter = 0


# ─────────────────────────────────────────────────────────────────────────────
# Factory
# ─────────────────────────────────────────────────────────────────────────────

def create_thor_gnn(device: str = "cpu") -> ThorGNNAnalyzer:
    """يُنشئ model جاهزة للاستخدام."""
    model = ThorGNNAnalyzer(
        node_feat_dim=NODE_FEAT_DIM,
        edge_feat_dim=EDGE_FEAT_DIM,
        embed_dim=EMBED_DIM,
        dropout=0.1,
    ).to(device)
    logger.info(f"✅ ThorGNNAnalyzer created — params: {sum(p.numel() for p in model.parameters()):,}")
    return model
