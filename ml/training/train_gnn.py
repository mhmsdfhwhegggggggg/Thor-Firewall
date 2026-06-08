"""
Thor Firewall — GNN Training Pipeline
تدريب شبكة GNN على أنماط الشبكة

GraphSAGE + GATv2 لتحليل هيكل الشبكة وكشف الحركات الجانبية.
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
import logging, json, os, time
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import numpy as np

logger = logging.getLogger("thor.training.gnn")

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    logger.warning("PyTorch not available")

try:
    import mlflow
    import mlflow.pytorch
    MLFLOW_AVAILABLE = True
except ImportError:
    MLFLOW_AVAILABLE = False


class GATv2Layer(nn.Module):
    """Graph Attention Network v2 layer"""
    def __init__(self, in_dim: int, out_dim: int, heads: int = 4, dropout: float = 0.1):
        super().__init__()
        self.heads = heads
        self.out_dim = out_dim
        self.W = nn.Linear(in_dim, heads * out_dim, bias=False)
        self.a = nn.Parameter(torch.zeros(1, heads, 2 * out_dim))
        nn.init.xavier_uniform_(self.a)
        self.leaky = nn.LeakyReLU(0.2)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x: "torch.Tensor", edge_index: "torch.Tensor") -> "torch.Tensor":
        """Forward pass — simplified GAT without PyG dependency"""
        N = x.size(0)
        Wh = self.W(x).view(N, self.heads, self.out_dim)  # [N, H, D]
        src, dst = edge_index[0], edge_index[1]
        a_input = torch.cat([Wh[src], Wh[dst]], dim=-1)   # [E, H, 2D]
        attn = self.leaky((a_input * self.a).sum(dim=-1))   # [E, H]
        attn = torch.softmax(attn, dim=0)
        attn = self.dropout(attn)
        out = torch.zeros(N, self.heads, self.out_dim, device=x.device)
        out.index_add_(0, dst, Wh[src] * attn.unsqueeze(-1))
        return out.mean(dim=1)  # [N, D]


class GraphSAGELayer(nn.Module):
    """GraphSAGE aggregation layer"""
    def __init__(self, in_dim: int, out_dim: int):
        super().__init__()
        self.W = nn.Linear(in_dim * 2, out_dim)
        self.bn = nn.BatchNorm1d(out_dim)

    def forward(self, x: "torch.Tensor", edge_index: "torch.Tensor") -> "torch.Tensor":
        N = x.size(0)
        src, dst = edge_index[0], edge_index[1]
        neighbor_agg = torch.zeros_like(x)
        count = torch.zeros(N, 1, device=x.device)
        neighbor_agg.index_add_(0, dst, x[src])
        count.index_add_(0, dst, torch.ones(src.size(0), 1, device=x.device))
        count = count.clamp(min=1)
        neighbor_agg = neighbor_agg / count
        out = self.W(torch.cat([x, neighbor_agg], dim=-1))
        out = self.bn(F.relu(out))
        return F.normalize(out, p=2, dim=-1)


class ThorGNN(nn.Module):
    """
    Thor Graph Neural Network
    Input: Node features (IP stats, port activity, connection patterns)
    Output: Node risk embeddings (32-dim) + anomaly score
    """
    def __init__(self, in_dim: int = 32, hidden_dim: int = 128, embed_dim: int = 32):
        super().__init__()
        self.sage1 = GraphSAGELayer(in_dim, hidden_dim)
        self.gat1 = GATv2Layer(hidden_dim, hidden_dim // 2, heads=4)
        self.sage2 = GraphSAGELayer(hidden_dim // 2, hidden_dim // 2)
        self.gat2 = GATv2Layer(hidden_dim // 2, embed_dim, heads=2)
        self.anomaly_head = nn.Sequential(
            nn.Linear(embed_dim, embed_dim // 2),
            nn.ReLU(),
            nn.Linear(embed_dim // 2, 1),
            nn.Sigmoid(),
        )

    def forward(self, x: "torch.Tensor", edge_index: "torch.Tensor"):
        h = self.sage1(x, edge_index)
        h = self.gat1(h, edge_index)
        h = self.sage2(h, edge_index)
        emb = self.gat2(h, edge_index)
        score = self.anomaly_head(emb)
        return emb, score


def generate_synthetic_graph(n_nodes: int = 100, n_edges: int = 300):
    """Graph صناعي للاختبار"""
    rng = np.random.default_rng(42)
    x = rng.standard_normal((n_nodes, 32)).astype(np.float32)
    src = rng.integers(0, n_nodes, n_edges)
    dst = rng.integers(0, n_nodes, n_edges)
    edge_index = np.stack([src, dst], axis=0)
    # 10% anomalous nodes
    y = (rng.random(n_nodes) < 0.1).astype(np.float32)
    return x, edge_index, y


def train_gnn(
    epochs: int = 50,
    lr: float = 1e-3,
    output_dir: str = "/models/gnn",
    mlflow_uri: str = "http://mlflow:5000",
    experiment: str = "thor-gnn-v1",
):
    if not TORCH_AVAILABLE:
        logger.error("PyTorch required for GNN training")
        return

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logger.info("GNN Training on: %s", device)

    if MLFLOW_AVAILABLE:
        mlflow.set_tracking_uri(mlflow_uri)
        mlflow.set_experiment(experiment)
        mlflow.start_run(run_name=f"gnn_training_{int(time.time())}")
        mlflow.log_params({"epochs": epochs, "lr": lr, "device": str(device)})

    x_np, ei_np, y_np = generate_synthetic_graph(n_nodes=200, n_edges=600)
    x = torch.FloatTensor(x_np).to(device)
    edge_index = torch.LongTensor(ei_np).to(device)
    y = torch.FloatTensor(y_np).to(device)

    model = ThorGNN(in_dim=32, hidden_dim=128, embed_dim=32).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    criterion = nn.BCELoss()

    best_loss = float("inf")
    os.makedirs(output_dir, exist_ok=True)

    for epoch in range(epochs):
        model.train()
        emb, scores = model(x, edge_index)
        loss = criterion(scores.squeeze(), y)
        optimizer.zero_grad()
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        optimizer.step()

        if loss.item() < best_loss:
            best_loss = loss.item()
            torch.save(model.state_dict(), f"{output_dir}/thor_gnn_best.pt")

        if (epoch + 1) % 10 == 0:
            logger.info("Epoch %d/%d | loss=%.4f", epoch + 1, epochs, loss.item())
            if MLFLOW_AVAILABLE:
                mlflow.log_metric("gnn/train_loss", loss.item(), step=epoch)

    if MLFLOW_AVAILABLE:
        mlflow.pytorch.log_model(model, "models/gnn", registered_model_name="thor_gnn")
        mlflow.end_run()

    logger.info("✅ GNN training complete. Best loss: %.4f", best_loss)


if __name__ == "__main__":
    import argparse
    logging.basicConfig(level=logging.INFO)
    p = argparse.ArgumentParser()
    p.add_argument("--epochs", type=int, default=50)
    p.add_argument("--lr", type=float, default=1e-3)
    p.add_argument("--output-dir", default="/models/gnn")
    p.add_argument("--mlflow-uri", default="http://mlflow:5000")
    args = p.parse_args()
    train_gnn(args.epochs, args.lr, args.output_dir, args.mlflow_uri)
