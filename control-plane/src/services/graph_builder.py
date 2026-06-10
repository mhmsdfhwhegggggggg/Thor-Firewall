"""
Thor Firewall — Threat Graph Builder
بناء وتحديث رسم بياني (graph) للتهديدات في الوقت الفعلي
مكافئ CrowdStrike Threat Graph

SPDX-License-Identifier: MIT
"""
from __future__ import annotations
import logging, time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
import json

logger = logging.getLogger("thor.services.graph_builder")

# ── Data Structures ───────────────────────────────────────────────────────────

@dataclass
class GraphNode:
    node_id:    str
    node_type:  str           # "ip" | "host" | "user" | "domain" | "file" | "process"
    risk_score: float = 0.0
    ioc_match:  bool  = False
    threat_tags: List[str] = field(default_factory=list)
    country:    str = ""
    hostname:   str = ""
    first_seen: float = field(default_factory=time.time)
    last_seen:  float = field(default_factory=time.time)
    metadata:   Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "node_id":    self.node_id,
            "node_type":  self.node_type,
            "risk_score": round(self.risk_score, 3),
            "ioc_match":  self.ioc_match,
            "threat_tags": self.threat_tags,
            "country":    self.country,
            "hostname":   self.hostname,
            "first_seen": self.first_seen,
            "last_seen":  self.last_seen,
        }


@dataclass
class GraphEdge:
    src_node:    str
    dst_node:    str
    edge_type:   str    # "network_flow" | "authenticated" | "resolved_domain" | ...
    flow_count:  int   = 0
    bytes_total: int   = 0
    risk_score:  float = 0.0
    protocols:   List[str] = field(default_factory=list)
    dst_ports:   List[int] = field(default_factory=list)
    first_seen:  float = field(default_factory=time.time)
    last_seen:   float = field(default_factory=time.time)

    @property
    def edge_id(self) -> str:
        return f"{self.src_node}→{self.dst_node}:{self.edge_type}"

    def to_dict(self) -> Dict:
        return {
            "src_node":   self.src_node,
            "dst_node":   self.dst_node,
            "edge_type":  self.edge_type,
            "flow_count": self.flow_count,
            "bytes_total": self.bytes_total,
            "risk_score": round(self.risk_score, 3),
            "protocols":  self.protocols,
            "dst_ports":  self.dst_ports[:20],
            "first_seen": self.first_seen,
            "last_seen":  self.last_seen,
        }


@dataclass
class Campaign:
    """مجموعة أحداث متصلة تشكّل حملة هجومية"""
    campaign_id:    str
    node_ids:       Set[str] = field(default_factory=set)
    mitre_ids:      List[str] = field(default_factory=list)
    severity:       str = "medium"
    confidence:     float = 0.5
    start_time:     float = field(default_factory=time.time)
    last_activity:  float = field(default_factory=time.time)
    description:    str = ""


# ── Graph Builder ─────────────────────────────────────────────────────────────

class ThreatGraphBuilder:
    """
    يبني ويُحدّث رسماً بيانياً لعلاقات التهديدات.

    - Nodes: IPs, hosts, users, domains, files
    - Edges: network flows, auth, DNS, lateral movement
    - خوارزمية الكشف عن الحملات: connected components + risk propagation
    """

    def __init__(self, max_nodes: int = 100_000, max_edges: int = 500_000):
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: Dict[str, GraphEdge] = {}
        self._adj:   Dict[str, Set[str]]  = {}   # src_node → {dst_nodes}
        self._campaigns: Dict[str, Campaign] = {}
        self._max_nodes = max_nodes
        self._max_edges = max_edges

    # ── Public API ─────────────────────────────────────────────────────────────

    def add_flow(
        self,
        src_ip:     str,
        dst_ip:     str,
        protocol:   str,
        dst_port:   int,
        bytes_:     int,
        risk_score: float,
    ) -> None:
        """أضف flow للـ graph"""
        ts = time.time()
        # Upsert nodes
        self._upsert_node(src_ip, "ip", risk_score * 0.6, ts)
        self._upsert_node(dst_ip, "ip", risk_score * 0.4, ts)
        # Upsert edge
        edge_key  = f"{src_ip}→{dst_ip}:network_flow"
        if edge_key in self._edges:
            edge             = self._edges[edge_key]
            edge.flow_count  += 1
            edge.bytes_total += bytes_
            edge.risk_score   = max(edge.risk_score, risk_score)
            edge.last_seen    = ts
            if protocol not in edge.protocols:
                edge.protocols.append(protocol)
            if dst_port not in edge.dst_ports:
                edge.dst_ports.append(dst_port)
        else:
            if len(self._edges) < self._max_edges:
                self._edges[edge_key] = GraphEdge(
                    src_node   = src_ip,
                    dst_node   = dst_ip,
                    edge_type  = "network_flow",
                    flow_count = 1,
                    bytes_total= bytes_,
                    risk_score = risk_score,
                    protocols  = [protocol],
                    dst_ports  = [dst_port],
                )
                if src_ip not in self._adj:
                    self._adj[src_ip] = set()
                self._adj[src_ip].add(dst_ip)

    def add_threat_tag(self, node_id: str, tag: str, ioc: bool = False) -> None:
        """أضف threat tag لـ node"""
        node = self._nodes.get(node_id)
        if node:
            if tag not in node.threat_tags:
                node.threat_tags.append(tag)
            if ioc:
                node.ioc_match = True
                node.risk_score = min(node.risk_score + 0.3, 1.0)

    def get_neighbors(
        self,
        node_id: str,
        depth:   int = 1,
        max_per_level: int = 50,
    ) -> Dict[str, Any]:
        """أعد جيران node حتى عمق معين"""
        visited: Set[str] = {node_id}
        result: Dict[str, Any] = {"center": node_id, "levels": []}

        current_level = {node_id}
        for d in range(depth):
            next_level: Set[str] = set()
            level_nodes: List[Dict] = []
            level_edges: List[Dict] = []
            for nid in current_level:
                neighbors = list(self._adj.get(nid, set()))[:max_per_level]
                for neighbor in neighbors:
                    if neighbor not in visited:
                        visited.add(neighbor)
                        next_level.add(neighbor)
                        node = self._nodes.get(neighbor)
                        if node:
                            level_nodes.append(node.to_dict())
                    edge_key = f"{nid}→{neighbor}:network_flow"
                    edge = self._edges.get(edge_key)
                    if edge:
                        level_edges.append(edge.to_dict())
            result["levels"].append({
                "depth":  d + 1,
                "nodes":  level_nodes,
                "edges":  level_edges,
            })
            current_level = next_level
            if not current_level:
                break

        return result

    def get_high_risk_nodes(self, min_risk: float = 0.7, limit: int = 100) -> List[Dict]:
        """أعد قائمة الـ nodes عالية الخطورة"""
        nodes = sorted(
            [n for n in self._nodes.values() if n.risk_score >= min_risk],
            key=lambda n: n.risk_score,
            reverse=True,
        )
        return [n.to_dict() for n in nodes[:limit]]

    def get_ioc_nodes(self, limit: int = 200) -> List[Dict]:
        """أعد الـ nodes التي تطابق IOC"""
        return [n.to_dict() for n in self._nodes.values() if n.ioc_match][:limit]

    def stats(self) -> Dict[str, int]:
        return {
            "nodes":     len(self._nodes),
            "edges":     len(self._edges),
            "campaigns": len(self._campaigns),
            "ioc_nodes": sum(1 for n in self._nodes.values() if n.ioc_match),
            "high_risk": sum(1 for n in self._nodes.values() if n.risk_score >= 0.7),
        }

    # ── Private ────────────────────────────────────────────────────────────────

    def _upsert_node(
        self, node_id: str, node_type: str, risk: float, ts: float
    ) -> GraphNode:
        if node_id in self._nodes:
            n             = self._nodes[node_id]
            n.risk_score  = max(n.risk_score, risk)
            n.last_seen   = ts
            return n
        if len(self._nodes) >= self._max_nodes:
            return GraphNode(node_id=node_id, node_type=node_type)
        node = GraphNode(node_id=node_id, node_type=node_type,
                         risk_score=risk, first_seen=ts, last_seen=ts)
        self._nodes[node_id] = node
        return node


# Singleton
_graph_builder = ThreatGraphBuilder()

def get_graph_builder() -> ThreatGraphBuilder:
    return _graph_builder
