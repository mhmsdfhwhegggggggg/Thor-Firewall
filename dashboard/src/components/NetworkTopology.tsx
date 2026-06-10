/**
 * Thor Firewall — Network Topology View (React Flow)
 * Real-time interactive network graph showing hosts, flows, threats.
 * Based on: https://github.com/xyflow/xyflow (MIT)
 */
import React, { useCallback, useEffect, useState } from "react";
import ReactFlow, {
  Node, Edge, Background, Controls, MiniMap,
  useNodesState, useEdgesState, addEdge, Connection,
  BackgroundVariant, NodeTypes, MarkerType,
  Handle, Position,
} from "reactflow";
import "reactflow/dist/style.css";

const API_BASE = import.meta.env.BASE_URL?.replace(/\/$/, "") ?? "";

// ── Custom Node Types ─────────────────────────────────────────────────────────

function HostNode({ data }: { data: any }) {
  const riskColor = data.risk > 0.7 ? "#ef4444" : data.risk > 0.4 ? "#f97316" : "#22c55e";
  return (
    <div style={{
      background: "#1e293b", border: `2px solid ${riskColor}`,
      borderRadius: 10, padding: "10px 14px", minWidth: 120, position: "relative",
      boxShadow: `0 0 12px ${riskColor}44`,
    }}>
      <Handle type="target" position={Position.Left} style={{ background: riskColor }} />
      <Handle type="source" position={Position.Right} style={{ background: riskColor }} />
      <div style={{ fontSize: 18, textAlign: "center", marginBottom: 4 }}>
        {data.type === "server" ? "🖥️" : data.type === "attacker" ? "💀" : "💻"}
      </div>
      <div style={{ color: "#e2e8f0", fontSize: 11, textAlign: "center", fontFamily: "monospace" }}>
        {data.ip}
      </div>
      {data.threat && (
        <div style={{
          marginTop: 4, background: "#450a0a", borderRadius: 4,
          padding: "2px 6px", fontSize: 10, color: "#fca5a5", textAlign: "center",
        }}>
          ⚠ {data.threat}
        </div>
      )}
    </div>
  );
}

function GatewayNode({ data }: { data: any }) {
  return (
    <div style={{
      background: "#172554", border: "2px solid #3b82f6",
      borderRadius: 12, padding: "12px 18px", textAlign: "center",
      boxShadow: "0 0 16px #3b82f644",
    }}>
      <Handle type="target" position={Position.Left} style={{ background: "#3b82f6" }} />
      <Handle type="source" position={Position.Right} style={{ background: "#3b82f6" }} />
      <Handle type="source" position={Position.Bottom} style={{ background: "#3b82f6" }} />
      <div style={{ fontSize: 24, marginBottom: 4 }}>⚡</div>
      <div style={{ color: "#93c5fd", fontSize: 12, fontWeight: 600 }}>Thor Firewall</div>
      <div style={{ color: "#1d4ed8", fontSize: 10 }}>XDP Active</div>
    </div>
  );
}

const NODE_TYPES: NodeTypes = {
  host:    HostNode,
  gateway: GatewayNode,
};

// ── Fetch topology from API ───────────────────────────────────────────────────

async function fetchTopology() {
  try {
    const r = await fetch(`${API_BASE}/api/flows?limit=50&aggregate=topology`, {
      headers: { "Authorization": `Bearer ${localStorage.getItem("thor_token") ?? ""}` },
    });
    if (!r.ok) return null;
    return await r.json();
  } catch {
    return null;
  }
}

// Build demo topology if API unavailable
function buildDemoTopology(): { nodes: Node[]; edges: Edge[] } {
  const nodes: Node[] = [
    { id: "gw",    type: "gateway", position: { x: 400, y: 250 }, data: {} },
    { id: "srv1",  type: "host",    position: { x: 700, y: 100 }, data: { ip: "10.0.0.10", type: "server",   risk: 0.1 } },
    { id: "srv2",  type: "host",    position: { x: 700, y: 250 }, data: { ip: "10.0.0.11", type: "server",   risk: 0.2 } },
    { id: "srv3",  type: "host",    position: { x: 700, y: 400 }, data: { ip: "10.0.0.12", type: "server",   risk: 0.1 } },
    { id: "ext1",  type: "host",    position: { x: 100, y: 150 }, data: { ip: "45.33.32.156", type: "attacker", risk: 0.9, threat: "PortScan" } },
    { id: "ext2",  type: "host",    position: { x: 100, y: 350 }, data: { ip: "192.241.220.138", type: "client",   risk: 0.3 } },
  ];
  const edges: Edge[] = [
    { id: "e1", source: "ext1", target: "gw",   animated: true,  markerEnd: { type: MarkerType.ArrowClosed }, style: { stroke: "#ef4444", strokeWidth: 2 } },
    { id: "e2", source: "ext2", target: "gw",   animated: false, markerEnd: { type: MarkerType.ArrowClosed }, style: { stroke: "#22c55e" } },
    { id: "e3", source: "gw",   target: "srv1", animated: false, markerEnd: { type: MarkerType.ArrowClosed }, style: { stroke: "#3b82f6" } },
    { id: "e4", source: "gw",   target: "srv2", animated: false, markerEnd: { type: MarkerType.ArrowClosed }, style: { stroke: "#3b82f6" } },
    { id: "e5", source: "gw",   target: "srv3", animated: false, markerEnd: { type: MarkerType.ArrowClosed }, style: { stroke: "#3b82f6" } },
  ];
  return { nodes, edges };
}

// ── Main component ─────────────────────────────────────────────────────────────
export default function NetworkTopology() {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [selected, setSelected] = useState<string | null>(null);

  useEffect(() => {
    const load = async () => {
      const live = await fetchTopology();
      if (live?.nodes?.length) {
        setNodes(live.nodes);
        setEdges(live.edges);
      } else {
        const { nodes: n, edges: e } = buildDemoTopology();
        setNodes(n);
        setEdges(e);
      }
    };
    load();
    const id = setInterval(load, 30_000);
    return () => clearInterval(id);
  }, []);

  const onConnect = useCallback(
    (params: Connection) => setEdges(eds => addEdge(params, eds)),
    [setEdges]
  );

  return (
    <div style={{ background: "#0f172a", height: "100vh", display: "flex", flexDirection: "column" }}>
      <div style={{
        padding: "14px 24px", background: "#1e293b",
        borderBottom: "1px solid #334155", display: "flex",
        alignItems: "center", gap: 16,
      }}>
        <h2 style={{ margin: 0, color: "#f1f5f9", fontSize: 18 }}>🌐 Network Topology</h2>
        <span style={{ color: "#475569", fontSize: 13 }}>
          {nodes.length} hosts · {edges.length} flows · live
        </span>
      </div>
      <div style={{ flex: 1 }}>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onConnect={onConnect}
          nodeTypes={NODE_TYPES}
          fitView
          attributionPosition="bottom-right"
        >
          <Background color="#334155" variant={BackgroundVariant.Dots} gap={20} size={1} />
          <Controls style={{ background: "#1e293b", border: "1px solid #334155" }} />
          <MiniMap
            style={{ background: "#0f172a", border: "1px solid #334155" }}
            nodeColor={n => n.data?.risk > 0.7 ? "#ef4444" : "#3b82f6"}
          />
        </ReactFlow>
      </div>
    </div>
  );
}
