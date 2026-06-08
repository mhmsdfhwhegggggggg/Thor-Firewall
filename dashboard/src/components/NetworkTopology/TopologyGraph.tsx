// Thor Firewall — Network Topology Graph (Digital Twin)
// خريطة الشبكة الحية باستخدام D3-force
import React, { useEffect, useRef, useState, useCallback } from "react";

interface TopoNode {
  id: string; label: string; type: "server" | "workstation" | "router" | "external" | "honeypot";
  ip: string; risk_score: number; active_connections: number;
  x?: number; y?: number; vx?: number; vy?: number; fx?: number | null; fy?: number | null;
}

interface TopoEdge {
  source: string; target: string; bytes: number;
  protocol: string; risk: number; active: boolean;
}

interface TopologyData { nodes: TopoNode[]; edges: TopoEdge[] }

// Mock topology — in production, fetched from /api/v1/topology
const MOCK_TOPOLOGY: TopologyData = {
  nodes: [
    { id: "gw", label: "Thor Gateway", type: "router", ip: "10.0.0.1", risk_score: 0.12, active_connections: 42 },
    { id: "ws1", label: "WS-HR-042", type: "workstation", ip: "10.0.5.42", risk_score: 0.72, active_connections: 18 },
    { id: "ws2", label: "WS-IT-101", type: "workstation", ip: "10.0.1.101", risk_score: 0.05, active_connections: 7 },
    { id: "srv1", label: "SRV-WEB-03", type: "server", ip: "10.0.2.3", risk_score: 0.85, active_connections: 124 },
    { id: "srv2", label: "SRV-DB-01", type: "server", ip: "10.0.2.10", risk_score: 0.08, active_connections: 8 },
    { id: "ext1", label: "185.220.101.45", type: "external", ip: "185.220.101.45", risk_score: 0.97, active_connections: 3 },
    { id: "honey", label: "Honeypot-SSH", type: "honeypot", ip: "10.0.99.1", risk_score: 0.0, active_connections: 5 },
  ],
  edges: [
    { source: "ext1", target: "gw", bytes: 847000, protocol: "TCP", risk: 0.9, active: true },
    { source: "gw", target: "srv1", bytes: 234000, protocol: "HTTP", risk: 0.6, active: true },
    { source: "ws1", target: "srv2", bytes: 98000000, protocol: "SQL", risk: 0.7, active: true },
    { source: "gw", target: "ws1", bytes: 12000, protocol: "TCP", risk: 0.3, active: true },
    { source: "gw", target: "ws2", bytes: 5000, protocol: "TCP", risk: 0.05, active: true },
    { source: "ext1", target: "honey", bytes: 24000, protocol: "SSH", risk: 0.95, active: true },
  ],
};

const NODE_COLOR: Record<string, string> = {
  server: "#0ea5e9", workstation: "#6366f1",
  router: "#10b981", external: "#ef4444", honeypot: "#f59e0b",
};

const riskColor = (r: number) =>
  r > 0.8 ? "#ef4444" : r > 0.5 ? "#f59e0b" : r > 0.2 ? "#6366f1" : "#10b981";

function nodeRadius(n: TopoNode) { return 14 + n.active_connections * 0.15; }

export default function TopologyGraph({ width = 800, height = 500 }: { width?: number; height?: number }) {
  const svgRef = useRef<SVGSVGElement>(null);
  const [selected, setSelected] = useState<TopoNode | null>(null);
  const [data] = useState<TopologyData>(MOCK_TOPOLOGY);

  // Simple force simulation without external deps
  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) return;

    const nodes = data.nodes.map(n => ({ ...n,
      x: width / 2 + (Math.random() - 0.5) * 400,
      y: height / 2 + (Math.random() - 0.5) * 300,
    }));

    const edgeMap = new Map(nodes.map(n => [n.id, n]));

    // Render once (static layout for non-D3 environment)
    const g = svg.querySelector(".graph-group") as SVGGElement;
    if (!g) return;

    g.innerHTML = "";

    // Draw edges
    data.edges.forEach(edge => {
      const src = edgeMap.get(edge.source);
      const tgt = edgeMap.get(edge.target);
      if (!src || !tgt) return;

      const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
      line.setAttribute("x1", String(src.x));
      line.setAttribute("y1", String(src.y));
      line.setAttribute("x2", String(tgt.x));
      line.setAttribute("y2", String(tgt.y));
      line.setAttribute("stroke", riskColor(edge.risk));
      line.setAttribute("stroke-width", String(1 + Math.log(edge.bytes / 10000)));
      line.setAttribute("stroke-opacity", "0.6");
      g.appendChild(line);
    });

    // Draw nodes
    nodes.forEach(node => {
      const r = nodeRadius(node);
      const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
      circle.setAttribute("cx", String(node.x));
      circle.setAttribute("cy", String(node.y));
      circle.setAttribute("r", String(r));
      circle.setAttribute("fill", NODE_COLOR[node.type] || "#64748b");
      circle.setAttribute("fill-opacity", "0.85");
      circle.setAttribute("stroke", riskColor(node.risk_score));
      circle.setAttribute("stroke-width", node.risk_score > 0.5 ? "3" : "1.5");
      circle.style.cursor = "pointer";
      circle.addEventListener("click", () => setSelected(node));
      g.appendChild(circle);

      const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
      text.setAttribute("x", String(node.x));
      text.setAttribute("y", String((node.y || 0) + r + 14));
      text.setAttribute("text-anchor", "middle");
      text.setAttribute("fill", "#94a3b8");
      text.setAttribute("font-size", "11");
      text.setAttribute("font-family", "monospace");
      text.textContent = node.label;
      g.appendChild(text);
    });
  }, [data, width, height]);

  return (
    <div className="relative rounded-xl border border-white/10 bg-gray-900/50 overflow-hidden">
      <div className="absolute top-3 left-3 z-10 flex flex-wrap gap-2">
        {Object.entries(NODE_COLOR).map(([type, color]) => (
          <span key={type} className="flex items-center gap-1 text-xs text-white/60">
            <span className="h-2.5 w-2.5 rounded-full inline-block" style={{ background: color }} />
            {type}
          </span>
        ))}
      </div>
      <svg ref={svgRef} width={width} height={height} className="w-full">
        <g className="graph-group" />
      </svg>
      {selected && (
        <div className="absolute bottom-3 left-3 rounded-xl border border-white/20 bg-gray-950/90 p-3 min-w-48">
          <div className="text-sm font-bold text-white">{selected.label}</div>
          <div className="text-xs text-white/60 font-mono mt-0.5">{selected.ip}</div>
          <div className="mt-2 space-y-1 text-xs">
            <div className="flex justify-between">
              <span className="text-white/40">Risk</span>
              <span className={`font-mono font-bold ${riskColor(selected.risk_score) === "#ef4444" ? "text-red-400" : "text-green-400"}`}>
                {Math.round(selected.risk_score * 100)}%
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-white/40">Connections</span>
              <span className="text-white/80">{selected.active_connections}</span>
            </div>
          </div>
          <button onClick={() => setSelected(null)} className="mt-2 text-xs text-white/30 hover:text-white/60">✕ Close</button>
        </div>
      )}
    </div>
  );
}
