import React, { useEffect, useRef, useState, useCallback } from 'react';
import { Network, RefreshCw, ZoomIn, ZoomOut, Maximize2 } from 'lucide-react';

// ────────────────────────────────────────────────────────────────────────────
// Types
// ────────────────────────────────────────────────────────────────────────────

interface TopoNode {
  id:        string;
  label:     string;
  type:      'host' | 'server' | 'router' | 'firewall' | 'attacker' | 'unknown';
  ip:        string;
  risk:      number;   // [0,1]
  active:    boolean;
  x?:        number;
  y?:        number;
}

interface TopoEdge {
  src:      string;
  dst:      string;
  bytes:    number;
  packets:  number;
  decision: 'allow' | 'block' | 'throttle';
  risk:     number;
}

// ────────────────────────────────────────────────────────────────────────────
// Constants
// ────────────────────────────────────────────────────────────────────────────

const NODE_ICONS: Record<TopoNode['type'], string> = {
  host:     '💻',
  server:   '🖥️',
  router:   '🌐',
  firewall: '🛡',
  attacker: '☠️',
  unknown:  '❓',
};

const NODE_COLOR: Record<TopoNode['type'], string> = {
  host:     '#3b82f6',
  server:   '#8b5cf6',
  router:   '#06b6d4',
  firewall: '#10b981',
  attacker: '#ef4444',
  unknown:  '#6b7280',
};

const RISK_COLOR = (r: number) =>
  r > 0.8 ? '#ef4444' : r > 0.5 ? '#f97316' : r > 0.2 ? '#eab308' : '#10b981';

const EDGE_COLOR: Record<string, string> = {
  allow:    '#4b5563',
  block:    '#ef4444',
  throttle: '#f59e0b',
};

// ────────────────────────────────────────────────────────────────────────────
// Mock topology
// ────────────────────────────────────────────────────────────────────────────

function mockTopology() {
  const W = 700, H = 400;
  const cx = W / 2, cy = H / 2;

  const nodes: TopoNode[] = [
    { id: 'fw',      label: 'Thor FW',    type: 'firewall', ip: '10.0.0.1',   risk: 0.0, active: true,  x: cx,      y: cy      },
    { id: 'r1',      label: 'Core Router',type: 'router',   ip: '10.0.0.2',   risk: 0.1, active: true,  x: cx-180,  y: cy      },
    { id: 'web1',    label: 'Web Server', type: 'server',   ip: '10.0.1.10',  risk: 0.3, active: true,  x: cx+180,  y: cy-80   },
    { id: 'db1',     label: 'DB Primary', type: 'server',   ip: '10.0.2.10',  risk: 0.15,active: true,  x: cx+180,  y: cy+80   },
    { id: 'h1',      label: 'Host-01',    type: 'host',     ip: '10.0.10.50', risk: 0.5, active: true,  x: cx-80,   y: cy-120  },
    { id: 'h2',      label: 'Host-02',    type: 'host',     ip: '10.0.10.51', risk: 0.1, active: true,  x: cx+80,   y: cy-120  },
    { id: 'h3',      label: 'Host-03',    type: 'host',     ip: '10.0.10.52', risk: 0.85,active: true,  x: cx-80,   y: cy+120  },
    { id: 'atk1',    label: 'Attacker',   type: 'attacker', ip: '185.2.3.44', risk: 0.99,active: true,  x: cx-300,  y: cy-80   },
    { id: 'atk2',    label: 'Scanner',    type: 'attacker', ip: '45.33.32.100',risk:0.72,active: true,  x: cx-300,  y: cy+80   },
  ];

  const edges: TopoEdge[] = [
    { src: 'atk1', dst: 'fw',   bytes: 500000,  packets: 5000,  decision: 'block',    risk: 0.95 },
    { src: 'atk2', dst: 'fw',   bytes: 12000,   packets: 300,   decision: 'throttle', risk: 0.72 },
    { src: 'fw',   dst: 'web1', bytes: 1200000, packets: 8000,  decision: 'allow',    risk: 0.1  },
    { src: 'fw',   dst: 'r1',   bytes: 4000000, packets: 20000, decision: 'allow',    risk: 0.05 },
    { src: 'r1',   dst: 'h1',   bytes: 300000,  packets: 2000,  decision: 'allow',    risk: 0.4  },
    { src: 'r1',   dst: 'h2',   bytes: 150000,  packets: 900,   decision: 'allow',    risk: 0.08 },
    { src: 'r1',   dst: 'h3',   bytes: 80000,   packets: 1200,  decision: 'throttle', risk: 0.80 },
    { src: 'web1', dst: 'db1',  bytes: 600000,  packets: 3500,  decision: 'allow',    risk: 0.12 },
  ];

  return { nodes, edges };
}

// ────────────────────────────────────────────────────────────────────────────
// Main
// ────────────────────────────────────────────────────────────────────────────

const W = 700, H = 400;

export default function NetworkTopology() {
  const [{ nodes, edges }, setTopo] = useState(mockTopology);
  const [selected, setSelected]     = useState<TopoNode | null>(null);
  const [zoom, setZoom]             = useState(1);
  const [dragging, setDragging]     = useState<string | null>(null);
  const svgRef                      = useRef<SVGSVGElement>(null);
  const offsetRef                   = useRef({ x: 0, y: 0 });

  const fmt = (b: number) => b > 1e6 ? `${(b/1e6).toFixed(1)}MB` : b > 1e3 ? `${(b/1e3).toFixed(0)}KB` : `${b}B`;

  const onNodeMouseDown = useCallback((e: React.MouseEvent, nodeId: string) => {
    e.preventDefault();
    setDragging(nodeId);
    setSelected(nodes.find(n => n.id === nodeId) || null);
    const svgRect = svgRef.current?.getBoundingClientRect();
    if (svgRect) {
      const node = nodes.find(n => n.id === nodeId)!;
      offsetRef.current = {
        x: e.clientX - (node.x! / W * svgRect.width),
        y: e.clientY - (node.y! / H * svgRect.height),
      };
    }
  }, [nodes]);

  const onMouseMove = useCallback((e: React.MouseEvent) => {
    if (!dragging || !svgRef.current) return;
    const rect = svgRef.current.getBoundingClientRect();
    const nx   = ((e.clientX - offsetRef.current.x) / rect.width) * W;
    const ny   = ((e.clientY - offsetRef.current.y) / rect.height) * H;
    setTopo(prev => ({
      ...prev,
      nodes: prev.nodes.map(n => n.id === dragging ? { ...n, x: Math.max(20, Math.min(W-20, nx)), y: Math.max(20, Math.min(H-20, ny)) } : n),
    }));
  }, [dragging]);

  const onMouseUp = useCallback(() => setDragging(null), []);

  const nodeMap = new Map(nodes.map(n => [n.id, n]));

  return (
    <div className="bg-gray-900 border border-gray-700 rounded-2xl overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-5 py-4 border-b border-gray-700">
        <div className="flex items-center gap-3">
          <Network className="w-5 h-5 text-cyan-400" />
          <h2 className="font-bold text-white">Network Topology</h2>
          <span className="text-xs text-gray-500">{nodes.length} nodes · {edges.length} flows</span>
        </div>
        <div className="flex gap-2">
          <button onClick={() => setZoom(z => Math.min(z+0.2, 2))} className="p-1.5 bg-gray-700 hover:bg-gray-600 rounded-lg text-gray-300">
            <ZoomIn className="w-3.5 h-3.5" />
          </button>
          <button onClick={() => setZoom(z => Math.max(z-0.2, 0.5))} className="p-1.5 bg-gray-700 hover:bg-gray-600 rounded-lg text-gray-300">
            <ZoomOut className="w-3.5 h-3.5" />
          </button>
          <button onClick={() => setTopo(mockTopology())} className="p-1.5 bg-gray-700 hover:bg-gray-600 rounded-lg text-gray-300">
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      <div className="flex">
        {/* SVG Canvas */}
        <div className="flex-1 bg-gray-950 overflow-hidden">
          <svg
            ref={svgRef}
            viewBox={`0 0 ${W} ${H}`}
            width="100%" height="auto"
            style={{ transform: `scale(${zoom})`, transformOrigin: '50% 50%', transition: dragging ? 'none' : 'transform 0.3s', cursor: dragging ? 'grabbing' : 'default' }}
            onMouseMove={onMouseMove}
            onMouseUp={onMouseUp}
            onMouseLeave={onMouseUp}
          >
            <defs>
              <marker id="arrow-allow"    markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
                <path d="M 0 0 L 6 3 L 0 6 Z" fill={EDGE_COLOR.allow} opacity="0.6" />
              </marker>
              <marker id="arrow-block"    markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
                <path d="M 0 0 L 6 3 L 0 6 Z" fill={EDGE_COLOR.block} />
              </marker>
              <marker id="arrow-throttle" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
                <path d="M 0 0 L 6 3 L 0 6 Z" fill={EDGE_COLOR.throttle} />
              </marker>
            </defs>

            {/* Edges */}
            {edges.map((e, i) => {
              const src = nodeMap.get(e.src), dst = nodeMap.get(e.dst);
              if (!src?.x || !dst?.x) return null;
              const thick = Math.max(1, Math.log(e.bytes / 10000 + 1));
              return (
                <g key={i}>
                  <line
                    x1={src.x} y1={src.y} x2={dst.x} y2={dst.y}
                    stroke={EDGE_COLOR[e.decision]}
                    strokeWidth={thick}
                    opacity={e.decision === 'block' ? 0.9 : 0.4}
                    strokeDasharray={e.decision === 'block' ? '6 3' : undefined}
                    markerEnd={`url(#arrow-${e.decision})`}
                  />
                  {/* Bandwidth label on hover */}
                  <text
                    x={(src.x + dst.x) / 2} y={(src.y! + dst.y!) / 2 - 6}
                    fill="#6b7280" fontSize="9" textAnchor="middle" fontFamily="monospace"
                  >
                    {fmt(e.bytes)}
                  </text>
                </g>
              );
            })}

            {/* Nodes */}
            {nodes.map(node => (
              <g key={node.id} style={{ cursor: 'grab' }}
                onMouseDown={e => onNodeMouseDown(e, node.id)}>
                {/* Risk aura */}
                {node.risk > 0.3 && (
                  <circle cx={node.x} cy={node.y} r={26}
                    fill={RISK_COLOR(node.risk)} opacity={node.risk * 0.15} />
                )}
                {/* Node circle */}
                <circle
                  cx={node.x} cy={node.y} r={18}
                  fill={NODE_COLOR[node.type]}
                  opacity={selected?.id === node.id ? 1 : 0.85}
                  stroke={selected?.id === node.id ? 'white' : 'transparent'}
                  strokeWidth={2}
                />
                {/* Risk ring */}
                <circle
                  cx={node.x} cy={node.y} r={20}
                  fill="none"
                  stroke={RISK_COLOR(node.risk)}
                  strokeWidth={node.risk > 0.5 ? 2 : 1}
                  opacity={node.risk > 0.2 ? 0.9 : 0.2}
                />
                {/* Icon */}
                <text x={node.x} y={node.y! + 5} textAnchor="middle" fontSize="14">
                  {NODE_ICONS[node.type]}
                </text>
                {/* Label */}
                <text x={node.x} y={node.y! + 32} textAnchor="middle"
                  fill="white" fontSize="9" fontFamily="monospace">
                  {node.label}
                </text>
                <text x={node.x} y={node.y! + 42} textAnchor="middle"
                  fill="#6b7280" fontSize="8" fontFamily="monospace">
                  {node.ip}
                </text>
              </g>
            ))}
          </svg>
        </div>

        {/* Side panel */}
        {selected && (
          <div className="w-48 bg-gray-800 border-l border-gray-700 p-4 text-sm">
            <div className="font-bold text-white mb-3 flex items-center gap-2">
              {NODE_ICONS[selected.type]} {selected.label}
            </div>
            <div className="space-y-2 text-xs">
              {[
                ['IP', selected.ip],
                ['Type', selected.type],
                ['Risk', `${(selected.risk*100).toFixed(0)}%`],
                ['Status', selected.active ? '🟢 Active' : '🔴 Down'],
              ].map(([k, v]) => (
                <div key={k}>
                  <div className="text-gray-500">{k}</div>
                  <div className="text-white font-mono">{v}</div>
                </div>
              ))}
            </div>
            <div className="mt-4 space-y-2">
              <button className="w-full bg-red-700 hover:bg-red-600 text-white rounded-lg py-1.5 text-xs font-bold">
                🚫 Block
              </button>
              <button className="w-full bg-gray-700 hover:bg-gray-600 text-white rounded-lg py-1.5 text-xs">
                📋 Details
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Legend */}
      <div className="px-5 py-3 border-t border-gray-700 flex items-center gap-6 text-xs text-gray-400">
        {Object.entries(EDGE_COLOR).map(([k, c]) => (
          <span key={k} className="flex items-center gap-1.5">
            <span className="w-6 h-0.5 inline-block" style={{ background: c }} />
            {k}
          </span>
        ))}
        <span className="ml-auto opacity-50">Drag nodes to rearrange</span>
      </div>
    </div>
  );
}
