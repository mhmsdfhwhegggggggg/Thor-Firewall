/**
 * Thor Firewall — Network Topology Visualizer (Cytoscape.js)
 * ============================================================
 * مستوحى من: https://github.com/cytoscape/cytoscape.js
 *            https://github.com/plotly/dash-cytoscape
 *
 * يُظهر خريطة الشبكة الحية مع:
 *  - الأجهزة (hosts) كـ nodes
 *  - التدفقات (flows) كـ edges ملونة بالخطورة
 *  - تحديث فوري عبر WebSocket
 *  - تخطيطات: fcose, dagre, cola, cose-bilkent
 *  - تظليل بالوان MITRE ATT&CK tactics
 */

import React, {
  useCallback, useEffect, useRef, useState, useMemo,
} from 'react';
import CytoscapeComponent from 'react-cytoscapejs';
import cytoscape, {
  Core, ElementDefinition, LayoutOptions,
  NodeSingular, EdgeSingular,
} from 'cytoscape';

// Layout extensions
// @ts-ignore
import cola    from 'cytoscape-cola';
// @ts-ignore
import dagre   from 'cytoscape-dagre';
// @ts-ignore
import fcose   from 'cytoscape-fcose';
// @ts-ignore
import coseBilkent from 'cytoscape-cosebilkent';

// Register layout extensions once
cytoscape.use(cola);
cytoscape.use(dagre);
cytoscape.use(fcose);
cytoscape.use(coseBilkent);

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export interface ThorNode {
  id:           string;
  label:        string;
  ip:           string;
  type:         'host' | 'server' | 'gateway' | 'unknown' | 'threat';
  riskScore:    number;   // [0, 1]
  isAnomalous:  boolean;
  mitreTag?:    string;
  osType?:      'linux' | 'windows' | 'network_device' | 'unknown';
  openPorts?:   number[];
  lastSeen?:    number;
}

export interface ThorEdge {
  id:         string;
  source:     string;
  target:     string;
  protocol:   'tcp' | 'udp' | 'icmp';
  packets:    number;
  bytes:      number;
  riskScore:  number;
  decision:   'allow' | 'block' | 'throttle' | 'mirror';
  pps?:       number;
}

export interface TopologyData {
  nodes: ThorNode[];
  edges: ThorEdge[];
  timestamp: number;
}

type LayoutName = 'fcose' | 'cola' | 'dagre' | 'coseBilkent' | 'circle' | 'grid';

// ─────────────────────────────────────────────────────────────────────────────
// Risk Color Mapping
// ─────────────────────────────────────────────────────────────────────────────

const riskColor = (score: number): string => {
  if (score >= 0.9) return '#ef4444';  // critical — red
  if (score >= 0.7) return '#f97316';  // high — orange
  if (score >= 0.5) return '#eab308';  // medium — yellow
  if (score >= 0.3) return '#22c55e';  // low — green
  return '#3b82f6';                     // info — blue
};

const decisionColor = (decision: string): string => {
  switch (decision) {
    case 'block':    return '#ef4444';
    case 'throttle': return '#f97316';
    case 'mirror':   return '#a855f7';
    default:         return '#22c55e';
  }
};

const nodeIcon = (type: string, os?: string): string => {
  if (type === 'gateway') return '🔰';
  if (type === 'threat')  return '⚠️';
  if (type === 'server')  return '🖥️';
  if (os === 'windows')   return '💻';
  if (os === 'linux')     return '🐧';
  return '📦';
};

// ─────────────────────────────────────────────────────────────────────────────
// Cytoscape Stylesheet
// ─────────────────────────────────────────────────────────────────────────────

const buildStylesheet = () => [
  // Default node
  {
    selector: 'node',
    style: {
      'background-color': (ele: NodeSingular) =>
        riskColor((ele.data('riskScore') as number) || 0),
      'border-color': (ele: NodeSingular) =>
        (ele.data('isAnomalous') as boolean) ? '#ef4444' : '#1e293b',
      'border-width': (ele: NodeSingular) =>
        (ele.data('isAnomalous') as boolean) ? 3 : 1,
      'label': 'data(label)',
      'font-size': 11,
      'font-family': 'JetBrains Mono, monospace',
      'color': '#f8fafc',
      'text-valign': 'bottom',
      'text-halign': 'center',
      'text-margin-y': 4,
      'width': 36,
      'height': 36,
      'shape': (ele: NodeSingular) => {
        const t = ele.data('type') as string;
        if (t === 'gateway') return 'diamond';
        if (t === 'server')  return 'rectangle';
        if (t === 'threat')  return 'star';
        return 'ellipse';
      },
      'text-background-color': '#0f172a',
      'text-background-opacity': 0.7,
      'text-background-padding': '2px',
    } as any,
  },
  // Selected node
  {
    selector: 'node:selected',
    style: {
      'border-width': 4,
      'border-color': '#60a5fa',
      'shadow-blur': 12,
      'shadow-color': '#60a5fa',
      'shadow-opacity': 0.8,
    } as any,
  },
  // Anomalous node pulsing
  {
    selector: 'node[?isAnomalous]',
    style: {
      'border-color': '#ef4444',
      'border-width': 4,
      'border-style': 'dashed',
    } as any,
  },
  // Default edge
  {
    selector: 'edge',
    style: {
      'curve-style': 'bezier',
      'target-arrow-shape': 'triangle',
      'arrow-scale': 0.7,
      'line-color': (ele: EdgeSingular) =>
        decisionColor((ele.data('decision') as string) || 'allow'),
      'target-arrow-color': (ele: EdgeSingular) =>
        decisionColor((ele.data('decision') as string) || 'allow'),
      'width': (ele: EdgeSingular) => {
        const pps = (ele.data('pps') as number) || 1;
        return Math.min(8, Math.max(1, Math.log10(pps + 1)));
      },
      'opacity': 0.75,
      'label': (ele: EdgeSingular) => {
        const pps = ele.data('pps') as number;
        return pps > 0 ? `${pps.toFixed(0)} pps` : '';
      },
      'font-size': 9,
      'color': '#94a3b8',
      'text-background-color': '#0f172a',
      'text-background-opacity': 0.6,
      'text-background-padding': '1px',
    } as any,
  },
  // Blocked edges
  {
    selector: 'edge[decision="block"]',
    style: {
      'line-style': 'dashed',
      'line-dash-pattern': [6, 3],
    } as any,
  },
  // Selected edge
  {
    selector: 'edge:selected',
    style: {
      'width': 4,
      'line-color': '#60a5fa',
      'target-arrow-color': '#60a5fa',
    } as any,
  },
];

// ─────────────────────────────────────────────────────────────────────────────
// Layout Configurations
// ─────────────────────────────────────────────────────────────────────────────

const layoutConfigs: Record<LayoutName, LayoutOptions> = {
  fcose: {
    name: 'fcose',
    animate: true,
    animationDuration: 800,
    quality: 'default',
    nodeSeparation: 100,
    idealEdgeLength: 120,
    edgeElasticity: 0.45,
    nestingFactor: 0.1,
    gravity: 0.25,
    numIter: 2500,
    tile: true,
    tilingPaddingVertical: 10,
    tilingPaddingHorizontal: 10,
  } as any,
  cola: {
    name: 'cola',
    animate: true,
    maxSimulationTime: 2000,
    nodeSpacing: 80,
    edgeLength: 150,
    avoidOverlap: true,
    convergenceThreshold: 0.001,
  } as any,
  dagre: {
    name: 'dagre',
    rankDir: 'TB',
    nodeSep: 60,
    rankSep: 100,
    edgeSep: 20,
    animate: true,
  } as any,
  coseBilkent: {
    name: 'cose-bilkent',
    animate: true,
    animationDuration: 1000,
    idealEdgeLength: 100,
    nodeRepulsion: 4500,
    gravity: 0.25,
    gravityRange: 3.8,
    tilingPaddingVertical: 10,
    tilingPaddingHorizontal: 10,
  } as any,
  circle: { name: 'circle', animate: true } as any,
  grid:   { name: 'grid',   animate: true } as any,
};

// ─────────────────────────────────────────────────────────────────────────────
// Convert ThorNodes/Edges → Cytoscape Elements
// ─────────────────────────────────────────────────────────────────────────────

const toElements = (data: TopologyData): ElementDefinition[] => {
  const nodes: ElementDefinition[] = data.nodes.map(n => ({
    data: {
      id:          n.id,
      label:       `${nodeIcon(n.type, n.osType)} ${n.label}\n${n.ip}`,
      ip:          n.ip,
      type:        n.type,
      riskScore:   n.riskScore,
      isAnomalous: n.isAnomalous,
      mitreTag:    n.mitreTag,
      osType:      n.osType,
    },
  }));

  const edges: ElementDefinition[] = data.edges.map(e => ({
    data: {
      id:        e.id,
      source:    e.source,
      target:    e.target,
      protocol:  e.protocol,
      packets:   e.packets,
      bytes:     e.bytes,
      riskScore: e.riskScore,
      decision:  e.decision,
      pps:       e.pps,
    },
  }));

  return [...nodes, ...edges];
};

// ─────────────────────────────────────────────────────────────────────────────
// Main Component
// ─────────────────────────────────────────────────────────────────────────────

interface CytoscapeGraphProps {
  data:           TopologyData;
  height?:        number | string;
  onNodeClick?:   (node: ThorNode) => void;
  onEdgeClick?:   (edge: ThorEdge) => void;
  apiUrl?:        string;
  autoRefresh?:   boolean;
  refreshMs?:     number;
}

export const CytoscapeGraph: React.FC<CytoscapeGraphProps> = ({
  data,
  height = 600,
  onNodeClick,
  onEdgeClick,
  apiUrl,
  autoRefresh = false,
  refreshMs   = 5000,
}) => {
  const cyRef = useRef<Core | null>(null);
  const [layout,  setLayout]  = useState<LayoutName>('fcose');
  const [tooltip, setTooltip] = useState<{ content: string; x: number; y: number } | null>(null);
  const [stats,   setStats]   = useState({ nodes: 0, edges: 0, threats: 0, blocked: 0 });

  const elements = useMemo(() => toElements(data), [data]);

  // Update stats when data changes
  useEffect(() => {
    setStats({
      nodes:   data.nodes.length,
      edges:   data.edges.length,
      threats: data.nodes.filter(n => n.isAnomalous || n.riskScore > 0.7).length,
      blocked: data.edges.filter(e => e.decision === 'block').length,
    });
  }, [data]);

  // Register Cytoscape event handlers
  const onCyInit = useCallback((cy: Core) => {
    cyRef.current = cy;

    // Node click → show details
    cy.on('tap', 'node', (evt) => {
      const d = evt.target.data();
      const node: ThorNode = {
        id: d.id, label: d.label, ip: d.ip, type: d.type,
        riskScore: d.riskScore, isAnomalous: d.isAnomalous,
        mitreTag: d.mitreTag, osType: d.osType,
      };
      onNodeClick?.(node);
    });

    // Edge click → show flow details
    cy.on('tap', 'edge', (evt) => {
      const d = evt.target.data();
      const edge: ThorEdge = {
        id: d.id, source: d.source, target: d.target,
        protocol: d.protocol, packets: d.packets, bytes: d.bytes,
        riskScore: d.riskScore, decision: d.decision, pps: d.pps,
      };
      onEdgeClick?.(edge);
    });

    // Hover tooltip
    cy.on('mouseover', 'node', (evt) => {
      const d   = evt.target.data();
      const pos = evt.renderedPosition;
      setTooltip({
        content: `IP: ${d.ip}\nRisk: ${((d.riskScore || 0) * 100).toFixed(0)}%${d.isAnomalous ? '\n⚠️ ANOMALOUS' : ''}${d.mitreTag ? `\nMITRE: ${d.mitreTag}` : ''}`,
        x: pos.x + 12,
        y: pos.y - 20,
      });
    });

    cy.on('mouseover', 'edge', (evt) => {
      const d   = evt.target.data();
      const pos = evt.renderedPosition;
      setTooltip({
        content: `${d.protocol.toUpperCase()} ${d.decision.toUpperCase()}\nPPS: ${(d.pps || 0).toFixed(0)}\nRisk: ${((d.riskScore || 0) * 100).toFixed(0)}%`,
        x: pos.x + 12,
        y: pos.y - 20,
      });
    });

    cy.on('mouseout', () => setTooltip(null));
    cy.on('pan zoom', () => setTooltip(null));
  }, [onNodeClick, onEdgeClick]);

  // Apply layout
  const applyLayout = useCallback((layoutName: LayoutName) => {
    if (!cyRef.current) return;
    cyRef.current.layout(layoutConfigs[layoutName]).run();
    setLayout(layoutName);
  }, []);

  // Fit graph to viewport
  const fitGraph = useCallback(() => {
    cyRef.current?.fit(undefined, 40);
  }, []);

  // Highlight threat nodes
  const highlightThreats = useCallback(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.nodes().addClass('dimmed');
    cy.nodes('[?isAnomalous]').removeClass('dimmed').addClass('highlighted');
    cy.edges('[decision="block"]').addClass('highlighted');
  }, []);

  const resetHighlight = useCallback(() => {
    cyRef.current?.elements().removeClass('dimmed highlighted');
  }, []);

  return (
    <div className="relative bg-slate-900 rounded-xl border border-slate-700 overflow-hidden" style={{ height }}>
      {/* Controls */}
      <div className="absolute top-3 left-3 z-10 flex flex-wrap gap-2">
        {/* Layout selector */}
        <div className="flex gap-1 bg-slate-800/90 rounded-lg p-1 border border-slate-700">
          {(['fcose', 'cola', 'dagre', 'circle'] as LayoutName[]).map(l => (
            <button
              key={l}
              onClick={() => applyLayout(l)}
              className={`px-2 py-1 text-xs rounded font-mono transition-colors
                ${layout === l
                  ? 'bg-blue-600 text-white'
                  : 'text-slate-400 hover:text-white hover:bg-slate-700'}`}
            >
              {l}
            </button>
          ))}
        </div>

        {/* Action buttons */}
        <div className="flex gap-1 bg-slate-800/90 rounded-lg p-1 border border-slate-700">
          <button onClick={fitGraph} className="px-2 py-1 text-xs text-slate-400 hover:text-white rounded hover:bg-slate-700 transition-colors" title="Fit graph">
            ⊡ Fit
          </button>
          <button onClick={highlightThreats} className="px-2 py-1 text-xs text-red-400 hover:text-red-300 rounded hover:bg-slate-700 transition-colors">
            ⚠️ Threats
          </button>
          <button onClick={resetHighlight} className="px-2 py-1 text-xs text-slate-400 hover:text-white rounded hover:bg-slate-700 transition-colors">
            ↺ Reset
          </button>
        </div>
      </div>

      {/* Stats overlay */}
      <div className="absolute top-3 right-3 z-10 flex gap-2 text-xs font-mono">
        <span className="bg-slate-800/90 text-blue-400 px-2 py-1 rounded border border-slate-700">
          {stats.nodes} hosts
        </span>
        <span className="bg-slate-800/90 text-green-400 px-2 py-1 rounded border border-slate-700">
          {stats.edges} flows
        </span>
        {stats.threats > 0 && (
          <span className="bg-red-900/80 text-red-400 px-2 py-1 rounded border border-red-700 animate-pulse">
            ⚠ {stats.threats} threats
          </span>
        )}
        {stats.blocked > 0 && (
          <span className="bg-orange-900/80 text-orange-400 px-2 py-1 rounded border border-orange-700">
            🚫 {stats.blocked} blocked
          </span>
        )}
      </div>

      {/* Cytoscape Graph */}
      <CytoscapeComponent
        elements={elements}
        stylesheet={buildStylesheet() as any}
        layout={layoutConfigs[layout]}
        cy={onCyInit}
        style={{ width: '100%', height: '100%', background: '#0f172a' }}
        wheelSensitivity={0.3}
        minZoom={0.1}
        maxZoom={5}
        boxSelectionEnabled={true}
        autounselectify={false}
      />

      {/* Tooltip */}
      {tooltip && (
        <div
          className="absolute z-20 bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 whitespace-pre pointer-events-none shadow-xl"
          style={{ left: tooltip.x, top: tooltip.y, maxWidth: 240 }}
        >
          {tooltip.content}
        </div>
      )}

      {/* Legend */}
      <div className="absolute bottom-3 left-3 z-10 flex gap-3 text-xs bg-slate-800/90 rounded-lg px-3 py-2 border border-slate-700">
        {[
          { color: '#3b82f6', label: 'Low' },
          { color: '#22c55e', label: 'Medium' },
          { color: '#eab308', label: 'High' },
          { color: '#ef4444', label: 'Critical' },
        ].map(({ color, label }) => (
          <div key={label} className="flex items-center gap-1">
            <div className="w-3 h-3 rounded-full" style={{ backgroundColor: color }} />
            <span className="text-slate-400">{label}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

// ─────────────────────────────────────────────────────────────────────────────
// Hook: useLiveTopology — WebSocket-powered live updates
// ─────────────────────────────────────────────────────────────────────────────

export function useLiveTopology(apiUrl: string = ''): {
  topology: TopologyData;
  isConnected: boolean;
  error: string | null;
} {
  const [topology, setTopology] = useState<TopologyData>({
    nodes: [], edges: [], timestamp: Date.now(),
  });
  const [isConnected, setIsConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const wsUrl = (apiUrl || window.location.origin)
      .replace('http://', 'ws://')
      .replace('https://', 'wss://') + '/api/ws/topology';

    let ws: WebSocket | null = null;
    let reconnectTimer: ReturnType<typeof setTimeout>;

    const connect = () => {
      ws = new WebSocket(wsUrl);

      ws.onopen = () => {
        setIsConnected(true);
        setError(null);
      };

      ws.onmessage = (evt) => {
        try {
          const msg = JSON.parse(evt.data);
          if (msg.type === 'topology_update') {
            setTopology(msg.data);
          }
        } catch { /* ignore parse errors */ }
      };

      ws.onclose = () => {
        setIsConnected(false);
        reconnectTimer = setTimeout(connect, 3000);
      };

      ws.onerror = () => {
        setError('WebSocket connection failed');
        setIsConnected(false);
      };
    };

    connect();
    return () => {
      clearTimeout(reconnectTimer);
      ws?.close();
    };
  }, [apiUrl]);

  return { topology, isConnected, error };
}

export default CytoscapeGraph;
