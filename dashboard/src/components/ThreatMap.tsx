import React, { useEffect, useRef, useState, useMemo } from 'react';
import { Globe, ZoomIn, ZoomOut, RefreshCw } from 'lucide-react';

// ────────────────────────────────────────────────────────────────────────────
// GeoPoint type
// ────────────────────────────────────────────────────────────────────────────

interface GeoThreat {
  id:          string;
  src_lat:     number;
  src_lon:     number;
  dst_lat:     number;
  dst_lon:     number;
  src_country: string;
  src_ip:      string;
  threat_type: string;
  severity:    'low' | 'medium' | 'high' | 'critical';
  risk_score:  number;
  timestamp:   number;
}

// ────────────────────────────────────────────────────────────────────────────
// Convert lat/lon → SVG coords (equirectangular projection)
// ────────────────────────────────────────────────────────────────────────────

const W = 960, H = 480;
const toX = (lon: number) => ((lon + 180) / 360) * W;
const toY = (lat: number) => ((90  - lat)  / 180) * H;

const SEVERITY_COLOR: Record<string, string> = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#3b82f6',
};

// Mock geo threats for demonstration (replaced by real WebSocket data)
function mockThreats(): GeoThreat[] {
  const sources = [
    { lat: 39.9, lon: 116.4, country: 'CN' },
    { lat: 55.7, lon: 37.6,  country: 'RU' },
    { lat:  4.2, lon:  9.2,  country: 'NG' },
    { lat: 28.6, lon: 77.2,  country: 'IN' },
    { lat: 37.5, lon: 126.9, country: 'KR' },
    { lat: 48.8, lon:  2.3,  country: 'FR' },
    { lat: 52.5, lon: 13.4,  country: 'DE' },
    { lat: 35.7, lon: 139.7, country: 'JP' },
    { lat: -23.5, lon: -46.6, country: 'BR' },
    { lat: 19.4, lon: -99.1, country: 'MX' },
  ];
  const dst = { lat: 37.3, lon: -121.9 };   // Silicon Valley DC
  const types = ['syn-flood','port-scan','brute-force','c2-comm','dns-tunnel','data-exfil'];
  const severities: Array<'low'|'medium'|'high'|'critical'> = ['low','medium','high','critical'];

  return Array.from({ length: 40 }, (_, i) => {
    const src = sources[i % sources.length];
    const jitterLat = (Math.random() - 0.5) * 10;
    const jitterLon = (Math.random() - 0.5) * 10;
    return {
      id:          String(i),
      src_lat:     src.lat + jitterLat,
      src_lon:     src.lon + jitterLon,
      dst_lat:     dst.lat + (Math.random() - 0.5) * 2,
      dst_lon:     dst.dst_lon ?? dst.lon + (Math.random() - 0.5) * 2,
      src_country: src.country,
      src_ip:      `${10 + Math.floor(Math.random()*240)}.${Math.floor(Math.random()*256)}.${Math.floor(Math.random()*256)}.${Math.floor(Math.random()*256)}`,
      threat_type: types[i % types.length],
      severity:    severities[Math.floor(Math.random() * 4)],
      risk_score:  Math.random(),
      timestamp:   Date.now() / 1000 - Math.random() * 3600,
    };
  });
}

// ────────────────────────────────────────────────────────────────────────────
// Animated arc
// ────────────────────────────────────────────────────────────────────────────

function Arc({
  x1, y1, x2, y2,
  color,
  delay = 0,
  animate = true,
}: {
  x1: number; y1: number; x2: number; y2: number;
  color: string; delay?: number; animate?: boolean;
}) {
  const mx = (x1 + x2) / 2;
  const my = (y1 + y2) / 2 - Math.abs(x2 - x1) * 0.25;
  const d  = `M ${x1} ${y1} Q ${mx} ${my} ${x2} ${y2}`;

  return (
    <g>
      {/* Glow base */}
      <path d={d} fill="none" stroke={color} strokeWidth="1.5" opacity="0.2" />
      {/* Animated dash */}
      {animate && (
        <path d={d} fill="none" stroke={color} strokeWidth="1.5" opacity="0.8"
          strokeDasharray="6 20"
          style={{ animation: `dash-flow 3s linear ${delay}s infinite` }}
        />
      )}
      {/* Static */}
      {!animate && (
        <path d={d} fill="none" stroke={color} strokeWidth="1" opacity="0.5" />
      )}
    </g>
  );
}

// ────────────────────────────────────────────────────────────────────────────
// Main Component
// ────────────────────────────────────────────────────────────────────────────

export default function ThreatMap({ threats: externalThreats }: { threats?: GeoThreat[] }) {
  const [threats, setThreats]   = useState<GeoThreat[]>(mockThreats());
  const [selected, setSelected] = useState<GeoThreat | null>(null);
  const [filter, setFilter]     = useState<string>('all');
  const [zoom, setZoom]         = useState(1);
  const [live, setLive]         = useState(true);
  const intervalRef             = useRef<ReturnType<typeof setInterval>>();

  // Refresh mock data every 5s to simulate live feed
  useEffect(() => {
    if (!live) return;
    intervalRef.current = setInterval(() => {
      setThreats(mockThreats());
    }, 5000);
    return () => clearInterval(intervalRef.current);
  }, [live]);

  useEffect(() => {
    if (externalThreats?.length) setThreats(externalThreats);
  }, [externalThreats]);

  const filtered = useMemo(() =>
    filter === 'all' ? threats : threats.filter(t => t.severity === filter),
  [threats, filter]);

  const stats = useMemo(() => ({
    critical: threats.filter(t => t.severity === 'critical').length,
    high:     threats.filter(t => t.severity === 'high').length,
    total:    threats.length,
  }), [threats]);

  // Target (defended) point — DC/HQ
  const TX = toX(-121.9), TY = toY(37.3);

  return (
    <div className="bg-gray-900 border border-gray-700 rounded-2xl overflow-hidden">
      <style>{`
        @keyframes dash-flow {
          from { stroke-dashoffset: 100; }
          to   { stroke-dashoffset: -100; }
        }
        @keyframes pulse-ring {
          0%   { r: 4; opacity: 0.8; }
          100% { r: 14; opacity: 0; }
        }
      `}</style>

      {/* Header */}
      <div className="flex items-center justify-between px-5 py-4 border-b border-gray-700">
        <div className="flex items-center gap-3">
          <Globe className="w-5 h-5 text-cyan-400" />
          <h2 className="font-bold text-white">Global Threat Map</h2>
          {live && <span className="flex items-center gap-1.5 text-xs text-green-400">
            <span className="w-2 h-2 bg-green-400 rounded-full animate-pulse" />LIVE
          </span>}
        </div>
        <div className="flex items-center gap-3">
          <div className="flex gap-1.5 text-xs">
            <span className="bg-red-900/50 text-red-300 px-2 py-0.5 rounded-full border border-red-700">
              {stats.critical} Critical
            </span>
            <span className="bg-orange-900/50 text-orange-300 px-2 py-0.5 rounded-full border border-orange-700">
              {stats.high} High
            </span>
            <span className="bg-gray-700 text-gray-300 px-2 py-0.5 rounded-full">
              {stats.total} Total
            </span>
          </div>
          {/* Severity filter */}
          <select value={filter} onChange={e => setFilter(e.target.value)}
            className="bg-gray-800 border border-gray-700 text-white text-xs rounded-lg px-2 py-1">
            <option value="all">All</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <div className="flex gap-1">
            <button onClick={() => setZoom(z => Math.min(z + 0.2, 2.5))}
              className="p-1.5 bg-gray-700 hover:bg-gray-600 rounded-lg text-gray-300">
              <ZoomIn className="w-3.5 h-3.5" />
            </button>
            <button onClick={() => setZoom(z => Math.max(z - 0.2, 0.6))}
              className="p-1.5 bg-gray-700 hover:bg-gray-600 rounded-lg text-gray-300">
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
            <button onClick={() => setThreats(mockThreats())}
              className="p-1.5 bg-gray-700 hover:bg-gray-600 rounded-lg text-gray-300">
              <RefreshCw className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Map SVG */}
      <div className="relative overflow-hidden bg-gray-950">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          width="100%" height="auto"
          style={{ transform: `scale(${zoom})`, transformOrigin: 'center', transition: 'transform 0.3s' }}
        >
          {/* World map background — simplified outlines */}
          <rect width={W} height={H} fill="#030712" />
          {/* Grid lines */}
          {[-60,-30,0,30,60].map(lat => (
            <line key={lat} x1={0} y1={toY(lat)} x2={W} y2={toY(lat)}
              stroke="#1f2937" strokeWidth="0.5" />
          ))}
          {[-150,-120,-90,-60,-30,0,30,60,90,120,150].map(lon => (
            <line key={lon} x1={toX(lon)} y1={0} x2={toX(lon)} y2={H}
              stroke="#1f2937" strokeWidth="0.5" />
          ))}

          {/* Equator & prime meridian (highlighted) */}
          <line x1={0} y1={toY(0)} x2={W} y2={toY(0)} stroke="#374151" strokeWidth="1" />
          <line x1={toX(0)} y1={0} x2={toX(0)} y2={H} stroke="#374151" strokeWidth="1" />

          {/* Attack arcs */}
          {filtered.map((t, i) => (
            <Arc
              key={t.id}
              x1={toX(t.src_lon)} y1={toY(t.src_lat)}
              x2={TX} y2={TY}
              color={SEVERITY_COLOR[t.severity]}
              delay={i * 0.3}
              animate={t.severity === 'critical' || t.severity === 'high'}
            />
          ))}

          {/* Source dots */}
          {filtered.map(t => (
            <g key={`dot-${t.id}`} onClick={() => setSelected(t)} style={{ cursor: 'pointer' }}>
              {/* Pulse ring for high severity */}
              {(t.severity === 'critical' || t.severity === 'high') && (
                <circle
                  cx={toX(t.src_lon)} cy={toY(t.src_lat)} r={4}
                  fill="none" stroke={SEVERITY_COLOR[t.severity]} strokeWidth="1"
                  style={{ animation: `pulse-ring 2s ease-out infinite` }}
                />
              )}
              <circle
                cx={toX(t.src_lon)} cy={toY(t.src_lat)} r={3}
                fill={SEVERITY_COLOR[t.severity]}
                opacity={selected?.id === t.id ? 1 : 0.75}
              />
            </g>
          ))}

          {/* Target (defended asset) */}
          <g>
            <circle cx={TX} cy={TY} r={8} fill="#06b6d4" opacity="0.2" />
            <circle cx={TX} cy={TY} r={5} fill="#06b6d4" opacity="0.5" />
            <circle cx={TX} cy={TY} r={3} fill="#06b6d4" />
            <text x={TX + 10} y={TY - 6} fill="#06b6d4" fontSize="9" fontFamily="monospace">
              🛡 HQ
            </text>
          </g>
        </svg>

        {/* Tooltip */}
        {selected && (
          <div className="absolute bottom-4 left-4 bg-gray-900/95 border border-gray-600 rounded-xl p-4 max-w-xs shadow-2xl">
            <div className="flex items-center justify-between mb-2">
              <span className={`text-xs px-2 py-0.5 rounded-full font-bold text-white bg-${selected.severity === 'critical' ? 'red' : selected.severity === 'high' ? 'orange' : selected.severity === 'medium' ? 'yellow' : 'blue'}-600`}>
                {selected.severity.toUpperCase()}
              </span>
              <button onClick={() => setSelected(null)} className="text-gray-500 hover:text-white text-lg">✕</button>
            </div>
            <div className="space-y-1 text-xs text-gray-300">
              <div><span className="text-gray-500">IP:</span> <span className="font-mono">{selected.src_ip}</span></div>
              <div><span className="text-gray-500">Country:</span> {selected.src_country}</div>
              <div><span className="text-gray-500">Threat:</span> {selected.threat_type.replace(/-/g, ' ')}</div>
              <div><span className="text-gray-500">Risk:</span> {(selected.risk_score * 100).toFixed(0)}%</div>
            </div>
            <button className="mt-3 w-full bg-red-600 hover:bg-red-700 text-white rounded-lg py-1.5 text-xs font-bold transition-colors">
              🚫 Block This IP
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
