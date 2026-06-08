import React, { useState, useMemo } from 'react';
import { ShieldAlert, TrendingUp, AlertTriangle, Globe, Zap, Clock, ExternalLink } from 'lucide-react';
import { useThreats } from '../hooks/useApi';
import type { ThreatEvent } from '../types';

// ────────────────────────────────────────────────────────────────────────────
const SEVERITY_CONFIG = {
  critical: { bg: 'bg-red-900/40', border: 'border-red-600', text: 'text-red-300', badge: 'bg-red-600', dot: 'bg-red-500', glow: 'shadow-red-900' },
  high:     { bg: 'bg-orange-900/40', border: 'border-orange-600', text: 'text-orange-300', badge: 'bg-orange-600', dot: 'bg-orange-500', glow: 'shadow-orange-900' },
  medium:   { bg: 'bg-yellow-900/40', border: 'border-yellow-600', text: 'text-yellow-300', badge: 'bg-yellow-600', dot: 'bg-yellow-500', glow: 'shadow-yellow-900' },
  low:      { bg: 'bg-blue-900/40', border: 'border-blue-600', text: 'text-blue-300', badge: 'bg-blue-600', dot: 'bg-blue-400', glow: '' },
};

const THREAT_ICON: Record<string, string> = {
  'syn-flood': '🌊', 'port-scan': '🔍', 'brute-force': '🔨',
  'dns-tunnel': '🌀', 'data-exfil': '📤', 'c2-comm': '📡',
  'zero-day': '💀', 'malware': '🦠', 'ransomware': '🔒',
};

const rel = (ts: number) => {
  const diff = Math.floor(Date.now() / 1000 - ts);
  if (diff < 60)   return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff/60)}m ago`;
  return `${Math.floor(diff/3600)}h ago`;
};

// ────────────────────────────────────────────────────────────────────────────
// Threat Card
// ────────────────────────────────────────────────────────────────────────────

function ThreatCard({ threat, onClick }: { threat: ThreatEvent; onClick: () => void }) {
  const cfg = SEVERITY_CONFIG[threat.severity as keyof typeof SEVERITY_CONFIG] ?? SEVERITY_CONFIG.low;
  return (
    <div
      onClick={onClick}
      className={`${cfg.bg} border ${cfg.border} rounded-xl p-4 cursor-pointer hover:scale-[1.01] transition-all duration-200 shadow-lg ${cfg.glow}`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-3">
          <span className="text-2xl">{THREAT_ICON[threat.threat_type] ?? '⚠️'}</span>
          <div>
            <div className={`font-bold ${cfg.text} capitalize`}>{threat.threat_type.replace(/-/g, ' ')}</div>
            <div className="text-xs text-gray-400 font-mono mt-0.5">{threat.src_ip} → {threat.dst_ip}</div>
          </div>
        </div>
        <div className="flex flex-col items-end gap-1 shrink-0">
          <span className={`text-xs px-2 py-0.5 rounded-full font-bold text-white uppercase ${cfg.badge}`}>
            {threat.severity}
          </span>
          <span className="text-xs text-gray-500">{rel(threat.timestamp)}</span>
        </div>
      </div>

      <div className="mt-3 flex items-center gap-4 text-xs text-gray-400">
        <span className="font-mono">Port {threat.dst_port}</span>
        <span>Risk: <span className={`font-bold ${cfg.text}`}>{(threat.risk_score * 100).toFixed(0)}%</span></span>
        <span>{threat.blocked ? '🚫 Blocked' : '⚠️ Detected'}</span>
        {threat.mitre && (
          <span className="font-mono bg-gray-800 px-1.5 py-0.5 rounded text-gray-300">{threat.mitre}</span>
        )}
      </div>
    </div>
  );
}

// ────────────────────────────────────────────────────────────────────────────
// Detail Modal
// ────────────────────────────────────────────────────────────────────────────

function ThreatDetail({ threat, onClose }: { threat: ThreatEvent; onClose: () => void }) {
  const cfg = SEVERITY_CONFIG[threat.severity as keyof typeof SEVERITY_CONFIG] ?? SEVERITY_CONFIG.low;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm" onClick={onClose}>
      <div className="bg-gray-900 border border-gray-700 rounded-2xl p-6 max-w-2xl w-full mx-4 shadow-2xl" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <span className="text-3xl">{THREAT_ICON[threat.threat_type] ?? '⚠️'}</span>
            <div>
              <h2 className={`text-xl font-bold ${cfg.text} capitalize`}>{threat.threat_type.replace(/-/g,' ')}</h2>
              <span className={`text-xs px-2 py-0.5 rounded-full font-bold text-white ${cfg.badge}`}>{threat.severity.toUpperCase()}</span>
            </div>
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-white text-2xl">✕</button>
        </div>

        <div className="grid grid-cols-2 gap-3 mb-4">
          {[
            ['Source IP', threat.src_ip], ['Destination IP', threat.dst_ip],
            ['Source Port', String(threat.src_port ?? '—')], ['Destination Port', String(threat.dst_port)],
            ['Risk Score', `${(threat.risk_score*100).toFixed(1)}%`], ['Confidence', `${(threat.confidence*100).toFixed(1)}%`],
            ['MITRE Technique', threat.mitre ?? 'N/A'], ['Status', threat.blocked ? '🚫 Blocked' : '⚠️ Active'],
            ['Detected', new Date(threat.timestamp * 1000).toLocaleString()], ['Agent', threat.agent_id ?? 'thor-agent-01'],
          ].map(([l, v]) => (
            <div key={l} className="bg-gray-800 rounded-lg p-3">
              <div className="text-xs text-gray-400 mb-1">{l}</div>
              <div className="text-white font-mono text-sm">{v}</div>
            </div>
          ))}
        </div>

        {threat.explanation && (
          <div className="bg-gray-800 rounded-xl p-4 mb-4">
            <div className="flex items-center gap-2 mb-2">
              <Zap className="w-4 h-4 text-cyan-400" />
              <span className="text-sm font-semibold text-cyan-400">AI Analysis</span>
            </div>
            <p className="text-gray-200 text-sm leading-relaxed">{threat.explanation}</p>
          </div>
        )}

        {threat.mitre && (
          <div className="bg-blue-900/30 border border-blue-700 rounded-xl p-4 mb-4">
            <div className="text-xs text-blue-400 mb-1 font-semibold">MITRE ATT&CK</div>
            <a href={`https://attack.mitre.org/techniques/${threat.mitre.replace('.', '/')}`}
              target="_blank" rel="noopener noreferrer"
              className="text-blue-300 hover:text-blue-200 flex items-center gap-1 text-sm">
              {threat.mitre} <ExternalLink className="w-3 h-3" />
            </a>
          </div>
        )}

        <div className="flex gap-3">
          <button className="flex-1 bg-red-600 hover:bg-red-700 text-white rounded-xl py-2.5 font-bold transition-colors">
            🚫 Block Source IP
          </button>
          <button className="flex-1 bg-orange-600 hover:bg-orange-700 text-white rounded-xl py-2.5 font-bold transition-colors">
            ⚡ Throttle
          </button>
          <button className="flex-1 bg-gray-700 hover:bg-gray-600 text-white rounded-xl py-2.5 font-bold transition-colors">
            📋 Report
          </button>
        </div>
      </div>
    </div>
  );
}

// ────────────────────────────────────────────────────────────────────────────
// Main
// ────────────────────────────────────────────────────────────────────────────

export default function ThreatsPage() {
  const { threats, loading } = useThreats();
  const [severity, setSeverity] = useState('all');
  const [type,     setType]     = useState('all');
  const [selected, setSelected] = useState<ThreatEvent | null>(null);

  const filtered = useMemo(() => {
    let out = threats ?? [];
    if (severity !== 'all') out = out.filter(t => t.severity === severity);
    if (type !== 'all')     out = out.filter(t => t.threat_type === type);
    return out.sort((a, b) => b.timestamp - a.timestamp);
  }, [threats, severity, type]);

  const counts = useMemo(() => ({
    critical: (threats ?? []).filter(t => t.severity === 'critical').length,
    high:     (threats ?? []).filter(t => t.severity === 'high').length,
    medium:   (threats ?? []).filter(t => t.severity === 'medium').length,
    blocked:  (threats ?? []).filter(t => t.blocked).length,
  }), [threats]);

  const threatTypes = useMemo(() =>
    [...new Set((threats ?? []).map(t => t.threat_type))].sort(),
  [threats]);

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center gap-3">
        <ShieldAlert className="w-6 h-6 text-red-400" />
        <h1 className="text-2xl font-bold text-white">Threat Intelligence</h1>
        <span className="bg-red-900/50 text-red-300 text-xs px-2 py-1 rounded-full border border-red-700">
          {filtered.length} events
        </span>
      </div>

      {/* Severity cards */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: 'Critical', val: counts.critical, color: 'text-red-400', bg: 'bg-red-900/20 border-red-700' },
          { label: 'High', val: counts.high, color: 'text-orange-400', bg: 'bg-orange-900/20 border-orange-700' },
          { label: 'Medium', val: counts.medium, color: 'text-yellow-400', bg: 'bg-yellow-900/20 border-yellow-700' },
          { label: 'Blocked', val: counts.blocked, color: 'text-green-400', bg: 'bg-green-900/20 border-green-700' },
        ].map(({ label, val, color, bg }) => (
          <div key={label} className={`${bg} border rounded-xl p-4`}>
            <div className={`text-3xl font-black ${color}`}>{val}</div>
            <div className="text-xs text-gray-400 mt-1">{label} events</div>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="flex gap-3 flex-wrap">
        <select value={severity} onChange={e => setSeverity(e.target.value)}
          className="bg-gray-800 border border-gray-700 text-white rounded-lg px-3 py-2 text-sm">
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select value={type} onChange={e => setType(e.target.value)}
          className="bg-gray-800 border border-gray-700 text-white rounded-lg px-3 py-2 text-sm">
          <option value="all">All Types</option>
          {threatTypes.map(t => <option key={t} value={t}>{t}</option>)}
        </select>
      </div>

      {/* Threat grid */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        {loading ? (
          Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="bg-gray-800 border border-gray-700 rounded-xl p-4 animate-pulse h-28" />
          ))
        ) : filtered.length === 0 ? (
          <div className="col-span-2 text-center text-gray-500 py-16">
            <ShieldAlert className="w-12 h-12 mx-auto mb-3 opacity-30" />
            <p>No threats matching your filters</p>
          </div>
        ) : (
          filtered.map((t, i) => (
            <ThreatCard key={`${t.src_ip}-${t.timestamp}-${i}`} threat={t} onClick={() => setSelected(t)} />
          ))
        )}
      </div>

      {selected && <ThreatDetail threat={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
