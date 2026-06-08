import React, { useState, useCallback, useMemo } from 'react';
import { Activity, Filter, Download, RefreshCw, Shield, ShieldAlert, ChevronUp, ChevronDown, Eye } from 'lucide-react';
import { useFlows } from '../hooks/useApi';
import type { Flow } from '../types';

// ────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────

const PROTOCOL_COLOR: Record<string, string> = {
  TCP: 'text-blue-400',
  UDP: 'text-purple-400',
  ICMP: 'text-yellow-400',
};

const DECISION_STYLE: Record<string, string> = {
  allow:    'bg-green-900/50 text-green-300 border border-green-700',
  block:    'bg-red-900/50 text-red-300 border border-red-700',
  throttle: 'bg-yellow-900/50 text-yellow-300 border border-yellow-700',
  mirror:   'bg-blue-900/50 text-blue-300 border border-blue-700',
};

const fmt = {
  bytes: (b: number) => b > 1e9 ? `${(b/1e9).toFixed(1)}GB` : b > 1e6 ? `${(b/1e6).toFixed(1)}MB` : b > 1e3 ? `${(b/1e3).toFixed(1)}KB` : `${b}B`,
  pct:   (n: number) => `${(n * 100).toFixed(1)}%`,
  time:  (ts: number) => new Date(ts * 1000).toLocaleTimeString(),
  dur:   (ms: number) => ms > 60000 ? `${(ms/60000).toFixed(1)}m` : ms > 1000 ? `${(ms/1000).toFixed(1)}s` : `${ms}ms`,
};

// ────────────────────────────────────────────────────────────────────────────
// Flow Detail Panel
// ────────────────────────────────────────────────────────────────────────────

function FlowDetail({ flow, onClose }: { flow: Flow; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm" onClick={onClose}>
      <div className="bg-gray-900 border border-gray-700 rounded-xl p-6 max-w-2xl w-full mx-4 shadow-2xl" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-xl font-bold text-white">Flow Details</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-white text-2xl">✕</button>
        </div>

        <div className="grid grid-cols-2 gap-4">
          {[
            ['Source IP', flow.src_ip],
            ['Destination IP', flow.dst_ip],
            ['Source Port', String(flow.src_port)],
            ['Destination Port', String(flow.dst_port)],
            ['Protocol', flow.protocol],
            ['Decision', flow.decision.toUpperCase()],
            ['Packets', flow.packets?.toLocaleString() ?? '—'],
            ['Bytes', fmt.bytes(flow.bytes ?? 0)],
            ['Duration', fmt.dur(flow.duration_ms ?? 0)],
            ['Risk Score', fmt.pct(flow.risk_score)],
            ['Confidence', fmt.pct(flow.confidence)],
            ['First Seen', fmt.time(flow.first_seen)],
          ].map(([label, value]) => (
            <div key={label} className="bg-gray-800 rounded-lg p-3">
              <div className="text-xs text-gray-400 mb-1">{label}</div>
              <div className="text-white font-mono text-sm">{value}</div>
            </div>
          ))}
        </div>

        {flow.explanation && (
          <div className="mt-4 bg-gray-800 rounded-lg p-4">
            <div className="text-xs text-gray-400 mb-2">AI Explanation</div>
            <p className="text-gray-200 text-sm leading-relaxed">{flow.explanation}</p>
          </div>
        )}

        <div className="mt-6 flex gap-3">
          <button className="flex-1 bg-red-600 hover:bg-red-700 text-white rounded-lg py-2 font-medium transition-colors">
            🚫 Block IP
          </button>
          <button className="flex-1 bg-green-700 hover:bg-green-800 text-white rounded-lg py-2 font-medium transition-colors">
            ✅ Whitelist
          </button>
          <button className="flex-1 bg-gray-700 hover:bg-gray-600 text-white rounded-lg py-2 font-medium transition-colors">
            📋 Copy
          </button>
        </div>
      </div>
    </div>
  );
}

// ────────────────────────────────────────────────────────────────────────────
// Main Component
// ────────────────────────────────────────────────────────────────────────────

type SortKey = keyof Flow;
type SortDir = 'asc' | 'desc';

export default function FlowsPage() {
  const { flows, loading, refresh } = useFlows();

  const [search,    setSearch]    = useState('');
  const [decision,  setDecision]  = useState('all');
  const [protocol,  setProtocol]  = useState('all');
  const [minRisk,   setMinRisk]   = useState(0);
  const [sortKey,   setSortKey]   = useState<SortKey>('first_seen');
  const [sortDir,   setSortDir]   = useState<SortDir>('desc');
  const [selected,  setSelected]  = useState<Flow | null>(null);
  const [page,      setPage]      = useState(1);
  const PAGE_SIZE = 50;

  const toggleSort = useCallback((key: SortKey) => {
    if (sortKey === key) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortKey(key); setSortDir('desc'); }
  }, [sortKey]);

  const filtered = useMemo(() => {
    let out = flows ?? [];
    if (search)   out = out.filter(f => f.src_ip.includes(search) || f.dst_ip.includes(search));
    if (decision !== 'all') out = out.filter(f => f.decision === decision);
    if (protocol !== 'all') out = out.filter(f => f.protocol === protocol);
    if (minRisk > 0)        out = out.filter(f => f.risk_score >= minRisk / 100);

    out = [...out].sort((a, b) => {
      const av = a[sortKey] as number, bv = b[sortKey] as number;
      return sortDir === 'asc' ? (av > bv ? 1 : -1) : (av < bv ? 1 : -1);
    });

    return out;
  }, [flows, search, decision, protocol, minRisk, sortKey, sortDir]);

  const paged = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));

  const SortIcon = ({ k }: { k: SortKey }) =>
    sortKey === k
      ? (sortDir === 'asc' ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />)
      : <ChevronUp className="w-3 h-3 opacity-20" />;

  const Th = ({ k, label }: { k: SortKey; label: string }) => (
    <th
      className="px-4 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider cursor-pointer hover:text-white select-none"
      onClick={() => toggleSort(k)}
    >
      <span className="flex items-center gap-1">{label}<SortIcon k={k} /></span>
    </th>
  );

  const stats = useMemo(() => ({
    total:   filtered.length,
    blocked: filtered.filter(f => f.decision === 'block').length,
    allowed: filtered.filter(f => f.decision === 'allow').length,
    highRisk: filtered.filter(f => f.risk_score > 0.8).length,
  }), [filtered]);

  const exportCSV = () => {
    const header = 'src_ip,dst_ip,src_port,dst_port,protocol,decision,risk_score,bytes\n';
    const rows = filtered.map(f =>
      `${f.src_ip},${f.dst_ip},${f.src_port},${f.dst_port},${f.protocol},${f.decision},${f.risk_score},${f.bytes}`
    ).join('\n');
    const blob = new Blob([header + rows], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = 'thor-flows.csv'; a.click();
  };

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Activity className="w-6 h-6 text-cyan-400" />
          <h1 className="text-2xl font-bold text-white">Network Flows</h1>
          <span className="bg-gray-700 text-gray-300 text-xs px-2 py-1 rounded-full">
            {filtered.length.toLocaleString()} flows
          </span>
        </div>
        <div className="flex gap-2">
          <button onClick={exportCSV} className="flex items-center gap-2 bg-gray-700 hover:bg-gray-600 text-white px-4 py-2 rounded-lg text-sm transition-colors">
            <Download className="w-4 h-4" /> Export CSV
          </button>
          <button onClick={refresh} className="flex items-center gap-2 bg-cyan-600 hover:bg-cyan-700 text-white px-4 py-2 rounded-lg text-sm transition-colors">
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> Refresh
          </button>
        </div>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: 'Total Flows', value: stats.total.toLocaleString(), icon: Activity, color: 'text-cyan-400' },
          { label: 'Allowed', value: stats.allowed.toLocaleString(), icon: Shield, color: 'text-green-400' },
          { label: 'Blocked', value: stats.blocked.toLocaleString(), icon: ShieldAlert, color: 'text-red-400' },
          { label: 'High Risk (>80%)', value: stats.highRisk.toLocaleString(), icon: ShieldAlert, color: 'text-orange-400' },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="bg-gray-800 border border-gray-700 rounded-xl p-4 flex items-center gap-4">
            <Icon className={`w-8 h-8 ${color}`} />
            <div>
              <div className="text-2xl font-bold text-white">{value}</div>
              <div className="text-xs text-gray-400">{label}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="bg-gray-800 border border-gray-700 rounded-xl p-4 flex flex-wrap gap-4 items-center">
        <Filter className="w-4 h-4 text-gray-400" />
        <input
          type="text"
          placeholder="Search IP address…"
          value={search}
          onChange={e => { setSearch(e.target.value); setPage(1); }}
          className="bg-gray-700 text-white rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500 w-52"
        />
        <select value={decision} onChange={e => { setDecision(e.target.value); setPage(1); }}
          className="bg-gray-700 text-white rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500">
          <option value="all">All Decisions</option>
          <option value="allow">Allow</option>
          <option value="block">Block</option>
          <option value="throttle">Throttle</option>
          <option value="mirror">Mirror</option>
        </select>
        <select value={protocol} onChange={e => { setProtocol(e.target.value); setPage(1); }}
          className="bg-gray-700 text-white rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500">
          <option value="all">All Protocols</option>
          <option value="TCP">TCP</option>
          <option value="UDP">UDP</option>
          <option value="ICMP">ICMP</option>
        </select>
        <div className="flex items-center gap-2">
          <span className="text-gray-400 text-sm">Min Risk:</span>
          <input type="range" min={0} max={100} value={minRisk} onChange={e => { setMinRisk(+e.target.value); setPage(1); }}
            className="w-24 accent-cyan-500" />
          <span className="text-white text-sm w-10">{minRisk}%</span>
        </div>
      </div>

      {/* Table */}
      <div className="bg-gray-800 border border-gray-700 rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="border-b border-gray-700 bg-gray-900/50">
              <tr>
                <Th k="src_ip"      label="Source IP" />
                <Th k="dst_ip"      label="Dest IP" />
                <Th k="dst_port"    label="Port" />
                <Th k="protocol"    label="Proto" />
                <Th k="decision"    label="Decision" />
                <Th k="risk_score"  label="Risk" />
                <Th k="bytes"       label="Bytes" />
                <Th k="packets"     label="Pkts" />
                <Th k="first_seen"  label="Time" />
                <th className="px-4 py-3"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700/50">
              {loading && !paged.length ? (
                Array.from({ length: 10 }).map((_, i) => (
                  <tr key={i}>
                    {Array.from({ length: 10 }).map((_, j) => (
                      <td key={j} className="px-4 py-3">
                        <div className="h-4 bg-gray-700 rounded animate-pulse" />
                      </td>
                    ))}
                  </tr>
                ))
              ) : paged.map((flow, i) => (
                <tr key={`${flow.src_ip}-${flow.dst_ip}-${flow.src_port}-${i}`}
                  className="hover:bg-gray-700/50 transition-colors cursor-pointer"
                  onClick={() => setSelected(flow)}>
                  <td className="px-4 py-3 font-mono text-gray-200">{flow.src_ip}</td>
                  <td className="px-4 py-3 font-mono text-gray-200">{flow.dst_ip}</td>
                  <td className="px-4 py-3 text-gray-400">{flow.dst_port}</td>
                  <td className="px-4 py-3">
                    <span className={`font-mono text-xs font-bold ${PROTOCOL_COLOR[flow.protocol] ?? 'text-gray-400'}`}>
                      {flow.protocol}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${DECISION_STYLE[flow.decision] ?? ''}`}>
                      {flow.decision.toUpperCase()}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div className="w-16 bg-gray-700 rounded-full h-1.5">
                        <div
                          className={`h-1.5 rounded-full ${flow.risk_score > 0.8 ? 'bg-red-500' : flow.risk_score > 0.5 ? 'bg-yellow-500' : 'bg-green-500'}`}
                          style={{ width: `${flow.risk_score * 100}%` }}
                        />
                      </div>
                      <span className="text-xs text-gray-300">{fmt.pct(flow.risk_score)}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-gray-400 font-mono text-xs">{fmt.bytes(flow.bytes ?? 0)}</td>
                  <td className="px-4 py-3 text-gray-400">{(flow.packets ?? 0).toLocaleString()}</td>
                  <td className="px-4 py-3 text-gray-500 text-xs font-mono">{fmt.time(flow.first_seen)}</td>
                  <td className="px-4 py-3">
                    <Eye className="w-4 h-4 text-gray-500 hover:text-cyan-400 transition-colors" />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <div className="border-t border-gray-700 px-4 py-3 flex items-center justify-between">
          <span className="text-xs text-gray-400">
            Showing {Math.min((page-1)*PAGE_SIZE+1, filtered.length)}–{Math.min(page*PAGE_SIZE, filtered.length)} of {filtered.length.toLocaleString()}
          </span>
          <div className="flex gap-2">
            <button disabled={page === 1} onClick={() => setPage(p => p-1)}
              className="px-3 py-1 rounded-lg bg-gray-700 text-white text-sm disabled:opacity-40 hover:bg-gray-600 transition-colors">
              ← Prev
            </button>
            <span className="px-3 py-1 text-gray-300 text-sm">{page} / {totalPages}</span>
            <button disabled={page === totalPages} onClick={() => setPage(p => p+1)}
              className="px-3 py-1 rounded-lg bg-gray-700 text-white text-sm disabled:opacity-40 hover:bg-gray-600 transition-colors">
              Next →
            </button>
          </div>
        </div>
      </div>

      {selected && <FlowDetail flow={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
