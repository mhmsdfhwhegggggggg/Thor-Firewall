// Thor Firewall — Threat Hunting Workspace
// مساحة عمل الصيد الاستباقي للتهديدات
import React, { useState, useCallback, useRef } from "react";
import { Search, Play, Save, BookOpen, Download, Clock, ChevronRight } from "lucide-react";
import type { FlowRecord } from "../../types";

// ─── ThorQL Preset Library ───────────────────────────────────────────────────
const SAVED_HUNTS = [
  {
    id: "dns-tunnel",
    name: "DNS Tunneling Detection",
    mitre: "T1071.004",
    query: `flows
  WHERE protocol = "UDP"
    AND dst_port = 53
    AND payload_entropy > 7.0
    AND bytes_per_packet > 200
  LAST 4h
  GROUP BY src_ip
  HAVING count(*) > 100
  ORDER BY max(risk_score) DESC`,
  },
  {
    id: "beaconing",
    name: "C2 Beaconing Pattern",
    mitre: "T1071.001",
    query: `flows
  WHERE risk_score > 0.5
    AND dst_port IN (80, 443, 8080, 8443)
    AND decision = "allow"
  LAST 1h
  GROUP BY src_ip, dst_ip
  HAVING stddev(interval_ms) < 500
    AND count(*) > 20
  ORDER BY count(*) DESC`,
  },
  {
    id: "lateral-movement",
    name: "Lateral Movement",
    mitre: "T1021",
    query: `flows
  WHERE src_ip LIKE "10.%"
    AND dst_ip LIKE "10.%"
    AND dst_port IN (22, 445, 3389, 5985, 5986)
    AND is_new_connection = true
  LAST 2h
  GROUP BY src_ip
  HAVING count(DISTINCT dst_ip) > 5
  ORDER BY count(DISTINCT dst_ip) DESC`,
  },
  {
    id: "data-exfil",
    name: "Data Exfiltration",
    mitre: "T1041",
    query: `flows
  WHERE direction = "outbound"
    AND bytes > 10000000
    AND dst_ip NOT IN whitelist
  LAST 6h
  GROUP BY src_ip, dst_ip
  ORDER BY sum(bytes) DESC
  LIMIT 20`,
  },
  {
    id: "port-scan",
    name: "Port Scan Detection",
    mitre: "T1046",
    query: `flows
  WHERE connection_state = "SYN_SENT"
    OR (decision = "block" AND risk_score > 0.3)
  LAST 30m
  GROUP BY src_ip
  HAVING count(DISTINCT dst_port) > 20
  ORDER BY count(DISTINCT dst_port) DESC`,
  },
  {
    id: "brute-force",
    name: "Multi-Service Brute Force",
    mitre: "T1110",
    query: `flows
  WHERE dst_port IN (22, 21, 3389, 5432, 3306, 1433)
    AND connection_state = "SYN_SENT"
  LAST 1h
  GROUP BY src_ip
  HAVING count(*) > 50
  ORDER BY count(*) DESC`,
  },
];

// ─── Mock Results Generator ──────────────────────────────────────────────────
function mockQueryResults(query: string): Record<string, unknown>[] {
  return Array.from({ length: Math.floor(Math.random() * 15) + 3 }, (_, i) => ({
    src_ip: `${Math.floor(Math.random() * 200 + 50)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 254) + 1}`,
    dst_ip: `10.0.${Math.floor(Math.random() * 5)}.${Math.floor(Math.random() * 254) + 1}`,
    count: Math.floor(Math.random() * 10000) + 100,
    max_risk_score: (Math.random() * 0.5 + 0.5).toFixed(3),
    bytes: Math.floor(Math.random() * 10_000_000),
    country: ["CN", "RU", "KP", "IR", "BR", "US"][Math.floor(Math.random() * 6)],
  }));
}

// ─── Column Renderer ─────────────────────────────────────────────────────────
function renderCell(key: string, value: unknown): React.ReactNode {
  if (key.includes("risk") || key.includes("score")) {
    const v = parseFloat(String(value));
    const color = v > 0.8 ? "text-red-400" : v > 0.5 ? "text-amber-400" : "text-green-400";
    return <span className={`font-mono font-bold ${color}`}>{(v * 100).toFixed(0)}%</span>;
  }
  if (key.includes("bytes")) {
    const v = parseInt(String(value));
    return <span className="font-mono text-cyan-300">{v > 1e6 ? `${(v/1e6).toFixed(1)}MB` : v > 1e3 ? `${(v/1e3).toFixed(1)}KB` : `${v}B`}</span>;
  }
  if (key.includes("ip")) {
    return <span className="font-mono text-white">{String(value)}</span>;
  }
  return <span className="text-white/80">{String(value)}</span>;
}

// ─── Main Component ──────────────────────────────────────────────────────────
export default function ThreatHunting() {
  const [query, setQuery] = useState(SAVED_HUNTS[0].query);
  const [results, setResults] = useState<Record<string, unknown>[]>([]);
  const [running, setRunning] = useState(false);
  const [elapsed, setElapsed] = useState<number | null>(null);
  const [activeHunt, setActiveHunt] = useState(SAVED_HUNTS[0].id);
  const [notes, setNotes] = useState("");
  const timerRef = useRef<ReturnType<typeof setTimeout>>();

  const runQuery = useCallback(async () => {
    if (!query.trim()) return;
    setRunning(true);
    setResults([]);
    const t0 = Date.now();
    await new Promise(r => setTimeout(r, 800 + Math.random() * 600));
    const r = mockQueryResults(query);
    setResults(r);
    setElapsed(Date.now() - t0);
    setRunning(false);
  }, [query]);

  const loadHunt = (hunt: typeof SAVED_HUNTS[0]) => {
    setQuery(hunt.query);
    setActiveHunt(hunt.id);
    setResults([]);
    setElapsed(null);
  };

  const columns = results.length > 0 ? Object.keys(results[0]) : [];

  return (
    <div className="flex h-full bg-gray-950 text-white overflow-hidden">
      {/* ── Sidebar: Saved Hunts ── */}
      <div className="w-64 shrink-0 border-r border-white/10 flex flex-col">
        <div className="flex items-center gap-2 p-4 border-b border-white/10">
          <BookOpen className="h-4 w-4 text-cyan-400" />
          <h2 className="text-sm font-semibold">Hunt Library</h2>
        </div>
        <div className="flex-1 overflow-y-auto py-2">
          {SAVED_HUNTS.map(hunt => (
            <button
              key={hunt.id}
              onClick={() => loadHunt(hunt)}
              className={`w-full text-left px-4 py-3 hover:bg-white/5 transition-colors border-l-2 ${
                activeHunt === hunt.id ? "border-cyan-400 bg-cyan-950/30" : "border-transparent"
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium text-white/90">{hunt.name}</span>
                <ChevronRight className="h-3 w-3 text-white/30" />
              </div>
              <span className="text-xs font-mono text-cyan-600 mt-0.5 block">{hunt.mitre}</span>
            </button>
          ))}
        </div>
      </div>

      {/* ── Main: Query + Results ── */}
      <div className="flex flex-1 flex-col min-w-0 overflow-hidden">
        {/* Query Editor */}
        <div className="border-b border-white/10 p-4 space-y-3">
          <div className="flex items-center gap-2 text-sm text-white/60">
            <Search className="h-4 w-4 text-cyan-400" />
            <span className="font-semibold text-white">ThorQL Query</span>
            {elapsed && (
              <span className="ml-auto flex items-center gap-1 text-xs text-green-400">
                <Clock className="h-3 w-3" />
                {elapsed}ms · {results.length} results
              </span>
            )}
          </div>
          <div className="relative">
            <textarea
              value={query}
              onChange={e => setQuery(e.target.value)}
              className="w-full rounded-lg border border-white/10 bg-gray-900 font-mono text-sm text-green-300 p-3 resize-none focus:outline-none focus:border-cyan-500 leading-relaxed"
              rows={8}
              spellCheck={false}
              onKeyDown={e => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); runQuery(); } }}
            />
          </div>
          <div className="flex gap-2">
            <button
              onClick={runQuery}
              disabled={running}
              className="flex items-center gap-2 rounded-lg bg-cyan-600 px-4 py-2 text-sm font-semibold hover:bg-cyan-500 disabled:opacity-50 transition-colors"
            >
              <Play className="h-4 w-4" />
              {running ? "Running…" : "Run (Ctrl+Enter)"}
            </button>
            <button className="flex items-center gap-2 rounded-lg border border-white/20 px-4 py-2 text-sm text-white/70 hover:bg-white/5 transition-colors">
              <Save className="h-4 w-4" />
              Save Hunt
            </button>
            {results.length > 0 && (
              <button className="ml-auto flex items-center gap-2 rounded-lg border border-white/20 px-4 py-2 text-sm text-white/70 hover:bg-white/5 transition-colors">
                <Download className="h-4 w-4" />
                Export CSV
              </button>
            )}
          </div>
        </div>

        {/* Results Table */}
        <div className="flex-1 overflow-auto p-4">
          {running && (
            <div className="flex items-center justify-center h-40 text-white/40 text-sm gap-2">
              <div className="h-4 w-4 animate-spin rounded-full border-2 border-cyan-500 border-t-transparent" />
              Executing query against ClickHouse…
            </div>
          )}
          {!running && results.length > 0 && (
            <div className="rounded-xl border border-white/10 overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="bg-gray-900 border-b border-white/10">
                    {columns.map(col => (
                      <th key={col} className="px-4 py-2 text-left text-xs font-semibold text-white/50 uppercase tracking-wider">
                        {col.replace(/_/g, " ")}
                      </th>
                    ))}
                    <th className="px-4 py-2 text-left text-xs font-semibold text-white/50 uppercase">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {results.map((row, i) => (
                    <tr key={i} className="border-b border-white/5 hover:bg-white/3 transition-colors">
                      {columns.map(col => (
                        <td key={col} className="px-4 py-2">{renderCell(col, row[col])}</td>
                      ))}
                      <td className="px-4 py-2">
                        <button className="rounded bg-red-900/40 border border-red-800/50 px-2 py-0.5 text-xs text-red-300 hover:bg-red-800/60 transition-colors">
                          Block IP
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {!running && results.length === 0 && !elapsed && (
            <div className="flex flex-col items-center justify-center h-40 text-white/30 text-sm">
              <Search className="h-10 w-10 mb-3 opacity-50" />
              <p>Select a hunt from the library or write a ThorQL query</p>
              <p className="text-xs mt-1 text-white/20">Press Ctrl+Enter to run</p>
            </div>
          )}
        </div>

        {/* Investigation Notes */}
        <div className="border-t border-white/10 p-3">
          <textarea
            value={notes}
            onChange={e => setNotes(e.target.value)}
            placeholder="Investigation notes (markdown supported)…"
            rows={2}
            className="w-full bg-transparent text-sm text-white/60 placeholder-white/20 resize-none focus:outline-none"
          />
        </div>
      </div>
    </div>
  );
}
