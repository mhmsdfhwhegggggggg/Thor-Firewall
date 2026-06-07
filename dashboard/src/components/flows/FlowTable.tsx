// Thor Firewall Dashboard — Flow Table
import React, { memo, useState, useMemo } from "react";
import { ChevronUp, ChevronDown, Search, Filter, Ban } from "lucide-react";
import type { FlowRecord, FlowState, Decision } from "../../types";

// ============================================================================
// Helpers
// ============================================================================

function fmtBytes(b: number) {
  if (b > 1e9) return `${(b / 1e9).toFixed(2)}GB`;
  if (b > 1e6) return `${(b / 1e6).toFixed(2)}MB`;
  if (b > 1e3) return `${(b / 1e3).toFixed(2)}KB`;
  return `${b}B`;
}

function fmtRate(bps: number) {
  if (bps > 1e9) return `${(bps / 1e9).toFixed(1)}Gbps`;
  if (bps > 1e6) return `${(bps / 1e6).toFixed(1)}Mbps`;
  if (bps > 1e3) return `${(bps / 1e3).toFixed(1)}Kbps`;
  return `${bps}bps`;
}

const STATE_BADGE: Record<FlowState, string> = {
  new:         "bg-slate-700 text-slate-300",
  analyzing:   "bg-violet-900 text-violet-300 animate-pulse",
  allowed:     "bg-green-900 text-green-300",
  blocked:     "bg-red-900 text-red-300",
  suspicious:  "bg-amber-900 text-amber-300",
  terminated:  "bg-gray-800 text-gray-400",
};

const RISK_COLOR = (r: number) => {
  if (r >= 0.8) return "text-red-400";
  if (r >= 0.5) return "text-amber-400";
  if (r >= 0.3) return "text-yellow-400";
  return "text-green-400";
};

// ============================================================================
// Table Column Definition
// ============================================================================

type SortKey = "riskScore" | "stats.pps" | "stats.bytes" | "stats.packets";

interface Column {
  key: string;
  label: string;
  sortKey?: SortKey;
  render: (f: FlowRecord) => React.ReactNode;
  className?: string;
}

const COLUMNS: Column[] = [
  {
    key: "src",
    label: "Source",
    render: (f) => (
      <span className="font-mono text-xs text-white/80">
        {f.key.srcIp}:<span className="text-white/50">{f.key.srcPort}</span>
      </span>
    ),
  },
  {
    key: "dst",
    label: "Destination",
    render: (f) => (
      <span className="font-mono text-xs text-white/80">
        {f.key.dstIp}:<span className="text-white/50">{f.key.dstPort}</span>
      </span>
    ),
  },
  {
    key: "proto",
    label: "Proto",
    render: (f) => (
      <span className="rounded bg-white/10 px-1.5 py-0.5 font-mono text-xs text-white/70">
        {f.key.protocol.toUpperCase()}
      </span>
    ),
    className: "w-16 text-center",
  },
  {
    key: "state",
    label: "State",
    render: (f) => (
      <span className={`rounded px-2 py-0.5 text-xs font-medium ${STATE_BADGE[f.state]}`}>
        {f.state}
      </span>
    ),
    className: "w-24 text-center",
  },
  {
    key: "risk",
    label: "Risk",
    sortKey: "riskScore",
    render: (f) => (
      <div className="flex items-center gap-1.5">
        <div className="h-1.5 w-16 rounded-full bg-white/10">
          <div
            className={`h-full rounded-full ${f.riskScore >= 0.8 ? "bg-red-500" : f.riskScore >= 0.5 ? "bg-amber-500" : "bg-green-500"}`}
            style={{ width: `${Math.round(f.riskScore * 100)}%` }}
          />
        </div>
        <span className={`font-mono text-xs ${RISK_COLOR(f.riskScore)}`}>
          {Math.round(f.riskScore * 100)}%
        </span>
      </div>
    ),
    className: "w-28",
  },
  {
    key: "pps",
    label: "PPS",
    sortKey: "stats.pps",
    render: (f) => (
      <span className="font-mono text-xs text-white/70">{Math.round(f.stats.pps)}</span>
    ),
    className: "w-20 text-right",
  },
  {
    key: "bytes",
    label: "Traffic",
    sortKey: "stats.bytes",
    render: (f) => (
      <span className="font-mono text-xs text-white/70">{fmtBytes(f.stats.bytes)}</span>
    ),
    className: "w-24 text-right",
  },
  {
    key: "entropy",
    label: "Entropy",
    render: (f) => (
      <span
        className={`font-mono text-xs ${f.stats.payloadEntropy > 7 ? "text-red-400" : "text-white/50"}`}
      >
        {f.stats.payloadEntropy.toFixed(2)}
      </span>
    ),
    className: "w-20 text-right",
  },
];

// ============================================================================
// FlowTable
// ============================================================================

interface Props {
  flows: FlowRecord[];
  onBlock?: (flow: FlowRecord) => void;
  onInspect?: (flow: FlowRecord) => void;
  loading?: boolean;
}

export const FlowTable = memo(function FlowTable({ flows, onBlock, onInspect, loading }: Props) {
  const [search, setSearch] = useState("");
  const [stateFilter, setStateFilter] = useState<FlowState | "all">("all");
  const [sortKey, setSortKey] = useState<SortKey>("riskScore");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");

  const handleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir("desc");
    }
  };

  const filtered = useMemo(() => {
    let list = flows;
    if (search) {
      const q = search.toLowerCase();
      list = list.filter(
        (f) =>
          f.key.srcIp.includes(q) ||
          f.key.dstIp.includes(q) ||
          f.key.srcPort.toString().includes(q) ||
          f.key.dstPort.toString().includes(q)
      );
    }
    if (stateFilter !== "all") {
      list = list.filter((f) => f.state === stateFilter);
    }

    list = [...list].sort((a, b) => {
      let av = 0, bv = 0;
      if (sortKey === "riskScore") { av = a.riskScore; bv = b.riskScore; }
      else if (sortKey === "stats.pps") { av = a.stats.pps; bv = b.stats.pps; }
      else if (sortKey === "stats.bytes") { av = a.stats.bytes; bv = b.stats.bytes; }
      else if (sortKey === "stats.packets") { av = a.stats.packets; bv = b.stats.packets; }
      return sortDir === "asc" ? av - bv : bv - av;
    });

    return list.slice(0, 500);
  }, [flows, search, stateFilter, sortKey, sortDir]);

  return (
    <div className="flex h-full flex-col gap-3">
      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-40">
          <Search className="absolute left-2.5 top-2 h-4 w-4 text-white/30" />
          <input
            type="text"
            placeholder="Search IP or port..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full rounded-lg border border-white/10 bg-white/5 py-1.5 pl-8 pr-3 text-sm text-white placeholder-white/30 focus:border-cyan-500 focus:outline-none"
          />
        </div>
        <select
          value={stateFilter}
          onChange={(e) => setStateFilter(e.target.value as FlowState | "all")}
          className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-sm text-white focus:border-cyan-500 focus:outline-none"
        >
          <option value="all">All states</option>
          <option value="blocked">Blocked</option>
          <option value="suspicious">Suspicious</option>
          <option value="analyzing">Analyzing</option>
          <option value="allowed">Allowed</option>
        </select>
        <span className="text-xs text-white/40">
          {filtered.length} / {flows.length} flows
        </span>
      </div>

      {/* Table */}
      <div className="flex-1 overflow-auto rounded-lg border border-white/10">
        <table className="w-full min-w-max text-left text-sm">
          <thead className="sticky top-0 z-10 bg-gray-900/95 backdrop-blur">
            <tr>
              {COLUMNS.map((col) => (
                <th
                  key={col.key}
                  className={`px-3 py-2 text-xs font-semibold uppercase tracking-wider text-white/50 ${col.className ?? ""} ${col.sortKey ? "cursor-pointer select-none hover:text-white/80" : ""}`}
                  onClick={() => col.sortKey && handleSort(col.sortKey)}
                >
                  <span className="flex items-center gap-1">
                    {col.label}
                    {col.sortKey && (
                      <span className="flex flex-col">
                        <ChevronUp className={`h-2.5 w-2.5 ${sortKey === col.sortKey && sortDir === "asc" ? "text-cyan-400" : "text-white/20"}`} />
                        <ChevronDown className={`h-2.5 w-2.5 ${sortKey === col.sortKey && sortDir === "desc" ? "text-cyan-400" : "text-white/20"}`} />
                      </span>
                    )}
                  </span>
                </th>
              ))}
              <th className="px-3 py-2 text-xs font-semibold uppercase tracking-wider text-white/50">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {loading ? (
              Array.from({ length: 8 }).map((_, i) => (
                <tr key={i} className="animate-pulse">
                  {COLUMNS.map((c) => (
                    <td key={c.key} className="px-3 py-2">
                      <div className="h-3.5 rounded bg-white/10" />
                    </td>
                  ))}
                  <td className="px-3 py-2" />
                </tr>
              ))
            ) : (
              filtered.map((flow) => (
                <tr
                  key={flow.flowId}
                  onClick={() => onInspect?.(flow)}
                  className={`cursor-pointer transition-colors hover:bg-white/5 ${flow.state === "blocked" ? "bg-red-950/20" : flow.state === "suspicious" ? "bg-amber-950/10" : ""}`}
                >
                  {COLUMNS.map((col) => (
                    <td key={col.key} className={`px-3 py-2 ${col.className ?? ""}`}>
                      {col.render(flow)}
                    </td>
                  ))}
                  <td className="px-3 py-2">
                    {flow.state !== "blocked" && onBlock && (
                      <button
                        onClick={(e) => { e.stopPropagation(); onBlock(flow); }}
                        className="flex items-center gap-1 rounded bg-red-900/50 px-2 py-0.5 text-xs text-red-400 hover:bg-red-800"
                      >
                        <Ban className="h-3 w-3" />
                        Block
                      </button>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
});
