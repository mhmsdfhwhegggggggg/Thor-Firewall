// Thor Firewall Dashboard — Flow Table Component
import React, { useState, useMemo } from "react";
import { Shield, ChevronUp, ChevronDown, Minus, Search, Filter } from "lucide-react";
import type { Decision, FlowRecord, FlowState } from "../../types";

// ============================================================================
// Helpers
// ============================================================================

function fmt(n: number): string {
  if (n >= 1e9) return `${(n / 1e9).toFixed(1)}G`;
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)}M`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(1)}K`;
  return String(n);
}

const STATE_STYLE: Record<FlowState, string> = {
  new:         "bg-blue-500/20 text-blue-300",
  analyzing:   "bg-violet-500/20 text-violet-300",
  allowed:     "bg-green-500/20 text-green-300",
  blocked:     "bg-red-500/20 text-red-300",
  suspicious:  "bg-amber-500/20 text-amber-300",
  terminated:  "bg-gray-500/20 text-gray-400",
};

const DECISION_STYLE: Record<Decision, string> = {
  allow:    "text-green-400",
  block:    "text-red-400",
  throttle: "text-amber-400",
  mirror:   "text-blue-400",
  redirect: "text-violet-400",
};

function RiskBadge({ score }: { score: number }) {
  const color =
    score > 0.7 ? "bg-red-500/20 text-red-400" :
    score > 0.4 ? "bg-amber-500/20 text-amber-400" :
                  "bg-green-500/20 text-green-400";

  return (
    <div className={`flex items-center gap-1.5 rounded-full px-2 py-0.5 ${color}`}>
      <div className={`h-1.5 w-1.5 rounded-full ${
        score > 0.7 ? "bg-red-400" : score > 0.4 ? "bg-amber-400" : "bg-green-400"
      }`} />
      <span className="text-xs font-mono">{(score * 100).toFixed(0)}%</span>
    </div>
  );
}

// ============================================================================
// Sorting
// ============================================================================

type SortKey = "riskScore" | "packets" | "bytes" | "pps" | "lastSeen";
type SortDir = "asc" | "desc";

function SortIcon({ col, cur, dir }: { col: SortKey; cur: SortKey; dir: SortDir }) {
  if (col !== cur) return <Minus className="h-3 w-3 opacity-20" />;
  return dir === "asc"
    ? <ChevronUp   className="h-3 w-3 text-cyan-400" />
    : <ChevronDown className="h-3 w-3 text-cyan-400" />;
}

// ============================================================================
// Main Component
// ============================================================================

interface FlowTableProps {
  flows:   FlowRecord[];
  loading: boolean;
  onBlock?: (flowId: string) => void;
}

export function FlowTable({ flows, loading, onBlock }: FlowTableProps) {
  const [sort,    setSort]    = useState<SortKey>("riskScore");
  const [dir,     setDir]     = useState<SortDir>("desc");
  const [filter,  setFilter]  = useState("");
  const [stateFl, setStateFl] = useState<FlowState | "all">("all");
  const [selected, setSelected] = useState<string | null>(null);

  function toggleSort(col: SortKey) {
    if (col === sort) setDir((d) => (d === "asc" ? "desc" : "asc"));
    else { setSort(col); setDir("desc"); }
  }

  const filtered = useMemo(() => {
    let result = [...flows];

    // text filter
    if (filter.trim()) {
      const f = filter.toLowerCase();
      result = result.filter(
        (fl) =>
          fl.key.srcIp.includes(f) ||
          fl.key.dstIp.includes(f) ||
          fl.key.protocol.includes(f) ||
          fl.tags.some((t) => t.includes(f))
      );
    }

    // state filter
    if (stateFl !== "all") {
      result = result.filter((fl) => fl.state === stateFl);
    }

    // sort
    result.sort((a, b) => {
      let av = 0, bv = 0;
      switch (sort) {
        case "riskScore": av = a.riskScore;       bv = b.riskScore;       break;
        case "packets":   av = a.stats.packets;   bv = b.stats.packets;   break;
        case "bytes":     av = a.stats.bytes;     bv = b.stats.bytes;     break;
        case "pps":       av = a.stats.pps;       bv = b.stats.pps;       break;
        case "lastSeen":  av = a.stats.lastSeen;  bv = b.stats.lastSeen;  break;
      }
      return dir === "asc" ? av - bv : bv - av;
    });

    return result;
  }, [flows, filter, stateFl, sort, dir]);

  const selectedFlow = selected ? flows.find((f) => f.flowId === selected) : null;

  const headers: { key: SortKey; label: string }[] = [
    { key: "riskScore", label: "Risk"      },
    { key: "packets",   label: "Pkts"      },
    { key: "pps",       label: "PPS"       },
    { key: "bytes",     label: "Bytes"     },
    { key: "lastSeen",  label: "Last Seen" },
  ];

  return (
    <div className="flex h-full flex-col gap-3">
      {/* Filter bar */}
      <div className="flex gap-2 shrink-0">
        <div className="relative flex-1">
          <Search className="absolute left-2.5 top-2 h-3.5 w-3.5 text-white/30" />
          <input
            type="text"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter by IP, protocol, tag..."
            className="w-full rounded-lg border border-white/10 bg-white/5 py-1.5 pl-8 pr-3 text-xs text-white placeholder-white/30 focus:border-cyan-500 focus:outline-none"
          />
        </div>
        <div className="flex gap-1">
          {(["all", "allowed", "blocked", "suspicious"] as const).map((s) => (
            <button
              key={s}
              onClick={() => setStateFl(s)}
              className={`rounded-lg px-2.5 py-1.5 text-xs capitalize transition-all ${
                stateFl === s
                  ? "bg-cyan-600/30 text-cyan-400 border border-cyan-500/40"
                  : "bg-white/5 text-white/50 border border-white/10 hover:bg-white/10"
              }`}
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      {/* Table */}
      <div className="flex-1 overflow-auto">
        <table className="w-full text-xs">
          <thead className="sticky top-0 z-10 bg-gray-950">
            <tr className="border-b border-white/10 text-left text-white/40">
              <th className="pb-2 pr-3 font-medium">State</th>
              <th className="pb-2 pr-3 font-medium">Source</th>
              <th className="pb-2 pr-3 font-medium">Destination</th>
              <th className="pb-2 pr-3 font-medium">Proto</th>
              {headers.map((h) => (
                <th
                  key={h.key}
                  className="pb-2 pr-3 font-medium cursor-pointer hover:text-white/80"
                  onClick={() => toggleSort(h.key)}
                >
                  <div className="flex items-center gap-1">
                    {h.label}
                    <SortIcon col={h.key} cur={sort} dir={dir} />
                  </div>
                </th>
              ))}
              <th className="pb-2 font-medium">Tags</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={9} className="py-8 text-center text-white/30">
                  Loading flows…
                </td>
              </tr>
            ) : filtered.length === 0 ? (
              <tr>
                <td colSpan={9} className="py-8 text-center text-white/30">
                  No flows match filter
                </td>
              </tr>
            ) : (
              filtered.map((flow) => (
                <tr
                  key={flow.flowId}
                  onClick={() => setSelected(flow.flowId === selected ? null : flow.flowId)}
                  className={`border-b border-white/5 cursor-pointer transition-colors hover:bg-white/5 ${
                    selected === flow.flowId ? "bg-cyan-900/20" : ""
                  }`}
                >
                  {/* State */}
                  <td className="py-2 pr-3">
                    <span className={`rounded-full px-2 py-0.5 text-[10px] font-medium ${STATE_STYLE[flow.state]}`}>
                      {flow.state}
                    </span>
                  </td>
                  {/* Source */}
                  <td className="py-2 pr-3 font-mono text-white/70">
                    {flow.key.srcIp}<span className="text-white/30">:{flow.key.srcPort}</span>
                  </td>
                  {/* Destination */}
                  <td className="py-2 pr-3 font-mono text-white/70">
                    {flow.key.dstIp}<span className="text-white/30">:{flow.key.dstPort}</span>
                  </td>
                  {/* Protocol */}
                  <td className="py-2 pr-3">
                    <span className="rounded bg-white/10 px-1.5 py-0.5 text-[10px] font-mono uppercase text-white/60">
                      {flow.key.protocol}
                    </span>
                  </td>
                  {/* Risk */}
                  <td className="py-2 pr-3">
                    <RiskBadge score={flow.riskScore} />
                  </td>
                  {/* Packets */}
                  <td className="py-2 pr-3 tabular-nums text-white/60">{fmt(flow.stats.packets)}</td>
                  {/* PPS */}
                  <td className="py-2 pr-3 tabular-nums text-white/60">{fmt(flow.stats.pps)}</td>
                  {/* Bytes */}
                  <td className="py-2 pr-3 tabular-nums text-white/60">{fmt(flow.stats.bytes)}</td>
                  {/* Last Seen */}
                  <td className="py-2 pr-3 text-white/40">
                    {Math.round((Date.now() - flow.stats.lastSeen) / 1000)}s ago
                  </td>
                  {/* Tags */}
                  <td className="py-2">
                    <div className="flex flex-wrap gap-1">
                      {flow.tags.slice(0, 3).map((tag) => (
                        <span key={tag}
                              className="rounded bg-red-500/20 px-1 py-0.5 text-[10px] text-red-400">
                          {tag}
                        </span>
                      ))}
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Detail panel */}
      {selectedFlow && (
        <div className="shrink-0 rounded-lg border border-cyan-900/50 bg-cyan-950/30 p-3 text-xs">
          <div className="flex items-center justify-between mb-2">
            <span className="font-semibold text-cyan-400">Flow Details</span>
            {onBlock && selectedFlow.state !== "blocked" && (
              <button
                onClick={() => onBlock(selectedFlow.flowId)}
                className="flex items-center gap-1 rounded bg-red-600/30 px-2 py-1 text-red-400 hover:bg-red-600/50"
              >
                <Shield className="h-3 w-3" />
                Block
              </button>
            )}
          </div>
          <div className="grid grid-cols-4 gap-3 text-white/60">
            <div><span className="text-white/30">Flow ID:</span> <span className="font-mono">{selectedFlow.flowId.slice(0,16)}</span></div>
            <div><span className="text-white/30">Agent:</span> {selectedFlow.agentId}</div>
            <div><span className="text-white/30">Confidence:</span> {(selectedFlow.confidence * 100).toFixed(1)}%</div>
            <div><span className="text-white/30">Entropy:</span> {selectedFlow.stats.payloadEntropy.toFixed(2)}</div>
            <div><span className="text-white/30">Decision:</span>
              <span className={`ml-1 ${selectedFlow.decision ? DECISION_STYLE[selectedFlow.decision] : "text-white/50"}`}>
                {selectedFlow.decision ?? "pending"}
              </span>
            </div>
            <div><span className="text-white/30">Avg pkt:</span> {fmt(selectedFlow.stats.avgPacketSize)} B</div>
            <div><span className="text-white/30">Retrans:</span> {selectedFlow.stats.retransmissions}</div>
            <div><span className="text-white/30">Bps:</span> {fmt(selectedFlow.stats.bps)}</div>
          </div>
          {selectedFlow.explanation && (
            <p className="mt-2 text-white/50 italic">{selectedFlow.explanation}</p>
          )}
        </div>
      )}
    </div>
  );
}
