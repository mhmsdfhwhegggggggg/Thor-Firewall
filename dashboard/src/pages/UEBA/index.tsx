// Thor Firewall — UEBA Dashboard
// تحليل سلوك المستخدمين والكيانات
import React, { useState } from "react";
import { Users, TrendingUp, AlertTriangle, Activity, ChevronRight, Shield } from "lucide-react";

interface Entity {
  id: string; type: "user" | "device" | "ip";
  name: string; risk_score: number; anomalies: number;
  last_seen: number; status: "normal" | "suspicious" | "critical";
  top_anomaly?: string; mitre?: string;
}

const ENTITIES: Entity[] = [
  { id: "u1", type: "user", name: "john.doe@corp.com", risk_score: 0.89, anomalies: 4,
    last_seen: Date.now() - 120_000, status: "critical",
    top_anomaly: "847 files accessed in 2h (7.2σ)", mitre: "T1039" },
  { id: "u2", type: "user", name: "svc-backup", risk_score: 0.72, anomalies: 2,
    last_seen: Date.now() - 300_000, status: "suspicious",
    top_anomaly: "New geographic location: CN (never seen before)", mitre: "T1078" },
  { id: "d1", type: "device", name: "WS-HR-042 (10.0.5.42)", risk_score: 0.65, anomalies: 3,
    last_seen: Date.now() - 60_000, status: "suspicious",
    top_anomaly: "27 new external connections in 30m", mitre: "T1046" },
  { id: "u3", type: "user", name: "admin@corp.com", risk_score: 0.15, anomalies: 0,
    last_seen: Date.now() - 3600_000, status: "normal" },
  { id: "u4", type: "user", name: "mary.smith@corp.com", risk_score: 0.08, anomalies: 0,
    last_seen: Date.now() - 1800_000, status: "normal" },
  { id: "ip1", type: "ip", name: "185.220.101.45", risk_score: 0.97, anomalies: 6,
    last_seen: Date.now() - 30_000, status: "critical",
    top_anomaly: "TOR exit node — 2,847 SSH probes", mitre: "T1110" },
];

const SEV_COLOR = { normal: "text-green-400", suspicious: "text-amber-400", critical: "text-red-400" };
const SEV_BG = { normal: "bg-green-950/30 border-green-700/30", suspicious: "bg-amber-950/30 border-amber-700/30", critical: "bg-red-950/30 border-red-700/40" };
const TYPE_ICON: Record<string, React.ReactNode> = {
  user: <Users className="h-4 w-4" />,
  device: <Activity className="h-4 w-4" />,
  ip: <Shield className="h-4 w-4" />,
};

function timeAgo(ts: number) {
  const s = Math.floor((Date.now() - ts) / 1000);
  return s < 60 ? `${s}s ago` : s < 3600 ? `${Math.floor(s/60)}m ago` : `${Math.floor(s/3600)}h ago`;
}

function RiskBar({ score }: { score: number }) {
  const pct = Math.round(score * 100);
  const color = pct >= 80 ? "bg-red-500" : pct >= 50 ? "bg-amber-500" : "bg-green-500";
  return (
    <div className="flex items-center gap-2">
      <div className="w-24 h-1.5 rounded-full bg-white/10">
        <div className={`h-1.5 rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className={`text-xs font-mono font-bold ${pct >= 80 ? "text-red-400" : pct >= 50 ? "text-amber-400" : "text-green-400"}`}>{pct}%</span>
    </div>
  );
}

export default function UEBADashboard() {
  const [filter, setFilter] = useState<"all" | "critical" | "suspicious">("all");
  const [selected, setSelected] = useState<Entity | null>(null);

  const filtered = ENTITIES.filter(e =>
    filter === "all" || e.status === filter
  ).sort((a, b) => b.risk_score - a.risk_score);

  const critical = ENTITIES.filter(e => e.status === "critical").length;
  const suspicious = ENTITIES.filter(e => e.status === "suspicious").length;

  return (
    <div className="flex h-full bg-gray-950 text-white overflow-hidden">
      <div className={`flex flex-col transition-all ${selected ? "w-1/2" : "w-full"}`}>
        {/* Header */}
        <div className="shrink-0 border-b border-white/10 px-6 py-4">
          <div className="flex items-center gap-3">
            <TrendingUp className="h-5 w-5 text-cyan-400" />
            <h1 className="text-lg font-bold">UEBA — User & Entity Behavior Analytics</h1>
          </div>
          <div className="flex gap-4 mt-3">
            {[
              { label: "Total Entities", val: ENTITIES.length, color: "text-white" },
              { label: "Critical", val: critical, color: "text-red-400" },
              { label: "Suspicious", val: suspicious, color: "text-amber-400" },
              { label: "Anomalies", val: ENTITIES.reduce((s, e) => s + e.anomalies, 0), color: "text-orange-400" },
            ].map(({ label, val, color }) => (
              <div key={label} className="rounded-lg border border-white/10 bg-gray-900/50 px-4 py-2 text-center">
                <div className={`text-xl font-bold ${color}`}>{val}</div>
                <div className="text-xs text-white/40">{label}</div>
              </div>
            ))}
          </div>
          <div className="flex gap-2 mt-3">
            {(["all", "critical", "suspicious"] as const).map(f => (
              <button key={f} onClick={() => setFilter(f)}
                className={`rounded-full px-3 py-1 text-xs font-medium transition-colors capitalize ${
                  filter === f ? "bg-cyan-600 text-white" : "bg-white/5 text-white/50 hover:bg-white/10"
                }`}>{f === "all" ? "All Entities" : f}</button>
            ))}
          </div>
        </div>

        {/* Entity List */}
        <div className="flex-1 overflow-y-auto divide-y divide-white/5">
          {filtered.map(entity => (
            <button key={entity.id} onClick={() => setSelected(entity === selected ? null : entity)}
              className={`w-full text-left px-6 py-4 hover:bg-white/3 transition-colors ${selected?.id === entity.id ? "bg-white/5" : ""}`}>
              <div className={`rounded-xl border p-3 ${SEV_BG[entity.status]}`}>
                <div className="flex items-center gap-3">
                  <div className={`${SEV_COLOR[entity.status]}`}>{TYPE_ICON[entity.type]}</div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-sm text-white truncate">{entity.name}</span>
                      <span className={`text-xs font-medium uppercase ${SEV_COLOR[entity.status]}`}>{entity.status}</span>
                    </div>
                    {entity.top_anomaly && <p className="text-xs text-white/60 mt-0.5 truncate">{entity.top_anomaly}</p>}
                  </div>
                  <div className="shrink-0 text-right">
                    <RiskBar score={entity.risk_score} />
                    <span className="text-xs text-white/30 mt-1 block">{timeAgo(entity.last_seen)}</span>
                  </div>
                  <ChevronRight className={`h-4 w-4 shrink-0 text-white/30 transition-transform ${selected?.id === entity.id ? "rotate-90" : ""}`} />
                </div>
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Detail Panel */}
      {selected && (
        <div className="w-1/2 border-l border-white/10 flex flex-col overflow-y-auto">
          <div className="sticky top-0 bg-gray-950/95 border-b border-white/10 px-6 py-4">
            <div className="flex items-center justify-between">
              <h2 className="font-bold">Entity Detail</h2>
              <button onClick={() => setSelected(null)} className="text-white/40 hover:text-white text-xs">✕ Close</button>
            </div>
          </div>
          <div className="p-6 space-y-4">
            <div className={`rounded-xl border p-4 ${SEV_BG[selected.status]}`}>
              <div className="flex items-center gap-3 mb-3">
                <div className={`h-10 w-10 rounded-full border-2 flex items-center justify-center ${SEV_COLOR[selected.status]} border-current`}>
                  {TYPE_ICON[selected.type]}
                </div>
                <div>
                  <div className="font-bold">{selected.name}</div>
                  <div className="text-xs text-white/50">{selected.type.toUpperCase()} · {timeAgo(selected.last_seen)}</div>
                </div>
              </div>
              <RiskBar score={selected.risk_score} />
            </div>
            {selected.top_anomaly && (
              <div className="rounded-xl border border-amber-700/30 bg-amber-950/20 p-4">
                <div className="text-xs font-semibold text-amber-400 mb-1">⚠️ Top Anomaly</div>
                <p className="text-sm text-white/80">{selected.top_anomaly}</p>
                {selected.mitre && (
                  <span className="mt-2 inline-block font-mono text-xs bg-white/10 rounded px-2 py-0.5 text-white/60">
                    MITRE: {selected.mitre}
                  </span>
                )}
              </div>
            )}
            <div className="rounded-xl border border-white/10 p-4 space-y-3">
              <div className="text-xs font-semibold text-white/50">BEHAVIORAL BASELINE (30-day)</div>
              {[
                { label: "Avg files/hour", baseline: 23, current: selected.anomalies > 2 ? 412 : 21 },
                { label: "Avg connections/hour", baseline: 12, current: selected.anomalies > 2 ? 89 : 10 },
                { label: "Active hours", baseline: "09:00–18:00", current: selected.anomalies > 2 ? "02:00–04:00" : "09:00–17:00" },
              ].map(row => (
                <div key={row.label} className="flex justify-between text-sm">
                  <span className="text-white/60">{row.label}</span>
                  <div className="text-right">
                    <span className="text-white/40 text-xs">baseline: {row.baseline}</span>
                    <span className={`ml-3 font-mono font-bold ${
                      String(row.current) !== String(row.baseline) ? "text-red-400" : "text-green-400"
                    }`}>{row.current}</span>
                  </div>
                </div>
              ))}
            </div>
            <div className="flex gap-2">
              <button className="flex-1 rounded-lg bg-red-900/40 border border-red-700/50 py-2 text-sm text-red-300 hover:bg-red-800/50 transition-colors">
                Block Entity
              </button>
              <button className="flex-1 rounded-lg bg-amber-900/40 border border-amber-700/50 py-2 text-sm text-amber-300 hover:bg-amber-800/50 transition-colors">
                Open Case
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
