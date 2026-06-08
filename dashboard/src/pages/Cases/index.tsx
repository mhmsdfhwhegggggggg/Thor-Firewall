// Thor Firewall — Case Management
// إدارة القضايا الأمنية
import React, { useState } from "react";
import { Briefcase, Plus, Clock, User, AlertTriangle, CheckCircle2, ChevronRight } from "lucide-react";

type CaseStatus = "new" | "investigating" | "escalated" | "resolved" | "closed";
type CaseSeverity = "low" | "medium" | "high" | "critical";

interface Case {
  id: string; title: string; severity: CaseSeverity; status: CaseStatus;
  assignee: string; created_at: number; updated_at: number;
  incident_count: number; sla_hours: number; description: string;
}

const CASES: Case[] = [
  { id: "CASE-001", title: "Suspected APT — Lateral Movement Detected",
    severity: "critical", status: "investigating", assignee: "ahmed.soc@corp.com",
    created_at: Date.now() - 7200_000, updated_at: Date.now() - 900_000,
    incident_count: 7, sla_hours: 4,
    description: "Multiple IOCs correlated: port scan → known malicious IP → SSH brute force → UEBA anomaly" },
  { id: "CASE-002", title: "DNS Tunneling — Possible Data Exfiltration",
    severity: "high", status: "new", assignee: "sara.analyst@corp.com",
    created_at: Date.now() - 3600_000, updated_at: Date.now() - 3600_000,
    incident_count: 2, sla_hours: 8,
    description: "High-entropy DNS queries exceeding baseline by 7σ from workstation WS-HR-042" },
  { id: "CASE-003", title: "Web Application Brute Force Attack",
    severity: "medium", status: "resolved", assignee: "khaled.ir@corp.com",
    created_at: Date.now() - 86400_000, updated_at: Date.now() - 43200_000,
    incident_count: 1, sla_hours: 24,
    description: "2,847 failed login attempts. IP blocked via SOAR. No successful authentication." },
  { id: "CASE-004", title: "Crypto Miner Detected on Server",
    severity: "high", status: "escalated", assignee: "noor.soc@corp.com",
    created_at: Date.now() - 172800_000, updated_at: Date.now() - 86400_000,
    incident_count: 3, sla_hours: 4,
    description: "XMRig process detected on srv-web-03. Outbound connections to known mining pools." },
];

const STATUS_META: Record<CaseStatus, { label: string; color: string; icon: React.ReactNode }> = {
  new:          { label: "New",          color: "text-blue-400 border-blue-700/50 bg-blue-950/30", icon: <Plus className="h-3 w-3" /> },
  investigating:{ label: "Investigating", color: "text-amber-400 border-amber-700/50 bg-amber-950/30", icon: <Clock className="h-3 w-3" /> },
  escalated:    { label: "Escalated",    color: "text-red-400 border-red-700/50 bg-red-950/30", icon: <AlertTriangle className="h-3 w-3" /> },
  resolved:     { label: "Resolved",     color: "text-green-400 border-green-700/50 bg-green-950/30", icon: <CheckCircle2 className="h-3 w-3" /> },
  closed:       { label: "Closed",       color: "text-gray-400 border-gray-700/50 bg-gray-950/30", icon: <CheckCircle2 className="h-3 w-3" /> },
};

const SEV_COLOR: Record<CaseSeverity, string> = {
  critical: "text-red-400", high: "text-orange-400", medium: "text-amber-400", low: "text-blue-400"
};

function timeAgo(ts: number) {
  const s = Math.floor((Date.now() - ts) / 1000);
  return s < 60 ? `${s}s` : s < 3600 ? `${Math.floor(s/60)}m` : s < 86400 ? `${Math.floor(s/3600)}h` : `${Math.floor(s/86400)}d`;
}

function SLAIndicator({ case: c }: { case: Case }) {
  const elapsed = (Date.now() - c.created_at) / 3600_000;
  const pct = Math.min((elapsed / c.sla_hours) * 100, 100);
  const color = pct >= 90 ? "bg-red-500" : pct >= 70 ? "bg-amber-500" : "bg-green-500";
  return (
    <div className="flex items-center gap-1.5">
      <div className="w-16 h-1.5 rounded-full bg-white/10">
        <div className={`h-1.5 rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className={`text-xs ${pct >= 90 ? "text-red-400" : "text-white/40"}`}>{Math.round(pct)}%</span>
    </div>
  );
}

export default function CaseManagement() {
  const [filter, setFilter] = useState<CaseStatus | "all">("all");
  const [selected, setSelected] = useState<Case | null>(null);
  const [note, setNote] = useState("");

  const filtered = (filter === "all" ? CASES : CASES.filter(c => c.status === filter))
    .sort((a, b) => {
      const sev = { critical: 4, high: 3, medium: 2, low: 1 };
      return sev[b.severity] - sev[a.severity];
    });

  const counts = CASES.reduce((acc, c) => {
    acc[c.status] = (acc[c.status] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  return (
    <div className="flex h-full bg-gray-950 text-white overflow-hidden">
      {/* List */}
      <div className={`flex flex-col transition-all border-r border-white/10 ${selected ? "w-1/2" : "w-full"}`}>
        <div className="shrink-0 border-b border-white/10 px-6 py-4">
          <div className="flex items-center gap-3">
            <Briefcase className="h-5 w-5 text-cyan-400" />
            <h1 className="text-lg font-bold">Case Management</h1>
            <button className="ml-auto flex items-center gap-1.5 rounded-lg bg-cyan-600 px-3 py-1.5 text-xs font-semibold hover:bg-cyan-500 transition-colors">
              <Plus className="h-3.5 w-3.5" /> New Case
            </button>
          </div>
          <div className="flex gap-2 mt-3 flex-wrap">
            {(["all", "new", "investigating", "escalated", "resolved"] as const).map(f => (
              <button key={f} onClick={() => setFilter(f)}
                className={`rounded-full px-3 py-1 text-xs font-medium transition-colors flex items-center gap-1 capitalize ${
                  filter === f ? "bg-cyan-600 text-white" : "bg-white/5 text-white/50 hover:bg-white/10"
                }`}>
                {f !== "all" && STATUS_META[f as CaseStatus].icon}
                {f === "all" ? "All Cases" : STATUS_META[f as CaseStatus].label}
                {f !== "all" && counts[f] && <span className="ml-0.5 rounded-full bg-white/20 px-1 text-xs">{counts[f]}</span>}
              </button>
            ))}
          </div>
        </div>

        <div className="flex-1 overflow-y-auto divide-y divide-white/5">
          {filtered.map(c => {
            const sm = STATUS_META[c.status];
            return (
              <button key={c.id} onClick={() => setSelected(c === selected ? null : c)}
                className={`w-full text-left px-6 py-4 hover:bg-white/3 transition-colors ${selected?.id === c.id ? "bg-white/5" : ""}`}>
                <div className="flex items-start gap-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs font-mono text-white/40">{c.id}</span>
                      <span className={`text-xs font-bold uppercase ${SEV_COLOR[c.severity]}`}>{c.severity}</span>
                      <span className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs ${sm.color}`}>
                        {sm.icon}{sm.label}
                      </span>
                    </div>
                    <p className="text-sm font-semibold text-white mt-1 line-clamp-1">{c.title}</p>
                    <p className="text-xs text-white/50 mt-0.5 line-clamp-1">{c.description}</p>
                    <div className="flex items-center gap-3 mt-2">
                      <span className="flex items-center gap-1 text-xs text-white/40">
                        <User className="h-3 w-3" />{c.assignee.split("@")[0]}
                      </span>
                      <span className="text-xs text-white/30">{c.incident_count} incidents</span>
                      <SLAIndicator case={c} />
                      <span className="ml-auto text-xs text-white/30">{timeAgo(c.created_at)} ago</span>
                    </div>
                  </div>
                  <ChevronRight className={`h-4 w-4 shrink-0 text-white/30 transition-transform mt-1 ${selected?.id === c.id ? "rotate-90" : ""}`} />
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Detail Panel */}
      {selected && (
        <div className="w-1/2 flex flex-col overflow-y-auto">
          <div className="sticky top-0 bg-gray-950/95 border-b border-white/10 px-6 py-4">
            <div className="flex items-center justify-between">
              <div>
                <span className="text-xs font-mono text-white/40">{selected.id}</span>
                <h2 className="font-bold text-sm mt-0.5 line-clamp-2">{selected.title}</h2>
              </div>
              <button onClick={() => setSelected(null)} className="shrink-0 text-white/40 hover:text-white text-xs ml-3">✕</button>
            </div>
          </div>
          <div className="p-6 space-y-4">
            {/* Status + Actions */}
            <div className="flex gap-2">
              {(["new", "investigating", "escalated", "resolved"] as CaseStatus[]).map(s => (
                <button key={s} className={`rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors ${
                  selected.status === s ? STATUS_META[s].color : "border-white/10 text-white/40 hover:bg-white/5"
                }`}>{STATUS_META[s].label}</button>
              ))}
            </div>
            {/* Description */}
            <div className="rounded-xl border border-white/10 bg-gray-900/50 p-4">
              <div className="text-xs font-semibold text-white/50 mb-2">Description</div>
              <p className="text-sm text-white/80">{selected.description}</p>
            </div>
            {/* Metadata */}
            <div className="grid grid-cols-2 gap-3">
              {[
                ["Severity", <span className={`font-bold ${SEV_COLOR[selected.severity]}`}>{selected.severity.toUpperCase()}</span>],
                ["Assignee", selected.assignee.split("@")[0]],
                ["Created", timeAgo(selected.created_at) + " ago"],
                ["Incidents", selected.incident_count.toString()],
              ].map(([k, v]) => (
                <div key={String(k)} className="rounded-lg border border-white/10 bg-gray-900/30 px-3 py-2">
                  <div className="text-xs text-white/40">{k}</div>
                  <div className="text-sm font-medium text-white mt-0.5">{v}</div>
                </div>
              ))}
            </div>
            {/* SLA */}
            <div className="rounded-xl border border-white/10 p-3">
              <div className="flex justify-between text-xs mb-1">
                <span className="text-white/50">SLA Progress ({selected.sla_hours}h)</span>
              </div>
              <SLAIndicator case={selected} />
            </div>
            {/* Investigation Notes */}
            <div className="rounded-xl border border-white/10 bg-gray-900/30 p-3">
              <div className="text-xs font-semibold text-white/50 mb-2">Investigation Notes</div>
              <textarea value={note} onChange={e => setNote(e.target.value)}
                placeholder="Add investigation notes (markdown)..."
                rows={4}
                className="w-full bg-transparent text-sm text-white/80 placeholder-white/20 resize-none focus:outline-none" />
              <div className="flex justify-end mt-2">
                <button className="rounded-lg bg-cyan-600 px-3 py-1.5 text-xs font-semibold hover:bg-cyan-500 transition-colors">
                  Save Note
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
