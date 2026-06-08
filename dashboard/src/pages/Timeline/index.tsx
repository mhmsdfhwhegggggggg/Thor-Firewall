// Thor Firewall — Incident Timeline
// الجدول الزمني للحوادث مع MITRE Kill Chain

import React, { useState, useMemo } from "react";
import {
  Shield, AlertTriangle, Cpu, Globe, Lock, Zap,
  ChevronDown, ChevronRight, ExternalLink, Clock
} from "lucide-react";

// ─── Types ───────────────────────────────────────────────────────────────────
type EventSource = "network" | "endpoint" | "ueba" | "threat_intel" | "soar";
type KillChainPhase =
  | "reconnaissance" | "initial_access" | "execution"
  | "persistence" | "privilege_escalation" | "lateral_movement"
  | "collection" | "exfiltration" | "command_and_control" | "impact";

interface TimelineEvent {
  id: string;
  timestamp: number;
  source: EventSource;
  phase?: KillChainPhase;
  severity: "low" | "medium" | "high" | "critical";
  title: string;
  description: string;
  src_ip?: string;
  dst_ip?: string;
  mitre_id?: string;
  mitre_name?: string;
  evidence?: string[];
  blocked: boolean;
}

// ─── Mock Data ────────────────────────────────────────────────────────────────
const MOCK_EVENTS: TimelineEvent[] = [
  { id: "e1", timestamp: Date.now() - 3600_000 * 3, source: "network", phase: "reconnaissance",
    severity: "medium", title: "Port Scan Detected", description: "Systematic scan of 847 ports from external IP",
    src_ip: "185.220.101.45", dst_ip: "10.0.0.1", mitre_id: "T1046", mitre_name: "Network Service Discovery",
    evidence: ["2,847 SYN packets", "0 established connections", "Sequential port pattern"],
    blocked: false },
  { id: "e2", timestamp: Date.now() - 3600_000 * 2.5, source: "threat_intel", phase: "initial_access",
    severity: "high", title: "Known Malicious IP", description: "Source IP found in OTX + AbuseIPDB (94% confidence)",
    src_ip: "185.220.101.45", mitre_id: "T1190", mitre_name: "Exploit Public-Facing Application",
    evidence: ["OTX: 12 malicious reports", "AbuseIPDB: 94/100 confidence", "TOR exit node"],
    blocked: false },
  { id: "e3", timestamp: Date.now() - 3600_000 * 2, source: "network", phase: "initial_access",
    severity: "critical", title: "SSH Brute Force Attack", description: "2,847 failed SSH login attempts in 30 seconds",
    src_ip: "185.220.101.45", dst_ip: "10.0.0.5", mitre_id: "T1110.001", mitre_name: "Password Guessing",
    evidence: ["2,847 SYN to port 22", "MARL confidence: 97%", "Rate: 94 attempts/sec"],
    blocked: true },
  { id: "e4", timestamp: Date.now() - 3600_000 * 1.5, source: "ueba", phase: "lateral_movement",
    severity: "high", title: "UEBA: Unusual Access Pattern", description: "User 'svc-backup' accessed 234 files — 7.2σ above baseline",
    mitre_id: "T1078", mitre_name: "Valid Accounts",
    evidence: ["Baseline: 12 files/hour", "Current: 234 files/2min", "Never accessed /finance before"],
    blocked: false },
  { id: "e5", timestamp: Date.now() - 3600_000, source: "endpoint", phase: "execution",
    severity: "critical", title: "Suspicious Process Spawned", description: "cmd.exe spawned by IIS worker process with encoded payload",
    dst_ip: "10.0.0.5", mitre_id: "T1059.003", mitre_name: "Windows Command Shell",
    evidence: ["Parent: w3wp.exe (PID 4821)", "Base64 encoded args", "Network connection initiated"],
    blocked: true },
  { id: "e6", timestamp: Date.now() - 1800_000, source: "soar", phase: "impact",
    severity: "high", title: "SOAR: Automated Response", description: "IP blocked, host quarantined, SOC alerted, MISP IOC created",
    src_ip: "185.220.101.45", blocked: true,
    evidence: ["block_ip: SUCCESS (2ms)", "quarantine: SUCCESS (145ms)", "alert_soc: SUCCESS", "create_ioc: SUCCESS (MISP)"] },
];

// ─── Constants ────────────────────────────────────────────────────────────────
const PHASE_ORDER: KillChainPhase[] = [
  "reconnaissance", "initial_access", "execution", "persistence",
  "privilege_escalation", "lateral_movement", "collection", "exfiltration",
  "command_and_control", "impact",
];

const PHASE_META: Record<KillChainPhase, { label: string; color: string }> = {
  reconnaissance:      { label: "Recon", color: "border-blue-500 bg-blue-950/40 text-blue-400" },
  initial_access:      { label: "Initial Access", color: "border-yellow-500 bg-yellow-950/40 text-yellow-400" },
  execution:           { label: "Execution", color: "border-orange-500 bg-orange-950/40 text-orange-400" },
  persistence:         { label: "Persistence", color: "border-purple-500 bg-purple-950/40 text-purple-400" },
  privilege_escalation:{ label: "Privesc", color: "border-pink-500 bg-pink-950/40 text-pink-400" },
  lateral_movement:    { label: "Lateral Move", color: "border-red-500 bg-red-950/40 text-red-400" },
  collection:          { label: "Collection", color: "border-rose-500 bg-rose-950/40 text-rose-400" },
  exfiltration:        { label: "Exfiltration", color: "border-red-600 bg-red-950/50 text-red-300" },
  command_and_control: { label: "C2", color: "border-red-700 bg-red-950/60 text-red-300" },
  impact:              { label: "Impact", color: "border-gray-500 bg-gray-900/60 text-gray-400" },
};

const SOURCE_ICON: Record<EventSource, React.ReactNode> = {
  network:      <Globe className="h-3.5 w-3.5" />,
  endpoint:     <Cpu className="h-3.5 w-3.5" />,
  ueba:         <AlertTriangle className="h-3.5 w-3.5" />,
  threat_intel: <Shield className="h-3.5 w-3.5" />,
  soar:         <Zap className="h-3.5 w-3.5" />,
};

const SEV_COLOR: Record<string, string> = {
  critical: "text-red-400 border-red-500/50",
  high:     "text-orange-400 border-orange-500/50",
  medium:   "text-amber-400 border-amber-500/50",
  low:      "text-blue-400 border-blue-500/50",
};

function timeLabel(ts: number) {
  const s = Math.floor((Date.now() - ts) / 1000);
  if (s < 3600) return `${Math.floor(s/60)}m ago`;
  return `${Math.floor(s/3600)}h ago`;
}

// ─── Attack Chain Strip ───────────────────────────────────────────────────────
function AttackChainStrip({ events }: { events: TimelineEvent[] }) {
  const activePhasesSet = new Set(events.map(e => e.phase).filter(Boolean));

  return (
    <div className="flex items-center gap-0.5 overflow-x-auto pb-2">
      {PHASE_ORDER.map((phase, i) => {
        const isActive = activePhasesSet.has(phase);
        const meta = PHASE_META[phase];
        return (
          <React.Fragment key={phase}>
            <div className={`shrink-0 rounded px-2 py-1 text-xs font-medium border ${
              isActive ? meta.color : "border-white/10 bg-white/5 text-white/30"
            }`}>
              {meta.label}
            </div>
            {i < PHASE_ORDER.length - 1 && (
              <ChevronRight className={`h-3 w-3 shrink-0 ${isActive ? "text-white/40" : "text-white/15"}`} />
            )}
          </React.Fragment>
        );
      })}
    </div>
  );
}

// ─── Single Event Card ────────────────────────────────────────────────────────
function EventCard({ event }: { event: TimelineEvent }) {
  const [expanded, setExpanded] = useState(false);
  const phase = event.phase ? PHASE_META[event.phase] : null;

  return (
    <div className={`flex gap-3 group`}>
      {/* Left: Time + line */}
      <div className="flex flex-col items-center w-16 shrink-0 pt-1">
        <span className="text-xs text-white/40 tabular-nums">{timeLabel(event.timestamp)}</span>
        <div className="w-px flex-1 bg-white/10 mt-1" />
      </div>

      {/* Dot */}
      <div className="mt-1 shrink-0">
        <div className={`h-3 w-3 rounded-full border-2 ${
          event.blocked ? "bg-red-500 border-red-400" : "bg-amber-500 border-amber-400"
        }`} />
      </div>

      {/* Card */}
      <div className={`flex-1 mb-3 rounded-xl border p-3 transition-all ${SEV_COLOR[event.severity]} bg-gray-900/60`}>
        <div className="flex items-start gap-2">
          <div className="mt-0.5 text-white/40">{SOURCE_ICON[event.source]}</div>
          <div className="flex-1 min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-semibold text-sm text-white">{event.title}</span>
              {phase && (
                <span className={`rounded-full px-2 py-0.5 text-xs border ${phase.color}`}>
                  {phase.label}
                </span>
              )}
              {event.mitre_id && (
                <span className="rounded bg-white/10 px-1.5 py-0.5 text-xs font-mono text-white/60">
                  {event.mitre_id}
                </span>
              )}
              {event.blocked && (
                <span className="rounded-full bg-red-950 border border-red-700 px-2 py-0.5 text-xs text-red-300">
                  🚫 Blocked
                </span>
              )}
            </div>
            <p className="text-xs text-white/60 mt-1">{event.description}</p>
            {(event.src_ip || event.dst_ip) && (
              <div className="mt-1 flex gap-3 text-xs font-mono text-cyan-400/70">
                {event.src_ip && <span>src: {event.src_ip}</span>}
                {event.dst_ip && <span>dst: {event.dst_ip}</span>}
              </div>
            )}
          </div>
          <button onClick={() => setExpanded(!expanded)} className="shrink-0 text-white/30 hover:text-white/70">
            <ChevronDown className={`h-4 w-4 transition-transform ${expanded ? "rotate-180" : ""}`} />
          </button>
        </div>

        {expanded && event.evidence && (
          <div className="mt-3 rounded-lg bg-black/30 p-2.5">
            <div className="text-xs font-semibold text-white/50 mb-1.5">Evidence</div>
            <ul className="space-y-0.5">
              {event.evidence.map((e, i) => (
                <li key={i} className="flex items-start gap-1.5 text-xs text-white/70">
                  <span className="text-cyan-500 mt-0.5">•</span>
                  <span>{e}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Page ─────────────────────────────────────────────────────────────────────
export default function IncidentTimeline() {
  const [filter, setFilter] = useState<EventSource | "all">("all");
  const filtered = filter === "all" ? MOCK_EVENTS : MOCK_EVENTS.filter(e => e.source === filter);
  const sorted = [...filtered].sort((a, b) => a.timestamp - b.timestamp);

  return (
    <div className="flex h-full flex-col bg-gray-950 text-white overflow-hidden">
      <div className="shrink-0 border-b border-white/10 px-6 py-4 space-y-3">
        <div className="flex items-center gap-3">
          <Clock className="h-5 w-5 text-cyan-400" />
          <h1 className="text-lg font-bold">Incident Timeline</h1>
          <span className="ml-auto text-xs text-white/40">{MOCK_EVENTS.length} events · MITRE ATT&CK mapped</span>
        </div>
        <AttackChainStrip events={MOCK_EVENTS} />
        <div className="flex gap-2">
          {(["all", "network", "endpoint", "ueba", "threat_intel", "soar"] as const).map(f => (
            <button key={f} onClick={() => setFilter(f)}
              className={`rounded-full px-3 py-1 text-xs font-medium transition-colors ${
                filter === f ? "bg-cyan-600 text-white" : "bg-white/5 text-white/50 hover:bg-white/10"
              }`}>
              {f === "all" ? "All Sources" : f.replace("_", " ")}
            </button>
          ))}
        </div>
      </div>
      <div className="flex-1 overflow-y-auto px-6 py-4">
        {sorted.map(event => <EventCard key={event.id} event={event} />)}
      </div>
    </div>
  );
}
