// Thor Firewall Dashboard — Live Threat Feed
import React, { memo, useMemo } from "react";
import { AlertOctagon, AlertTriangle, Info, ShieldOff, Clock } from "lucide-react";
import type { ThreatEvent, Severity } from "../../types";

const SEVERITY_META: Record<Severity, { label: string; icon: React.ReactNode; classes: string }> = {
  critical: {
    label: "CRITICAL",
    icon: <AlertOctagon className="h-4 w-4" />,
    classes: "border-red-500 bg-red-950/60 text-red-400",
  },
  high: {
    label: "HIGH",
    icon: <AlertTriangle className="h-4 w-4" />,
    classes: "border-orange-500 bg-orange-950/60 text-orange-400",
  },
  medium: {
    label: "MEDIUM",
    icon: <AlertTriangle className="h-4 w-4" />,
    classes: "border-amber-500 bg-amber-950/60 text-amber-400",
  },
  low: {
    label: "LOW",
    icon: <Info className="h-4 w-4" />,
    classes: "border-blue-500 bg-blue-950/60 text-blue-400",
  },
};

function timeAgo(ts: number): string {
  const s = Math.floor((Date.now() - ts) / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  return `${Math.floor(m / 60)}h ago`;
}

interface ThreatRowProps {
  event: ThreatEvent;
  onBlock?: (event: ThreatEvent) => void;
}

const ThreatRow = memo(function ThreatRow({ event, onBlock }: ThreatRowProps) {
  const meta = SEVERITY_META[event.severity];

  return (
    <div
      className={`group flex items-start gap-3 rounded-lg border p-3 transition-all hover:brightness-110 ${meta.classes}`}
    >
      <div className="mt-0.5 shrink-0">{meta.icon}</div>

      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs font-bold tracking-widest">{meta.label}</span>
          <span className="rounded bg-white/10 px-1.5 py-0.5 text-xs font-mono text-white/80">
            {event.threatType}
          </span>
          {event.mitreTechnique && (
            <span className="rounded bg-white/10 px-1.5 py-0.5 text-xs font-mono text-white/60">
              {event.mitreTechnique}
            </span>
          )}
          <span className="ml-auto flex items-center gap-1 text-xs text-white/50">
            <Clock className="h-3 w-3" />
            {timeAgo(event.timestamp)}
          </span>
        </div>

        <div className="mt-1 font-mono text-sm text-white/90">
          {event.flow.srcIp}:{event.flow.srcPort}
          <span className="mx-2 text-white/40">→</span>
          {event.flow.dstIp}:{event.flow.dstPort}
          <span className="ml-2 text-white/40">[{event.flow.protocol.toUpperCase()}]</span>
        </div>

        <div className="mt-1 flex items-center gap-4 text-xs text-white/60">
          <span>Risk: <strong className="text-white/90">{(event.riskScore * 100).toFixed(0)}%</strong></span>
          <span>Confidence: <strong className="text-white/90">{(event.confidence * 100).toFixed(0)}%</strong></span>
          {event.blocked
            ? <span className="text-red-400">● Blocked</span>
            : <span className="text-amber-400">● Monitoring</span>
          }
          <span>Agent: <span className="font-mono">{event.agentId}</span></span>
        </div>

        {event.explanation && (
          <p className="mt-1.5 text-xs text-white/50 italic">{event.explanation}</p>
        )}
      </div>

      {!event.blocked && onBlock && (
        <button
          onClick={() => onBlock(event)}
          className="hidden shrink-0 items-center gap-1 rounded bg-red-800/60 px-2 py-1 text-xs font-medium text-red-300 hover:bg-red-700/80 group-hover:flex"
        >
          <ShieldOff className="h-3 w-3" />
          Block
        </button>
      )}
    </div>
  );
});

// ============================================================================

interface Props {
  events: ThreatEvent[];
  onBlock?: (event: ThreatEvent) => void;
  filter?: Severity | "all";
  maxHeight?: string;
}

export const ThreatFeed = memo(function ThreatFeed({
  events,
  onBlock,
  filter = "all",
  maxHeight = "480px",
}: Props) {
  const filtered = useMemo(
    () =>
      filter === "all"
        ? events
        : events.filter((e) => e.severity === filter),
    [events, filter]
  );

  const counts = useMemo(
    () => ({
      critical: events.filter((e) => e.severity === "critical").length,
      high: events.filter((e) => e.severity === "high").length,
      medium: events.filter((e) => e.severity === "medium").length,
      low: events.filter((e) => e.severity === "low").length,
    }),
    [events]
  );

  return (
    <div className="flex h-full flex-col gap-3">
      {/* Header */}
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="text-sm font-semibold text-white/90">Live Threat Feed</h3>
        <div className="ml-auto flex gap-2 text-xs">
          {(["critical", "high", "medium", "low"] as Severity[]).map((s) => (
            <span key={s} className={`rounded px-2 py-0.5 font-mono ${SEVERITY_META[s].classes}`}>
              {counts[s]} {s}
            </span>
          ))}
        </div>
      </div>

      {/* Feed */}
      <div
        className="flex flex-col gap-2 overflow-y-auto pr-1 scrollbar-thin scrollbar-track-transparent scrollbar-thumb-white/10"
        style={{ maxHeight }}
      >
        {filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-white/30">
            <Shield className="mb-3 h-12 w-12" />
            <p className="text-sm">No threats detected</p>
          </div>
        ) : (
          filtered.map((event) => (
            <ThreatRow key={event.eventId} event={event} onBlock={onBlock} />
          ))
        )}
      </div>
    </div>
  );
});
