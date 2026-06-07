// Thor Firewall Dashboard — Live Threat Feed
import React, { useRef, useEffect } from "react";
import { AlertTriangle, ShieldOff, Shield, Clock, ExternalLink } from "lucide-react";
import type { Severity, ThreatEvent } from "../../types";

// ============================================================================
// Severity styling
// ============================================================================

const SEV_CONFIG: Record<Severity, { border: string; bg: string; text: string; icon: React.ReactNode }> = {
  low:      { border: "border-blue-500/30",  bg: "bg-blue-500/10",  text: "text-blue-400",   icon: <AlertTriangle className="h-3.5 w-3.5" /> },
  medium:   { border: "border-amber-500/30", bg: "bg-amber-500/10", text: "text-amber-400",  icon: <AlertTriangle className="h-3.5 w-3.5" /> },
  high:     { border: "border-orange-500/30",bg: "bg-orange-500/10",text: "text-orange-400", icon: <ShieldOff     className="h-3.5 w-3.5" /> },
  critical: { border: "border-red-500/40",   bg: "bg-red-500/15",   text: "text-red-400",    icon: <ShieldOff     className="h-3.5 w-3.5" /> },
};

// ============================================================================
// Single threat card
// ============================================================================

function ago(ts: number): string {
  const s = Math.floor((Date.now() - ts) / 1000);
  if (s < 60)   return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  return `${Math.floor(s / 3600)}h ago`;
}

interface ThreatCardProps {
  event: ThreatEvent;
  isNew?: boolean;
}

function ThreatCard({ event, isNew }: ThreatCardProps) {
  const sev = SEV_CONFIG[event.severity];

  return (
    <div
      className={`rounded-lg border ${sev.border} ${sev.bg} p-3 transition-all duration-300 ${
        isNew ? "ring-1 ring-white/20 animate-pulse-once" : ""
      }`}
    >
      {/* Header row */}
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <span className={sev.text}>{sev.icon}</span>
          <span className={`text-xs font-semibold uppercase tracking-wide ${sev.text}`}>
            {event.severity}
          </span>
          <span className="text-xs font-medium text-white/80 truncate">{event.threatType}</span>
        </div>
        <div className="flex shrink-0 items-center gap-2 text-[10px] text-white/40">
          <Clock className="h-3 w-3" />
          {ago(event.timestamp)}
        </div>
      </div>

      {/* Flow info */}
      <div className="mt-2 flex flex-wrap gap-x-4 gap-y-0.5 font-mono text-[10px] text-white/50">
        <span>
          <span className="text-white/30">SRC </span>
          <span className="text-white/70">{event.flow.srcIp}:{event.flow.srcPort}</span>
        </span>
        <span className="text-white/20">→</span>
        <span>
          <span className="text-white/30">DST </span>
          <span className="text-white/70">{event.flow.dstIp}:{event.flow.dstPort}</span>
        </span>
        <span className="rounded bg-white/10 px-1 uppercase">{event.flow.protocol}</span>
      </div>

      {/* Explanation */}
      {event.explanation && (
        <p className="mt-1.5 text-[11px] text-white/50 leading-relaxed line-clamp-2">
          {event.explanation}
        </p>
      )}

      {/* Footer */}
      <div className="mt-2 flex items-center justify-between">
        <div className="flex items-center gap-3 text-[10px]">
          {/* Risk score bar */}
          <div className="flex items-center gap-1.5">
            <span className="text-white/30">Risk</span>
            <div className="h-1 w-16 rounded-full bg-white/10">
              <div
                className={`h-full rounded-full ${
                  event.riskScore > 0.7 ? "bg-red-500" :
                  event.riskScore > 0.4 ? "bg-amber-500" : "bg-green-500"
                }`}
                style={{ width: `${event.riskScore * 100}%` }}
              />
            </div>
            <span className={`font-mono ${sev.text}`}>{(event.riskScore * 100).toFixed(0)}%</span>
          </div>

          {/* MITRE */}
          {event.mitreTechnique && (
            <a
              href={`https://attack.mitre.org/techniques/${event.mitreTechnique.replace(".", "/")}/`}
              target="_blank"
              rel="noreferrer"
              className="flex items-center gap-0.5 rounded bg-white/5 px-1.5 py-0.5 text-white/30 hover:text-white/60"
            >
              {event.mitreTechnique}
              <ExternalLink className="h-2.5 w-2.5" />
            </a>
          )}
        </div>

        {/* Block status */}
        <div className={`flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-medium ${
          event.blocked
            ? "bg-green-500/20 text-green-400"
            : "bg-red-500/20 text-red-400"
        }`}>
          {event.blocked ? <Shield className="h-3 w-3" /> : <ShieldOff className="h-3 w-3" />}
          {event.blocked ? "Blocked" : "Active"}
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// Main Component
// ============================================================================

interface ThreatFeedProps {
  events:    ThreatEvent[];
  maxHeight?: string;
}

export function ThreatFeed({ events, maxHeight = "100%" }: ThreatFeedProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const isAtBottom   = useRef(true);

  // Auto-scroll to bottom if user is already at bottom
  useEffect(() => {
    const el = containerRef.current;
    if (!el || !isAtBottom.current) return;
    el.scrollTop = 0; // newest at top
  }, [events.length]);

  const criticalCount  = events.filter((e) => e.severity === "critical").length;
  const highCount      = events.filter((e) => e.severity === "high").length;
  const blockedCount   = events.filter((e) => e.blocked).length;

  return (
    <div className="flex flex-col h-full gap-3">
      {/* Header */}
      <div className="flex shrink-0 items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldOff className="h-4 w-4 text-red-400" />
          <span className="text-sm font-semibold text-white/70">Live Threat Feed</span>
          <span className="rounded-full bg-red-500/20 px-2 py-0.5 text-[10px] font-bold text-red-400">
            {events.length}
          </span>
        </div>
        <div className="flex gap-2 text-[10px]">
          {criticalCount > 0 && (
            <span className="rounded-full bg-red-500/20 px-2 py-0.5 text-red-400">
              {criticalCount} critical
            </span>
          )}
          {highCount > 0 && (
            <span className="rounded-full bg-orange-500/20 px-2 py-0.5 text-orange-400">
              {highCount} high
            </span>
          )}
          <span className="rounded-full bg-green-500/20 px-2 py-0.5 text-green-400">
            {blockedCount} blocked
          </span>
        </div>
      </div>

      {/* Feed */}
      <div
        ref={containerRef}
        className="flex-1 space-y-2 overflow-y-auto pr-1"
        style={{ maxHeight }}
        onScroll={(e) => {
          const el = e.currentTarget;
          isAtBottom.current = el.scrollTop < 100;
        }}
      >
        {events.length === 0 ? (
          <div className="flex h-32 items-center justify-center text-white/20 text-sm">
            No threats detected
          </div>
        ) : (
          events.map((event, i) => (
            <ThreatCard key={event.eventId} event={event} isNew={i === 0} />
          ))
        )}
      </div>
    </div>
  );
}
