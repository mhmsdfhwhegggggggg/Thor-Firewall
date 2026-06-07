// Thor Firewall Dashboard — Real-Time Statistics Panel
import React from "react";
import {
  Shield, Zap, Brain, Activity, TrendingDown, TrendingUp,
  Eye, CheckCircle, XCircle, AlertTriangle
} from "lucide-react";
import type { MLStats, NetworkStats, SystemStats } from "../../types";

// ============================================================================
// Helpers
// ============================================================================

function fmt(n: number, decimals = 0): string {
  if (n >= 1e9) return `${(n / 1e9).toFixed(1)}B`;
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)}M`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(1)}K`;
  return n.toFixed(decimals);
}

function pct(n: number, d = 1): string {
  return `${(n * 100).toFixed(d)}%`;
}

function uptime(seconds: number): string {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

// ============================================================================
// Stat Card
// ============================================================================

interface StatCardProps {
  title: string;
  value: string;
  sub?: string;
  icon: React.ReactNode;
  color: "cyan" | "red" | "amber" | "green" | "violet" | "indigo";
  trend?: "up" | "down" | "neutral";
  trendLabel?: string;
}

const COLOR_MAP = {
  cyan:   { bg: "bg-cyan-500/10",   border: "border-cyan-500/20",   text: "text-cyan-400",   icon: "text-cyan-400" },
  red:    { bg: "bg-red-500/10",    border: "border-red-500/20",    text: "text-red-400",    icon: "text-red-400"  },
  amber:  { bg: "bg-amber-500/10",  border: "border-amber-500/20",  text: "text-amber-400",  icon: "text-amber-400"},
  green:  { bg: "bg-green-500/10",  border: "border-green-500/20",  text: "text-green-400",  icon: "text-green-400"},
  violet: { bg: "bg-violet-500/10", border: "border-violet-500/20", text: "text-violet-400", icon: "text-violet-400"},
  indigo: { bg: "bg-indigo-500/10", border: "border-indigo-500/20", text: "text-indigo-400", icon: "text-indigo-400"},
};

function StatCard({ title, value, sub, icon, color, trend, trendLabel }: StatCardProps) {
  const c = COLOR_MAP[color];
  return (
    <div className={`relative overflow-hidden rounded-xl border ${c.border} ${c.bg} p-4 transition-all hover:brightness-110`}>
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-medium text-white/50 uppercase tracking-wider">{title}</p>
          <p className={`mt-1 text-2xl font-bold tabular-nums ${c.text}`}>{value}</p>
          {sub && <p className="mt-0.5 text-xs text-white/40">{sub}</p>}
        </div>
        <div className={`rounded-lg ${c.bg} p-2 ${c.icon}`}>{icon}</div>
      </div>
      {trend && trendLabel && (
        <div className="mt-2 flex items-center gap-1 text-xs">
          {trend === "up"   && <TrendingUp   className="h-3 w-3 text-green-400" />}
          {trend === "down" && <TrendingDown  className="h-3 w-3 text-red-400"   />}
          <span className="text-white/40">{trendLabel}</span>
        </div>
      )}
    </div>
  );
}

// ============================================================================
// Accuracy Bar
// ============================================================================

function AccuracyBar({ value, label, color }: { value: number; label: string; color: string }) {
  return (
    <div>
      <div className="flex justify-between text-xs text-white/50 mb-1">
        <span>{label}</span>
        <span className="text-white/80">{pct(value)}</span>
      </div>
      <div className="h-1.5 rounded-full bg-white/10">
        <div
          className={`h-full rounded-full ${color} transition-all duration-500`}
          style={{ width: `${value * 100}%` }}
        />
      </div>
    </div>
  );
}

// ============================================================================
// Main Component
// ============================================================================

interface RealTimeStatsProps {
  network: NetworkStats;
  system:  SystemStats;
  ml:      MLStats;
}

export function RealTimeStats({ network, system, ml }: RealTimeStatsProps) {
  return (
    <div className="flex flex-col gap-4">
      {/* ===== Row 1: Core Metrics ===== */}
      <div className="grid grid-cols-4 gap-3 xl:grid-cols-8">
        <div className="xl:col-span-2">
          <StatCard
            title="Packets / Second"
            value={fmt(network.packetsPerSecond)}
            sub={`${fmt(network.totalPackets)} total`}
            icon={<Zap className="h-5 w-5" />}
            color="cyan"
            trend="up"
            trendLabel="↑ 12% vs last hour"
          />
        </div>
        <div className="xl:col-span-2">
          <StatCard
            title="Active Flows"
            value={fmt(network.activeFlows)}
            sub={`${pct(network.tableUtilization)} table fill`}
            icon={<Activity className="h-5 w-5" />}
            color="indigo"
          />
        </div>
        <div className="xl:col-span-2">
          <StatCard
            title="Blocked Flows"
            value={fmt(network.blockedFlows)}
            sub={`${fmt(network.suspiciousFlows)} suspicious`}
            icon={<Shield className="h-5 w-5" />}
            color="red"
            trend="down"
            trendLabel="↓ 3% vs last hour"
          />
        </div>
        <div className="xl:col-span-2">
          <StatCard
            title="Throughput"
            value={`${fmt(network.throughputMbps, 1)} Mbps`}
            sub={`${(network.bitsPerSecond / 1e9).toFixed(2)} Gbps`}
            icon={<TrendingUp className="h-5 w-5" />}
            color="green"
          />
        </div>
      </div>

      {/* ===== Row 2: AI + System ===== */}
      <div className="grid grid-cols-3 gap-3">
        {/* AI Stats */}
        <div className="col-span-1 rounded-xl border border-white/10 bg-gray-900/60 p-4">
          <div className="flex items-center gap-2 mb-3">
            <Brain className="h-4 w-4 text-violet-400" />
            <span className="text-sm font-semibold text-white/70">AI Engine</span>
          </div>
          <div className="space-y-3">
            <AccuracyBar value={ml.currentAccuracy}    label="Overall Accuracy"   color="bg-violet-500" />
            <AccuracyBar value={1 - ml.falsePositives / Math.max(1, ml.totalAnalyzed)}
                         label="Precision (FP rate)"  color="bg-cyan-500" />
            <AccuracyBar value={1 - ml.falseNegatives / Math.max(1, ml.totalAnalyzed)}
                         label="Recall (FN rate)"     color="bg-green-500" />
          </div>
          <div className="mt-3 grid grid-cols-2 gap-2 text-xs">
            <div className="rounded-lg bg-white/5 p-2 text-center">
              <p className="text-white/40">Inference</p>
              <p className="font-bold text-violet-400">{ml.avgLatencyUs}µs</p>
            </div>
            <div className="rounded-lg bg-white/5 p-2 text-center">
              <p className="text-white/40">Analyzed</p>
              <p className="font-bold text-cyan-400">{fmt(ml.totalAnalyzed)}</p>
            </div>
          </div>
        </div>

        {/* System Health */}
        <div className="col-span-1 rounded-xl border border-white/10 bg-gray-900/60 p-4">
          <div className="flex items-center gap-2 mb-3">
            <Activity className="h-4 w-4 text-green-400" />
            <span className="text-sm font-semibold text-white/70">System Health</span>
          </div>
          <div className="space-y-2.5">
            <AccuracyBar value={system.agentCpuPct / 100}
                         label={`CPU — Agent (${system.agentCpuPct.toFixed(1)}%)`}
                         color="bg-green-500" />
            <AccuracyBar value={Math.min(1, system.agentMemoryMb / 1024)}
                         label={`Memory — ${system.agentMemoryMb}MB`}
                         color="bg-amber-500" />
            <AccuracyBar value={system.ebpfMapUtilization}
                         label={`eBPF Map Fill (${pct(system.ebpfMapUtilization)})`}
                         color={system.ebpfMapUtilization > 0.9 ? "bg-red-500" : "bg-cyan-500"} />
          </div>
          <div className="mt-3 grid grid-cols-2 gap-2 text-xs">
            <div className="rounded-lg bg-white/5 p-2 text-center">
              <p className="text-white/40">RL Latency</p>
              <p className="font-bold text-green-400">{system.rlInferenceLatencyUs}µs</p>
            </div>
            <div className="rounded-lg bg-white/5 p-2 text-center">
              <p className="text-white/40">Uptime</p>
              <p className="font-bold text-green-400">{uptime(system.uptime)}</p>
            </div>
          </div>
        </div>

        {/* Decision Summary */}
        <div className="col-span-1 rounded-xl border border-white/10 bg-gray-900/60 p-4">
          <div className="flex items-center gap-2 mb-3">
            <Eye className="h-4 w-4 text-cyan-400" />
            <span className="text-sm font-semibold text-white/70">Decision Summary</span>
          </div>
          <div className="space-y-2">
            {[
              { icon: <CheckCircle className="h-4 w-4" />, label: "Allowed", value: fmt(ml.totalAllowed),  color: "text-green-400", bg: "bg-green-500/10" },
              { icon: <XCircle     className="h-4 w-4" />, label: "Blocked", value: fmt(ml.totalBlocked),  color: "text-red-400",   bg: "bg-red-500/10"   },
              { icon: <AlertTriangle className="h-4 w-4"/>,label: "False +",  value: String(ml.falsePositives), color: "text-amber-400", bg: "bg-amber-500/10"},
              { icon: <AlertTriangle className="h-4 w-4"/>,label: "False −",  value: String(ml.falseNegatives), color: "text-orange-400",bg: "bg-orange-500/10"},
            ].map((item) => (
              <div key={item.label}
                   className={`flex items-center justify-between rounded-lg ${item.bg} px-3 py-2`}>
                <div className={`flex items-center gap-2 ${item.color}`}>
                  {item.icon}
                  <span className="text-xs font-medium">{item.label}</span>
                </div>
                <span className={`text-sm font-bold tabular-nums ${item.color}`}>{item.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
