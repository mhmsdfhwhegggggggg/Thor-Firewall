// Thor Firewall Dashboard — Real-Time Stats Cards
import React, { memo } from "react";
import { Activity, Shield, Zap, AlertTriangle, TrendingUp, Wifi } from "lucide-react";
import type { NetworkStats, SystemStats, MLStats } from "../../types";

interface StatCardProps {
  icon: React.ReactNode;
  label: string;
  value: string | number;
  sub?: string;
  color?: "blue" | "green" | "red" | "amber" | "violet" | "cyan";
  pulse?: boolean;
}

function StatCard({ icon, label, value, sub, color = "blue", pulse = false }: StatCardProps) {
  const colors = {
    blue:   "from-blue-900/60 to-blue-800/40 border-blue-700/50 text-blue-400",
    green:  "from-green-900/60 to-green-800/40 border-green-700/50 text-green-400",
    red:    "from-red-900/60 to-red-800/40 border-red-700/50 text-red-400",
    amber:  "from-amber-900/60 to-amber-800/40 border-amber-700/50 text-amber-400",
    violet: "from-violet-900/60 to-violet-800/40 border-violet-700/50 text-violet-400",
    cyan:   "from-cyan-900/60 to-cyan-800/40 border-cyan-700/50 text-cyan-400",
  };

  return (
    <div className={`relative rounded-xl border bg-gradient-to-br p-4 ${colors[color]}`}>
      {pulse && (
        <span className="absolute right-3 top-3 flex h-2 w-2">
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-red-400 opacity-75" />
          <span className="relative inline-flex h-2 w-2 rounded-full bg-red-500" />
        </span>
      )}
      <div className="flex items-start gap-3">
        <div className="mt-0.5 shrink-0">{icon}</div>
        <div className="min-w-0 flex-1">
          <p className="text-xs font-medium uppercase tracking-wider opacity-70">{label}</p>
          <p className="mt-1 truncate text-2xl font-bold text-white">{value}</p>
          {sub && <p className="mt-0.5 truncate text-xs opacity-60">{sub}</p>}
        </div>
      </div>
    </div>
  );
}

// ============================================================================

function fmtBytes(bytes: number): string {
  if (bytes >= 1e12) return `${(bytes / 1e12).toFixed(1)}T`;
  if (bytes >= 1e9)  return `${(bytes / 1e9).toFixed(1)}G`;
  if (bytes >= 1e6)  return `${(bytes / 1e6).toFixed(1)}M`;
  if (bytes >= 1e3)  return `${(bytes / 1e3).toFixed(1)}K`;
  return String(bytes);
}

function fmtNum(n: number): string {
  if (n >= 1e9) return `${(n / 1e9).toFixed(2)}B`;
  if (n >= 1e6) return `${(n / 1e6).toFixed(2)}M`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(2)}K`;
  return String(n);
}

// ============================================================================

interface Props {
  network: NetworkStats;
  system: SystemStats;
  ml: MLStats;
}

export const RealTimeStats = memo(function RealTimeStats({ network, system, ml }: Props) {
  const utilPct = Math.round(network.tableUtilization * 100);
  const accuracy = (ml.currentAccuracy * 100).toFixed(1);
  const fps = system.ebpfMapUtilization > 0.9;

  return (
    <div className="grid grid-cols-2 gap-3 xl:grid-cols-3 2xl:grid-cols-6">
      <StatCard
        icon={<Wifi className="h-5 w-5" />}
        label="Throughput"
        value={`${network.throughputMbps.toFixed(0)} Mbps`}
        sub={`${fmtNum(network.packetsPerSecond)} pps`}
        color="cyan"
      />
      <StatCard
        icon={<Activity className="h-5 w-5" />}
        label="Active Flows"
        value={fmtNum(network.activeFlows)}
        sub={`${utilPct}% table`}
        color="blue"
        pulse={utilPct > 85}
      />
      <StatCard
        icon={<Shield className="h-5 w-5" />}
        label="Blocked"
        value={fmtNum(network.blockedFlows)}
        sub="flows blocked today"
        color="red"
        pulse={network.blockedFlows > 0}
      />
      <StatCard
        icon={<AlertTriangle className="h-5 w-5" />}
        label="Suspicious"
        value={fmtNum(network.suspiciousFlows)}
        sub="under analysis"
        color="amber"
      />
      <StatCard
        icon={<Zap className="h-5 w-5" />}
        label="AI Latency"
        value={`${system.rlInferenceLatencyUs.toFixed(0)} μs`}
        sub={`${ml.totalAnalyzed.toLocaleString()} analyzed`}
        color="violet"
      />
      <StatCard
        icon={<TrendingUp className="h-5 w-5" />}
        label="ML Accuracy"
        value={`${accuracy}%`}
        sub={`FP: ${ml.falsePositives} | FN: ${ml.falseNegatives}`}
        color="green"
      />
    </div>
  );
});
