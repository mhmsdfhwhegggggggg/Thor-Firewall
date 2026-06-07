// Thor Firewall Dashboard — Throughput Time-Series Chart
import React, { memo, useEffect, useRef, useState } from "react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";
import type { ChartDataPoint } from "../../types";

interface DataPoint {
  time: string;
  throughputMbps: number;
  blockedPps: number;
  suspiciousPps: number;
}

interface Props {
  /** Current throughput in Mbps */
  currentMbps: number;
  /** Current blocked flows per second */
  blockedPps: number;
  /** Current suspicious flows per second */
  suspiciousPps: number;
  /** Window size in seconds (default 120) */
  windowSecs?: number;
}

function formatTime(ts: number): string {
  const d = new Date(ts);
  return `${d.getMinutes().toString().padStart(2, "0")}:${d.getSeconds().toString().padStart(2, "0")}`;
}

export const ThroughputChart = memo(function ThroughputChart({
  currentMbps,
  blockedPps,
  suspiciousPps,
  windowSecs = 120,
}: Props) {
  const [history, setHistory] = useState<DataPoint[]>([]);
  const tsRef = useRef(Date.now());

  useEffect(() => {
    const now = Date.now();
    setHistory((prev) => {
      const cutoff = now - windowSecs * 1000;
      const trimmed = prev.filter((p) => {
        const t = new Date(`1970-01-01T${p.time}:00`).getTime();
        return t > cutoff;
      });
      return [
        ...trimmed,
        {
          time: formatTime(now),
          throughputMbps: Math.round(currentMbps * 100) / 100,
          blockedPps: Math.round(blockedPps),
          suspiciousPps: Math.round(suspiciousPps),
        },
      ].slice(-windowSecs);
    });
  }, [currentMbps, blockedPps, suspiciousPps, windowSecs]);

  const CustomTooltip = ({ active, payload, label }: any) => {
    if (!active || !payload?.length) return null;
    return (
      <div className="rounded-lg border border-white/10 bg-gray-900/95 p-3 text-xs shadow-xl backdrop-blur">
        <p className="mb-2 font-mono font-bold text-white">{label}</p>
        {payload.map((p: any) => (
          <div key={p.name} className="flex items-center gap-2">
            <span
              className="inline-block h-2 w-2 rounded-full"
              style={{ background: p.color }}
            />
            <span className="text-white/70">{p.name}:</span>
            <span className="font-mono font-semibold" style={{ color: p.color }}>
              {p.value} {p.name === "throughputMbps" ? "Mbps" : "pps"}
            </span>
          </div>
        ))}
      </div>
    );
  };

  return (
    <div className="h-full w-full">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={history} margin={{ top: 5, right: 10, left: -10, bottom: 0 }}>
          <defs>
            <linearGradient id="throughputGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
              <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
            </linearGradient>
            <linearGradient id="blockedGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4} />
              <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
            </linearGradient>
            <linearGradient id="suspiciousGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.3} />
              <stop offset="95%" stopColor="#f59e0b" stopOpacity={0} />
            </linearGradient>
          </defs>

          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />

          <XAxis
            dataKey="time"
            tick={{ fill: "rgba(255,255,255,0.4)", fontSize: 10 }}
            tickLine={false}
            axisLine={{ stroke: "rgba(255,255,255,0.1)" }}
            interval="preserveStartEnd"
          />

          <YAxis
            tick={{ fill: "rgba(255,255,255,0.4)", fontSize: 10 }}
            tickLine={false}
            axisLine={false}
            width={45}
          />

          <Tooltip content={<CustomTooltip />} />

          <Legend
            wrapperStyle={{ fontSize: 11, color: "rgba(255,255,255,0.5)", paddingTop: 8 }}
          />

          <Area
            type="monotone"
            dataKey="throughputMbps"
            name="Throughput (Mbps)"
            stroke="#06b6d4"
            strokeWidth={2}
            fill="url(#throughputGrad)"
            dot={false}
            activeDot={{ r: 4, fill: "#06b6d4" }}
            isAnimationActive={false}
          />
          <Area
            type="monotone"
            dataKey="blockedPps"
            name="Blocked (pps)"
            stroke="#ef4444"
            strokeWidth={1.5}
            fill="url(#blockedGrad)"
            dot={false}
            activeDot={{ r: 4, fill: "#ef4444" }}
            isAnimationActive={false}
          />
          <Area
            type="monotone"
            dataKey="suspiciousPps"
            name="Suspicious (pps)"
            stroke="#f59e0b"
            strokeWidth={1.5}
            fill="url(#suspiciousGrad)"
            dot={false}
            activeDot={{ r: 4, fill: "#f59e0b" }}
            isAnimationActive={false}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
});
