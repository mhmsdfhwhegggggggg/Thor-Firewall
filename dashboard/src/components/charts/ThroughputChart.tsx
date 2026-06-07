// Thor Firewall Dashboard — Throughput & Threat Rate Chart
import React, { useEffect, useRef, useState } from "react";
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, Area, AreaChart, Legend
} from "recharts";

// ============================================================================
// Data point
// ============================================================================

interface DataPoint {
  time:      string;
  mbps:      number;
  blocked:   number;
  suspicious: number;
}

function now(): string {
  return new Date().toLocaleTimeString("en", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

// ============================================================================
// Custom Tooltip
// ============================================================================

function CustomTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-lg border border-white/10 bg-gray-900 p-3 text-xs shadow-xl">
      <p className="mb-2 text-white/50">{label}</p>
      {payload.map((p: any) => (
        <div key={p.name} className="flex justify-between gap-4" style={{ color: p.color }}>
          <span>{p.name}</span>
          <span className="font-mono font-bold">
            {p.name === "Mbps"
              ? `${Number(p.value).toFixed(1)} Mb/s`
              : p.name === "Blocked"
              ? `${Number(p.value).toFixed(0)}/s`
              : `${Number(p.value).toFixed(0)}/s`}
          </span>
        </div>
      ))}
    </div>
  );
}

// ============================================================================
// Component
// ============================================================================

interface ThroughputChartProps {
  currentMbps:    number;
  blockedPps:     number;
  suspiciousPps:  number;
  maxPoints?:     number;
}

export function ThroughputChart({
  currentMbps,
  blockedPps,
  suspiciousPps,
  maxPoints = 60,
}: ThroughputChartProps) {
  const [data, setData] = useState<DataPoint[]>(() =>
    Array.from({ length: maxPoints }, (_, i) => ({
      time:       new Date(Date.now() - (maxPoints - i) * 1000).toLocaleTimeString("en", {
                    hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit"
                  }),
      mbps:       currentMbps * (0.85 + Math.random() * 0.3),
      blocked:    blockedPps  * (0.8  + Math.random() * 0.4),
      suspicious: suspiciousPps * (0.7 + Math.random() * 0.6),
    }))
  );

  // Add a new point every second
  useEffect(() => {
    const interval = setInterval(() => {
      setData((prev) => {
        const next = [...prev.slice(-(maxPoints - 1)), {
          time:       now(),
          mbps:       currentMbps    * (0.9 + Math.random() * 0.2),
          blocked:    blockedPps     * (0.8 + Math.random() * 0.4),
          suspicious: suspiciousPps  * (0.7 + Math.random() * 0.6),
        }];
        return next;
      });
    }, 1000);
    return () => clearInterval(interval);
  }, [currentMbps, blockedPps, suspiciousPps, maxPoints]);

  return (
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart data={data} margin={{ top: 5, right: 5, bottom: 0, left: 0 }}>
        <defs>
          <linearGradient id="gradMbps" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%"  stopColor="#06b6d4" stopOpacity={0.3} />
            <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.02} />
          </linearGradient>
          <linearGradient id="gradBlocked" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%"  stopColor="#ef4444" stopOpacity={0.25} />
            <stop offset="95%" stopColor="#ef4444" stopOpacity={0.02} />
          </linearGradient>
          <linearGradient id="gradSuspicious" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%"  stopColor="#f59e0b" stopOpacity={0.2} />
            <stop offset="95%" stopColor="#f59e0b" stopOpacity={0.02} />
          </linearGradient>
        </defs>

        <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />

        <XAxis
          dataKey="time"
          tick={{ fill: "rgba(255,255,255,0.3)", fontSize: 9 }}
          tickLine={false}
          axisLine={false}
          interval={Math.floor(maxPoints / 6)}
        />
        <YAxis
          tick={{ fill: "rgba(255,255,255,0.3)", fontSize: 9 }}
          tickLine={false}
          axisLine={false}
          width={40}
        />
        <Tooltip content={<CustomTooltip />} />
        <Legend
          wrapperStyle={{ fontSize: 10, color: "rgba(255,255,255,0.4)" }}
          iconSize={8}
          iconType="circle"
        />

        <Area
          type="monotone"
          dataKey="mbps"
          name="Mbps"
          stroke="#06b6d4"
          strokeWidth={1.5}
          fill="url(#gradMbps)"
          dot={false}
          activeDot={{ r: 3, fill: "#06b6d4" }}
        />
        <Area
          type="monotone"
          dataKey="blocked"
          name="Blocked"
          stroke="#ef4444"
          strokeWidth={1}
          fill="url(#gradBlocked)"
          dot={false}
          activeDot={{ r: 3, fill: "#ef4444" }}
        />
        <Area
          type="monotone"
          dataKey="suspicious"
          name="Suspicious"
          stroke="#f59e0b"
          strokeWidth={1}
          fill="url(#gradSuspicious)"
          dot={false}
          activeDot={{ r: 3, fill: "#f59e0b" }}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}
