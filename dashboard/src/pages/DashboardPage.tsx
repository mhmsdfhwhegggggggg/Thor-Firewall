/**
 * Thor Firewall — Main Dashboard Page
 * Real-time threat monitoring with live metrics.
 */
import React, { useEffect, useState, useCallback } from "react";
import {
  LineChart, Line, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer,
  AreaChart, Area,
} from "recharts";

// Types
interface ThreatSummary {
  total_threats: number;
  blocked: number;
  allowed: number;
  by_type: Record<string, number>;
  by_severity: Record<string, number>;
  top_attackers: Array<{ ip: string; count: number }>;
  time_series: Array<{ timestamp: number; total: number; blocked: number; by_type: Record<string, number> }>;
}

interface HealthComponent {
  status: "ok" | "degraded" | "down";
  latency_ms?: number;
  detail?: string;
}

interface SystemHealth {
  status: string;
  components: Record<string, HealthComponent>;
  timestamp: number;
}

// Constants
const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high:     "#f97316",
  medium:   "#eab308",
  low:      "#22c55e",
};

const TYPE_COLORS = [
  "#3b82f6", "#8b5cf6", "#ef4444", "#f97316",
  "#22c55e", "#06b6d4", "#ec4899", "#84cc16",
];

const API_BASE = import.meta.env.BASE_URL?.replace(/\/$/, "") ?? "";

// Hooks
function useThreatSummary(windowHours = 24) {
  const [data, setData] = useState<ThreatSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetch_ = useCallback(async () => {
    try {
      const r = await fetch(`${API_BASE}/api/threats/summary?window_hours=${windowHours}`, {
        headers: { "Authorization": `Bearer ${localStorage.getItem("thor_token") ?? ""}` },
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      setData(await r.json());
      setError(null);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [windowHours]);

  useEffect(() => {
    fetch_();
    const id = setInterval(fetch_, 15_000);
    return () => clearInterval(id);
  }, [fetch_]);

  return { data, loading, error, refetch: fetch_ };
}

function useSystemHealth() {
  const [data, setData] = useState<SystemHealth | null>(null);

  useEffect(() => {
    const fetch_ = async () => {
      try {
        const r = await fetch(`${API_BASE}/health`);
        if (r.ok) setData(await r.json());
      } catch {}
    };
    fetch_();
    const id = setInterval(fetch_, 10_000);
    return () => clearInterval(id);
  }, []);

  return data;
}

// ── Sub-components ─────────────────────────────────────────────────────────────

function MetricCard({
  title, value, sub, color = "#3b82f6", icon,
}: {
  title: string; value: string | number; sub?: string;
  color?: string; icon?: string;
}) {
  return (
    <div style={{
      background: "#1e293b", borderRadius: 12, padding: "20px 24px",
      borderLeft: `4px solid ${color}`, minWidth: 160,
    }}>
      {icon && <div style={{ fontSize: 28, marginBottom: 8 }}>{icon}</div>}
      <div style={{ color: "#94a3b8", fontSize: 13, marginBottom: 4 }}>{title}</div>
      <div style={{ color: "#f1f5f9", fontSize: 28, fontWeight: 700 }}>{value}</div>
      {sub && <div style={{ color: "#64748b", fontSize: 12, marginTop: 4 }}>{sub}</div>}
    </div>
  );
}

function StatusDot({ status }: { status: string }) {
  const color = status === "ok" ? "#22c55e" : status === "degraded" ? "#eab308" : "#ef4444";
  return (
    <span style={{
      display: "inline-block", width: 10, height: 10,
      borderRadius: "50%", background: color,
      boxShadow: `0 0 6px ${color}`,
    }} />
  );
}

function HealthPanel({ health }: { health: SystemHealth | null }) {
  if (!health) return null;
  const components = Object.entries(health.components ?? {});
  return (
    <div style={{ background: "#1e293b", borderRadius: 12, padding: 20 }}>
      <div style={{ color: "#94a3b8", fontSize: 13, marginBottom: 12, fontWeight: 600 }}>
        SYSTEM STATUS
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(180px, 1fr))", gap: 10 }}>
        {components.map(([name, comp]) => (
          <div key={name} style={{
            background: "#0f172a", borderRadius: 8, padding: "10px 14px",
            display: "flex", alignItems: "center", gap: 10,
          }}>
            <StatusDot status={comp.status} />
            <div>
              <div style={{ color: "#e2e8f0", fontSize: 13, fontWeight: 500 }}>
                {name.replace(/_/g, " ")}
              </div>
              {comp.latency_ms != null && (
                <div style={{ color: "#64748b", fontSize: 11 }}>
                  {comp.latency_ms.toFixed(1)}ms
                </div>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Time-series chart ─────────────────────────────────────────────────────────
function ThreatTimelineChart({ timeSeries }: {
  timeSeries: ThreatSummary["time_series"];
}) {
  const data = timeSeries.map(b => ({
    time:    new Date(b.timestamp * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    total:   b.total,
    blocked: b.blocked,
    allowed: b.total - b.blocked,
  }));

  return (
    <div style={{ background: "#1e293b", borderRadius: 12, padding: 20 }}>
      <div style={{ color: "#94a3b8", fontSize: 13, marginBottom: 16, fontWeight: 600 }}>
        THREAT TIMELINE (HOURLY)
      </div>
      <ResponsiveContainer width="100%" height={220}>
        <AreaChart data={data} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
          <defs>
            <linearGradient id="gradBlocked" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%"  stopColor="#ef4444" stopOpacity={0.3} />
              <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
            </linearGradient>
            <linearGradient id="gradAllowed" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%"  stopColor="#22c55e" stopOpacity={0.2} />
              <stop offset="95%" stopColor="#22c55e" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
          <XAxis dataKey="time" stroke="#475569" tick={{ fill: "#64748b", fontSize: 11 }} />
          <YAxis stroke="#475569" tick={{ fill: "#64748b", fontSize: 11 }} />
          <Tooltip
            contentStyle={{ background: "#0f172a", border: "1px solid #334155", borderRadius: 8 }}
            labelStyle={{ color: "#e2e8f0" }}
          />
          <Legend wrapperStyle={{ color: "#94a3b8", fontSize: 12 }} />
          <Area type="monotone" dataKey="blocked" stroke="#ef4444" fill="url(#gradBlocked)" name="Blocked" />
          <Area type="monotone" dataKey="allowed" stroke="#22c55e" fill="url(#gradAllowed)" name="Allowed" />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

// ── Threat type breakdown ─────────────────────────────────────────────────────
function ThreatTypeChart({ byType }: { byType: Record<string, number> }) {
  const data = Object.entries(byType)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([name, value]) => ({ name, value }));

  return (
    <div style={{ background: "#1e293b", borderRadius: 12, padding: 20 }}>
      <div style={{ color: "#94a3b8", fontSize: 13, marginBottom: 16, fontWeight: 600 }}>
        THREATS BY TYPE
      </div>
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={data} margin={{ top: 5, right: 10, left: 0, bottom: 30 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
          <XAxis dataKey="name" stroke="#475569" tick={{ fill: "#64748b", fontSize: 11 }}
                 angle={-30} textAnchor="end" />
          <YAxis stroke="#475569" tick={{ fill: "#64748b", fontSize: 11 }} />
          <Tooltip
            contentStyle={{ background: "#0f172a", border: "1px solid #334155", borderRadius: 8 }}
            labelStyle={{ color: "#e2e8f0" }}
          />
          <Bar dataKey="value" name="Count" radius={[4, 4, 0, 0]}>
            {data.map((_, i) => (
              <Cell key={i} fill={TYPE_COLORS[i % TYPE_COLORS.length]} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

// ── Severity pie ──────────────────────────────────────────────────────────────
function SeverityPie({ bySeverity }: { bySeverity: Record<string, number> }) {
  const data = Object.entries(bySeverity).map(([name, value]) => ({ name, value }));
  return (
    <div style={{ background: "#1e293b", borderRadius: 12, padding: 20 }}>
      <div style={{ color: "#94a3b8", fontSize: 13, marginBottom: 8, fontWeight: 600 }}>
        SEVERITY BREAKDOWN
      </div>
      <ResponsiveContainer width="100%" height={200}>
        <PieChart>
          <Pie data={data} cx="50%" cy="50%" outerRadius={75} dataKey="value" nameKey="name">
            {data.map((entry, i) => (
              <Cell key={i} fill={SEVERITY_COLORS[entry.name] ?? "#64748b"} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{ background: "#0f172a", border: "1px solid #334155", borderRadius: 8 }}
          />
          <Legend wrapperStyle={{ color: "#94a3b8", fontSize: 12 }} />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}

// ── Top Attackers ─────────────────────────────────────────────────────────────
function TopAttackers({ attackers }: { attackers: Array<{ ip: string; count: number }> }) {
  return (
    <div style={{ background: "#1e293b", borderRadius: 12, padding: 20 }}>
      <div style={{ color: "#94a3b8", fontSize: 13, marginBottom: 12, fontWeight: 600 }}>
        TOP ATTACKERS
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        {attackers.slice(0, 8).map((a, i) => {
          const max = attackers[0]?.count ?? 1;
          const pct = (a.count / max) * 100;
          return (
            <div key={a.ip} style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <span style={{ color: "#64748b", fontSize: 11, width: 18, textAlign: "right" }}>
                #{i + 1}
              </span>
              <div style={{ flex: 1 }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 3 }}>
                  <span style={{ color: "#e2e8f0", fontSize: 13, fontFamily: "monospace" }}>{a.ip}</span>
                  <span style={{ color: "#ef4444", fontSize: 12, fontWeight: 600 }}>{a.count}</span>
                </div>
                <div style={{ height: 4, background: "#0f172a", borderRadius: 2 }}>
                  <div style={{
                    height: "100%", width: `${pct}%`,
                    background: `linear-gradient(to right, #ef4444, #f97316)`,
                    borderRadius: 2, transition: "width 0.3s",
                  }} />
                </div>
              </div>
            </div>
          );
        })}
        {attackers.length === 0 && (
          <div style={{ color: "#475569", fontSize: 13, textAlign: "center", padding: "20px 0" }}>
            No attackers detected
          </div>
        )}
      </div>
    </div>
  );
}

// ── Main Dashboard ─────────────────────────────────────────────────────────────
export default function DashboardPage() {
  const [windowHours, setWindowHours] = useState(24);
  const { data, loading, error } = useThreatSummary(windowHours);
  const health = useSystemHealth();

  const blockRate = data
    ? data.total_threats > 0 ? ((data.blocked / data.total_threats) * 100).toFixed(1) : "100.0"
    : "—";

  return (
    <div style={{
      background: "#0f172a", minHeight: "100vh", padding: "24px",
      color: "#e2e8f0", fontFamily: "'Inter', 'Segoe UI', sans-serif",
    }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 24 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 22, fontWeight: 700, color: "#f1f5f9" }}>
            ⚡ Thor Firewall Dashboard
          </h1>
          <div style={{ color: "#475569", fontSize: 13, marginTop: 4 }}>
            Enterprise Next-Generation Firewall — Real-time Monitoring
          </div>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <span style={{ color: "#64748b", fontSize: 12 }}>Window:</span>
          {[1, 6, 24, 72].map(h => (
            <button key={h}
              onClick={() => setWindowHours(h)}
              style={{
                padding: "6px 14px", borderRadius: 6, border: "1px solid",
                borderColor: windowHours === h ? "#3b82f6" : "#334155",
                background:  windowHours === h ? "#1d4ed8" : "#1e293b",
                color:       windowHours === h ? "#fff" : "#94a3b8",
                cursor: "pointer", fontSize: 12,
              }}
            >{h}h</button>
          ))}
        </div>
      </div>

      {/* Error banner */}
      {error && (
        <div style={{
          background: "#450a0a", border: "1px solid #991b1b", borderRadius: 8,
          padding: "10px 16px", marginBottom: 16, color: "#fca5a5", fontSize: 13,
        }}>
          ⚠ API Error: {error}
        </div>
      )}

      {/* System health */}
      <div style={{ marginBottom: 20 }}>
        <HealthPanel health={health} />
      </div>

      {/* KPI cards */}
      <div style={{ display: "flex", gap: 16, flexWrap: "wrap", marginBottom: 20 }}>
        <MetricCard title="Total Threats"  value={loading ? "…" : (data?.total_threats ?? 0).toLocaleString()} icon="🎯" color="#ef4444" />
        <MetricCard title="Blocked"        value={loading ? "…" : (data?.blocked ?? 0).toLocaleString()} icon="🛡️" color="#22c55e" />
        <MetricCard title="Block Rate"     value={loading ? "…" : `${blockRate}%`} icon="📊" color="#3b82f6" />
        <MetricCard title="Threat Types"   value={loading ? "…" : Object.keys(data?.by_type ?? {}).length} icon="🔬" color="#8b5cf6" />
        <MetricCard title="Top Attacker"   value={data?.top_attackers?.[0]?.ip ?? "—"} sub={`${data?.top_attackers?.[0]?.count ?? 0} hits`} icon="🌐" color="#f97316" />
      </div>

      {/* Charts row 1 */}
      <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 16, marginBottom: 16 }}>
        <ThreatTimelineChart timeSeries={data?.time_series ?? []} />
        <SeverityPie bySeverity={data?.by_severity ?? {}} />
      </div>

      {/* Charts row 2 */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        <ThreatTypeChart byType={data?.by_type ?? {}} />
        <TopAttackers attackers={data?.top_attackers ?? []} />
      </div>
    </div>
  );
}
