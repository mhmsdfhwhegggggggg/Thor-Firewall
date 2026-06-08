// Thor Firewall — Compliance Dashboard
// لوحة امتثال SOC2 + ISO 27001 + NCA-ECC
import React, { useState } from "react";
import { Shield, CheckCircle2, XCircle, AlertCircle, Download, RefreshCw } from "lucide-react";

type ControlStatus = "compliant" | "non_compliant" | "partially_compliant" | "needs_review";

interface Control {
  id: string; name: string; category: string;
  status: ControlStatus; score: number; framework: string;
}

const CONTROLS: Control[] = [
  { id: "CC6.1", name: "Logical Access Security", category: "Access Control", status: "compliant", score: 1.0, framework: "SOC2" },
  { id: "CC6.2", name: "New User Registration", category: "Access Control", status: "compliant", score: 0.95, framework: "SOC2" },
  { id: "CC6.6", name: "Network Access Restrictions", category: "Access Control", status: "compliant", score: 1.0, framework: "SOC2" },
  { id: "CC7.1", name: "Detection & Monitoring", category: "Operations", status: "compliant", score: 1.0, framework: "SOC2" },
  { id: "CC7.2", name: "System Component Monitoring", category: "Operations", status: "compliant", score: 0.95, framework: "SOC2" },
  { id: "CC7.4", name: "Incident Response", category: "Operations", status: "compliant", score: 1.0, framework: "SOC2" },
  { id: "CC8.1", name: "Change Management", category: "Change Mgmt", status: "partially_compliant", score: 0.70, framework: "SOC2" },
  { id: "CC9.1", name: "Risk Assessment", category: "Risk", status: "needs_review", score: 0.5, framework: "SOC2" },
  { id: "A1.1", name: "Capacity Management", category: "Availability", status: "compliant", score: 0.90, framework: "SOC2" },
  { id: "A.8.16", name: "Network Monitoring", category: "Monitoring", status: "compliant", score: 1.0, framework: "ISO27001" },
  { id: "A.8.20", name: "Network Security", category: "Network", status: "compliant", score: 0.95, framework: "ISO27001" },
  { id: "A.8.22", name: "Network Segregation", category: "Network", status: "compliant", score: 1.0, framework: "ISO27001" },
  { id: "A.8.23", name: "Web Filtering", category: "Filtering", status: "compliant", score: 0.90, framework: "ISO27001" },
  { id: "A.5.28", name: "Evidence Collection", category: "Forensics", status: "compliant", score: 0.95, framework: "ISO27001" },
  { id: "NCA-1.1", name: "Asset Classification", category: "Governance", status: "partially_compliant", score: 0.65, framework: "NCA-ECC" },
  { id: "NCA-2.3", name: "Network Defense", category: "Network", status: "compliant", score: 0.95, framework: "NCA-ECC" },
  { id: "NCA-3.1", name: "Threat Intelligence", category: "Intelligence", status: "compliant", score: 1.0, framework: "NCA-ECC" },
];

const STATUS_META: Record<ControlStatus, { icon: React.ReactNode; label: string; color: string }> = {
  compliant:             { icon: <CheckCircle2 className="h-4 w-4" />, label: "Compliant",    color: "text-green-400 bg-green-950/40 border-green-700/50" },
  non_compliant:         { icon: <XCircle className="h-4 w-4" />,     label: "Non-Compliant", color: "text-red-400 bg-red-950/40 border-red-700/50" },
  partially_compliant:   { icon: <AlertCircle className="h-4 w-4" />, label: "Partial",       color: "text-amber-400 bg-amber-950/40 border-amber-700/50" },
  needs_review:          { icon: <AlertCircle className="h-4 w-4" />, label: "Review Needed", color: "text-blue-400 bg-blue-950/40 border-blue-700/50" },
};

const FRAMEWORKS = ["All", "SOC2", "ISO27001", "NCA-ECC"];

export default function ComplianceDashboard() {
  const [framework, setFramework] = useState("All");
  const [generating, setGenerating] = useState(false);

  const filtered = framework === "All" ? CONTROLS : CONTROLS.filter(c => c.framework === framework);
  const overallScore = Math.round(filtered.reduce((s, c) => s + c.score, 0) / filtered.length * 100);

  const bySt = filtered.reduce((acc, c) => {
    acc[c.status] = (acc[c.status] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const handleGenerateReport = async () => {
    setGenerating(true);
    await new Promise(r => setTimeout(r, 1800));
    setGenerating(false);
    // In production: POST /api/v1/compliance/report
    alert("Report generated! Check /reports/thor_soc2_report.pdf");
  };

  return (
    <div className="flex h-full flex-col bg-gray-950 text-white overflow-hidden">
      {/* Header */}
      <div className="shrink-0 border-b border-white/10 px-6 py-4">
        <div className="flex items-center gap-3">
          <Shield className="h-5 w-5 text-cyan-400" />
          <h1 className="text-lg font-bold">Compliance Dashboard</h1>
          <div className="ml-auto flex gap-2">
            <button className="flex items-center gap-1.5 rounded-lg border border-white/10 px-3 py-1.5 text-xs text-white/60 hover:bg-white/5">
              <RefreshCw className="h-3.5 w-3.5" />
              Re-evaluate
            </button>
            <button
              onClick={handleGenerateReport}
              disabled={generating}
              className="flex items-center gap-1.5 rounded-lg bg-cyan-600 px-4 py-1.5 text-xs font-semibold hover:bg-cyan-500 disabled:opacity-50"
            >
              <Download className="h-3.5 w-3.5" />
              {generating ? "Generating PDF…" : "Export PDF Report"}
            </button>
          </div>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-6 space-y-6">
        {/* KPI Row */}
        <div className="grid grid-cols-5 gap-4">
          <div className="col-span-1 rounded-xl border border-white/10 bg-gradient-to-br from-cyan-900/30 to-cyan-950/50 p-4 text-center">
            <div className="text-3xl font-bold text-cyan-400">{overallScore}%</div>
            <div className="text-xs text-white/50 mt-1">Overall Score</div>
            <div className="mt-2 rounded-full bg-white/10 h-2">
              <div className="h-2 rounded-full bg-gradient-to-r from-cyan-500 to-green-500" style={{ width: `${overallScore}%` }} />
            </div>
          </div>
          {Object.entries({ compliant: "green", partially_compliant: "amber", needs_review: "blue", non_compliant: "red" }).map(([status, color]) => (
            <div key={status} className={`rounded-xl border border-${color}-700/30 bg-${color}-950/20 p-4 text-center`}>
              <div className={`text-2xl font-bold text-${color}-400`}>{bySt[status] || 0}</div>
              <div className="text-xs text-white/50 mt-1">{STATUS_META[status as ControlStatus].label}</div>
            </div>
          ))}
        </div>

        {/* Framework Filter */}
        <div className="flex gap-2">
          {FRAMEWORKS.map(f => (
            <button key={f} onClick={() => setFramework(f)}
              className={`rounded-full px-4 py-1.5 text-sm font-medium transition-colors ${
                framework === f ? "bg-cyan-600 text-white" : "bg-white/5 text-white/50 hover:bg-white/10"
              }`}>
              {f}
            </button>
          ))}
        </div>

        {/* Controls Table */}
        <div className="rounded-xl border border-white/10 overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-gray-900 border-b border-white/10">
                <th className="px-4 py-3 text-left text-xs font-semibold text-white/50 uppercase">Control ID</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-white/50 uppercase">Control Name</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-white/50 uppercase">Framework</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-white/50 uppercase">Category</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-white/50 uppercase">Status</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-white/50 uppercase">Score</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(control => {
                const meta = STATUS_META[control.status];
                return (
                  <tr key={control.id} className="border-b border-white/5 hover:bg-white/3 transition-colors">
                    <td className="px-4 py-3 font-mono text-cyan-400 font-bold">{control.id}</td>
                    <td className="px-4 py-3 text-white/90">{control.name}</td>
                    <td className="px-4 py-3">
                      <span className="rounded-full bg-white/10 px-2 py-0.5 text-xs text-white/60">{control.framework}</span>
                    </td>
                    <td className="px-4 py-3 text-white/60">{control.category}</td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs font-medium ${meta.color}`}>
                        {meta.icon}
                        {meta.label}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <div className="w-20 h-1.5 rounded-full bg-white/10">
                          <div className={`h-1.5 rounded-full ${
                            control.score >= 0.9 ? "bg-green-500" :
                            control.score >= 0.7 ? "bg-amber-500" : "bg-red-500"
                          }`} style={{ width: `${control.score * 100}%` }} />
                        </div>
                        <span className="text-xs font-mono text-white/60">{Math.round(control.score * 100)}%</span>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
