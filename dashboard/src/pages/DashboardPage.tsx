// Thor Firewall Dashboard — Main Dashboard Page
import React, { useCallback, useEffect, useState } from "react";
import { Shield, Wifi, Brain, Settings, Terminal, Bell, Moon, Sun } from "lucide-react";

import { RealTimeStats } from "../components/dashboard/RealTimeStats";
import { ThreatFeed } from "../components/threats/ThreatFeed";
import { ThroughputChart } from "../components/charts/ThroughputChart";
import { FlowTable } from "../components/flows/FlowTable";
import { useNetworkStats, useThreats, useFlows, useSecurityQuery } from "../hooks/useApi";
import { useWebSocket } from "../hooks/useWebSocket";
import type { WebSocketMessage, ThreatEvent, NetworkStats, SystemStats, MLStats, FlowRecord } from "../types";

// ============================================================================
// Demo / Mock data (used when API not available)
// ============================================================================

const MOCK_NETWORK: NetworkStats = {
  totalPackets: 92_847_123,
  totalBytes: 1_234_567_890,
  packetsPerSecond: 847_293,
  bitsPerSecond: 9_876_543_210,
  activeFlows: 142_847,
  blockedFlows: 3_847,
  suspiciousFlows: 284,
  throughputMbps: 9876.5,
  tableUtilization: 0.67,
};

const MOCK_SYSTEM: SystemStats = {
  agentCpuPct: 4.2,
  agentMemoryMb: 512,
  ebpfMapUtilization: 0.67,
  rlInferenceLatencyUs: 87,
  llmQueriesPerMin: 23,
  uptime: 86_400,
};

const MOCK_ML: MLStats = {
  totalAnalyzed: 92_847_123,
  totalBlocked: 3_847,
  totalAllowed: 92_843_276,
  avgLatencyUs: 87,
  falsePositives: 12,
  falseNegatives: 3,
  currentAccuracy: 0.9983,
};

function generateMockFlow(i: number): FlowRecord {
  const states: Array<FlowRecord["state"]> = ["allowed", "allowed", "allowed", "suspicious", "blocked"];
  const protos: Array<FlowRecord["key"]["protocol"]> = ["tcp", "tcp", "udp", "tcp", "icmp"];
  const state = states[i % states.length];
  return {
    flowId: `flow-${i}`,
    key: {
      srcIp: `192.168.${Math.floor(i / 256) % 256}.${i % 256}`,
      dstIp: `10.0.${(i * 3) % 256}.${(i * 7) % 256}`,
      srcPort: 32768 + (i % 32767),
      dstPort: [80, 443, 22, 53, 8080][i % 5],
      protocol: protos[i % protos.length],
    },
    stats: {
      packets: 1000 + i * 17,
      bytes: 100_000 + i * 1337,
      pps: 50 + (i % 500),
      bps: 400_000 + i * 10_000,
      firstSeen: Date.now() - 60_000,
      lastSeen: Date.now(),
      avgPacketSize: 800 + (i % 700),
      payloadEntropy: state === "blocked" ? 7.8 + Math.random() * 0.2 : 3 + Math.random() * 4,
      retransmissions: i % 10,
    },
    state,
    decision: state === "blocked" ? "block" : state === "suspicious" ? "mirror" : "allow",
    riskScore: state === "blocked" ? 0.8 + Math.random() * 0.2 : state === "suspicious" ? 0.4 + Math.random() * 0.3 : Math.random() * 0.3,
    confidence: 0.8 + Math.random() * 0.2,
    tags: state === "blocked" ? ["syn-flood", "anomaly"] : [],
    agentId: `marl-tcp-agent`,
  };
}

const MOCK_FLOWS: FlowRecord[] = Array.from({ length: 100 }, (_, i) => generateMockFlow(i));

const MOCK_THREATS: ThreatEvent[] = [
  {
    eventId: "t1",
    timestamp: Date.now() - 5000,
    flow: { srcIp: "103.45.67.89", dstIp: "10.0.0.5", srcPort: 54321, dstPort: 22, protocol: "tcp" },
    threatType: "ssh-brute-force",
    severity: "critical",
    riskScore: 0.97,
    confidence: 0.95,
    explanation: "SSH brute force: 2847 attempts in 30s. Pattern matches known botnet fingerprint.",
    blocked: true,
    agentId: "marl-tcp-agent",
    mitreTechnique: "T1110.001",
  },
  {
    eventId: "t2",
    timestamp: Date.now() - 15000,
    flow: { srcIp: "185.220.101.23", dstIp: "10.0.0.1", srcPort: 45000, dstPort: 80, protocol: "tcp" },
    threatType: "syn-flood",
    severity: "high",
    riskScore: 0.89,
    confidence: 0.92,
    explanation: "SYN flood: 184,293 packets/s from TOR exit node. Applied SYN cookie mitigation.",
    blocked: true,
    agentId: "marl-tcp-agent",
    mitreTechnique: "T1498.001",
  },
  {
    eventId: "t3",
    timestamp: Date.now() - 45000,
    flow: { srcIp: "192.168.1.45", dstIp: "8.8.8.8", srcPort: 54000, dstPort: 53, protocol: "udp" },
    threatType: "dns-tunnel",
    severity: "medium",
    riskScore: 0.72,
    confidence: 0.78,
    explanation: "DNS tunneling detected: entropy=7.91, unusually long subdomain labels, CICIDS pattern match.",
    blocked: false,
    agentId: "marl-udp-agent",
    mitreTechnique: "T1071.004",
  },
];

// ============================================================================
// Navigation
// ============================================================================

type Tab = "overview" | "flows" | "threats" | "rules" | "query" | "settings";

const TABS: { id: Tab; label: string; icon: React.ReactNode }[] = [
  { id: "overview",  label: "Overview",  icon: <Shield className="h-4 w-4" /> },
  { id: "flows",     label: "Flows",     icon: <Wifi className="h-4 w-4" /> },
  { id: "threats",   label: "Threats",   icon: <Bell className="h-4 w-4" /> },
  { id: "query",     label: "AI Query",  icon: <Brain className="h-4 w-4" /> },
  { id: "settings",  label: "Settings",  icon: <Settings className="h-4 w-4" /> },
];

// ============================================================================
// AI Query Panel
// ============================================================================

function AIQueryPanel() {
  const { ask, loading, answer } = useSecurityQuery();
  const [question, setQuestion] = useState("");

  const presets = [
    "What are the top 5 threat actors in the last hour?",
    "Show suspicious flows with entropy > 7.5",
    "Explain the current SYN flood mitigation status",
    "Which IPs should be added to the blocklist?",
  ];

  return (
    <div className="flex h-full flex-col gap-4 p-4">
      <div>
        <h2 className="text-lg font-semibold text-white">AI Security Assistant</h2>
        <p className="text-sm text-white/50">Powered by Mistral-7B + RAG (MISP / CVE / OTX)</p>
      </div>

      {/* Preset questions */}
      <div className="flex flex-wrap gap-2">
        {presets.map((p) => (
          <button
            key={p}
            onClick={() => setQuestion(p)}
            className="rounded-full border border-cyan-800/50 bg-cyan-900/20 px-3 py-1 text-xs text-cyan-400 hover:bg-cyan-800/30"
          >
            {p}
          </button>
        ))}
      </div>

      {/* Input */}
      <div className="flex gap-2">
        <div className="relative flex-1">
          <Terminal className="absolute left-3 top-3 h-4 w-4 text-white/30" />
          <textarea
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey && question.trim()) { e.preventDefault(); ask(question); } }}
            placeholder="Ask anything about network security..."
            rows={3}
            className="w-full rounded-xl border border-white/10 bg-white/5 py-3 pl-10 pr-4 text-sm text-white placeholder-white/30 focus:border-cyan-500 focus:outline-none resize-none"
          />
        </div>
        <button
          onClick={() => question.trim() && ask(question)}
          disabled={loading || !question.trim()}
          className="self-end rounded-xl bg-cyan-600 px-4 py-3 text-sm font-semibold text-white hover:bg-cyan-500 disabled:opacity-50"
        >
          {loading ? "…" : "Ask"}
        </button>
      </div>

      {/* Answer */}
      {answer && (
        <div className="flex-1 rounded-xl border border-cyan-900/50 bg-cyan-950/30 p-4 text-sm text-white/80 whitespace-pre-wrap overflow-auto">
          {answer}
        </div>
      )}
    </div>
  );
}

// ============================================================================
// Dashboard Page
// ============================================================================

export function DashboardPage() {
  const [tab, setTab] = useState<Tab>("overview");
  const [dark, setDark] = useState(true);
  const [wsEvents, setWsEvents] = useState<ThreatEvent[]>([...MOCK_THREATS]);

  // API data (falls back to mocks when unavailable)
  const { data: networkData } = useNetworkStats(1000);
  const { data: threatData } = useThreats(100);
  const { data: flowData, loading: flowLoading } = useFlows();

  const network = networkData ?? MOCK_NETWORK;
  const threats = (threatData ?? []).length > 0 ? (threatData ?? []) : wsEvents;
  const flows   = flowData?.flows ?? MOCK_FLOWS;

  // WebSocket live updates
  const wsUrl = `${window.location.protocol === "https:" ? "wss" : "ws"}://${window.location.host}/ws/live`;
  const { isConnected } = useWebSocket({
    url: wsUrl,
    onMessage: useCallback((msg: WebSocketMessage) => {
      if (msg.type === "threat_detected") {
        setWsEvents((prev) => [msg.data as ThreatEvent, ...prev].slice(0, 200));
      }
    }, []),
  });

  return (
    <div className="flex h-screen flex-col bg-gray-950 text-white overflow-hidden">
      {/* ===== Header ===== */}
      <header className="flex shrink-0 items-center gap-4 border-b border-white/10 px-6 py-3">
        <div className="flex items-center gap-2">
          <Shield className="h-7 w-7 text-cyan-400" />
          <div>
            <h1 className="text-base font-bold tracking-tight">Thor Firewall</h1>
            <p className="text-xs text-white/40">Next-Generation AI Security Platform</p>
          </div>
        </div>

        {/* Nav */}
        <nav className="ml-8 flex gap-1">
          {TABS.map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm transition-all ${
                tab === t.id
                  ? "bg-cyan-600/20 text-cyan-400"
                  : "text-white/50 hover:bg-white/5 hover:text-white/80"
              }`}
            >
              {t.icon}
              {t.label}
            </button>
          ))}
        </nav>

        <div className="ml-auto flex items-center gap-3 text-xs text-white/40">
          <span
            className={`flex items-center gap-1.5 ${isConnected ? "text-green-400" : "text-red-400"}`}
          >
            <span className={`h-1.5 w-1.5 rounded-full ${isConnected ? "bg-green-400 animate-pulse" : "bg-red-400"}`} />
            {isConnected ? "Live" : "Disconnected"}
          </span>
          <span>v0.1.0</span>
        </div>
      </header>

      {/* ===== Content ===== */}
      <main className="flex-1 overflow-hidden">
        {/* Overview */}
        {tab === "overview" && (
          <div className="flex h-full flex-col gap-4 overflow-auto p-6">
            <RealTimeStats
              network={network}
              system={MOCK_SYSTEM}
              ml={MOCK_ML}
            />

            <div className="grid flex-1 grid-cols-5 gap-4" style={{ minHeight: 0 }}>
              {/* Throughput chart */}
              <div className="col-span-3 rounded-xl border border-white/10 bg-gray-900/60 p-4">
                <h3 className="mb-3 text-sm font-semibold text-white/70">Network Throughput</h3>
                <div className="h-48">
                  <ThroughputChart
                    currentMbps={network.throughputMbps}
                    blockedPps={network.blockedFlows / 60}
                    suspiciousPps={network.suspiciousFlows / 60}
                  />
                </div>
              </div>

              {/* Threat feed */}
              <div className="col-span-2 overflow-hidden rounded-xl border border-white/10 bg-gray-900/60 p-4">
                <ThreatFeed events={threats} maxHeight="240px" />
              </div>
            </div>

            {/* Flow table */}
            <div className="h-72 rounded-xl border border-white/10 bg-gray-900/60 p-4">
              <h3 className="mb-3 text-sm font-semibold text-white/70">Top Flows</h3>
              <div className="h-52">
                <FlowTable
                  flows={flows.slice(0, 20)}
                  loading={flowLoading}
                />
              </div>
            </div>
          </div>
        )}

        {/* Flows tab */}
        {tab === "flows" && (
          <div className="flex h-full flex-col p-6 gap-4">
            <h2 className="text-lg font-semibold text-white">Flow Monitor</h2>
            <div className="flex-1 overflow-hidden rounded-xl border border-white/10 bg-gray-900/60 p-4">
              <FlowTable
                flows={flows}
                loading={flowLoading}
              />
            </div>
          </div>
        )}

        {/* Threats tab */}
        {tab === "threats" && (
          <div className="flex h-full flex-col p-6 gap-4">
            <h2 className="text-lg font-semibold text-white">Threat Intelligence</h2>
            <div className="flex-1 overflow-hidden rounded-xl border border-white/10 bg-gray-900/60 p-4">
              <ThreatFeed events={threats} maxHeight="100%" />
            </div>
          </div>
        )}

        {/* AI Query tab */}
        {tab === "query" && (
          <div className="h-full rounded-none">
            <AIQueryPanel />
          </div>
        )}

        {/* Settings */}
        {tab === "settings" && (
          <div className="p-6 text-white/50">
            <h2 className="mb-4 text-lg font-semibold text-white">Settings</h2>
            <p>Configuration panel — coming soon.</p>
          </div>
        )}
      </main>
    </div>
  );
}
