// Thor Firewall Dashboard — TypeScript Types

export interface FlowKey {
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  protocol: "tcp" | "udp" | "icmp" | "other";
}

export interface FlowStats {
  packets: number;
  bytes: number;
  pps: number;
  bps: number;
  firstSeen: number;
  lastSeen: number;
  avgPacketSize: number;
  payloadEntropy: number;
  retransmissions: number;
}

export type FlowState = "new" | "analyzing" | "allowed" | "blocked" | "suspicious" | "terminated";
export type Decision = "allow" | "block" | "throttle" | "mirror" | "redirect";
export type Severity = "low" | "medium" | "high" | "critical";

export interface FlowRecord {
  flowId: string;
  key: FlowKey;
  stats: FlowStats;
  state: FlowState;
  decision?: Decision;
  riskScore: number;
  confidence: number;
  explanation?: string;
  tags: string[];
  agentId?: string;
}

export interface ThreatEvent {
  eventId: string;
  timestamp: number;
  flow: FlowKey;
  threatType: string;
  severity: Severity;
  riskScore: number;
  confidence: number;
  explanation?: string;
  blocked: boolean;
  agentId: string;
  mitreTechnique?: string;
}

export interface FirewallRule {
  ruleId: string;
  name: string;
  description?: string;
  srcIp?: string;
  srcCidr?: string;
  dstIp?: string;
  dstCidr?: string;
  dstPort?: number;
  protocol?: string;
  action: Decision;
  priority: number;
  hitCount: number;
  isActive: boolean;
  createdAt: number;
  expiresAt?: number;
}

export interface NetworkStats {
  totalPackets: number;
  totalBytes: number;
  packetsPerSecond: number;
  bitsPerSecond: number;
  activeFlows: number;
  blockedFlows: number;
  suspiciousFlows: number;
  throughputMbps: number;
  tableUtilization: number;
}

export interface SystemStats {
  agentCpuPct: number;
  agentMemoryMb: number;
  ebpfMapUtilization: number;
  rlInferenceLatencyUs: number;
  llmQueriesPerMin: number;
  uptime: number;
}

export interface MLStats {
  totalAnalyzed: number;
  totalBlocked: number;
  totalAllowed: number;
  avgLatencyUs: number;
  falsePositives: number;
  falseNegatives: number;
  currentAccuracy: number;
}

export interface DashboardData {
  network: NetworkStats;
  system: SystemStats;
  ml: MLStats;
  recentThreats: ThreatEvent[];
  topAttackers: Array<{ ip: string; count: number; lastSeen: number }>;
}

export interface WebSocketMessage {
  type: "flow_blocked" | "threat_detected" | "stats_update" | "alert" | "rule_created";
  channel: string;
  timestamp: number;
  data: unknown;
}

export interface AlertMessage {
  alertId: string;
  severity: Severity;
  title: string;
  message: string;
  timestamp: number;
  flow?: FlowKey;
}

export interface ChartDataPoint {
  time: number;
  value: number;
  label?: string;
}

export interface TimeSeriesData {
  name: string;
  data: ChartDataPoint[];
  color?: string;
}

export interface GeoThreat {
  srcIp: string;
  country: string;
  city?: string;
  lat: number;
  lng: number;
  count: number;
  lastSeen: number;
  severity: Severity;
}

export interface PaginatedResponse<T> {
  total: number;
  items: T[];
  page: number;
  pageSize: number;
}

export interface ApiError {
  status: number;
  message: string;
  detail?: string;
}
