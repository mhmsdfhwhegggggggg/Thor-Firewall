// Thor Firewall Dashboard — API Hooks
// خطافات API للتواصل مع Control Plane

import { useCallback, useEffect, useState } from "react";
import type {
  DashboardData,
  FlowRecord,
  FirewallRule,
  ThreatEvent,
  NetworkStats,
  PaginatedResponse,
  ApiError,
} from "../types";

const API_BASE = import.meta.env.VITE_API_URL ?? "http://localhost:8080";

// ============================================================================
// Generic fetch wrapper
// ============================================================================

async function apiFetch<T>(
  path: string,
  options?: RequestInit
): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...options?.headers,
    },
    ...options,
  });

  if (!res.ok) {
    const error: ApiError = {
      status: res.status,
      message: res.statusText,
    };
    try {
      const body = await res.json();
      error.detail = body.detail ?? body.message;
    } catch {}
    throw error;
  }

  return res.json();
}

// ============================================================================
// Generic hook factory
// ============================================================================

function useApiData<T>(
  endpoint: string,
  refreshInterval?: number
): {
  data: T | null;
  loading: boolean;
  error: ApiError | null;
  refetch: () => void;
} {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<ApiError | null>(null);
  const [trigger, setTrigger] = useState(0);

  const refetch = useCallback(() => setTrigger((t) => t + 1), []);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);

    apiFetch<T>(endpoint)
      .then((d) => {
        if (!cancelled) {
          setData(d);
          setError(null);
          setLoading(false);
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setError(err);
          setLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [endpoint, trigger]);

  useEffect(() => {
    if (!refreshInterval) return;
    const id = setInterval(refetch, refreshInterval);
    return () => clearInterval(id);
  }, [refetch, refreshInterval]);

  return { data, loading, error, refetch };
}

// ============================================================================
// Specific Hooks
// ============================================================================

export function useNetworkStats(refreshMs = 1000) {
  return useApiData<NetworkStats>("/api/v1/analytics/network", refreshMs);
}

export function useThreats(limit = 50) {
  return useApiData<ThreatEvent[]>(`/api/v1/threats?limit=${limit}`, 5000);
}

export function useFlows(params?: {
  state?: string;
  minRisk?: number;
  limit?: number;
}) {
  const q = new URLSearchParams();
  if (params?.state) q.set("state", params.state);
  if (params?.minRisk != null) q.set("min_risk", String(params.minRisk));
  if (params?.limit) q.set("limit", String(params.limit));
  const qs = q.toString();

  return useApiData<{ total: number; flows: FlowRecord[] }>(
    `/api/v1/flows${qs ? `?${qs}` : ""}`,
    2000
  );
}

export function useRules() {
  const result = useApiData<FirewallRule[]>("/api/v1/rules", 10000);

  const createRule = useCallback(async (rule: Omit<FirewallRule, "ruleId" | "hitCount" | "createdAt">) => {
    const res = await apiFetch<FirewallRule>("/api/v1/rules", {
      method: "POST",
      body: JSON.stringify(rule),
    });
    result.refetch();
    return res;
  }, [result.refetch]);

  const deleteRule = useCallback(async (ruleId: string) => {
    await apiFetch(`/api/v1/rules/${ruleId}`, { method: "DELETE" });
    result.refetch();
  }, [result.refetch]);

  const toggleRule = useCallback(async (ruleId: string) => {
    await apiFetch(`/api/v1/rules/${ruleId}/toggle`, { method: "POST" });
    result.refetch();
  }, [result.refetch]);

  return { ...result, createRule, deleteRule, toggleRule };
}

export function useBlockFlow() {
  return useCallback(async (flowId: string, reason: string) => {
    return apiFetch(`/api/v1/flows/${flowId}/block`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    });
  }, []);
}

export function useSecurityQuery() {
  const [loading, setLoading] = useState(false);
  const [answer, setAnswer] = useState<string | null>(null);

  const ask = useCallback(async (question: string) => {
    setLoading(true);
    setAnswer(null);
    try {
      const res = await apiFetch<{ answer: string; model: string; latency_ms: number }>(
        "/api/v1/query",
        {
          method: "POST",
          body: JSON.stringify({ question }),
        }
      );
      setAnswer(res.answer);
      return res;
    } finally {
      setLoading(false);
    }
  }, []);

  return { ask, loading, answer };
}

export function useHealthCheck() {
  return useApiData<{
    status: string;
    version: string;
    components: Record<string, string>;
  }>("/api/health", 30000);
}
