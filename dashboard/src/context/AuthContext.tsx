/**
 * Thor Firewall — Authentication Context
 * سياق المصادقة لكامل التطبيق
 * SPDX-License-Identifier: MIT
 */
import React, { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";

const API_BASE = import.meta.env.VITE_API_URL ?? "";

// ── Types ─────────────────────────────────────────────────────────────────────

export type Role = "admin" | "analyst" | "readonly" | "agent";

export interface User {
  id: string;
  email: string;
  name: string;
  role: Role;
}

interface AuthState {
  user: User | null;
  accessToken: string | null;
  loading: boolean;
  error: string | null;
}

interface AuthContextValue extends AuthState {
  login:   (email: string, password: string) => Promise<void>;
  logout:  () => Promise<void>;
  refresh: () => Promise<boolean>;
  hasPermission: (perm: Permission) => boolean;
  isAdmin:   boolean;
  isAnalyst: boolean;
}

// ── Permissions (mirror backend rbac.py) ─────────────────────────────────────
export type Permission =
  | "threats:read" | "threats:block" | "threats:write"
  | "cases:read"   | "cases:write"   | "cases:delete"
  | "compliance:read" | "compliance:generate"
  | "users:manage" | "agents:register"
  | "config:read"  | "config:write"
  | "soar:execute" | "soar:read"
  | "audit:read"   | "audit:export"
  | "ml:read"      | "ml:retrain"
  | "dashboard:access" | "ueba:read";

const ROLE_PERMS: Record<Role, Permission[]> = {
  admin:    ["threats:read","threats:block","threats:write","cases:read","cases:write","cases:delete",
             "compliance:read","compliance:generate","users:manage","agents:register","config:read",
             "config:write","soar:execute","soar:read","audit:read","audit:export","ml:read",
             "ml:retrain","dashboard:access","ueba:read"],
  analyst:  ["threats:read","threats:block","cases:read","cases:write","compliance:read",
             "soar:execute","soar:read","audit:read","ml:read","dashboard:access","ueba:read",
             "config:read"],
  readonly: ["threats:read","cases:read","compliance:read","soar:read","ml:read",
             "dashboard:access","ueba:read","config:read"],
  agent:    ["threats:read","threats:block","threats:write","soar:execute","ml:read"],
};

// ── Token storage (memory + sessionStorage for refresh across tabs) ───────────
const TOKEN_KEY  = "thor_access_token";
const RTOKEN_KEY = "thor_refresh_token";

function saveTokens(access: string, refresh: string) {
  sessionStorage.setItem(TOKEN_KEY,  access);
  sessionStorage.setItem(RTOKEN_KEY, refresh);
}
function clearTokens() {
  sessionStorage.removeItem(TOKEN_KEY);
  sessionStorage.removeItem(RTOKEN_KEY);
}
function getStoredRefresh() { return sessionStorage.getItem(RTOKEN_KEY); }

// ── Context ───────────────────────────────────────────────────────────────────
export const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [state, setState] = useState<AuthState>({
    user: null, accessToken: null, loading: true, error: null,
  });
  const refreshTimer = useRef<ReturnType<typeof setTimeout>>();

  // Schedule token refresh 2 min before expiry (15min tokens)
  const scheduleRefresh = useCallback((token: string) => {
    clearTimeout(refreshTimer.current);
    refreshTimer.current = setTimeout(() => refresh(), (15 - 2) * 60 * 1000);
  }, []);

  const refresh = useCallback(async (): Promise<boolean> => {
    const rtoken = getStoredRefresh();
    if (!rtoken) return false;
    try {
      const res = await fetch(`${API_BASE}/api/auth/refresh`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refresh_token: rtoken }),
      });
      if (!res.ok) { clearTokens(); return false; }
      const data = await res.json();
      saveTokens(data.access_token, data.refresh_token);
      setState(s => ({ ...s, user: data.user, accessToken: data.access_token, loading: false }));
      scheduleRefresh(data.access_token);
      return true;
    } catch { return false; }
  }, [scheduleRefresh]);

  // On mount: try to restore session from stored refresh token
  useEffect(() => {
    refresh().finally(() => setState(s => ({ ...s, loading: false })));
    return () => clearTimeout(refreshTimer.current);
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    setState(s => ({ ...s, loading: true, error: null }));
    const res = await fetch(`${API_BASE}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    const data = await res.json();
    if (!res.ok) {
      setState(s => ({ ...s, loading: false, error: data.detail ?? "Login failed" }));
      throw new Error(data.detail ?? "Login failed");
    }
    saveTokens(data.access_token, data.refresh_token);
    setState({ user: data.user, accessToken: data.access_token, loading: false, error: null });
    scheduleRefresh(data.access_token);
  }, [scheduleRefresh]);

  const logout = useCallback(async () => {
    if (state.accessToken) {
      await fetch(`${API_BASE}/api/auth/logout`, {
        method: "POST",
        headers: { Authorization: `Bearer ${state.accessToken}` },
      }).catch(() => {});
    }
    clearTokens();
    clearTimeout(refreshTimer.current);
    setState({ user: null, accessToken: null, loading: false, error: null });
  }, [state.accessToken]);

  const hasPermission = useCallback((perm: Permission): boolean => {
    if (!state.user) return false;
    return ROLE_PERMS[state.user.role]?.includes(perm) ?? false;
  }, [state.user]);

  return (
    <AuthContext.Provider value={{
      ...state,
      login, logout, refresh, hasPermission,
      isAdmin:   state.user?.role === "admin",
      isAnalyst: state.user?.role === "analyst" || state.user?.role === "admin",
    }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside <AuthProvider>");
  return ctx;
}

/** Hook مساعد لحماية route */
export function useRequireAuth(redirectTo = "/login") {
  const { user, loading } = useAuth();
  useEffect(() => {
    if (!loading && !user) window.location.href = redirectTo;
  }, [user, loading, redirectTo]);
  return { user, loading };
}

/** Wrapper لتنفيذ fetch مع JWT تلقائياً */
export function useApiClient() {
  const { accessToken, logout, refresh } = useAuth();
  return useCallback(async (url: string, opts: RequestInit = {}) => {
    const doFetch = (token: string | null) => fetch(`${API_BASE}${url}`, {
      ...opts,
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...(opts.headers ?? {}),
      },
    });
    let res = await doFetch(accessToken);
    if (res.status === 401) {
      const ok = await refresh();
      if (!ok) { logout(); return res; }
      const newToken = sessionStorage.getItem(TOKEN_KEY);
      res = await doFetch(newToken);
    }
    return res;
  }, [accessToken, logout, refresh]);
}
