/**
 * Thor Firewall — Protected Route wrapper
 * يُحوِّل المستخدم غير المُصادَق إلى صفحة تسجيل الدخول
 */
import React from "react";
import { Loader2 } from "lucide-react";
import { useAuth } from "../../context/AuthContext";
import type { Permission } from "../../context/AuthContext";
import LoginPage from "./LoginPage";

interface Props {
  children: React.ReactNode;
  requiredPermission?: Permission;
}

export default function ProtectedRoute({ children, requiredPermission }: Props) {
  const { user, loading, hasPermission } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-950 flex items-center justify-center">
        <Loader2 className="h-8 w-8 text-cyan-400 animate-spin" />
      </div>
    );
  }

  if (!user) return <LoginPage />;

  if (requiredPermission && !hasPermission(requiredPermission)) {
    return (
      <div className="min-h-screen bg-gray-950 flex items-center justify-center p-4">
        <div className="rounded-2xl border border-red-500/20 bg-red-500/10 p-8 text-center max-w-sm">
          <div className="text-4xl mb-3">🛡️</div>
          <h2 className="text-lg font-semibold text-white mb-1">Access Denied</h2>
          <p className="text-sm text-white/40">
            Your role <span className="text-white/60 font-mono">{user.role}</span> does not have
            permission: <span className="text-red-400 font-mono">{requiredPermission}</span>
          </p>
        </div>
      </div>
    );
  }

  return <>{children}</>;
}
