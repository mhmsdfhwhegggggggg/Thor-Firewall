/**
 * Re-export from AuthContext for convenience
 * استخدام: import { useAuth } from '@/hooks/useAuth'
 */
export { useAuth, useRequireAuth, useApiClient } from "../context/AuthContext";
export type { User, Role, Permission } from "../context/AuthContext";
