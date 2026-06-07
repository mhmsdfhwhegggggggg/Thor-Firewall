// Thor Firewall Dashboard — WebSocket Hook
// خطاف الاتصال الحي

import { useCallback, useEffect, useRef, useState } from "react";
import type { WebSocketMessage } from "../types";

interface UseWebSocketOptions {
  url: string;
  onMessage?: (msg: WebSocketMessage) => void;
  onConnect?: () => void;
  onDisconnect?: () => void;
  reconnectInterval?: number;
  maxReconnectAttempts?: number;
}

interface WebSocketState {
  isConnected: boolean;
  isReconnecting: boolean;
  reconnectAttempts: number;
  lastMessage: WebSocketMessage | null;
  error: string | null;
}

export function useWebSocket({
  url,
  onMessage,
  onConnect,
  onDisconnect,
  reconnectInterval = 3000,
  maxReconnectAttempts = 10,
}: UseWebSocketOptions): WebSocketState & {
  send: (data: string) => void;
  disconnect: () => void;
} {
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout>>();
  const mountedRef = useRef(true);

  const [state, setState] = useState<WebSocketState>({
    isConnected: false,
    isReconnecting: false,
    reconnectAttempts: 0,
    lastMessage: null,
    error: null,
  });

  const connect = useCallback(() => {
    if (!mountedRef.current) return;

    try {
      const ws = new WebSocket(url);
      wsRef.current = ws;

      ws.onopen = () => {
        if (!mountedRef.current) return;
        setState((prev) => ({
          ...prev,
          isConnected: true,
          isReconnecting: false,
          reconnectAttempts: 0,
          error: null,
        }));
        onConnect?.();

        // Keep-alive ping
        const ping = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send("ping");
          } else {
            clearInterval(ping);
          }
        }, 30_000);
      };

      ws.onmessage = (event) => {
        if (!mountedRef.current) return;
        try {
          const msg = JSON.parse(event.data) as WebSocketMessage;
          setState((prev) => ({ ...prev, lastMessage: msg }));
          onMessage?.(msg);
        } catch {
          // Ignore pong messages
        }
      };

      ws.onerror = (event) => {
        if (!mountedRef.current) return;
        setState((prev) => ({
          ...prev,
          error: "WebSocket connection error",
        }));
      };

      ws.onclose = (event) => {
        if (!mountedRef.current) return;
        setState((prev) => ({
          ...prev,
          isConnected: false,
        }));
        onDisconnect?.();

        // Auto-reconnect
        if (
          mountedRef.current &&
          state.reconnectAttempts < maxReconnectAttempts
        ) {
          setState((prev) => ({
            ...prev,
            isReconnecting: true,
            reconnectAttempts: prev.reconnectAttempts + 1,
          }));

          reconnectTimerRef.current = setTimeout(
            connect,
            reconnectInterval * Math.min(state.reconnectAttempts + 1, 5)
          );
        }
      };
    } catch (err) {
      setState((prev) => ({
        ...prev,
        error: `Failed to connect: ${err}`,
      }));
    }
  }, [url, reconnectInterval, maxReconnectAttempts, onMessage, onConnect, onDisconnect]);

  useEffect(() => {
    mountedRef.current = true;
    connect();

    return () => {
      mountedRef.current = false;
      clearTimeout(reconnectTimerRef.current);
      wsRef.current?.close();
    };
  }, [connect]);

  const send = useCallback((data: string) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(data);
    }
  }, []);

  const disconnect = useCallback(() => {
    mountedRef.current = false;
    clearTimeout(reconnectTimerRef.current);
    wsRef.current?.close();
    setState((prev) => ({
      ...prev,
      isConnected: false,
      isReconnecting: false,
    }));
  }, []);

  return { ...state, send, disconnect };
}
