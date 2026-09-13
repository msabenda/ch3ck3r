'use client';

import { useEffect, useRef, useState, useCallback } from 'react';

export interface ScanEvent {
  type: 'connected' | 'scan_started' | 'scan_completed' | 'scan_failed' | 'finding' | 'pong';
  scan_id?: string;
  status?: string;
  risk_score?: number;
  total_findings?: number;
  critical_count?: number;
  high_count?: number;
  finding?: {
    title: string;
    severity: string;
    category: string;
    endpoint: string;
  };
  timestamp?: string;
  message?: string;
}

interface UseScanProgressOptions {
  scanId: string | null;
  token: string | null;
  enabled?: boolean;
}

export function useScanProgress({ scanId, token, enabled = true }: UseScanProgressOptions) {
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [latestEvent, setLatestEvent] = useState<ScanEvent | null>(null);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const eventsRef = useRef<ScanEvent[]>([]);

  const clear = useCallback(() => {
    eventsRef.current = [];
    setEvents([]);
    setLatestEvent(null);
  }, []);

  useEffect(() => {
    if (!scanId || !token || !enabled) return;

    let reconnectAttempts = 0;
    const maxReconnectAttempts = 5;

    function connect() {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const host = process.env.NEXT_PUBLIC_WS_URL || `${protocol}//${window.location.host}`;
      // If NEXT_PUBLIC_WS_URL is set, use it directly; otherwise construct from host
      const wsUrl = process.env.NEXT_PUBLIC_WS_URL
        ? `${process.env.NEXT_PUBLIC_WS_URL}/ws/scans/${scanId}?token=${token}`
        : `${protocol}//${window.location.hostname}:8000/ws/scans/${scanId}?token=${token}`;

      try {
        const ws = new WebSocket(wsUrl);
        wsRef.current = ws;

        ws.onopen = () => {
          setConnected(true);
          setError(null);
          reconnectAttempts = 0;
        };

        ws.onmessage = (event) => {
          try {
            const data: ScanEvent = JSON.parse(event.data);
            eventsRef.current = [...eventsRef.current.slice(-99), data]; // Keep last 100
            setEvents(eventsRef.current);
            setLatestEvent(data);

            if (data.type === 'scan_completed' || data.type === 'scan_failed') {
              // Auto-close after completion to avoid stale connections
              setTimeout(() => {
                if (ws.readyState === WebSocket.OPEN) {
                  ws.close();
                }
              }, 2000);
            }
          } catch (e) {
            console.warn('Failed to parse WS message:', e);
          }
        };

        ws.onerror = () => {
          setError('WebSocket connection error');
        };

        ws.onclose = () => {
          setConnected(false);
          // Reconnect unless completed or max attempts
          if (reconnectAttempts < maxReconnectAttempts) {
            const delay = Math.min(1000 * Math.pow(2, reconnectAttempts), 10000);
            reconnectAttempts++;
            reconnectTimeoutRef.current = setTimeout(connect, delay);
          }
        };
      } catch (e) {
        setError('Failed to create WebSocket connection');
      }
    }

    // Keepalive ping
    const pingInterval = setInterval(() => {
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send('ping');
      }
    }, 30000);

    connect();

    return () => {
      clearInterval(pingInterval);
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [scanId, token, enabled]);

  return { events, latestEvent, connected, error, clear };
}
