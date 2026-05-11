import { useEffect, useRef, useState } from 'react';
import { API_URL, WS_URL } from './config';

interface SecurityEvent {
  id: string;
  pid: number;
  ppid: number;
  uid: number;
  gid: number;
  command: string;
  argv_str: string;
  timestamp: number;
  comm: string;
  risk_score: number;
  classification: string;
  matched_rules: string[];
  ml_confidence: number;
  explanation?: string;
  detected_at: number;
  remediation_action?: string | null;
  remediation_status?: string | null;
}

export function useWebSocket() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const [ws, setWs] = useState<WebSocket | null>(null);
  const retryCountRef = useRef(0);
  const reconnectTimerRef = useRef<number | null>(null);
  const mountedRef = useRef(true);
  const seenEventIdsRef = useRef(new Set<string>());

  useEffect(() => {
    mountedRef.current = true;

    const clearReconnectTimer = () => {
      if (reconnectTimerRef.current !== null) {
        window.clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = null;
      }
    };

    // Defined first so connect()'s onopen closure can reference it safely
    const hydrateEvents = async () => {
      try {
        const response = await fetch(`${API_URL}/events?limit=100`);
        if (!response.ok) return;
        const history = (await response.json()) as SecurityEvent[];
        if (!mountedRef.current || history.length === 0) return;

        setEvents((current) => {
          const nextEvents: SecurityEvent[] = [];
          for (const event of history) {
            if (!seenEventIdsRef.current.has(event.id)) {
              seenEventIdsRef.current.add(event.id);
            }
            nextEvents.push(event);
          }
          return [...nextEvents, ...current]
            .filter((e, i, arr) => arr.findIndex((x) => x.id === e.id) === i)
            .sort((a, b) => b.detected_at - a.detected_at)
            .slice(0, 1000);
        });
      } catch (error) {
        console.error('Failed to hydrate events:', error);
      }
    };

    const connect = () => {
      const socket = new WebSocket(WS_URL);
      setWs(socket);

      socket.onopen = () => {
        if (!mountedRef.current) { socket.close(); return; }
        retryCountRef.current = 0;
        clearReconnectTimer();
        console.log('📡 WebSocket connected to backend');
        setIsConnected(true);
        // Re-hydrate on every (re)connect — picks up events missed during disconnection
        void hydrateEvents();
      };

      socket.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data) as SecurityEvent;
          console.log(`📨 Received event: ${data.command.substring(0, 40)} (${data.classification})`);
          // Always prepend — deduplication handled by React state updater below
          setEvents((prev) => {
            // If we already have this exact event, update it in place (e.g. remediation badge)
            const exists = prev.findIndex((e) => e.id === data.id);
            if (exists !== -1) {
              const updated = [...prev];
              updated[exists] = data;
              return updated;
            }
            seenEventIdsRef.current.add(data.id);
            return [data, ...prev].slice(0, 1000);
          });
        } catch (e) {
          console.error('Failed to parse event:', e);
        }
      };

      socket.onerror = (error) => {
        console.error('❌ WebSocket error:', error);
        setIsConnected(false);
      };

      socket.onclose = () => {
        if (!mountedRef.current) return;
        console.log('📡 WebSocket disconnected');
        setIsConnected(false);
        const attempt = retryCountRef.current + 1;
        retryCountRef.current = attempt;
        const backoffMs = Math.min(30000, 1000 * 2 ** Math.min(attempt - 1, 5));
        const jitterMs = Math.floor(Math.random() * 250);
        clearReconnectTimer();
        reconnectTimerRef.current = window.setTimeout(() => {
          if (mountedRef.current) connect();
        }, backoffMs + jitterMs);
      };
    };

    connect();

    return () => {
      mountedRef.current = false;
      clearReconnectTimer();
      setIsConnected(false);
      setWs(null);
      seenEventIdsRef.current.clear();
    };
  }, []);

  const clearEvents = () => {
    seenEventIdsRef.current.clear();
    setEvents([]);
  };

  return { events, isConnected, ws, clearEvents };
}
