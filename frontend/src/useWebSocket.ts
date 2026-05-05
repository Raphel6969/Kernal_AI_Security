import { useEffect, useRef, useState } from 'react';

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
}

export function useWebSocket(url: string) {
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

    const connect = () => {
      const socket = new WebSocket(url);

      setWs(socket);

      socket.onopen = () => {
        if (!mountedRef.current) {
          socket.close();
          return;
        }

        retryCountRef.current = 0;
        clearReconnectTimer();
        console.log('📡 WebSocket connected to backend');
        setIsConnected(true);
      };

      socket.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data) as SecurityEvent;
          console.log(`📨 Received event: ${data.command.substring(0, 40)} (${data.classification})`);
          setEvents((prev) => {
            if (seenEventIdsRef.current.has(data.id)) {
              return prev;
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
        if (!mountedRef.current) {
          return;
        }

        console.log('📡 WebSocket disconnected');
        setIsConnected(false);

        const attempt = retryCountRef.current + 1;
        retryCountRef.current = attempt;
        const backoffMs = Math.min(30000, 1000 * 2 ** Math.min(attempt - 1, 5));
        const jitterMs = Math.floor(Math.random() * 250);

        clearReconnectTimer();
        reconnectTimerRef.current = window.setTimeout(() => {
          if (mountedRef.current) {
            connect();
          }
        }, backoffMs + jitterMs);
      };
    };

    const hydrateEvents = async () => {
      try {
        const response = await fetch('http://localhost:8000/events?limit=100');
        if (!response.ok) {
          return;
        }

        const history = (await response.json()) as SecurityEvent[];
        if (!mountedRef.current || history.length === 0) {
          return;
        }

        setEvents((current) => {
          const nextEvents: SecurityEvent[] = [];

          for (const event of history) {
            if (!seenEventIdsRef.current.has(event.id)) {
              seenEventIdsRef.current.add(event.id);
            }
            nextEvents.push(event);
          }

          return [...nextEvents, ...current]
            .filter((event, index, list) => list.findIndex((candidate) => candidate.id === event.id) === index)
            .sort((left, right) => right.detected_at - left.detected_at)
            .slice(0, 1000);
        });
      } catch (error) {
        console.error('Failed to hydrate events:', error);
      }
    };

    connect();
    void hydrateEvents();

    return () => {
      mountedRef.current = false;
      clearReconnectTimer();
      setIsConnected(false);
      setWs(null);
      seenEventIdsRef.current.clear();
    };
  }, [url]);

  return { events, isConnected, ws };
}
