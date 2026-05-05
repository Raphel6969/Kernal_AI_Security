import { useEffect, useState } from 'react';

interface SecurityEvent {
  id: string;
  command: string;
  pid: number;
  uid: number;
  risk_score: number;
  classification: string;
  matched_rules: string[];
  timestamp: number;
  explanation?: string;
}

export function useWebSocket(url: string) {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const [ws, setWs] = useState<WebSocket | null>(null);

  useEffect(() => {
    const socket = new WebSocket(url);

    socket.onopen = () => {
      console.log('WebSocket connected');
      setIsConnected(true);
    };

    socket.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data) as SecurityEvent;
        setEvents((prev) => [data, ...prev].slice(0, 1000));
      } catch (e) {
        console.error('Failed to parse event:', e);
      }
    };

    socket.onerror = (error) => {
      console.error('WebSocket error:', error);
      setIsConnected(false);
    };

    socket.onclose = () => {
      console.log('WebSocket disconnected');
      setIsConnected(false);
      // Attempt reconnect after 3 seconds
      setTimeout(() => {
        const newSocket = new WebSocket(url);
        setWs(newSocket);
      }, 3000);
    };

    setWs(socket);

    return () => {
      socket.close();
    };
  }, [url]);

  return { events, isConnected, ws };
}
