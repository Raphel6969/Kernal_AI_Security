/**
 * Central frontend configuration.
 * All API URLs are driven by VITE_API_URL when provided.
 *
 * To change the backend target, edit frontend/.env:
 *   VITE_API_URL=http://localhost:8000
 */


const getApiUrl = (): string => {
  const envUrl = (import.meta.env.VITE_API_URL as string | undefined)?.trim();
  if (envUrl && envUrl.length > 0) {
    if (envUrl.startsWith('/')) {
      return (typeof window !== 'undefined' ? window.location.origin : '') + envUrl;
    }
    return envUrl;
  }

  if (typeof window !== 'undefined') {
    if (window.location.port === '5173') {
      return 'http://localhost:8000/api';
    }
    return `${window.location.origin}/api`;
  }

  return 'http://localhost:8000/api';
};

// Strip trailing slash for consistency (e.g. "https://kernal-ai-security.onrender.com/api")
export const API_URL = getApiUrl().replace(/\/+$/, '');

// WebSocket URL: guaranteed to be an absolute ws:// or wss:// URL
export const WS_URL = (() => {
  if (typeof window === 'undefined') {
    return 'ws://localhost:8000/ws';
  }
  try {
    const parsed = new URL(API_URL, window.location.origin);
    const wsProto = parsed.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${wsProto}//${parsed.host}/ws`;
  } catch {
    const wsProto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${wsProto}//${window.location.host}/ws`;
  }
})();
