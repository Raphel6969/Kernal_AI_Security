/**
 * Central frontend configuration.
 * All API URLs are driven by VITE_API_URL when provided.
 *
 * To change the backend target, edit frontend/.env:
 *   VITE_API_URL=http://localhost:8000
 */

const isLocalhost =
  typeof window !== 'undefined' &&
  (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1');

const rawBase =
  import.meta.env.VITE_API_URL ??
  (isLocalhost ? 'http://localhost:8000' : window.location.origin);

// Strip trailing slash for consistency
export const API_URL = rawBase.replace(/\/$/, '');

// WebSocket URL derived from the same base (http→ws, https→wss)
export const WS_URL = API_URL.replace(/^http/, 'ws') + '/ws';
