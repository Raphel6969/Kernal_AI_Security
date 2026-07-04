/**
 * Central frontend configuration.
 * All API URLs are driven by VITE_API_URL when provided.
 *
 * To change the backend target, edit frontend/.env:
 *   VITE_API_URL=http://localhost:8000
 */


const rawBase =
  import.meta.env.VITE_API_URL ??
  (window.location.port === '5173'
    ? 'http://localhost:8000/api'
    : window.location.origin + '/api');

// Strip trailing slash for consistency
export const API_URL = rawBase.replace(/\/$/, '');

// WebSocket URL derived from the same base but stripping /api so it matches NGINX's /ws path
export const WS_URL = API_URL.replace(/\/api$/, '').replace(/^http/, 'ws') + '/ws';
