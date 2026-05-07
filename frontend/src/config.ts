/**
 * Central frontend configuration.
 * All API URLs are driven by VITE_API_URL so you never hardcode localhost again.
 *
 * To change the backend target, edit frontend/.env:
 *   VITE_API_URL=http://localhost:8000
 */

const rawBase = import.meta.env.VITE_API_URL ?? 'http://localhost:8000';

// Strip trailing slash for consistency
export const API_URL = rawBase.replace(/\/$/, '');

// WebSocket URL derived from the same base (http→ws, https→wss)
export const WS_URL = API_URL.replace(/^http/, 'ws') + '/ws';
