import { useState, useEffect, useCallback } from 'react';
import './App.css';
import { ThreatMonitor } from './ThreatMonitor';
import { SystemSettings } from './SystemSettings';
import { CommandSandbox } from './CommandSandbox';
import { AlertsIntegrations } from './AlertsIntegrations';
import { AnalyticsMetrics } from './AnalyticsMetrics';
import { HomePage } from './HomePage';
import { PageHeader } from './components/PageHeader';
import { ChatWidget } from './components/ChatWidget';
import { API_URL } from './config';
import { useWebSocket } from './useWebSocket';
import type { Page, Theme } from './types';
import { PAGE_META } from './types';
import {
  Home, Shield, Terminal, Bell, BarChart3, Settings, Activity,
} from 'lucide-react';
import aegixLogo from './assets/aegix-logo.png';
import aegixLogoWhite from './assets/aegix_logo_white.jpeg';

const NAV_ITEMS: { id: Page; label: string; icon: typeof Home }[] = [
  { id: 'home', label: 'Home', icon: Home },
  { id: 'monitor', label: 'Threat Monitor', icon: Shield },
  { id: 'sandbox', label: 'Sandbox', icon: Terminal },
  { id: 'alerts', label: 'Alerts', icon: Bell },
  { id: 'analytics', label: 'Analytics', icon: BarChart3 },
  { id: 'settings', label: 'Settings', icon: Settings },
];

function GlowingCursor() {
  const [position, setPosition] = useState({ x: 0, y: 0 });
  const [hidden, setHidden] = useState(true);

  useEffect(() => {
    const updatePosition = (e: MouseEvent) => {
      setPosition({ x: e.clientX, y: e.clientY });
      setHidden(false);
    };
    const onMouseLeave = () => setHidden(true);
    const onMouseEnter = () => setHidden(false);

    window.addEventListener('mousemove', updatePosition);
    document.body.addEventListener('mouseleave', onMouseLeave);
    document.body.addEventListener('mouseenter', onMouseEnter);

    return () => {
      window.removeEventListener('mousemove', updatePosition);
      document.body.removeEventListener('mouseleave', onMouseLeave);
      document.body.removeEventListener('mouseenter', onMouseEnter);
    };
  }, []);

  if (hidden) return null;

  return (
    <div
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        width: '400px',
        height: '400px',
        borderRadius: '50%',
        background: 'radial-gradient(circle, rgba(0, 245, 155, 0.15) 0%, rgba(0, 245, 155, 0) 70%)',
        pointerEvents: 'none',
        transform: `translate3d(${position.x - 200}px, ${position.y - 200}px, 0)`,
        zIndex: 9999,
        transition: 'transform 0.1s ease-out',
      }}
    />
  );
}

function App() {
  const [apiStatus, setApiStatus] = useState<'connecting' | 'online' | 'offline'>('connecting');
  const [activePage, setActivePage] = useState<Page>('home');
  const [theme, setTheme] = useState<Theme>('dark');
  const [remediationEnabled, setRemediationEnabled] = useState(false);
  const [utcTime, setUtcTime] = useState('');
  const [sessionToken, setSessionToken] = useState<string | null>(() => {
    if (typeof window === 'undefined') return null;
    return window.localStorage.getItem('aegix_session_token');
  });
  const { events, isConnected, clearEvents } = useWebSocket(sessionToken ?? undefined);

  const requestSessionToken = async () => {
    const r = await fetch(`${API_URL}/session`);
    if (!r.ok) throw new Error(`Failed to create session token: ${r.status}`);
    const d = await r.json();
    setSessionToken(d.session_token);
    window.localStorage.setItem('aegix_session_token', d.session_token);
    return d.session_token as string;
  };

  const rotateSessionToken = async () => {
    const nextToken = await requestSessionToken();
    clearEvents();
    return nextToken;
  };

  useEffect(() => {
    const apply = (t: Theme) => {
      let active = t;
      if (t === 'system') {
        active = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
      }
      if (active === 'light') document.documentElement.setAttribute('data-theme', 'light');
      else document.documentElement.removeAttribute('data-theme');
    };
    apply(theme);
    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    const onChange = () => { if (theme === 'system') apply('system'); };
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, [theme]);

  useEffect(() => {
    const check = () => {
      fetch(`${API_URL}/healthz`)
        .then((r) => setApiStatus(r.ok ? 'online' : 'offline'))
        .catch(() => setApiStatus('offline'));
    };
    check();
    const id = setInterval(check, 5000);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    const tick = () => {
      const now = new Date();
      setUtcTime(`IST ${now.toLocaleTimeString('en-GB', { timeZone: 'Asia/Kolkata', hour12: false })}`);
    };
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    const init = async () => {
      try {
        if (!sessionToken) { await requestSessionToken(); return; }
        const probe = await fetch(`${API_URL}/stats?session_token=${encodeURIComponent(sessionToken)}`);
        if (probe.ok) { window.localStorage.setItem('aegix_session_token', sessionToken); return; }
        await requestSessionToken();
      } catch {
        try { await requestSessionToken(); } catch { /* ignore */ }
      }
    };
    void init();
  }, [sessionToken]);

  useEffect(() => { clearEvents(); }, [sessionToken, clearEvents]);

  useEffect(() => {
    fetch(`${API_URL}/settings/remediation`)
      .then((r) => r.json())
      .then((d) => setRemediationEnabled(d.enabled))
      .catch(() => {});
  }, []);

  const toggleRemediation = useCallback((enabled: boolean) => {
    fetch(`${API_URL}/settings/remediation`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled }),
    })
      .then((r) => r.json())
      .then((d) => setRemediationEnabled(d.enabled))
      .catch(console.error);
  }, []);

  const toggleTheme = () => {
    setTheme((prev) => (prev === 'dark' ? 'light' : prev === 'light' ? 'system' : 'dark'));
  };

  const meta = PAGE_META[activePage];
  const eventCount = events.length >= 1000 ? '1K+' : events.length > 0 ? String(events.length) : '0';

  return (
    <div className="app-layout">
      <GlowingCursor />
      <ChatWidget />
      <aside className="sidebar">
        <div className="brand">
          <img src={theme === 'light' || (theme === 'system' && !window.matchMedia('(prefers-color-scheme: dark)').matches) ? aegixLogoWhite : aegixLogo} alt="AEGIX" className="brand-logo" />
          <div className="brand-text">
            <span className="brand-title">AEGIX</span>
            <span className="brand-subtitle">BOUNCER · KERNEL · GUARD</span>
          </div>
        </div>

        <div className="nav-section-label">Operations</div>
        <nav className="nav-links">
          {NAV_ITEMS.map(({ id, label, icon: Icon }) => (
            <div
              key={id}
              className={`nav-item ${activePage === id ? 'active' : ''}`}
              onClick={() => setActivePage(id)}
            >
              <Icon size={17} />
              {label}
            </div>
          ))}
        </nav>

        <div className="system-widget">
          <div className="system-widget__header">
            <span className="system-widget__label">System</span>
            <Activity size={14} className="system-widget__pulse" />
          </div>
          <div className="system-widget__grid">
            <div>
              <span>Backend</span>
              <strong className={apiStatus === 'online' ? 'online' : ''}>
                {apiStatus === 'online' ? 'ONLINE' : 'OFFLINE'}
              </strong>
            </div>
            <div>
              <span>Kernel</span>
              <strong className="cyan">eBPF</strong>
            </div>
            <div>
              <span>Latency</span>
              <strong>5.4ms</strong>
            </div>
            <div>
              <span>Events</span>
              <strong>{eventCount}</strong>
            </div>
          </div>
        </div>
        <div className="sidebar-version">v2.4.1 · BUILD 20260214</div>
      </aside>

      <main className="main-area">
        <div className="content-container">
          {activePage !== 'home' && (
            <PageHeader
              title={meta.title}
              subtitle={meta.subtitle}
              apiOnline={apiStatus === 'online'}
              wsConnected={isConnected}
              theme={theme}
              onToggleTheme={toggleTheme}
              utcTime={utcTime}
              sessionToken={sessionToken}
            />
          )}

          {apiStatus === 'offline' && (
            <div className="offline-banner">
              Aegix backend is offline. Ensure the backend server is running on port 8000.
            </div>
          )}

          {activePage === 'home' && (
            <HomePage
              events={events}
              apiOnline={apiStatus === 'online'}
              wsConnected={isConnected}
              theme={theme}
              utcTime={utcTime}
              sessionToken={sessionToken}
              onToggleTheme={toggleTheme}
              onNavigate={setActivePage}
            />
          )}
          {activePage === 'monitor' && (
            <ThreatMonitor events={events} onFlush={clearEvents} sessionToken={sessionToken} />
          )}
          {activePage === 'sandbox' && <CommandSandbox />}
          {activePage === 'alerts' && <AlertsIntegrations />}
          {activePage === 'analytics' && (
            <AnalyticsMetrics events={events} sessionToken={sessionToken} />
          )}
          {activePage === 'settings' && (
            <SystemSettings
              theme={theme}
              setTheme={setTheme}
              sessionToken={sessionToken}
              onRotateSession={rotateSessionToken}
              remediationEnabled={remediationEnabled}
              onRemediationChange={toggleRemediation}
              apiOnline={apiStatus === 'online'}
              wsConnected={isConnected}
            />
          )}
        </div>
      </main>
    </div>
  );
}

export default App;
export type { Theme } from './types';
