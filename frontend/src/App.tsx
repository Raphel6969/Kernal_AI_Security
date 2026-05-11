import { useState, useEffect, useCallback } from 'react';
import './App.css';
import { ThreatMonitor } from './ThreatMonitor';
import { SystemSettings } from './SystemSettings';
import { API_URL } from './config';
import { useWebSocket } from './useWebSocket';
import { Shield, Settings, HelpCircle, LogOut, Moon, Sun, Monitor } from 'lucide-react';
import aegixLogo from './assets/aegix-logo.png';

export type Theme = 'light' | 'dark' | 'system';

function App() {
  const [apiStatus, setApiStatus] = useState('connecting');
  const [activePage, setActivePage] = useState<'monitor' | 'settings'>('monitor');
  const [theme, setTheme] = useState<Theme>('system');
  const [remediationEnabled, setRemediationEnabled] = useState(false);
  const { events, isConnected, clearEvents } = useWebSocket();

  // Handle Theme
  useEffect(() => {
    const applyTheme = (t: Theme) => {
      let activeTheme = t;
      if (t === 'system') {
        activeTheme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
      }
      if (activeTheme === 'dark') {
        document.documentElement.setAttribute('data-theme', 'dark');
      } else {
        document.documentElement.removeAttribute('data-theme');
      }
    };
    applyTheme(theme);
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    const handleChange = () => { if (theme === 'system') applyTheme('system'); };
    mediaQuery.addEventListener('change', handleChange);
    return () => mediaQuery.removeEventListener('change', handleChange);
  }, [theme]);

  // Check API health
  useEffect(() => {
    const checkHealth = () => {
      fetch(`${API_URL}/healthz`)
        .then((r) => { if (r.ok) setApiStatus('online'); else setApiStatus('offline'); })
        .catch(() => setApiStatus('offline'));
    };
    checkHealth();
    const interval = setInterval(checkHealth, 5000);
    return () => clearInterval(interval);
  }, []);

  // Fetch initial remediation state
  useEffect(() => {
    fetch(`${API_URL}/settings/remediation`)
      .then((r) => r.json())
      .then((d) => setRemediationEnabled(d.enabled))
      .catch(console.error);
  }, []);

  const toggleRemediation = useCallback(() => {
    const next = !remediationEnabled;
    fetch(`${API_URL}/settings/remediation`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: next }),
    })
      .then((r) => r.json())
      .then((d) => setRemediationEnabled(d.enabled))
      .catch(console.error);
  }, [remediationEnabled]);

  const toggleDarkMode = () => {
    setTheme(prev => {
      if (prev === 'light') return 'dark';
      if (prev === 'dark') return 'system';
      return 'light';
    });
  };

  const getThemeIcon = () => {
    if (theme === 'light') return <Sun size={18} />;
    if (theme === 'dark') return <Moon size={18} />;
    return <Monitor size={18} />;
  };

  return (
    <div className="app-layout">
      {/* SIDEBAR */}
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">
            <img src={aegixLogo} alt="Aegix Logo" className="brand-logo" />
          </div>
          <div className="brand-text">
            <span className="brand-title">Aegix</span>
            <span className="brand-subtitle">Aegix Platform</span>
          </div>
        </div>

        <nav className="nav-links">
          <div
            className={`nav-item ${activePage === 'monitor' ? 'active' : ''}`}
            onClick={() => setActivePage('monitor')}
          >
            <Shield size={18} />
            Threat Monitor
          </div>
          <div
            className={`nav-item ${activePage === 'settings' ? 'active' : ''}`}
            onClick={() => setActivePage('settings')}
          >
            <Settings size={18} />
            System Settings
          </div>
        </nav>

        <div className="sidebar-footer">
          <button className="kill-switch-btn">
            Emergency Kill Switch
          </button>
          <div className="footer-link">
            <HelpCircle size={18} />
            Help
          </div>
          <div className="footer-link">
            <LogOut size={18} />
            Logout
          </div>
        </div>
      </aside>

      {/* MAIN CONTENT AREA */}
      <main className="main-area">
        {/* TOP NAVIGATION BAR */}
        <header className="topbar">
          <div className="topbar-left">
            <div className="system-id">AEGIX</div>
            <nav className="top-nav">
              <div
                className={`top-nav-item ${activePage === 'monitor' ? 'active' : ''}`}
                onClick={() => setActivePage('monitor')}
              >
                Aegix Dashboard
              </div>
            </nav>
          </div>

          <div className="topbar-right">
            <div className="status-pill nominal">
              <div className="status-dot"></div>
              Nominal Active
            </div>
            <div className={`status-pill ws`} style={isConnected ? {} : { backgroundColor: 'var(--status-malicious-bg)', color: 'var(--status-malicious)' }}>
              <div className="status-dot"></div>
              {isConnected ? 'WS Connected' : 'WS Disconnected'}
            </div>

            <div style={{ width: '1px', height: '24px', backgroundColor: 'var(--border-color)', margin: '0 4px' }}></div>

            {/* ── AUTO-REMEDIATION BUTTON ── */}
            <button
              onClick={toggleRemediation}
              title={remediationEnabled ? 'Auto-Remediation is ON — click to disable' : 'Auto-Remediation is OFF — click to enable'}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                padding: '5px 12px',
                borderRadius: '4px',
                border: `1px solid ${remediationEnabled ? 'var(--status-malicious)' : 'var(--border-color)'}`,
                background: remediationEnabled ? 'var(--status-malicious-bg)' : 'transparent',
                color: remediationEnabled ? 'var(--status-malicious)' : 'var(--text-secondary)',
                fontFamily: 'var(--font-tech)',
                fontSize: '11px',
                fontWeight: 700,
                letterSpacing: '0.8px',
                textTransform: 'uppercase',
                cursor: 'pointer',
                transition: 'all 0.2s',
              }}
            >
              {/* pulsing dot when active */}
              <span style={{
                width: '7px', height: '7px', borderRadius: '50%',
                backgroundColor: remediationEnabled ? 'var(--status-malicious)' : 'var(--text-tertiary)',
                boxShadow: remediationEnabled ? '0 0 6px var(--status-malicious)' : 'none',
                flexShrink: 0,
              }} />
              Remediation {remediationEnabled ? 'ON' : 'OFF'}
            </button>

            <div style={{ width: '1px', height: '24px', backgroundColor: 'var(--border-color)', margin: '0 4px' }}></div>

            <button className="icon-btn" onClick={toggleDarkMode} title={`Current Theme: ${theme}`}>
              {getThemeIcon()}
            </button>
          </div>
        </header>

        {/* PAGE CONTENT */}
        <div className="content-container">
          {apiStatus === 'offline' && (
            <div style={{ backgroundColor: 'var(--status-malicious-bg)', color: 'var(--status-malicious)', padding: '16px', borderRadius: '8px', marginBottom: '24px', fontWeight: 600 }}>
              ⚠️ Aegix backend is offline. Ensure `python backend/app.py` is running.
            </div>
          )}

          {activePage === 'monitor' && <ThreatMonitor events={events} onFlush={clearEvents} />}
          {activePage === 'settings' && <SystemSettings theme={theme} setTheme={setTheme} />}
        </div>
      </main>
    </div>
  );
}

export default App;
