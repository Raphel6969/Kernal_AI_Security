import { useState, useEffect } from 'react';
import './App.css';
import { ThreatMonitor } from './ThreatMonitor';
import { SystemSettings } from './SystemSettings';
import { API_URL } from './config';
import { useWebSocket } from './useWebSocket';
import { Shield, Settings, HelpCircle, LogOut, Moon, Sun, Monitor } from 'lucide-react';

export type Theme = 'light' | 'dark' | 'system';

function App() {
  const [apiStatus, setApiStatus] = useState('connecting');
  const [activePage, setActivePage] = useState<'monitor' | 'settings'>('monitor');
  const [theme, setTheme] = useState<Theme>('system');
  const { events, isConnected } = useWebSocket();

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

    // Optional: listen for system theme changes
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    const handleChange = () => {
      if (theme === 'system') {
        applyTheme('system');
      }
    };
    mediaQuery.addEventListener('change', handleChange);
    return () => mediaQuery.removeEventListener('change', handleChange);
  }, [theme]);

  // Check API health
  useEffect(() => {
    const checkHealth = () => {
      fetch(`${API_URL}/healthz`)
        .then((r) => {
          if(r.ok) setApiStatus('online');
          else setApiStatus('offline');
        })
        .catch(() => setApiStatus('offline'));
    };
    checkHealth();
    const interval = setInterval(checkHealth, 5000);
    return () => clearInterval(interval);
  }, []);

  const toggleDarkMode = () => {
    setTheme(prev => {
      if (prev === 'light') return 'dark';
      if (prev === 'dark') return 'system';
      return 'light'; // system -> light
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
            <Shield size={24} strokeWidth={2.5} />
          </div>
          <div className="brand-text">
            <span className="brand-title">AI Bouncer</span>
            <span className="brand-subtitle">Kernel Guard Active</span>
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
            <div className="system-id">DEFENSE_CORE_V1</div>
            <nav className="top-nav">
              <div 
                className={`top-nav-item ${activePage === 'monitor' ? 'active' : ''}`}
                onClick={() => setActivePage('monitor')}
              >
                Dashboard
              </div>
            </nav>
          </div>

          <div className="topbar-right">
            <div className="status-pill nominal">
              <div className="status-dot"></div>
              Nominal Active
            </div>
            <div className={`status-pill ws`} style={isConnected ? {} : { backgroundColor: 'var(--status-malicious-bg)', color: 'var(--status-malicious)'}}>
              <div className="status-dot"></div>
              {isConnected ? 'WS Connected' : 'WS Disconnected'}
            </div>
            
            <div style={{ width: '1px', height: '24px', backgroundColor: 'var(--border-color)', margin: '0 8px' }}></div>
            
            <button className="icon-btn" onClick={toggleDarkMode} title={`Current Theme: ${theme}`}>
              {getThemeIcon()}
            </button>
          </div>
        </header>

        {/* PAGE CONTENT */}
        <div className="content-container">
          {apiStatus === 'offline' && (
            <div style={{ backgroundColor: 'var(--status-malicious-bg)', color: 'var(--status-malicious)', padding: '16px', borderRadius: '8px', marginBottom: '24px', fontWeight: 600 }}>
              ⚠️ Backend is offline. Ensure `python backend/app.py` is running.
            </div>
          )}
          
          {activePage === 'monitor' && <ThreatMonitor events={events} />}
          {activePage === 'settings' && <SystemSettings theme={theme} setTheme={setTheme} />}
        </div>
      </main>
    </div>
  );
}

export default App;
