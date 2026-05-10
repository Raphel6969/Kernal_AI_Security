import { useState, useEffect } from 'react';
import { API_URL } from './config';
import { Download, RefreshCw } from 'lucide-react';

interface ThreatMonitorProps {
  events: any[];
}

export function ThreatMonitor({ events }: ThreatMonitorProps) {
  const [stats, setStats] = useState({
    total_events: 0,
    safe: 0,
    suspicious: 0,
    malicious: 0,
  });

  const [remediationEnabled, setRemediationEnabled] = useState(false);

  const handleExport = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(events, null, 2));
    const downloadAnchorNode = document.createElement('a');
    downloadAnchorNode.setAttribute("href", dataStr);
    downloadAnchorNode.setAttribute("download", `kernel_guard_events_${new Date().toISOString()}.json`);
    document.body.appendChild(downloadAnchorNode);
    downloadAnchorNode.click();
    downloadAnchorNode.remove();
  };

  useEffect(() => {
    // Fetch stats
    const fetchStats = () => {
      fetch(`${API_URL}/stats`)
        .then((r) => r.json())
        .then(setStats)
        .catch(console.error);
    };

    // Fetch remediation state
    const fetchRemediationState = () => {
      fetch(`${API_URL}/settings/remediation`)
        .then((r) => r.json())
        .then((d) => setRemediationEnabled(d.enabled))
        .catch(console.error);
    };

    fetchStats();
    fetchRemediationState();

    const interval = setInterval(fetchStats, 3000);
    return () => clearInterval(interval);
  }, []);

  const toggleRemediation = () => {
    const next = !remediationEnabled;
    fetch(`${API_URL}/settings/remediation`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: next }),
    })
      .then((r) => r.json())
      .then((d) => setRemediationEnabled(d.enabled))
      .catch(console.error);
  };

  const getSeverityLabel = (classification: string) => {
    switch (classification) {
      case 'safe': return 'LOW';
      case 'suspicious': return 'MEDIUM';
      case 'malicious': return 'CRITICAL';
      default: return 'UNKNOWN';
    }
  };

  const getSeverityColor = (classification: string) => {
    switch (classification) {
      case 'safe': return 'var(--status-safe)';
      case 'suspicious': return 'var(--status-suspicious)';
      case 'malicious': return 'var(--status-malicious)';
      default: return 'var(--text-tertiary)';
    }
  };

  const latestEvent = events[0];
  const activeAlerts = events.filter((event) => event.classification !== 'safe').length;

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Threat Monitor Overview</h1>
        <p className="page-subtitle">Real-time kernel inspection and behavioral heuristic engine active.</p>
      </div>

      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-title">Active Threats</div>
          <div className="stat-value danger">
            {activeAlerts} <span className="stat-unit">DETECTED</span>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-title">Total Commands Scanned</div>
          <div className="stat-value">
            {stats.total_events} <span className="stat-unit">COMMANDS</span>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-title">Safe Events</div>
          <div className="stat-value safe">
            {stats.safe} <span className="stat-unit" style={{color: 'var(--status-safe)'}}>CLEAN</span>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-title">Malicious Events</div>
          <div className="stat-value danger">
            {stats.malicious} <span className="stat-unit" style={{color: 'var(--status-malicious)'}}>BLOCKED</span>
          </div>
        </div>
      </div>

      <div className="dashboard-split">
        {/* LATEST DETECTION */}
        <div className="panel-card" style={{ borderLeft: '4px solid var(--accent-primary)' }}>
          <div className="panel-header">
            <div className="panel-title">Latest Detection</div>
            {latestEvent && latestEvent.classification !== 'safe' && (
              <div className="badge high-priority">HIGH PRIORITY</div>
            )}
          </div>
          
          <div style={{ flex: 1 }}>
            <div className="confidence-bar-container">
              <div className="confidence-label">
                <span>Confidence Interval</span>
                <span className="confidence-value">{latestEvent ? (latestEvent.ml_confidence * 100).toFixed(1) : '0.0'}%</span>
              </div>
              <div className="progress-track">
                <div 
                  className="progress-fill" 
                  style={{ width: `${latestEvent ? latestEvent.ml_confidence * 100 : 0}%`, backgroundColor: latestEvent ? getSeverityColor(latestEvent.classification) : 'var(--accent-primary)' }}
                ></div>
              </div>
            </div>

            <div className="terminal-output">
              {latestEvent ? (
                <>
                  [{new Date(latestEvent.detected_at * 1000).toLocaleTimeString()}] THREAT_ENG:<br />
                  Command execution intercepted via parent PID {latestEvent.ppid}.<br /><br />
                  Payload: {latestEvent.command}<br /><br />
                  Analysis: {latestEvent.explanation || 'No signature match.'}<br /><br />
                  Rules matched: {latestEvent.matched_rules.join(', ') || 'None'}
                </>
              ) : (
                <>
                  [SYSTEM] Waiting for kernel telemetry...<br />
                  [SYSTEM] eBPF hooks attached to sys_enter_execve.<br />
                  [SYSTEM] Buffer polling active.
                </>
              )}
            </div>
          </div>

          <div className="remediation-control">
            <div className="remediation-label">Auto-Remediation</div>
            <div className="toggle-switch" onClick={toggleRemediation}>
              <span className="toggle-text">{remediationEnabled ? 'ON' : 'OFF'}</span>
              <div className={`toggle-track ${remediationEnabled ? 'active' : ''}`}>
                <div className="toggle-thumb"></div>
              </div>
            </div>
          </div>
          
          <div style={{ padding: '0 24px 24px' }}>
            <button className="btn-primary" style={{ width: '100%' }}>
              ANALYZE FULL TRACE
            </button>
          </div>
        </div>

        {/* LIVE EVENTS TABLE */}
        <div className="panel-card">
          <div className="panel-header">
            <div className="panel-title">Live Events Table</div>
            <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-secondary)' }}>
              ● {activeAlerts} ACTIVE EVENTS
            </div>
          </div>
          
          <div style={{ flex: 1, overflowY: 'auto', maxHeight: '400px' }}>
            {events.length === 0 ? (
              <div style={{ padding: '32px', textAlign: 'center', color: 'var(--text-secondary)' }}>
                No events recorded yet.
              </div>
            ) : (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>PID</th>
                    <th>Command</th>
                    <th>Risk</th>
                    <th>Severity</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((event) => {
                    const sev = getSeverityLabel(event.classification);
                    const color = getSeverityColor(event.classification);
                    const isMalicious = event.classification === 'malicious';
                    
                    return (
                      <tr key={event.id}>
                        <td>{new Date(event.detected_at * 1000).toLocaleTimeString()}</td>
                        <td>{event.pid}</td>
                        <td style={{ color: isMalicious ? 'var(--status-malicious)' : 'var(--text-primary)' }}>
                          {event.command.length > 30 ? event.command.substring(0, 30) + '...' : event.command}
                        </td>
                        <td>
                          <div className="badge" style={{ backgroundColor: isMalicious ? 'var(--status-malicious-bg)' : (event.classification === 'suspicious' ? 'var(--status-suspicious-bg)' : 'var(--status-safe-bg)'), color }}>
                            {sev}
                          </div>
                        </td>
                        <td>
                          <div style={{ display: 'flex', gap: '4px' }}>
                            <div style={{ width: '12px', height: '4px', backgroundColor: color }}></div>
                            <div style={{ width: '12px', height: '4px', backgroundColor: event.classification !== 'safe' ? color : 'var(--border-color)' }}></div>
                            <div style={{ width: '12px', height: '4px', backgroundColor: isMalicious ? color : 'var(--border-color)' }}></div>
                          </div>
                        </td>
                        <td>
                          <button style={{ background: '#1e293b', color: 'white', border: 'none', padding: '4px 8px', borderRadius: '4px', fontSize: '10px', cursor: 'pointer', fontFamily: 'monospace' }}>
                            DETAIL
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
          
          <div className="panel-footer-actions">
            <button className="btn-outline" onClick={handleExport}>
              <Download size={16} /> Export Log Report
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
