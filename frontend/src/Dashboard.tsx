import React, { CSSProperties } from 'react';
import { useWebSocket } from './useWebSocket';
import { API_URL } from './config';
import './Dashboard.css';

export function Dashboard() {
  const { events, isConnected } = useWebSocket();
  const [stats, setStats] = React.useState({
    total_events: 0,
    safe: 0,
    suspicious: 0,
    malicious: 0,
  });

  const [webhooks, setWebhooks] = React.useState<any[]>([]);
  const [alertHistory, setAlertHistory] = React.useState<any[]>([]);
  const [newWebhookUrl, setNewWebhookUrl] = React.useState("");
  const [remediationEnabled, setRemediationEnabled] = React.useState(false);
  const [isBackendOnline, setIsBackendOnline] = React.useState(false);

  const fetchWebhooks = () => {
    fetch(`${API_URL}/webhooks`)
      .then((r) => r.json())
      .then(setWebhooks)
      .catch(console.error);
  };

  const fetchAlertHistory = () => {
    fetch(`${API_URL}/alerts/history`)
      .then((r) => r.json())
      .then(setAlertHistory)
      .catch(console.error);
  };

  const fetchRemediationState = () => {
    fetch(`${API_URL}/settings/remediation`)
      .then((r) => r.json())
      .then((d) => setRemediationEnabled(d.enabled))
      .catch(console.error);
  };

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

  const handleAddWebhook = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newWebhookUrl) return;
    fetch(`${API_URL}/webhooks`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: newWebhookUrl }),
    })
      .then(() => {
        setNewWebhookUrl("");
        fetchWebhooks();
      })
      .catch(console.error);
  };

  const handleDeleteWebhook = (id: string) => {
    fetch(`${API_URL}/webhooks/${id}`, { method: 'DELETE' })
      .then(fetchWebhooks)
      .catch(console.error);
  };

  const latestEvent = events[0];
  const activeAlerts = events.filter((event) => event.classification !== 'safe').length;

  React.useEffect(() => {
    fetchWebhooks();
    fetchAlertHistory();
    fetchRemediationState();
    const interval = setInterval(() => {
      fetch(`${API_URL}/healthz`)
        .then((r) => setIsBackendOnline(r.ok))
        .catch(() => setIsBackendOnline(false));

      fetch(`${API_URL}/stats`)
        .then((r) => r.json())
        .then(setStats)
        .catch(console.error);
      fetchAlertHistory();
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  const getClassColor = (classification: string) => {
    switch (classification) {
      case 'safe':
        return '#10b981';
      case 'suspicious':
        return '#f59e0b';
      case 'malicious':
        return '#ef4444';
      default:
        return '#6b7280';
    }
  };

  const getRiskColor = (risk: number) => {
    if (risk < 30) return '#10b981';
    if (risk < 70) return '#f59e0b';
    return '#ef4444';
  };

  const getSeverityLabel = (classification: string) => {
    switch (classification) {
      case 'safe':
        return 'Low';
      case 'suspicious':
        return 'Elevated';
      case 'malicious':
        return 'Critical';
      default:
        return 'Unknown';
    }
  };

  return (
    <div className="dashboard">
      <div className="dashboard-hero">
        <div>
          <p className="eyebrow">AI Bouncer + Kernel Guard</p>
          <h1>Live process monitoring and RCE detection</h1>
          <p className="hero-copy">
            Kernel events are classified in real time, streamed to the dashboard, and surfaced with
            severity cues for fast triage.
          </p>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', alignItems: 'flex-end' }}>
          <div className={`connection-pill ${isBackendOnline ? 'connected' : 'disconnected'}`}>
            <span className="pulse-dot" />
            Backend: {isBackendOnline ? 'Online' : 'Offline'}
          </div>
          <div className={`connection-pill ${isConnected ? 'connected' : 'disconnected'}`}>
            <span className="pulse-dot" />
            WebSocket: {isConnected ? 'Connected' : 'Disconnected'}
          </div>

          <div
            title="Auto-Remediation Toggle"
            style={{ display: 'flex', alignItems: 'center', gap: '12px', cursor: 'pointer', background: 'rgba(255,255,255,0.1)', padding: '6px 16px', borderRadius: '20px', border: '1px solid rgba(255,255,255,0.2)' }}
            onClick={toggleRemediation}
          >
            <span style={{ fontSize: '13px', fontWeight: 600, color: remediationEnabled ? '#ef4444' : 'rgba(255,255,255,0.8)' } as CSSProperties}>
              🛡️ Remediation: {remediationEnabled ? 'ACTIVE' : 'OFF'}
            </span>
            <div
              style={{
                width: '40px', height: '22px', borderRadius: '11px',
                backgroundColor: remediationEnabled ? '#ef4444' : '#cbd5e1',
                position: 'relative', transition: 'background-color 0.2s',
              } as CSSProperties}
            >
              <div style={{
                width: '18px', height: '18px', borderRadius: '50%', backgroundColor: 'white',
                position: 'absolute', top: '2px',
                left: remediationEnabled ? '20px' : '2px',
                transition: 'left 0.2s', boxShadow: '0 1px 4px rgba(0,0,0,0.2)',
              } as CSSProperties} />
            </div>
          </div>
        </div>
      </div>

      <div className="stats-grid">
        <div className="stat-card">
          <h3>Total Events</h3>
          <p className="stat-value">{stats.total_events}</p>
        </div>
        <div className="stat-card safe">
          <h3>Safe</h3>
          <p className="stat-value">{stats.safe}</p>
        </div>
        <div className="stat-card suspicious">
          <h3>Suspicious</h3>
          <p className="stat-value">{stats.suspicious}</p>
        </div>
        <div className="stat-card malicious">
          <h3>Malicious</h3>
          <p className="stat-value">{stats.malicious}</p>
        </div>
        <div className="stat-card alert">
          <h3>Active Alerts</h3>
          <p className="stat-value">{activeAlerts}</p>
        </div>
      </div>

      {latestEvent && (
        <div className={`latest-event ${latestEvent.classification}`}>
          <div className="latest-event-header">
            <div>
              <p className="latest-event-label">Latest detection</p>
              <h2>{latestEvent.command}</h2>
            </div>
            <span className="severity-chip">{getSeverityLabel(latestEvent.classification)}</span>
          </div>
          <div className="latest-event-meta" style={{ flexWrap: 'wrap' }}>
            <span>PID {latestEvent.pid}</span>
            <span>Risk {latestEvent.risk_score.toFixed(1)}</span>
            <span>{latestEvent.matched_rules.join(', ') || 'No matched rules'}</span>
            <span style={{ flexBasis: '100%', marginTop: '6px', fontStyle: 'italic', fontSize: '13px', color: '#1e293b' }}>
              💡 <b>Why flagged:</b> {latestEvent.explanation || 'No explanation provided.'}
            </span>
          </div>
        </div>
      )}

      <div className="events-container">
        <h2>Recent Events</h2>
        {events.length === 0 ? (
          <p className="empty-state">Waiting for events...</p>
        ) : (
          <table className="events-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>PID</th>
                <th>Command</th>
                <th>Risk</th>
                <th>Classification</th>
                <th>Severity</th>
                <th>Confidence</th>
                <th>Patterns</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {events.map((event) => (
                <tr key={event.id} className={`event-row ${event.classification}`}>
                  <td>{new Date(event.detected_at * 1000).toLocaleTimeString()}</td>
                  <td className="pid">{event.pid}</td>
                  <td className="command" title={event.command}>{event.command.substring(0, 40)}</td>
                  <td>
                    <div className="risk-bar">
                      <div
                        className="risk-fill"
                        style={{
                          width: `${event.risk_score}%`,
                          backgroundColor: getRiskColor(event.risk_score),
                        }}
                      />
                      <span className="risk-text">{event.risk_score.toFixed(1)}</span>
                    </div>
                  </td>
                  <td>
                    <span
                      className="badge"
                      style={{ backgroundColor: getClassColor(event.classification) }}
                    >
                      {event.classification}
                    </span>
                  </td>
                  <td>
                    <span className="severity-text">{getSeverityLabel(event.classification)}</span>
                  </td>
                  <td>{(event.ml_confidence * 100).toFixed(0)}%</td>
                  <td>{event.matched_rules.join(', ') || '-'}</td>
                  <td>
                    {event.remediation_status === 'success' && (
                      <span className="badge" style={{ backgroundColor: '#7c3aed', fontSize: '11px' }} title="Process was automatically terminated">
                        🛑 Killed
                      </span>
                    )}
                    {event.remediation_status && event.remediation_status !== 'success' && (
                      <span style={{ fontSize: '11px', color: '#94a3b8' }} title={event.remediation_status}>
                        {event.remediation_status}
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="two-column-grid" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', marginTop: '20px' }}>
        <div className="events-container webhooks-container">
          <h2>Webhook Integrations</h2>
          <p style={{ color: '#64748b', fontSize: '13px', marginBottom: '16px' }}>
            Trigger a webhook when a <b>malicious</b> event is detected.
          </p>
          <form onSubmit={handleAddWebhook} style={{ display: 'flex', gap: '10px', marginBottom: '20px' }}>
            <input
              type="url"
              placeholder="https://hooks.slack.com/services/..."
              value={newWebhookUrl}
              onChange={(e) => setNewWebhookUrl(e.target.value)}
              style={{ flex: 1, padding: '8px 12px', borderRadius: '8px', border: '1px solid #cbd5e1' }}
              required
            />
            <button type="submit" style={{ padding: '8px 16px', background: '#0f172a', color: 'white', border: 'none', borderRadius: '8px', cursor: 'pointer', fontWeight: 600 }}>Add</button>
          </form>

          {webhooks.length === 0 ? (
            <p className="empty-state" style={{ padding: '20px' }}>No webhooks configured.</p>
          ) : (
            <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
              {webhooks.map(wh => (
                <li key={wh.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '12px', background: '#f8fafc', borderRadius: '8px', marginBottom: '8px', border: '1px solid #e2e8f0' }}>
                  <span style={{ fontSize: '13px', color: '#334155', wordBreak: 'break-all', marginRight: '10px' }}>{wh.url}</span>
                  <button onClick={() => handleDeleteWebhook(wh.id)} style={{ background: '#fee2e2', color: '#ef4444', border: 'none', padding: '6px 12px', borderRadius: '6px', cursor: 'pointer', fontWeight: 600, fontSize: '12px' }}>Remove</button>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="events-container alerts-container">
          <h2>Alert History</h2>
          {alertHistory.length === 0 ? (
            <p className="empty-state" style={{ padding: '20px' }}>No alerts triggered yet.</p>
          ) : (
            <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
              <table className="events-table">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Status</th>
                    <th>Destination</th>
                  </tr>
                </thead>
                <tbody>
                  {alertHistory.map(alert => (
                    <tr key={alert.id}>
                      <td style={{ fontSize: '12px' }}>{new Date(alert.timestamp * 1000).toLocaleTimeString()}</td>
                      <td>
                        <span className="badge" style={{ backgroundColor: alert.status === 'success' ? '#10b981' : '#ef4444' }}>
                          {alert.status}
                        </span>
                      </td>
                      <td style={{ fontSize: '12px', color: '#64748b' }}>{alert.url.substring(0, 30)}...</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
