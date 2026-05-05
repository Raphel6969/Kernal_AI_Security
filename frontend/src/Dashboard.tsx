import React from 'react';
import { useWebSocket } from './useWebSocket';
import './Dashboard.css';

export function Dashboard() {
  const { events, isConnected } = useWebSocket('ws://localhost:8000/ws');
  const [stats, setStats] = React.useState({
    total_events: 0,
    safe: 0,
    suspicious: 0,
    malicious: 0,
  });

  const latestEvent = events[0];
  const activeAlerts = events.filter((event) => event.classification !== 'safe').length;

  React.useEffect(() => {
    // Fetch stats every second
    const interval = setInterval(() => {
      fetch('http://localhost:8000/stats')
        .then((r) => r.json())
        .then(setStats)
        .catch(console.error);
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
        <div className={`connection-pill ${isConnected ? 'connected' : 'disconnected'}`}>
          <span className="pulse-dot" />
          {isConnected ? 'Connected' : 'Disconnected'}
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
          <div className="latest-event-meta">
            <span>PID {latestEvent.pid}</span>
            <span>Risk {latestEvent.risk_score.toFixed(1)}</span>
            <span>{latestEvent.matched_rules.join(', ') || 'No matched rules'}</span>
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
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
