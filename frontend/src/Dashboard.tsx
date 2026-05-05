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

  return (
    <div className="dashboard">
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
      </div>

      <div className="status-indicator">
        <span className={isConnected ? 'connected' : 'disconnected'}>
          {isConnected ? '🟢 Connected' : '🔴 Disconnected'}
        </span>
      </div>

      <div className="events-container">
        <h2>Recent Events</h2>
        {events.length === 0 ? (
          <p className="empty-state">Waiting for events...</p>
        ) : (
          <table className="events-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Command</th>
                <th>Risk</th>
                <th>Classification</th>
                <th>Patterns</th>
              </tr>
            </thead>
            <tbody>
              {events.map((event) => (
                <tr key={event.id}>
                  <td>{new Date(event.timestamp * 1000).toLocaleTimeString()}</td>
                  <td className="command">{event.command.substring(0, 50)}</td>
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
