import { useState, useEffect } from 'react';
import { API_URL } from './config';
import { Download, Trash2 } from 'lucide-react';

interface ThreatMonitorProps {
  events: any[];
  onFlush: () => void;
}

export function ThreatMonitor({ events, onFlush }: ThreatMonitorProps) {
  const [stats, setStats] = useState({
    total_events: 0,
    safe: 0,
    suspicious: 0,
    malicious: 0,
  });
  const [isFlushing, setIsFlushing] = useState(false);

  const fetchStats = () => {
    fetch(`${API_URL}/stats`)
      .then((r) => r.json())
      .then(setStats)
      .catch(console.error);
  };

  const handleExport = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(events, null, 2));
    const downloadAnchorNode = document.createElement('a');
    downloadAnchorNode.setAttribute("href", dataStr);
    downloadAnchorNode.setAttribute("download", `aegix_security_events_${new Date().toISOString()}.json`);
    document.body.appendChild(downloadAnchorNode);
    downloadAnchorNode.click();
    downloadAnchorNode.remove();
  };

  const handleFlush = async () => {
    const confirmed = window.confirm('This will permanently delete all stored events. Continue?');
    if (!confirmed) {
      return;
    }

    setIsFlushing(true);
    try {
      const response = await fetch(`${API_URL}/events`, { method: 'DELETE' });
      if (!response.ok) {
        throw new Error(`Flush failed with status ${response.status}`);
      }
      onFlush();
      fetchStats();
    } catch (error) {
      console.error(error);
      window.alert('Failed to flush events. See console for details.');
    } finally {
      setIsFlushing(false);
    }
  };

  useEffect(() => {
    fetchStats();

    const interval = setInterval(fetchStats, 3000);
    return () => clearInterval(interval);
  }, []);

  const getSeverityLabel = (classification: string) => {
    switch (classification) {
      case 'safe': return 'LOW';
      case 'suspicious': return 'MED';
      case 'malicious': return 'CRIT';
      default: return '???';
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

  // 24-hour time formatter
  const fmt24 = (ts: number) =>
    new Date(ts * 1000).toLocaleTimeString('en-GB', { hour12: false });

  const latestEvent = events[0];
  const activeAlerts = events.filter((e) => e.classification !== 'safe').length;
  const detectionBorderColor = latestEvent
    ? getSeverityColor(latestEvent.classification)
    : 'var(--accent-primary)';

  return (
    <div>
      {/* PAGE HEADER */}
      <div className="page-header">
        <h1 className="page-title">Threat Monitor Overview</h1>
        <p className="page-subtitle">Real-time kernel inspection and behavioral heuristic engine active.</p>
      </div>

      {/* STAT CARDS */}
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

      {/* ── LATEST DETECTION CARD (expanded) ── */}
      <div className="panel-card" style={{ marginBottom: '20px', borderLeft: `4px solid ${detectionBorderColor}` }}>
        {/* Row 1 — header */}
        <div className="panel-header" style={{ padding: '14px 20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div className="panel-title" style={{ fontSize: '14px' }}>Latest Detection</div>
            {latestEvent && latestEvent.classification !== 'safe' && (
              <div className="badge high-priority" style={{ fontSize: '10px', padding: '2px 8px' }}>HIGH PRIORITY</div>
            )}
          </div>
          {latestEvent && (
            <span style={{ fontFamily: 'var(--font-tech)', fontSize: '12px', color: 'var(--text-secondary)' }}>
              {fmt24(latestEvent.detected_at)} · PID {latestEvent.pid}
            </span>
          )}
        </div>

        {/* Row 2 — content */}
        <div style={{ padding: '14px 20px 18px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {latestEvent ? (
            <>
              {/* Command terminal line */}
              <div style={{
                fontFamily: 'var(--font-tech)', fontSize: '14px', fontWeight: 600,
                background: 'var(--surface-soft)', border: '1px solid var(--border-color)',
                borderRadius: '4px', padding: '10px 14px',
                color: getSeverityColor(latestEvent.classification),
                overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
              }} title={latestEvent.command}>
                $ {latestEvent.command}
              </div>

              {/* Stat chips row */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '20px', flexWrap: 'wrap' }}>
                {/* Severity badge */}
                <div className="badge" style={{
                  backgroundColor: latestEvent.classification === 'malicious' ? 'var(--status-malicious-bg)'
                    : latestEvent.classification === 'suspicious' ? 'var(--status-suspicious-bg)' : 'var(--status-safe-bg)',
                  color: getSeverityColor(latestEvent.classification),
                  fontSize: '12px', padding: '4px 12px', letterSpacing: '1.5px',
                }}>
                  {getSeverityLabel(latestEvent.classification)}
                </div>

                {/* Risk Score */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                  <span style={{ fontFamily: 'var(--font-tech)', fontSize: '10px', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.8px' }}>Risk Score</span>
                  <span style={{ fontFamily: 'var(--font-tech)', fontSize: '20px', fontWeight: 700, color: getSeverityColor(latestEvent.classification), lineHeight: 1 }}>
                    {latestEvent.risk_score.toFixed(1)}<span style={{ fontSize: '11px', color: 'var(--text-secondary)', fontWeight: 400 }}>/100</span>
                  </span>
                </div>

                {/* ML Confidence bar */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', minWidth: '140px', flex: 1, maxWidth: '220px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ fontFamily: 'var(--font-tech)', fontSize: '10px', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.8px' }}>ML Confidence</span>
                    <span style={{ fontFamily: 'var(--font-tech)', fontSize: '10px', color: 'var(--accent-primary)', fontWeight: 700 }}>
                      {(latestEvent.ml_confidence * 100).toFixed(1)}%
                    </span>
                  </div>
                  <div className="progress-track" style={{ height: '6px' }}>
                    <div className="progress-fill" style={{ width: `${latestEvent.ml_confidence * 100}%`, backgroundColor: getSeverityColor(latestEvent.classification), height: '6px', borderRadius: '3px' }} />
                  </div>
                </div>

                {/* Process Memory */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                  <span style={{ fontFamily: 'var(--font-tech)', fontSize: '10px', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.8px' }}>Process Mem</span>
                  <span style={{ fontFamily: 'var(--font-tech)', fontSize: '18px', fontWeight: 700, lineHeight: 1, color: (latestEvent.process_memory_mb ?? 0) > 50 ? 'var(--status-malicious)' : 'var(--text-primary)' }}>
                    {(latestEvent.process_memory_mb ?? 0).toFixed(1)}<span style={{ fontSize: '11px', color: 'var(--text-secondary)', fontWeight: 400 }}>MB</span>
                  </span>
                </div>

                {/* System RAM */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                  <span style={{ fontFamily: 'var(--font-tech)', fontSize: '10px', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.8px' }}>System RAM</span>
                  <span style={{ fontFamily: 'var(--font-tech)', fontSize: '18px', fontWeight: 700, lineHeight: 1, color: (latestEvent.system_memory_percent ?? 0) > 80 ? 'var(--status-suspicious)' : 'var(--text-primary)' }}>
                    {(latestEvent.system_memory_percent ?? 0).toFixed(1)}<span style={{ fontSize: '11px', color: 'var(--text-secondary)', fontWeight: 400 }}>%</span>
                  </span>
                </div>

                {/* Matched Rules */}
                {latestEvent.matched_rules.length > 0 && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '2px', flex: 1, minWidth: '160px' }}>
                    <span style={{ fontFamily: 'var(--font-tech)', fontSize: '10px', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.8px' }}>Triggered Rules</span>
                    <span style={{ fontFamily: 'var(--font-tech)', fontSize: '12px', color: 'var(--status-suspicious)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {latestEvent.matched_rules.join(' · ')}
                    </span>
                  </div>
                )}
              </div>

              {/* Explanation line */}
              {latestEvent.explanation && (
                <div style={{ fontFamily: 'var(--font-tech)', fontSize: '12px', color: 'var(--text-secondary)', borderTop: '1px solid var(--border-color)', paddingTop: '10px', lineHeight: 1.7 }}>
                  {latestEvent.explanation}
                </div>
              )}
            </>
          ) : (
            <div style={{ fontFamily: 'var(--font-tech)', fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.8 }}>
              [SYSTEM] Waiting for kernel telemetry...<br />
              [SYSTEM] eBPF hooks attached to sys_enter_execve.<br />
              [SYSTEM] Buffer polling active.
            </div>
          )}
        </div>
      </div>



      {/* ── FULL-WIDTH EVENTS TABLE ── */}
      <div className="panel-card">
        <div className="panel-header" style={{ padding: '10px 16px' }}>
          <div className="panel-title" style={{ fontSize: '13px' }}>Live Events Table</div>
          <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-secondary)' }}>
            ● {activeAlerts} ACTIVE
          </div>
        </div>

        <div style={{ flex: 1, overflowY: 'auto', maxHeight: 'calc(100vh - 460px)' }}>
          {events.length === 0 ? (
            <div style={{ padding: '32px', textAlign: 'center', color: 'var(--text-secondary)', fontFamily: 'var(--font-tech)', fontSize: '12px' }}>
              No events recorded yet.
            </div>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse', tableLayout: 'fixed', fontSize: '13px', fontFamily: 'var(--font-tech)' }}>
              <colgroup>
                <col style={{ width: '68px' }} />
                <col style={{ width: '50px' }} />
                <col style={{ width: '28%' }} />
                <col style={{ width: '56px' }} />
                <col style={{ width: '64px' }} />
                <col style={{ width: '56px' }} />
                <col style={{ width: '56px' }} />
                <col style={{ width: '60px' }} />
              </colgroup>
              <thead>
                <tr style={{ background: 'var(--surface-table-header)' }}>
                  {['Time','PID','Command','Risk','Sev.','Mem MB','RAM %','Action'].map((h) => (
                    <th key={h} style={{
                      padding: '7px 8px', textAlign: 'left', fontWeight: 700,
                      letterSpacing: '0.8px', textTransform: 'uppercase',
                      color: 'var(--text-secondary)', borderBottom: '1px solid var(--border-color)',
                      fontSize: '11px', whiteSpace: 'nowrap', overflow: 'hidden'
                    }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {events.map((event) => {
                  const sev = getSeverityLabel(event.classification);
                  const color = getSeverityColor(event.classification);
                  const isMalicious = event.classification === 'malicious';
                  const memHigh = (event.process_memory_mb ?? 0) > 50;
                  const ramHigh = (event.system_memory_percent ?? 0) > 80;

                  return (
                    <tr key={event.id} style={{ borderBottom: '1px solid var(--border-color)', transition: 'background 0.15s' }}
                      onMouseEnter={e => (e.currentTarget.style.background = 'rgba(255,255,255,0.03)')}
                      onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}>

                      {/* Time (24h) */}
                      <td style={{ padding: '6px 8px', color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>
                        {fmt24(event.detected_at)}
                      </td>

                      {/* PID */}
                      <td style={{ padding: '6px 8px', color: 'var(--text-secondary)' }}>
                        {event.pid}
                      </td>

                      {/* Command (truncated, colored if malicious) */}
                      <td style={{ padding: '6px 8px', color: isMalicious ? 'var(--status-malicious)' : 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                        title={event.command}>
                        {event.command}
                      </td>

                      {/* Risk Score */}
                      <td style={{ padding: '6px 8px', color: color, fontWeight: 700 }}>
                        {event.risk_score.toFixed(1)}
                      </td>

                      {/* Severity badge */}
                      <td style={{ padding: '6px 8px' }}>
                        <span style={{
                          display: 'inline-block', padding: '2px 5px', borderRadius: '2px', fontSize: '9px',
                          fontWeight: 700, letterSpacing: '0.6px', textTransform: 'uppercase',
                          backgroundColor: isMalicious ? 'var(--status-malicious-bg)' : event.classification === 'suspicious' ? 'var(--status-suspicious-bg)' : 'var(--status-safe-bg)',
                          color, border: '1px solid currentColor'
                        }}>
                          {sev}
                        </span>
                      </td>

                      {/* Process Memory */}
                      <td style={{ padding: '6px 8px', color: memHigh ? 'var(--status-malicious)' : 'var(--text-secondary)', fontWeight: memHigh ? 700 : 400 }}>
                        {(event.process_memory_mb ?? 0).toFixed(1)}
                      </td>

                      {/* System RAM % */}
                      <td style={{ padding: '6px 8px', color: ramHigh ? 'var(--status-suspicious)' : 'var(--text-secondary)', fontWeight: ramHigh ? 700 : 400 }}>
                        {(event.system_memory_percent ?? 0).toFixed(1)}%
                      </td>

                      {/* Action */}
                      <td style={{ padding: '6px 8px' }}>
                        <button style={{
                          background: 'var(--bg-sidebar)', color: 'var(--text-secondary)',
                          border: '1px solid var(--border-color)', padding: '3px 7px',
                          borderRadius: '3px', fontSize: '9px', cursor: 'pointer',
                          fontFamily: 'var(--font-tech)', letterSpacing: '0.5px',
                          textTransform: 'uppercase', whiteSpace: 'nowrap'
                        }}>
                          Detail
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
            <Download size={14} /> Export Log
          </button>
          <button
            className="btn-outline"
            onClick={handleFlush}
            disabled={isFlushing}
            style={{
              borderColor: 'var(--status-malicious)',
              color: 'var(--status-malicious)',
              opacity: isFlushing ? 0.7 : 1,
              cursor: isFlushing ? 'wait' : 'pointer',
            }}
          >
            <Trash2 size={14} /> {isFlushing ? 'Flushing...' : 'Flush Log'}
          </button>
        </div>
      </div>
    </div>
  );
}
