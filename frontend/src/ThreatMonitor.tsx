import { useState, useEffect, useMemo } from 'react';
import { API_URL } from './config';
import { SeverityBadge } from './components/SeverityBadge';
import { LlmExplainModal } from './components/LlmExplainModal';
import { useLlmExplain } from './useLlmExplain';
import { Search, Download, Trash2, X, Cpu, Brain, Sparkles } from 'lucide-react';
import type { SecurityEvent } from './useWebSocket';

interface ThreatMonitorProps {
  events: SecurityEvent[];
  onFlush: () => void;
  sessionToken?: string | null;
}

export function ThreatMonitor({ events, onFlush, sessionToken }: ThreatMonitorProps) {
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [selected, setSelected] = useState<SecurityEvent | null>(null);
  const [isFlushing, setIsFlushing] = useState(false);
  const [llmModalOpen, setLlmModalOpen] = useState(false);
  const { llmText, loading: llmLoading, error: llmError, cached, reset: resetLlm, explainEvent } = useLlmExplain();

  useEffect(() => {
    if (selected && !events.find((e) => e.id === selected.id)) {
      setSelected(null);
      resetLlm();
    }
  }, [events, selected, resetLlm]);

  useEffect(() => {
    resetLlm();
    setLlmModalOpen(false);
  }, [selected?.id, resetLlm]);

  const openLlmModal = (regenerate = false) => {
    if (!selected) return;
    setLlmModalOpen(true);
    const existing = llmText ?? selected.llm_explanation;
    if (regenerate || !existing) {
      void explainEvent(selected.id, sessionToken, regenerate);
    }
  };

  const filtered = useMemo(() => {
    return events.filter((e) => {
      if (severityFilter !== 'all' && e.classification !== severityFilter) return false;
      if (!search.trim()) return true;
      const q = search.toLowerCase();
      return (
        String(e.pid).includes(q) ||
        String(e.uid).includes(q) ||
        e.command.toLowerCase().includes(q)
      );
    });
  }, [events, search, severityFilter]);

  const fmt24 = (ts: number) =>
    new Date(ts * 1000).toLocaleTimeString('en-GB', { hour12: false });

  const handleExport = async () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(events, null, 2));
    const a = document.createElement('a');
    a.href = dataStr;
    a.download = `aegix_events_${new Date().toISOString()}.json`;
    a.click();
    try {
      const url = new URL(`${API_URL}/notifications/activity`);
      if (sessionToken) url.searchParams.set('session_token', sessionToken);
      await fetch(url.toString(), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: 'logs_exported',
          detail: `${events.length} event(s) exported to JSON.`,
        }),
      });
    } catch {
      /* non-blocking */
    }
  };

  const handleFlush = async () => {
    if (!window.confirm('Delete all stored events?')) return;
    setIsFlushing(true);
    try {
      const url = new URL(`${API_URL}/events`);
      if (sessionToken) url.searchParams.set('session_token', sessionToken);
      const res = await fetch(url.toString(), { method: 'DELETE' });
      if (!res.ok) throw new Error('Flush failed');
      onFlush();
      setSelected(null);
    } catch (e) {
      console.error(e);
      window.alert('Failed to flush events.');
    } finally {
      setIsFlushing(false);
    }
  };

  return (
    <div className="threat-monitor">
      <div className="threat-toolbar">
        <div className="threat-search">
          <Search size={16} />
          <input
            type="text"
            placeholder="search pid, user, command..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <select
          className="threat-filter"
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
        >
          <option value="all">Severity</option>
          <option value="safe">Safe</option>
          <option value="suspicious">Suspicious</option>
          <option value="malicious">Malicious</option>
        </select>
        <div className="threat-streaming">
          <span className="threat-streaming__dot" />
          STREAMING · {filtered.length} EVENTS
        </div>
      </div>

      <div className={`threat-layout ${selected ? 'threat-layout--panel-open' : ''}`}>
        <div className="glass-card threat-table-card">
          <table className="data-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>PID</th>
                <th>PPID</th>
                <th>UID</th>
                <th>Command</th>
                <th>Severity</th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={6} style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
                    No events recorded. Run the demo or POST to /analyze.
                  </td>
                </tr>
              ) : (
                filtered.map((ev) => (
                  <tr
                    key={ev.id}
                    className={selected?.id === ev.id ? 'selected' : ''}
                    onClick={() => setSelected(ev)}
                    style={{ cursor: 'pointer' }}
                  >
                    <td>{fmt24(ev.detected_at)}</td>
                    <td>{ev.pid}</td>
                    <td>{ev.ppid}</td>
                    <td>{ev.uid}</td>
                    <td
                      className={ev.classification === 'malicious' ? 'cmd-malicious' : ''}
                      title={ev.command}
                    >
                      {ev.command.length > 48 ? ev.command.slice(0, 48) + '…' : ev.command}
                    </td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <SeverityBadge classification={ev.classification} size="sm" />
                        {ev.remediation_status === 'success' && (
                          <span className="remediation-badge-success" style={{
                            fontSize: '9px',
                            fontWeight: 700,
                            padding: '2px 6px',
                            borderRadius: '4px',
                            background: 'rgba(168, 85, 247, 0.15)',
                            color: 'rgb(192, 132, 252)',
                            border: '1px solid rgba(168, 85, 247, 0.3)',
                            whiteSpace: 'nowrap',
                          }}>
                            🛑 KILLED
                          </span>
                        )}
                        {ev.remediation_status && ev.remediation_status !== 'success' && ev.remediation_status !== 'skipped_no_pid' && (
                          <span className="remediation-badge-skipped" style={{
                            fontSize: '9px',
                            fontWeight: 700,
                            padding: '2px 6px',
                            borderRadius: '4px',
                            background: 'rgba(156, 163, 175, 0.15)',
                            color: 'rgb(209, 213, 219)',
                            border: '1px solid rgba(156, 163, 175, 0.3)',
                            whiteSpace: 'nowrap',
                          }} title={ev.remediation_status}>
                            ⚠️ SKIPPED
                          </span>
                        )}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
          <div className="threat-table-footer">
            <button type="button" className="btn-outline" onClick={handleExport}>
              <Download size={14} /> Export Log
            </button>
            <button type="button" className="btn-danger-outline" onClick={handleFlush} disabled={isFlushing}>
              <Trash2 size={14} /> {isFlushing ? 'Flushing…' : 'Flush Log'}
            </button>
          </div>
        </div>

        {selected && (
          <div className="glass-card threat-detail-panel">
            <div className="threat-detail-panel__header">
              <div>
                <div className="threat-detail-panel__id">EVENT {selected.id.toUpperCase()}</div>
                <div className="threat-detail-panel__sub">
                  Process Trace · PID {selected.pid}
                </div>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <SeverityBadge classification={selected.classification} />
                <button type="button" className="bell-btn" onClick={() => setSelected(null)}>
                  <X size={18} />
                </button>
              </div>
            </div>
            <div className="threat-detail-panel__cmd">
              $ {selected.command}
            </div>
            <div className="threat-detail-meta">
              {[
                ['Timestamp', fmt24(selected.detected_at)],
                ['PID', String(selected.pid)],
                ['PPID', String(selected.ppid)],
                ['UID', String(selected.uid)],
                selected.process_memory_mb !== undefined && selected.process_memory_mb > 0
                  ? ['Process RAM', `${selected.process_memory_mb.toFixed(1)} MB`]
                  : null,
                selected.system_memory_percent !== undefined && selected.system_memory_percent > 0
                  ? ['System RAM', `${selected.system_memory_percent.toFixed(0)}%`]
                  : null,
                selected.remediation_status
                  ? ['Remediation', selected.remediation_status.toUpperCase().replace(/_/g, ' ')]
                  : null,
              ].filter((item): item is [string, string] => item !== null).map(([k, v]) => (
                <div key={k} className="threat-detail-meta__item">
                  <span>{k}</span>
                  <strong>{v}</strong>
                </div>
              ))}
            </div>
            <div className="threat-detail-tiers">
              <div className="threat-tier">
                <Cpu size={18} className="threat-tier__icon threat-tier__icon--cyan" />
                <div>
                  <strong>Tier A — Rule Engine</strong>
                  <span>
                    {selected.matched_rules.length
                      ? selected.matched_rules.join(', ')
                      : 'No patterns matched'}
                  </span>
                </div>
                <span className="threat-tier__status">PROCESSING</span>
              </div>
              <div className="threat-tier">
                <Brain size={18} className="threat-tier__icon threat-tier__icon--orange" />
                <div>
                  <strong>Tier B — ML Scorer</strong>
                  <span>confidence {(selected.ml_confidence * 100).toFixed(1)}%</span>
                </div>
                <SeverityBadge classification={selected.classification} size="sm" />
              </div>
            </div>
            {selected.explanation && (
              <p className="threat-detail-explanation">{selected.explanation}</p>
            )}
            <div className="threat-detail-llm-trigger">
              <button
                type="button"
                className="btn-cta-gradient threat-detail-llm-btn"
                onClick={() => openLlmModal(false)}
              >
                <Sparkles size={15} />
                {llmText ?? selected.llm_explanation ? 'VIEW LLM ANALYSIS' : 'GENERATE LLM ANALYSIS'}
              </button>
            </div>
          </div>
        )}
      </div>

      {selected && (
        <LlmExplainModal
          open={llmModalOpen}
          onClose={() => setLlmModalOpen(false)}
          command={selected.command}
          classification={selected.classification}
          llmText={llmText ?? selected.llm_explanation ?? null}
          loading={llmLoading}
          error={llmError}
          cached={cached}
          onGenerate={(regenerate) => void explainEvent(selected.id, sessionToken, regenerate)}
        />
      )}
    </div>
  );
}
