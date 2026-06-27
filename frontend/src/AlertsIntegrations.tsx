import { FormEvent, useCallback, useEffect, useState } from 'react';
import { Plus, Trash2, Link2, RefreshCw } from 'lucide-react';
import { API_URL } from './config';
import { SeverityBadge } from './components/SeverityBadge';

interface WebhookRecord {
  id: string;
  url: string;
  is_active: boolean;
  created_at: number;
  trigger_safe: boolean;
  trigger_suspicious: boolean;
  trigger_malicious: boolean;
}

interface AlertHistory {
  id: string;
  event_id: string;
  url: string;
  status: string;
  timestamp: number;
}

export function AlertsIntegrations() {
  const [webhooks, setWebhooks] = useState<WebhookRecord[]>([]);
  const [alertHistory, setAlertHistory] = useState<AlertHistory[]>([]);
  const [url, setUrl] = useState('');
  const [error, setError] = useState('');
  const [triggerSafe, setTriggerSafe] = useState(false);
  const [triggerSuspicious, setTriggerSuspicious] = useState(true);
  const [triggerMalicious, setTriggerMalicious] = useState(true);
  const [refreshCount, setRefreshCount] = useState(0);

  const loadWebhooks = useCallback(async () => {
    try {
      const res = await fetch(`${API_URL}/webhooks`);
      if (!res.ok) throw new Error('Failed to load webhooks');
      setWebhooks(await res.json());
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Load failed');
    }
  }, []);

  const loadHistory = useCallback(async () => {
    try {
      const res = await fetch(`${API_URL}/alerts/history?limit=50`);
      if (res.ok) setAlertHistory(await res.json());
    } catch { /* ignore */ }
    setRefreshCount((c) => c + 1);
  }, []);

  useEffect(() => {
    void loadWebhooks();
    void loadHistory();
    const id = setInterval(() => void loadHistory(), 5000);
    return () => clearInterval(id);
  }, [loadWebhooks, loadHistory]);

  const addWebhook = async (e: FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;
    if (!triggerSafe && !triggerSuspicious && !triggerMalicious) {
      setError('Select at least one trigger.');
      return;
    }
    setError('');
    try {
      const res = await fetch(`${API_URL}/webhooks`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url,
          trigger_safe: triggerSafe,
          trigger_suspicious: triggerSuspicious,
          trigger_malicious: triggerMalicious,
        }),
      });
      if (!res.ok) throw new Error('Failed to register webhook');
      setUrl('');
      await loadWebhooks();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed');
    }
  };

  const removeWebhook = async (id: string) => {
    await fetch(`${API_URL}/webhooks/${id}`, { method: 'DELETE' });
    setWebhooks((w) => w.filter((x) => x.id !== id));
  };

  const toggleActive = (wh: WebhookRecord) => {
    setWebhooks((list) =>
      list.map((w) => (w.id === wh.id ? { ...w, is_active: !w.is_active } : w))
    );
  };

  const activeCount = webhooks.filter((w) => w.is_active).length;
  const fmtDate = (ts: number) => new Date(ts * 1000).toLocaleDateString('en-GB');
  const fmtTime = (ts: number) => new Date(ts * 1000).toLocaleTimeString('en-GB', { hour12: false });

  return (
    <div className="alerts-page">
      <div className="grid-2 alerts-top">
        <div className="glass-card">
          <div className="glass-card__header">
            <div className="glass-card__title">
              <Link2 size={16} style={{ color: 'var(--neon-cyan)' }} />
              Register New Webhook
            </div>
          </div>
          <form className="glass-card__body" onSubmit={addWebhook}>
            <div className="form-group">
              <label className="form-label">Target URL</label>
              <input
                className="form-input"
                type="url"
                placeholder="https://hooks.example.com/..."
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                required
              />
            </div>
            <div className="form-group" style={{ marginTop: 32 }}>
              <label className="form-label">Event Triggers</label>
              <div className="trigger-tags-row">
                <span className={`trigger-tag ${triggerSafe ? 'active safe' : ''}`} onClick={() => setTriggerSafe(!triggerSafe)}>SAFE</span>
                <span className={`trigger-tag ${triggerSuspicious ? 'active suspicious' : ''}`} onClick={() => setTriggerSuspicious(!triggerSuspicious)}>SUSPICIOUS</span>
                <span className={`trigger-tag ${triggerMalicious ? 'active malicious' : ''}`} onClick={() => setTriggerMalicious(!triggerMalicious)}>MALICIOUS</span>
              </div>
            </div>
            {error && <p style={{ color: 'var(--neon-red)', fontSize: 12, marginBottom: 12 }}>{error}</p>}
            <button type="submit" className="btn-cyan" style={{ width: '100%', justifyContent: 'center', marginTop: 24 }}>
              <Plus size={16} /> REGISTER WEBHOOK
            </button>
          </form>
        </div>

        <div className="glass-card">
          <div className="glass-card__header">
            <div className="glass-card__title">Active Endpoints</div>
            <span className="alerts-count">{activeCount} ACTIVE / {webhooks.length} TOTAL</span>
          </div>
          <div className="glass-card__body alerts-endpoints">
            {webhooks.length === 0 ? (
              <p style={{ color: 'var(--text-muted)', fontSize: 13, textAlign: 'center', padding: 24 }}>No webhooks registered.</p>
            ) : (
              webhooks.map((wh) => (
                <div key={wh.id} className="endpoint-row">
                  <span className={`endpoint-row__dot ${wh.is_active ? 'on' : ''}`} />
                  <div className="endpoint-row__info">
                    <code>{wh.url.length > 42 ? wh.url.slice(0, 42) + '…' : wh.url}</code>
                    <div className="endpoint-row__tags">
                      {wh.trigger_malicious && <SeverityBadge classification="malicious" size="sm" />}
                      {wh.trigger_suspicious && <SeverityBadge classification="suspicious" size="sm" />}
                      {wh.trigger_safe && <SeverityBadge classification="safe" size="sm" />}
                    </div>
                  </div>
                  <span className="endpoint-row__date">{fmtDate(wh.created_at)}</span>
                  <button type="button" className="btn-outline" style={{ fontSize: 10, padding: '6px 10px' }} onClick={() => toggleActive(wh)}>
                    {wh.is_active ? 'DEACTIVATE' : 'ACTIVATE'}
                  </button>
                  <button type="button" className="bell-btn" onClick={() => void removeWebhook(wh.id)}>
                    <Trash2 size={16} />
                  </button>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      <div className="glass-card alerts-log">
        <div className="glass-card__header">
          <div className="glass-card__title">Alert Dispatch Log</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <span className="alerts-poll">POLLING 5S · REFRESH #{refreshCount}</span>
            <button type="button" className="btn-danger-outline" onClick={() => setAlertHistory([])}>
              <Trash2 size={14} /> CLEAR HISTORY LOG
            </button>
            <button type="button" className="bell-btn" onClick={() => void loadHistory()}>
              <RefreshCw size={16} />
            </button>
          </div>
        </div>
        <table className="data-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Target URL</th>
              <th>Status</th>
              <th>Code</th>
            </tr>
          </thead>
          <tbody>
            {alertHistory.length === 0 ? (
              <tr>
                <td colSpan={4} style={{ textAlign: 'center', padding: 32, color: 'var(--text-muted)' }}>
                  No dispatch history yet.
                </td>
              </tr>
            ) : (
              alertHistory.map((a) => (
                <tr key={a.id}>
                  <td>{fmtTime(a.timestamp)}</td>
                  <td>{a.url.length > 50 ? a.url.slice(0, 50) + '…' : a.url}</td>
                  <td>
                    <span className="dispatch-ok">{a.status === 'success' || a.status === 'ok' ? 'OK' : a.status}</span>
                  </td>
                  <td>{a.status === 'success' || a.status === 'ok' ? '200' : '—'}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
