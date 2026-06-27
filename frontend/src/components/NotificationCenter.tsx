import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  Bell, X, Mail, Trash2, CheckCheck, Webhook, FileDown, Settings2,
  Send, Building2,
} from 'lucide-react';
import { API_URL } from '../config';

export interface AppNotification {
  id: string;
  category: string;
  title: string;
  message: string;
  timestamp: number;
  read: boolean;
}

interface NotificationCenterProps {
  sessionToken?: string | null;
}

function categoryIcon(category: string) {
  switch (category) {
    case 'webhook':
      return <Webhook size={14} />;
    case 'logs':
      return <FileDown size={14} />;
    case 'settings':
      return <Settings2 size={14} />;
    case 'email':
      return <Mail size={14} />;
    default:
      return <Bell size={14} />;
  }
}

function fmtTime(ts: number) {
  return new Date(ts * 1000).toLocaleString('en-GB', {
    hour: '2-digit',
    minute: '2-digit',
    day: '2-digit',
    month: 'short',
  });
}

export function NotificationCenter({ sessionToken }: NotificationCenterProps) {
  const [open, setOpen] = useState(false);
  const [tab, setTab] = useState<'feed' | 'email'>('feed');
  const [notifications, setNotifications] = useState<AppNotification[]>([]);
  const [unread, setUnread] = useState(0);
  const [departments, setDepartments] = useState<Record<string, string>>({});
  const [email, setEmail] = useState('');
  const [department, setDepartment] = useState('');
  const [format, setFormat] = useState('json');
  const [sending, setSending] = useState(false);
  const [emailStatus, setEmailStatus] = useState('');
  const panelRef = useRef<HTMLDivElement>(null);

  // Department Management States
  const [manageDepts, setManageDepts] = useState(false);
  const [newDeptName, setNewDeptName] = useState('');
  const [newDeptEmail, setNewDeptEmail] = useState('');
  const [addingDept, setAddingDept] = useState(false);
  const [deptError, setDeptError] = useState('');

  const withSession = useCallback(
    (url: URL) => {
      if (sessionToken) url.searchParams.set('session_token', sessionToken);
      return url;
    },
    [sessionToken],
  );

  const refresh = useCallback(async () => {
    try {
      const listUrl = withSession(new URL(`${API_URL}/api/notifications`));
      listUrl.searchParams.set('limit', '40');
      const countUrl = withSession(new URL(`${API_URL}/api/notifications/unread-count`));
      const [listRes, countRes] = await Promise.all([
        fetch(listUrl.toString()),
        fetch(countUrl.toString()),
      ]);
      if (listRes.ok) setNotifications(await listRes.json());
      if (countRes.ok) {
        const d = await countRes.json();
        setUnread(d.count ?? 0);
      }
    } catch {
      /* backend offline */
    }
  }, [withSession]);

  const fetchDepartments = useCallback(() => {
    fetch(`${API_URL}/api/reports/departments`)
      .then((r) => r.json())
      .then((d) => setDepartments(d.departments ?? {}))
      .catch(() => {});
  }, []);

  useEffect(() => {
    void refresh();
    const id = setInterval(() => void refresh(), 8000);
    return () => clearInterval(id);
  }, [refresh]);

  useEffect(() => {
    if (open) {
      fetchDepartments();
    }
  }, [open, fetchDepartments]);

  useEffect(() => {
    const onDocClick = (e: MouseEvent) => {
      if (panelRef.current && !panelRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    if (open) document.addEventListener('mousedown', onDocClick);
    return () => document.removeEventListener('mousedown', onDocClick);
  }, [open]);

  const markAllRead = async () => {
    const url = withSession(new URL(`${API_URL}/api/notifications/read-all`));
    await fetch(url.toString(), { method: 'POST' });
    void refresh();
  };

  const clearAll = async () => {
    const url = withSession(new URL(`${API_URL}/api/notifications`));
    await fetch(url.toString(), { method: 'DELETE' });
    void refresh();
  };

  const addDept = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newDeptName.trim() || !newDeptEmail.trim()) return;
    setAddingDept(true);
    setDeptError('');
    try {
      const res = await fetch(`${API_URL}/api/reports/departments`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: newDeptName.trim(), email: newDeptEmail.trim() }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Failed to add');
      setNewDeptName('');
      setNewDeptEmail('');
      fetchDepartments();
    } catch (err) {
      setDeptError(err instanceof Error ? err.message : 'Error adding');
    } finally {
      setAddingDept(false);
    }
  };

  const deleteDept = async (name: string) => {
    try {
      const res = await fetch(`${API_URL}/api/reports/departments/${encodeURIComponent(name)}`, {
        method: 'DELETE',
      });
      if (res.ok) {
        fetchDepartments();
      }
    } catch {
      // ignore
    }
  };

  const sendReport = async () => {
    if (!email.trim()) return;
    setSending(true);
    setEmailStatus('');
    try {
      const res = await fetch(`${API_URL}/api/reports/email`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          to_email: email.trim(),
          provider: 'gmail',
          department: department || null,
          format: format,
          session_token: sessionToken,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Send failed');
      setEmailStatus(`Sent to ${data.recipients?.join(', ') || email}`);
      void refresh();
    } catch (e) {
      setEmailStatus(e instanceof Error ? e.message : 'Failed to send');
    } finally {
      setSending(false);
    }
  };

  return (
    <div className="notification-center" ref={panelRef}>
      <button
        type="button"
        className={`bell-btn ${open ? 'bell-btn--active' : ''}`}
        aria-label="Notifications"
        onClick={() => setOpen((v) => !v)}
      >
        <Bell size={18} />
        {unread > 0 && <span className="bell-btn__dot" />}
      </button>

      {open && (
        <div className="notification-panel glass-card">
          <div className="notification-panel__header">
            <strong>Notifications</strong>
            <button type="button" className="bell-btn" onClick={() => setOpen(false)}>
              <X size={16} />
            </button>
          </div>

          <div className="notification-tabs">
            <button
              type="button"
              className={tab === 'feed' ? 'active' : ''}
              onClick={() => {
                setTab('feed');
                setManageDepts(false);
              }}
            >
              Activity
            </button>
            <button
              type="button"
              className={tab === 'email' ? 'active' : ''}
              onClick={() => setTab('email')}
            >
              <Mail size={14} /> Email Report
            </button>
          </div>

          {tab === 'feed' ? (
            <>
              <div className="notification-panel__actions">
                <button type="button" className="btn-outline" style={{ padding: '6px 10px', fontSize: 11 }} onClick={markAllRead}>
                  <CheckCheck size={12} /> Mark all read
                </button>
                <button type="button" className="btn-danger-outline" style={{ padding: '6px 10px', fontSize: 11 }} onClick={clearAll}>
                  <Trash2 size={12} /> Clear
                </button>
              </div>
              <div className="notification-list">
                {notifications.length === 0 ? (
                  <p className="notification-empty">No activity yet. Webhook changes, log exports, and sensitivity updates appear here.</p>
                ) : (
                  notifications.map((n) => (
                    <div key={n.id} className={`notification-item ${n.read ? '' : 'unread'}`}>
                      <span className={`notification-item__icon notification-item__icon--${n.category}`}>
                        {categoryIcon(n.category)}
                      </span>
                      <div>
                        <strong>{n.title}</strong>
                        <p>{n.message}</p>
                        <span className="notification-item__time">{fmtTime(n.timestamp)}</span>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </>
          ) : manageDepts ? (
            <div className="email-report-form">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                <strong style={{ fontSize: 13, color: '#ffffff' }}>Manage Departments</strong>
                <button
                  type="button"
                  className="btn-link"
                  style={{ fontSize: 11, padding: 0, background: 'none', border: 'none', color: 'var(--neon-cyan)', cursor: 'pointer' }}
                  onClick={() => setManageDepts(false)}
                >
                  Back to Report
                </button>
              </div>

              {/* Add form */}
              <form onSubmit={(e) => void addDept(e)} style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 14 }}>
                <input
                  className="form-input"
                  type="text"
                  placeholder="Department Name (e.g. SOC)"
                  value={newDeptName}
                  onChange={(e) => setNewDeptName(e.target.value)}
                  required
                />
                <input
                  className="form-input"
                  type="email"
                  placeholder="email@company.com"
                  value={newDeptEmail}
                  onChange={(e) => setNewDeptEmail(e.target.value)}
                  required
                />
                <button type="submit" className="btn-cyan" style={{ justifyContent: 'center' }} disabled={addingDept}>
                  Add Department
                </button>
                {deptError && <p className="email-report-status err">{deptError}</p>}
              </form>

              {/* List */}
              <div className="dept-list" style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 180, overflowY: 'auto' }}>
                {Object.keys(departments).length === 0 ? (
                  <p className="notification-empty" style={{ margin: 0, padding: 10 }}>No departments added yet.</p>
                ) : (
                  Object.entries(departments).map(([name, addr]) => (
                    <div key={name} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '6px 8px', background: 'rgba(255,255,255,0.03)', borderRadius: 4, border: '1px solid var(--border-color)', fontSize: 12 }}>
                      <div style={{ minWidth: 0, flex: 1, paddingRight: 8 }}>
                        <strong style={{ display: 'block', color: 'var(--text-primary)', textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>{name}</strong>
                        <span style={{ fontSize: 11, color: 'var(--text-muted)', textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap', display: 'block' }}>{addr}</span>
                      </div>
                      <button
                        type="button"
                        style={{ background: 'none', border: 'none', color: 'var(--neon-red)', cursor: 'pointer', padding: 4 }}
                        onClick={() => deleteDept(name)}
                      >
                        <Trash2 size={12} />
                      </button>
                    </div>
                  ))
                )}
              </div>
            </div>
          ) : (
            <div className="email-report-form">
              <p className="email-report-form__hint">
                Sends event audits using Gmail SMTP. Attachments are configured below.
              </p>
              <label className="form-label">Your email</label>
              <input
                className="form-input"
                type="email"
                placeholder="you@company.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />

              <label className="form-label" style={{ marginTop: 12 }}>Report Format</label>
              <select
                className="form-input"
                value={format}
                onChange={(e) => setFormat(e.target.value)}
              >
                <option value="json">JSON Log Attachment</option>
                <option value="csv">CSV Spreadsheet Attachment</option>
                <option value="html">Rich HTML Email Summary</option>
              </select>

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 12 }}>
                <label className="form-label" style={{ margin: 0 }}>
                  <Building2 size={12} style={{ display: 'inline', marginRight: 4 }} />
                  Department (Gmail CC — internal routing)
                </label>
                <button
                  type="button"
                  className="btn-link"
                  style={{ fontSize: 11, padding: 0, background: 'none', border: 'none', color: 'var(--neon-cyan)', cursor: 'pointer' }}
                  onClick={() => setManageDepts(true)}
                >
                  Manage
                </button>
              </div>
              <select
                className="form-input"
                value={department}
                onChange={(e) => setDepartment(e.target.value)}
                style={{ marginTop: 6 }}
              >
                <option value="">None — send only to me</option>
                {Object.entries(departments).map(([name, addr]) => (
                  <option key={name} value={name}>
                    {name} ({addr})
                  </option>
                ))}
              </select>

              <div className="email-provider-pill" style={{ marginTop: 12 }}>
                <Mail size={14} /> Gmail SMTP
              </div>
              <button
                type="button"
                className="btn-cyan"
                style={{ width: '100%', justifyContent: 'center', marginTop: 14 }}
                disabled={sending || !email.trim()}
                onClick={() => void sendReport()}
              >
                <Send size={14} />
                {sending ? 'Sending…' : 'Send Log Report'}
              </button>
              {emailStatus && (
                <p className={`email-report-status ${emailStatus.startsWith('Sent') ? 'ok' : 'err'}`}>
                  {emailStatus}
                </p>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
