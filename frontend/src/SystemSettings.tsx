import { useState, useEffect } from 'react';
import { API_URL } from './config';
import { Theme } from './App';
import { Info, Sliders, Globe, Shield } from 'lucide-react';

interface SystemSettingsProps {
  theme: Theme;
  setTheme: React.Dispatch<React.SetStateAction<Theme>>;
}

interface Webhook {
  id: string;
  url: string;
  is_active: boolean;
  created_at: number;
  trigger_safe: boolean;
  trigger_suspicious: boolean;
  trigger_malicious: boolean;
}

export function SystemSettings({ theme, setTheme }: SystemSettingsProps) {
  const [webhooks, setWebhooks] = useState<Webhook[]>([]);
  const [newWebhookUrl, setNewWebhookUrl] = useState("");
  const [triggerSafe, setTriggerSafe] = useState(false);
  const [triggerSuspicious, setTriggerSuspicious] = useState(false);
  const [triggerMalicious, setTriggerMalicious] = useState(true);
  
  const [sensitivity, setSensitivity] = useState(30); // 100 - malicious_threshold

  const fetchSettings = () => {
    fetch(`${API_URL}/settings/thresholds`)
      .then((r) => {
        if (!r.ok) throw new Error("Failed to fetch settings");
        return r.json();
      })
      .then((d) => {
        if (d && typeof d.malicious_threshold === 'number') {
          setSensitivity(100 - d.malicious_threshold);
        }
      })
      .catch((err) => console.error("Could not load thresholds:", err));
  };

  const fetchWebhooks = () => {
    fetch(`${API_URL}/webhooks`)
      .then((r) => r.json())
      .then(setWebhooks)
      .catch(console.error);
  };

  useEffect(() => {
    fetchWebhooks();
    fetchSettings();
  }, []);

  const handleSensitivityChange = (val: number) => {
    setSensitivity(val);
    const newMalicious = 100 - val;
    const newSuspicious = newMalicious * 0.4; // arbitrary scale for suspicious
    
    fetch(`${API_URL}/settings/thresholds`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        suspicious_threshold: newSuspicious,
        malicious_threshold: newMalicious
      }),
    }).catch(console.error);
  };

  const handleAddWebhook = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newWebhookUrl) return;
    
    // Check if at least one tag is selected
    if (!triggerSafe && !triggerSuspicious && !triggerMalicious) {
      alert("Please select at least one trigger condition (Safe, Suspicious, or Malicious).");
      return;
    }

    fetch(`${API_URL}/webhooks`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        url: newWebhookUrl,
        trigger_safe: triggerSafe,
        trigger_suspicious: triggerSuspicious,
        trigger_malicious: triggerMalicious
      }),
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

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Configuration</h1>
        <p className="page-subtitle">Adjust the kernel-level defense parameters and AI decision thresholds for the active guarding instance.</p>
      </div>

      <div className="settings-grid">
        
        {/* GENERAL CONFIG */}
        <div className="panel-card">
          <div className="panel-header" style={{ color: 'var(--accent-primary)', padding: '16px 24px' }}>
            <div className="panel-title" style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '15px' }}>
              <Sliders size={18} /> General
            </div>
          </div>
          <div style={{ padding: '24px' }}>
            
            <div className="form-group">
              <label className="form-label">THEME SELECTION</label>
              <div className="theme-selector">
                <div className={`theme-btn ${theme === 'dark' ? 'active' : ''}`} onClick={() => setTheme('dark')}>
                  <div style={{ width: '16px', height: '16px', borderRadius: '50%', border: '2px solid currentColor' }}></div>
                  <span style={{ fontSize: '13px', fontWeight: 600 }}>Dark</span>
                </div>
                <div className={`theme-btn ${theme === 'light' ? 'active' : ''}`} onClick={() => setTheme('light')}>
                  <div style={{ width: '16px', height: '16px', borderRadius: '50%', backgroundColor: 'currentColor' }}></div>
                  <span style={{ fontSize: '13px', fontWeight: 600 }}>Light</span>
                </div>
                <div className={`theme-btn ${theme === 'system' ? 'active' : ''}`} onClick={() => setTheme('system')}>
                  <div style={{ width: '16px', height: '16px', borderRadius: '4px', border: '2px solid currentColor' }}></div>
                  <span style={{ fontSize: '13px', fontWeight: 600 }}>System</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* KERNEL GUARD CONFIG */}
        <div className="panel-card">
          <div className="panel-header" style={{ color: 'var(--accent-primary)', padding: '16px 24px' }}>
            <div className="panel-title" style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '15px' }}>
              <Shield size={18} /> Kernel Guard Config
            </div>
          </div>
          <div style={{ padding: '24px' }}>
            
            <div className="form-group">
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
                <label className="form-label" style={{ marginBottom: 0 }}>AI SENSITIVITY SLIDER</label>
                <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--accent-primary)' }}>{sensitivity}%</span>
              </div>
              <input 
                type="range" 
                min="0" max="100" 
                value={sensitivity} 
                onChange={(e) => handleSensitivityChange(Number(e.target.value))}
                style={{ width: '100%', accentColor: 'var(--accent-primary)', marginBottom: '8px' }}
              />
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
                <span>Passive</span>
                <span>Aggressive</span>
              </div>
            </div>

            <div className="form-group" style={{ marginTop: '32px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
                <label className="form-label" style={{ marginBottom: 0 }}>AUTO-KILL THRESHOLD</label>
                <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--status-malicious)' }}>CRITICAL</span>
              </div>
              <div style={{ display: 'flex', gap: '4px', marginBottom: '8px' }}>
                <div style={{ height: '6px', backgroundColor: 'var(--status-suspicious)', flex: 1, borderRadius: '3px' }}></div>
                <div style={{ height: '6px', backgroundColor: 'var(--status-malicious)', flex: 2, borderRadius: '3px' }}></div>
                <div style={{ height: '6px', backgroundColor: 'var(--border-color)', flex: 1, borderRadius: '3px' }}></div>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
                <span>Suspicious</span>
                <span>Malicious Only</span>
              </div>
            </div>

            <div style={{ backgroundColor: 'var(--bg-main)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '16px', display: 'flex', gap: '12px', marginTop: '32px' }}>
              <Info size={20} color="var(--accent-primary)" style={{ flexShrink: 0 }} />
              <div>
                <h4 style={{ fontSize: '13px', marginBottom: '4px', fontWeight: 600 }}>Defense Matrix Info</h4>
                <p style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.5, marginBottom: '12px' }}>
                  The AI Sensitivity Slider controls the strictness of the heuristic engine. A higher sensitivity (Aggressive) lowers the required risk score, allowing the engine to block potential threats faster but increasing the risk of false positives. The recommended optimum level is <b>30%</b> for standard production environments, balancing robust security with normal system operations.
                </p>
                <span style={{ fontSize: '10px', fontWeight: 700, color: 'var(--accent-primary)', textTransform: 'uppercase' }}>
                  ● AI ENGINE: V4.2.0-STABLE
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* ACTIVE WEBHOOKS */}
        <div className="panel-card" style={{ gridColumn: '1 / -1' }}>
          <div className="panel-header" style={{ color: 'var(--accent-primary)', padding: '16px 24px' }}>
            <div className="panel-title" style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '15px' }}>
              <Globe size={18} /> Active Webhooks
            </div>
          </div>
          
          <div style={{ flex: 1 }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Endpoint</th>
                  <th>Status</th>
                  <th>Triggers</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {webhooks.length === 0 && (
                  <tr>
                    <td colSpan={4} style={{ textAlign: 'center', padding: '24px', color: 'var(--text-secondary)' }}>
                      No webhooks configured.
                    </td>
                  </tr>
                )}
                {webhooks.map(wh => (
                  <tr key={wh.id}>
                    <td style={{ color: 'var(--accent-primary)', fontSize: '12px' }}>{wh.url.length > 50 ? wh.url.substring(0, 50) + '...' : wh.url}</td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', fontWeight: 600 }}>
                        <div style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: wh.is_active ? 'var(--status-safe)' : 'var(--status-malicious)' }}></div> {wh.is_active ? 'Active' : 'Disabled'}
                      </div>
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: '4px' }}>
                        {wh.trigger_safe && <div className="badge" style={{ backgroundColor: 'var(--status-safe-bg)', color: 'var(--status-safe)', fontSize: '10px' }}>SAFE</div>}
                        {wh.trigger_suspicious && <div className="badge" style={{ backgroundColor: 'var(--status-suspicious-bg)', color: 'var(--status-suspicious)', fontSize: '10px' }}>SUSPICIOUS</div>}
                        {wh.trigger_malicious && <div className="badge" style={{ backgroundColor: 'var(--status-malicious-bg)', color: 'var(--status-malicious)', fontSize: '10px' }}>MALICIOUS</div>}
                      </div>
                    </td>
                    <td>
                      <button className="btn-outline" onClick={() => handleDeleteWebhook(wh.id)} style={{ padding: '4px 12px', fontSize: '11px', color: 'var(--status-malicious)', borderColor: 'var(--status-malicious)' }}>Delete</button>
                    </td>
                  </tr>
                ))}
                <tr>
                  <td colSpan={4} style={{ padding: '16px 24px', backgroundColor: 'var(--bg-main)' }}>
                     <form onSubmit={handleAddWebhook} style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                        <input
                          type="url"
                          placeholder="Add webhook URL..."
                          value={newWebhookUrl}
                          onChange={(e) => setNewWebhookUrl(e.target.value)}
                          style={{ width: '100%', padding: '10px 12px', borderRadius: '4px', border: '1px solid var(--border-color)', backgroundColor: 'var(--bg-card)', color: 'var(--text-primary)', fontSize: '12px' }}
                          required
                        />
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <div style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
                            <span style={{ fontSize: '12px', color: 'var(--text-secondary)', fontWeight: 600 }}>Trigger On:</span>
                            <div 
                              className={`custom-checkbox ${triggerSafe ? 'active safe' : ''}`}
                              onClick={() => setTriggerSafe(!triggerSafe)}
                            >
                              Safe
                            </div>
                            <div 
                              className={`custom-checkbox ${triggerSuspicious ? 'active suspicious' : ''}`}
                              onClick={() => setTriggerSuspicious(!triggerSuspicious)}
                            >
                              Suspicious
                            </div>
                            <div 
                              className={`custom-checkbox ${triggerMalicious ? 'active malicious' : ''}`}
                              onClick={() => setTriggerMalicious(!triggerMalicious)}
                            >
                              Malicious
                            </div>
                          </div>
                          <button type="submit" className="btn-cyan" style={{ padding: '8px 24px', fontSize: '12px' }}>Add Webhook</button>
                        </div>
                      </form>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <div className="settings-footer">
        <button className="btn-outline" style={{ padding: '12px 24px', fontSize: '14px' }}>Reset to Defaults</button>
        <button className="btn-cyan" style={{ padding: '12px 24px', fontSize: '14px' }}>Commit Changes</button>
      </div>

    </div>
  );
}
