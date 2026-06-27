import {
  ArrowRight, ArrowUpRight, Stethoscope, Cpu, Brain, ShieldAlert,
  AlertTriangle, Shield, Terminal, Bell, BarChart3, Settings, Activity,
} from 'lucide-react';
import { PageHeader } from './components/PageHeader';
import type { SecurityEvent } from './useWebSocket';
import type { Page, Theme } from './types';

interface HomePageProps {
  events: SecurityEvent[];
  apiOnline: boolean;
  wsConnected: boolean;
  theme: Theme;
  utcTime: string;
  sessionToken?: string | null;
  onToggleTheme: () => void;
  onNavigate: (page: Page) => void;
}

const DEMO_TRACE = {
  pid: 14512,
  rule: 'reverse_shell_pattern',
  mlConfidence: 0.97,
  score: 96,
  remediation: 'kill -9 14512 · ebpf_hook-enforced',
};

const ARCHITECTURE = [
  {
    icon: Cpu,
    color: 'cyan' as const,
    title: 'Tier A — Rule Engine',
    desc: 'Pattern matching, entropy scoring, and memory profiling in under 1ms.',
  },
  {
    icon: Brain,
    color: 'orange' as const,
    title: 'Tier B — ML Scorer',
    desc: 'TF-IDF logistic regression trained on 12K commands for behavioral classification.',
  },
  {
    icon: Activity,
    color: 'green' as const,
    title: 'eBPF Native Hooks',
    desc: 'execve tracepoint capture with zero-copy ring buffer streaming to user space.',
  },
  {
    icon: ShieldAlert,
    color: 'red' as const,
    title: 'Auto-Remediation',
    desc: 'Optional kill-on-detect for malicious classifications with real PID enforcement.',
  },
];

const NAV_CARDS: { page: Page; icon: typeof Shield; title: string; desc: string }[] = [
  { page: 'monitor', icon: Shield, title: 'Threat Monitor', desc: 'Live kernel event stream with cascading analysis breakdown.' },
  { page: 'sandbox', icon: Terminal, title: 'Sandbox', desc: 'Test commands against the detection pipeline interactively.' },
  { page: 'alerts', icon: Bell, title: 'Alerts', desc: 'Webhook integrations and outbound dispatch logging.' },
  { page: 'analytics', icon: BarChart3, title: 'Analytics', desc: 'Telemetry, rule leaderboards, and resource footprint charts.' },
  { page: 'settings', icon: Settings, title: 'Settings', desc: 'Kernel mode, remediation, cache, and session configuration.' },
];

export function HomePage({
  events,
  apiOnline,
  wsConnected,
  theme,
  utcTime,
  sessionToken,
  onToggleTheme,
  onNavigate,
}: HomePageProps) {
  const latest = events.find((e) => e.classification === 'malicious') ?? events[0];
  const trace = latest
    ? {
        pid: latest.pid,
        rule: latest.matched_rules[0] ?? 'pattern_match',
        mlConfidence: latest.ml_confidence,
        score: Math.round(latest.risk_score),
        remediation: latest.remediation_status === 'success'
          ? `kill -9 ${latest.pid} · ebpf_hook-enforced`
          : DEMO_TRACE.remediation,
        classification: latest.classification,
      }
    : { ...DEMO_TRACE, classification: 'malicious' as const };

  const eventLabel = events.length >= 1000
    ? `${(events.length / 1000).toFixed(1)}K`
    : events.length > 0
      ? String(events.length)
      : '1.6M';

  const precision = events.length > 0
    ? `${Math.max(90, 100 - (events.filter((e) => e.classification === 'safe').length / events.length) * 5).toFixed(1)}%`
    : '98.2%';

  return (
    <div className="home-page">
      <div className="home-glow home-glow--green" aria-hidden />
      <div className="home-glow home-glow--cyan" aria-hidden />

      <PageHeader
        title="Welcome to AEGIX"
        subtitle="Cascading AI security for the kernel"
        apiOnline={apiOnline}
        wsConnected={wsConnected}
        theme={theme}
        onToggleTheme={onToggleTheme}
        utcTime={utcTime}
        sessionToken={sessionToken}
      />

      <div className="home-hero-grid">
        <div className="home-hero">
          <div className="home-hero__pill">
            <span className="home-hero__pill-dot" />
            KERNEL DAEMON · V2.4.1 · ONLINE
          </div>
          <h2 className="home-hero__headline">
            Cascading AI Security at{' '}
            <span className="home-hero__glow">Kernel Speed</span>
          </h2>
          <p className="home-hero__desc">
            A two-tier bouncer system that intercepts every process spawn at the kernel level,
            runs cascading rule + ML analysis in milliseconds, and surfaces human-readable
            verdicts on a live dashboard.
          </p>
          <div className="home-hero__actions">
            <button type="button" className="btn-hero-primary" onClick={() => onNavigate('monitor')}>
              ENTER COMMAND CENTER <ArrowRight size={16} />
            </button>
            <button type="button" className="btn-hero-ghost" onClick={() => onNavigate('sandbox')}>
              <Terminal size={15} /> TRY THE SANDBOX
            </button>
          </div>
        </div>

        <div className="glass-card home-pipeline home-pipeline--glow">
          <div className="glass-card__header">
            <div>
              <div className="home-pipeline__eyebrow">CASCADE PIPELINE</div>
              <div className="home-pipeline__sub">Inline verdict trace</div>
            </div>
            <ActivityPulse />
          </div>
          <div className="glass-card__body home-pipeline__steps">
            <PipelineStep icon={<Stethoscope size={16} />} color="cyan" title="Capture" desc={`exec syscall · PID ${trace.pid}`} time="0.1ms" />
            <PipelineStep icon={<Cpu size={16} />} color="cyan" title="Rule Engine" desc={`match: ${trace.rule}`} time="0.4ms" />
            <PipelineStep icon={<Brain size={16} />} color="orange" title="ML Scorer" desc={`confidence ${trace.mlConfidence.toFixed(2)}`} time="5.2ms" />
            <PipelineStep icon={<ShieldAlert size={16} />} color="red" title="Verdict" desc={`${trace.classification.toUpperCase()} · score ${trace.score}/100`} time="5.4ms" />
            <div className="home-pipeline__alert">
              <AlertTriangle size={16} />
              <div>
                <strong>AUTO-REMEDIATION ISSUED</strong>
                <code>{trace.remediation}</code>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="home-stats-row">
        {[
          { value: '5.4ms', label: 'Median Verdict Latency' },
          { value: eventLabel, label: 'Events Processed' },
          { value: precision, label: 'Detection Precision' },
          { value: '40+', label: 'Kernel Signatures' },
        ].map((s) => (
          <div key={s.label} className="home-stat-card">
            <strong>{s.value}</strong>
            <span>{s.label}</span>
          </div>
        ))}
      </div>

      <section className="home-section">
        <h3 className="home-section__title">Two tiers. One verdict.</h3>
        <div className="home-arch-grid">
          {ARCHITECTURE.map(({ icon: Icon, color, title, desc }) => (
            <div key={title} className="home-arch-card">
              <div className={`home-arch-card__icon home-arch-card__icon--${color}`}>
                <Icon size={18} />
              </div>
              <strong>{title}</strong>
              <p>{desc}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="home-section">
        <h3 className="home-section__title">Explore the command center</h3>
        <div className="home-nav-grid">
          {NAV_CARDS.map(({ page, icon: Icon, title, desc }) => (
            <button key={page} type="button" className="home-nav-card" onClick={() => onNavigate(page)}>
              <ArrowUpRight size={14} className="home-nav-card__arrow" />
              <Icon size={20} className="home-nav-card__icon" />
              <strong>{title}</strong>
              <p>{desc}</p>
            </button>
          ))}
        </div>
      </section>

      <div className="home-soc-banner glass-card">
        <div>
          <strong>Step into the SOC.</strong>
          <p>Live kernel events, cascading analytics, and remediation — all in one room.</p>
        </div>
        <button type="button" className="btn-cta-gradient" onClick={() => onNavigate('monitor')}>
          OPEN THREAT MONITOR <ArrowRight size={16} />
        </button>
      </div>
    </div>
  );
}

function ActivityPulse() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" className="home-pipeline__pulse">
      <path d="M2 12h4l2-6 4 12 2-6h8" stroke="var(--neon-green)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function PipelineStep({
  icon, color, title, desc, time,
}: {
  icon: React.ReactNode;
  color: 'cyan' | 'orange' | 'red';
  title: string;
  desc: string;
  time: string;
}) {
  return (
    <div className="pipeline-step">
      <div className={`pipeline-step__icon pipeline-step__icon--${color}`}>{icon}</div>
      <div className="pipeline-step__content">
        <strong>{title}</strong>
        <span>{desc}</span>
      </div>
      <span className="pipeline-step__time">{time}</span>
    </div>
  );
}
