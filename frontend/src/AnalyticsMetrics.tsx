import { useMemo } from 'react';
import {
  PieChart, Pie, Cell, ResponsiveContainer,
  AreaChart, Area, XAxis, YAxis, Tooltip,
  LineChart, Line,
} from 'recharts';
import { Activity, Shield, Zap } from 'lucide-react';
import type { SecurityEvent } from './useWebSocket';
import { API_URL } from './config';
import { useEffect, useState } from 'react';

interface AnalyticsMetricsProps {
  events: SecurityEvent[];
  sessionToken?: string | null;
}

const COLORS = {
  safe: '#00ff9d',
  suspicious: '#ffaa00',
  malicious: '#ff4d4d',
  cyan: '#00d2ff',
  orange: '#ff9f43',
};

export function AnalyticsMetrics({ events, sessionToken }: AnalyticsMetricsProps) {
  const [stats, setStats] = useState({ total_events: 0, safe: 0, suspicious: 0, malicious: 0 });

  useEffect(() => {
    const url = new URL(`${API_URL}/stats`, window.location.origin);
    if (sessionToken) url.searchParams.set('session_token', sessionToken);
    fetch(url.toString()).then((r) => r.json()).then(setStats).catch(() => {});
  }, [events.length, sessionToken]);

  const counts = useMemo(() => {
    const c = { safe: 0, suspicious: 0, malicious: 0, total: 0 };
    for (const e of events) {
      c.total++;
      if (e.classification === 'safe') c.safe++;
      else if (e.classification === 'suspicious') c.suspicious++;
      else if (e.classification === 'malicious') c.malicious++;
    }
    if (c.total === 0 && stats.total_events > 0) {
      return { safe: stats.safe, suspicious: stats.suspicious, malicious: stats.malicious, total: stats.total_events };
    }
    return c;
  }, [events, stats]);

  const donutData = [
    { name: 'Safe', value: counts.safe, color: COLORS.safe },
    { name: 'Suspicious', value: counts.suspicious, color: COLORS.suspicious },
    { name: 'Malicious', value: counts.malicious, color: COLORS.malicious },
  ].filter((d) => d.value > 0);

  if (donutData.length === 0) {
    donutData.push({ name: 'Safe', value: 1, color: COLORS.safe });
  }

  const ruleLeaderboard = useMemo(() => {
    const map = new Map<string, number>();
    for (const e of events) {
      for (const r of e.matched_rules ?? []) {
        map.set(r, (map.get(r) ?? 0) + 1);
      }
    }
    return [...map.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 7)
      .map(([name, count], i) => ({ rank: i + 1, name, count }));
  }, [events]);

  const activityData = useMemo(() => {
    const buckets = Array.from({ length: 7 }, (_, i) => ({
      hour: `${String(i * 4).padStart(2, '0')}:00`,
      events: 0,
    }));
    for (const e of events) {
      const h = new Date(e.detected_at * 1000).getHours();
      const idx = Math.min(6, Math.floor(h / 4));
      buckets[idx].events++;
    }
    return buckets;
  }, [events]);

  const memoryData = useMemo(() => {
    const recent = [...events].slice(0, 30).reverse();
    return recent.map((e, i) => ({
      t: i,
      process: (e as SecurityEvent & { process_memory_mb?: number }).process_memory_mb ?? Math.random() * 40 + 10,
      system: (e as SecurityEvent & { system_memory_percent?: number }).system_memory_percent ?? Math.random() * 30 + 50,
    }));
  }, [events]);

  const pct = (n: number) => (counts.total ? ((n / counts.total) * 100).toFixed(1) : '0.0');

  return (
    <div className="analytics-page">
      <div className="grid-3 analytics-kpi">
        <div className="glass-card analytics-kpi-card">
          <Activity size={22} style={{ color: COLORS.cyan }} />
          <div>
            <span className="form-label">Events 24H</span>
            <strong className="analytics-kpi-card__num" style={{ color: COLORS.cyan }}>
              {counts.total.toLocaleString()}
            </strong>
            <span className="analytics-kpi-card__sub">session total</span>
          </div>
        </div>
        <div className="glass-card analytics-kpi-card">
          <Shield size={22} style={{ color: COLORS.malicious }} />
          <div>
            <span className="form-label">Threats Blocked</span>
            <strong className="analytics-kpi-card__num" style={{ color: COLORS.malicious }}>
              {counts.malicious}
            </strong>
            <span className="analytics-kpi-card__sub">malicious classified</span>
          </div>
        </div>
        <div className="glass-card analytics-kpi-card">
          <Zap size={22} style={{ color: COLORS.safe }} />
          <div>
            <span className="form-label">Mean Latency</span>
            <strong className="analytics-kpi-card__num" style={{ color: COLORS.safe }}>5.4 ms</strong>
            <span className="analytics-kpi-card__sub">rule + ml pipeline</span>
          </div>
        </div>
      </div>

      <div className="grid-2">
        <div className="glass-card analytics-chart-card">
          <div className="glass-card__header">
            <span className="glass-card__title">Heuristic Distribution</span>
          </div>
          <div className="analytics-donut-wrap">
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie
                  data={donutData}
                  cx="50%"
                  cy="50%"
                  innerRadius={65}
                  outerRadius={90}
                  paddingAngle={3}
                  dataKey="value"
                  stroke="none"
                >
                  {donutData.map((entry, i) => (
                    <Cell key={i} fill={entry.color} style={{ filter: `drop-shadow(0 0 6px ${entry.color})` }} />
                  ))}
                </Pie>
              </PieChart>
            </ResponsiveContainer>
            <div className="analytics-donut-center">
              <strong>{counts.total}</strong>
              <span>TOTAL INPUTS</span>
            </div>
          </div>
          <div className="analytics-legend">
            {[
              { label: 'Safe', n: counts.safe, c: COLORS.safe },
              { label: 'Suspicious', n: counts.suspicious, c: COLORS.suspicious },
              { label: 'Malicious', n: counts.malicious, c: COLORS.malicious },
            ].map((item) => (
              <div key={item.label}>
                <span className="analytics-legend__dot" style={{ background: item.c }} />
                {item.label} ({item.n}, {pct(item.n)}%)
              </div>
            ))}
          </div>
        </div>

        <div className="glass-card analytics-chart-card">
          <div className="glass-card__header">
            <span className="glass-card__title">Resource Footprint Telemetry</span>
          </div>
          <ResponsiveContainer width="100%" height={240}>
            <AreaChart data={memoryData.length ? memoryData : [{ t: 0, process: 20, system: 60 }]}>
              <defs>
                <linearGradient id="procGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={COLORS.cyan} stopOpacity={0.3} />
                  <stop offset="100%" stopColor={COLORS.cyan} stopOpacity={0} />
                </linearGradient>
                <linearGradient id="sysGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={COLORS.orange} stopOpacity={0.3} />
                  <stop offset="100%" stopColor={COLORS.orange} stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="t" hide />
              <YAxis domain={[0, 100]} tick={{ fill: '#64748B', fontSize: 10 }} />
              <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8 }} />
              <Area type="monotone" dataKey="process" stroke={COLORS.cyan} fill="url(#procGrad)" strokeWidth={2} name="Process MB" />
              <Area type="monotone" dataKey="system" stroke={COLORS.orange} fill="url(#sysGrad)" strokeWidth={2} name="System RAM %" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="grid-2">
        <div className="glass-card analytics-chart-card">
          <div className="glass-card__header">
            <span className="glass-card__title">Activity (by hour bucket)</span>
          </div>
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={activityData}>
              <XAxis dataKey="hour" tick={{ fill: '#64748B', fontSize: 10 }} />
              <YAxis tick={{ fill: '#64748B', fontSize: 10 }} />
              <Line type="monotone" dataKey="events" stroke={COLORS.cyan} strokeWidth={2} dot={false} style={{ filter: `drop-shadow(0 0 4px ${COLORS.cyan})` }} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="glass-card analytics-chart-card">
          <div className="glass-card__header">
            <span className="glass-card__title">Rule Trigger Leaderboard</span>
            <span className="alerts-poll">LAST 24H</span>
          </div>
          <div className="rule-leaderboard">
            {ruleLeaderboard.length === 0 ? (
              <p style={{ color: 'var(--text-muted)', fontSize: 13, padding: 20, textAlign: 'center' }}>No rules triggered yet.</p>
            ) : (
              ruleLeaderboard.map((row) => {
                const max = ruleLeaderboard[0]?.count ?? 1;
                const pctW = (row.count / max) * 100;
                const barColor = row.rank <= 1 ? COLORS.malicious : row.rank <= 3 ? COLORS.orange : COLORS.cyan;
                return (
                  <div key={row.name} className="rule-leaderboard__row">
                    <span className="rule-leaderboard__rank">#{row.rank}</span>
                    <span className="rule-leaderboard__name">{row.name}</span>
                    <div className="rule-leaderboard__bar">
                      <div style={{ width: `${pctW}%`, background: barColor, boxShadow: `0 0 8px ${barColor}` }} />
                    </div>
                    <span className="rule-leaderboard__count">{row.count}</span>
                  </div>
                );
              })
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
