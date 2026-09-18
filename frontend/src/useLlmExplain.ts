import { useCallback, useState } from 'react';
import { API_URL } from './config';

export interface LlmExplainContext {
  command: string;
  classification: string;
  risk_score: number;
  matched_rules: string[];
  ml_confidence: number;
  pid?: number;
  ppid?: number;
  uid?: number;
  baseline_explanation?: string;
}

export function useLlmExplain() {
  const [llmText, setLlmText] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [cached, setCached] = useState(false);

  const reset = useCallback(() => {
    setLlmText(null);
    setError('');
    setCached(false);
  }, []);

  const explainEvent = useCallback(async (eventId: string, sessionToken?: string | null, force = false) => {
    setLoading(true);
    setError('');
    try {
      const url = new URL(`${API_URL}/events/${encodeURIComponent(eventId)}/llm-explain`, window.location.origin);
      if (sessionToken) url.searchParams.set('session_token', sessionToken);
      if (force) url.searchParams.set('force', 'true');
      const res = await fetch(url.toString(), { method: 'POST' });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(typeof data.detail === 'string' ? data.detail : 'LLM explanation failed');
      }
      setLlmText(data.llm_explanation);
      setCached(Boolean(data.cached));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'LLM explanation failed');
    } finally {
      setLoading(false);
    }
  }, []);

  const explainCommand = useCallback(async (ctx: LlmExplainContext, sessionToken?: string | null) => {
    setLoading(true);
    setError('');
    try {
      const url = new URL(`${API_URL}/analyze/llm-explain`, window.location.origin);
      if (sessionToken) url.searchParams.set('session_token', sessionToken);
      const res = await fetch(url.toString(), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(ctx),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(typeof data.detail === 'string' ? data.detail : 'LLM explanation failed');
      }
      setLlmText(data.llm_explanation);
      setCached(Boolean(data.cached));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'LLM explanation failed');
    } finally {
      setLoading(false);
    }
  }, []);

  return { llmText, loading, error, cached, reset, explainEvent, explainCommand };
}
