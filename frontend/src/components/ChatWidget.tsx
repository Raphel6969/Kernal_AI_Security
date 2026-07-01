import { useState, useRef, useEffect } from 'react';
import { API_URL } from '../config';
import { MessageCircle, X, Send, Sparkles, ChevronDown } from 'lucide-react';

interface Message {
  role: 'user' | 'assistant';
  content: string;
}

export function ChatWidget() {
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState<Message[]>([
    {
      role: 'assistant',
      content: "Hello! I'm **AEGIX Assistant**, powered by Gemini AI.\n\nI'm your dedicated cybersecurity analyst. Ask me about:\n- 🔍 Shell command analysis\n- 🛡️ Attack techniques & MITRE ATT&CK\n- 🦠 Malware & exploits\n- 🚨 Incident response\n\nWhat do you want to investigate?",
    },
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (open) {
      setTimeout(() => messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' }), 60);
      setTimeout(() => inputRef.current?.focus(), 100);
    }
  }, [open, messages]);

  const sendMessage = async () => {
    const text = input.trim();
    if (!text || loading) return;

    const userMsg: Message = { role: 'user', content: text };
    const newMessages = [...messages, userMsg];
    setMessages(newMessages);
    setInput('');
    setLoading(true);
    setError(null);

    try {
      const res = await fetch(`${API_URL}/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: text,
          history: messages.map((m) => ({ role: m.role, content: m.content })),
        }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || `Server error ${res.status}`);
      }

      const data = await res.json() as { response: string };
      setMessages((prev) => [...prev, { role: 'assistant', content: data.response }]);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to reach AEGIX Assistant.');
    } finally {
      setLoading(false);
    }
  };

  const handleKey = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      void sendMessage();
    }
  };

  const renderMessage = (content: string) => {
    // Simple markdown: bold, code blocks, inline code
    const parts = content.split(/(```[\s\S]*?```|`[^`]+`|\*\*[^*]+\*\*)/g);
    return parts.map((part, i) => {
      if (part.startsWith('```') && part.endsWith('```')) {
        const code = part.slice(3, -3).replace(/^\w+\n/, '');
        return <pre key={i} className="chat-code-block"><code>{code}</code></pre>;
      }
      if (part.startsWith('`') && part.endsWith('`')) {
        return <code key={i} className="chat-inline-code">{part.slice(1, -1)}</code>;
      }
      if (part.startsWith('**') && part.endsWith('**')) {
        return <strong key={i}>{part.slice(2, -2)}</strong>;
      }
      // Handle newlines
      return <span key={i}>{part.split('\n').map((line, j, arr) => (
        <span key={j}>{line}{j < arr.length - 1 && <br />}</span>
      ))}</span>;
    });
  };

  return (
    <>
      {/* Floating toggle button */}
      <button
        className={`chat-widget-btn ${open ? 'chat-widget-btn--active' : ''}`}
        onClick={() => setOpen((v) => !v)}
        aria-label="Toggle AEGIX Assistant"
        id="chat-widget-toggle"
      >
        {open ? <X size={22} /> : <MessageCircle size={22} />}
      </button>

      {/* Chat panel */}
      <div className={`chat-panel ${open ? 'chat-panel--open' : ''}`} role="dialog" aria-label="AEGIX Assistant">
        {/* Header */}
        <div className="chat-panel__header">
          <div className="chat-panel__header-left">
            <Sparkles size={15} className="chat-panel__icon" />
            <div>
              <div className="chat-panel__title">AEGIX Assistant</div>
              <div className="chat-panel__subtitle">Powered by Gemini · CyberSec Only</div>
            </div>
          </div>
          <button className="chat-panel__close" onClick={() => setOpen(false)} aria-label="Close chat">
            <ChevronDown size={18} />
          </button>
        </div>

        {/* Messages */}
        <div className="chat-panel__messages" id="chat-messages">
          {messages.map((msg, i) => (
            <div key={i} className={`chat-message chat-message--${msg.role}`}>
              {msg.role === 'assistant' && (
                <div className="chat-message__avatar">
                  <Sparkles size={12} />
                </div>
              )}
              <div className="chat-message__bubble">
                {renderMessage(msg.content)}
              </div>
            </div>
          ))}

          {loading && (
            <div className="chat-message chat-message--assistant">
              <div className="chat-message__avatar"><Sparkles size={12} /></div>
              <div className="chat-message__bubble">
                <div className="chat-typing">
                  <span /><span /><span />
                </div>
              </div>
            </div>
          )}

          {error && (
            <div className="chat-error">⚠ {error}</div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* Input */}
        <div className="chat-panel__input-row">
          <input
            ref={inputRef}
            className="chat-panel__input"
            type="text"
            placeholder="Ask about threats, commands, exploits…"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKey}
            disabled={loading}
            id="chat-input"
            autoComplete="off"
          />
          <button
            className="chat-panel__send"
            onClick={() => void sendMessage()}
            disabled={loading || !input.trim()}
            aria-label="Send message"
            id="chat-send-btn"
          >
            <Send size={16} />
          </button>
        </div>
      </div>
    </>
  );
}
