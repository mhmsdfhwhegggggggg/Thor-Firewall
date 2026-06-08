import React, { useState, useRef, useEffect } from 'react';
import { Zap, Send, Bot, User, Loader2, Copy, Check, AlertCircle } from 'lucide-react';

// ────────────────────────────────────────────────────────────────────────────

interface Message {
  id:        string;
  role:      'user' | 'assistant';
  content:   string;
  timestamp: number;
  loading?:  boolean;
  error?:    boolean;
}

const EXAMPLES = [
  'What are the top threats detected in the last hour?',
  'Explain the current SYN flood attack',
  'Is 192.168.1.50 behaving suspiciously?',
  'What MITRE techniques are being used against us?',
  'Show me all data exfiltration attempts today',
  'Why was 10.0.0.25 blocked 500 times?',
];

const MITRE_LABELS: Record<string, string> = {
  'T1046': 'Network Service Discovery',
  'T1498.001': 'Direct Network Flood',
  'T1071.004': 'DNS Tunneling',
  'T1110.001': 'Brute Force',
  'T1041': 'C2 Exfiltration',
};

// ────────────────────────────────────────────────────────────────────────────

function CodeBlock({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 2000); };
  return (
    <div className="relative mt-2 mb-2 bg-gray-950 rounded-lg border border-gray-700 overflow-hidden">
      <button onClick={copy} className="absolute top-2 right-2 text-gray-500 hover:text-white transition-colors">
        {copied ? <Check className="w-4 h-4 text-green-400" /> : <Copy className="w-4 h-4" />}
      </button>
      <pre className="p-4 text-sm text-green-300 font-mono overflow-x-auto">{text}</pre>
    </div>
  );
}

function renderContent(text: string) {
  const parts = text.split(/(```[\s\S]*?```|`[^`]+`|\*\*[^*]+\*\*)/g);
  return parts.map((part, i) => {
    if (part.startsWith('```') && part.endsWith('```')) {
      return <CodeBlock key={i} text={part.slice(3, -3).trim()} />;
    }
    if (part.startsWith('`') && part.endsWith('`')) {
      return <code key={i} className="bg-gray-800 text-cyan-300 px-1.5 py-0.5 rounded font-mono text-sm">{part.slice(1,-1)}</code>;
    }
    if (part.startsWith('**') && part.endsWith('**')) {
      return <strong key={i} className="text-white font-bold">{part.slice(2,-2)}</strong>;
    }
    return <span key={i}>{part}</span>;
  });
}

// ────────────────────────────────────────────────────────────────────────────

async function callQueryAPI(query: string): Promise<string> {
  const base = (import.meta as any).env?.VITE_API_URL ?? '';
  const res = await fetch(`${base}/api/v1/query`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ query, language: 'en' }),
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  const data = await res.json();
  return data.response ?? data.explanation ?? 'No response from AI';
}

// ────────────────────────────────────────────────────────────────────────────

export default function AIQueryPage() {
  const [messages, setMessages] = useState<Message[]>([
    {
      id: 'welcome',
      role: 'assistant',
      content: `**Thor AI Security Assistant** 🔥\n\nI'm powered by Mistral-7B fine-tuned on security data with RAG over MITRE ATT&CK, CVE, and live threat intel.\n\nAsk me anything about your network security posture, active threats, or specific flows.`,
      timestamp: Date.now() / 1000,
    }
  ]);
  const [input,    setInput]   = useState('');
  const [loading,  setLoading] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);
  const inputRef  = useRef<HTMLTextAreaElement>(null);

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [messages]);

  const send = async (text?: string) => {
    const query = (text ?? input).trim();
    if (!query || loading) return;
    setInput('');

    const userMsg: Message = { id: String(Date.now()), role: 'user', content: query, timestamp: Date.now()/1000 };
    const loadMsg: Message = { id: 'loading', role: 'assistant', content: '', timestamp: Date.now()/1000, loading: true };
    setMessages(prev => [...prev, userMsg, loadMsg]);
    setLoading(true);

    try {
      const response = await callQueryAPI(query);
      setMessages(prev => [
        ...prev.filter(m => m.id !== 'loading'),
        { id: String(Date.now()), role: 'assistant', content: response, timestamp: Date.now()/1000 }
      ]);
    } catch (err) {
      setMessages(prev => [
        ...prev.filter(m => m.id !== 'loading'),
        {
          id: String(Date.now()), role: 'assistant', timestamp: Date.now()/1000, error: true,
          content: `⚠️ Unable to reach the AI engine: ${err instanceof Error ? err.message : 'Unknown error'}. Make sure the control plane is running.`,
        }
      ]);
    } finally {
      setLoading(false);
      inputRef.current?.focus();
    }
  };

  const handleKey = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); }
  };

  return (
    <div className="h-full flex flex-col p-6">
      {/* Header */}
      <div className="flex items-center gap-3 mb-6">
        <div className="w-10 h-10 bg-gradient-to-br from-purple-500 to-cyan-500 rounded-xl flex items-center justify-center">
          <Zap className="w-6 h-6 text-white" />
        </div>
        <div>
          <h1 className="text-xl font-bold text-white">AI Security Query</h1>
          <p className="text-xs text-gray-400">Mistral-7B + MITRE RAG + Live Threat Intel</p>
        </div>
        <div className="ml-auto flex items-center gap-2 bg-green-900/30 border border-green-700 text-green-300 text-xs px-3 py-1.5 rounded-full">
          <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse" />
          AI Online
        </div>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto space-y-4 mb-4 pr-1">
        {messages.map(msg => (
          <div key={msg.id} className={`flex gap-3 ${msg.role === 'user' ? 'flex-row-reverse' : ''}`}>
            <div className={`w-8 h-8 rounded-full flex items-center justify-center shrink-0 ${
              msg.role === 'assistant'
                ? 'bg-gradient-to-br from-purple-600 to-cyan-600'
                : 'bg-gray-700'
            }`}>
              {msg.role === 'assistant' ? <Bot className="w-4 h-4 text-white" /> : <User className="w-4 h-4 text-white" />}
            </div>

            <div className={`max-w-[80%] rounded-2xl px-4 py-3 ${
              msg.role === 'user'
                ? 'bg-cyan-600/20 border border-cyan-700 text-cyan-100'
                : msg.error
                  ? 'bg-red-900/30 border border-red-700 text-red-200'
                  : 'bg-gray-800 border border-gray-700 text-gray-100'
            }`}>
              {msg.loading ? (
                <div className="flex items-center gap-2 text-gray-400">
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span className="text-sm">Thinking…</span>
                </div>
              ) : (
                <div className="text-sm leading-relaxed">
                  {msg.error && <AlertCircle className="w-4 h-4 inline mr-2 text-red-400" />}
                  {renderContent(msg.content)}
                </div>
              )}
              <div className="text-xs text-gray-500 mt-2">
                {new Date(msg.timestamp * 1000).toLocaleTimeString()}
              </div>
            </div>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>

      {/* Examples */}
      {messages.length <= 1 && (
        <div className="mb-4">
          <p className="text-xs text-gray-500 mb-2">Try asking:</p>
          <div className="flex flex-wrap gap-2">
            {EXAMPLES.map(ex => (
              <button key={ex} onClick={() => send(ex)}
                className="text-xs bg-gray-800 border border-gray-700 hover:border-cyan-600 text-gray-300 hover:text-white px-3 py-1.5 rounded-lg transition-colors">
                {ex}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Input */}
      <div className="flex gap-3 items-end bg-gray-800 border border-gray-700 rounded-2xl p-3 focus-within:border-cyan-500 transition-colors">
        <textarea
          ref={inputRef}
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={handleKey}
          placeholder="Ask about threats, flows, IPs, or request an analysis…"
          rows={1}
          className="flex-1 bg-transparent text-white text-sm resize-none focus:outline-none min-h-[24px] max-h-36 placeholder-gray-500"
          style={{ height: 'auto' }}
          onInput={e => {
            const t = e.target as HTMLTextAreaElement;
            t.style.height = 'auto';
            t.style.height = `${Math.min(t.scrollHeight, 144)}px`;
          }}
          disabled={loading}
        />
        <button
          onClick={() => send()}
          disabled={!input.trim() || loading}
          className="w-9 h-9 bg-cyan-600 hover:bg-cyan-700 disabled:bg-gray-700 disabled:text-gray-500 text-white rounded-xl flex items-center justify-center transition-colors shrink-0"
        >
          {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
        </button>
      </div>
      <p className="text-xs text-center text-gray-600 mt-2">Enter to send • Shift+Enter for new line</p>
    </div>
  );
}
