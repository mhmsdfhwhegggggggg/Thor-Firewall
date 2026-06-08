import React, { useState, useMemo } from 'react';
import { Shield, Plus, Trash2, ToggleLeft, ToggleRight, AlertCircle, CheckCircle } from 'lucide-react';
import { useRules } from '../hooks/useApi';
import type { FirewallRule } from '../types';

// ────────────────────────────────────────────────────────────────────────────

const ACTION_STYLE: Record<string, string> = {
  allow:    'bg-green-900/50 text-green-300 border-green-700',
  block:    'bg-red-900/50 text-red-300 border-red-700',
  throttle: 'bg-yellow-900/50 text-yellow-300 border-yellow-700',
  log:      'bg-blue-900/50 text-blue-300 border-blue-700',
  mirror:   'bg-purple-900/50 text-purple-300 border-purple-700',
};

// ────────────────────────────────────────────────────────────────────────────
// Add Rule Modal
// ────────────────────────────────────────────────────────────────────────────

function AddRuleModal({ onClose, onAdd }: { onClose: () => void; onAdd: (r: Partial<FirewallRule>) => void }) {
  const [form, setForm] = useState({
    name: '', src_cidr: '', dst_cidr: '',
    dst_port: '', protocol: 'TCP',
    action: 'block', priority: 100,
    description: '', expires_hours: '',
  });

  const set = (k: string, v: string | number) => setForm(f => ({ ...f, [k]: v }));

  const submit = () => {
    if (!form.name.trim()) return;
    onAdd({
      name:        form.name,
      description: form.description,
      src_cidr:    form.src_cidr || undefined,
      dst_cidr:    form.dst_cidr || undefined,
      dst_port:    form.dst_port ? { single: +form.dst_port } : undefined,
      protocol:    form.protocol === 'any' ? undefined : { TCP: 6, UDP: 17, ICMP: 1 }[form.protocol],
      action:      form.action,
      priority:    form.priority,
      is_active:   true,
      expires_at:  form.expires_hours ? Date.now()/1000 + +form.expires_hours * 3600 : undefined,
    });
    onClose();
  };

  const Label = ({ children }: { children: React.ReactNode }) => (
    <label className="text-xs text-gray-400 mb-1 block">{children}</label>
  );
  const In = ({ k, placeholder, type = 'text' }: { k: string; placeholder?: string; type?: string }) => (
    <input type={type} value={(form as any)[k]} onChange={e => set(k, e.target.value)} placeholder={placeholder}
      className="w-full bg-gray-700 border border-gray-600 text-white rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500" />
  );

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm" onClick={onClose}>
      <div className="bg-gray-900 border border-gray-700 rounded-2xl p-6 max-w-lg w-full mx-4" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-lg font-bold text-white">Add Firewall Rule</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-white text-xl">✕</button>
        </div>

        <div className="space-y-4">
          <div><Label>Rule Name *</Label><In k="name" placeholder="Block external DB access" /></div>
          <div><Label>Description</Label><In k="description" placeholder="Optional description" /></div>

          <div className="grid grid-cols-2 gap-3">
            <div><Label>Source CIDR</Label><In k="src_cidr" placeholder="1.2.3.0/24" /></div>
            <div><Label>Destination CIDR</Label><In k="dst_cidr" placeholder="10.0.0.0/8" /></div>
          </div>

          <div className="grid grid-cols-3 gap-3">
            <div>
              <Label>Protocol</Label>
              <select value={form.protocol} onChange={e => set('protocol', e.target.value)}
                className="w-full bg-gray-700 border border-gray-600 text-white rounded-lg px-3 py-2 text-sm">
                <option>any</option><option>TCP</option><option>UDP</option><option>ICMP</option>
              </select>
            </div>
            <div><Label>Destination Port</Label><In k="dst_port" placeholder="443" type="number" /></div>
            <div>
              <Label>Action</Label>
              <select value={form.action} onChange={e => set('action', e.target.value)}
                className="w-full bg-gray-700 border border-gray-600 text-white rounded-lg px-3 py-2 text-sm">
                <option value="block">Block</option>
                <option value="allow">Allow</option>
                <option value="throttle">Throttle</option>
                <option value="log">Log Only</option>
              </select>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <Label>Priority (higher = first)</Label>
              <input type="range" min={1} max={2000} value={form.priority} onChange={e => set('priority', +e.target.value)}
                className="w-full accent-cyan-500" />
              <span className="text-xs text-gray-400">{form.priority}</span>
            </div>
            <div><Label>Expires in (hours, empty=never)</Label><In k="expires_hours" placeholder="24" type="number" /></div>
          </div>
        </div>

        <div className="flex gap-3 mt-6">
          <button onClick={submit} className="flex-1 bg-cyan-600 hover:bg-cyan-700 text-white rounded-xl py-2.5 font-bold transition-colors">
            <Plus className="w-4 h-4 inline mr-2" />Add Rule
          </button>
          <button onClick={onClose} className="flex-1 bg-gray-700 hover:bg-gray-600 text-white rounded-xl py-2.5 transition-colors">
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}

// ────────────────────────────────────────────────────────────────────────────
// Main
// ────────────────────────────────────────────────────────────────────────────

export default function RuleManager() {
  const { rules, loading, addRule, removeRule, toggleRule } = useRules();
  const [showAdd, setShowAdd] = useState(false);
  const [filter,  setFilter]  = useState('');

  const filtered = useMemo(() =>
    (rules ?? []).filter(r =>
      r.name.toLowerCase().includes(filter.toLowerCase()) ||
      (r.description ?? '').toLowerCase().includes(filter.toLowerCase())
    ).sort((a, b) => b.priority - a.priority),
  [rules, filter]);

  const handleAdd = (partial: Partial<FirewallRule>) => {
    addRule({
      rule_id: `rule-${Date.now()}`,
      name: partial.name ?? 'New Rule',
      action: (partial.action ?? 'block') as any,
      priority: partial.priority ?? 100,
      is_active: true,
      created_at: Date.now() / 1000,
      hit_count: 0,
      ...partial,
    } as FirewallRule);
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Shield className="w-5 h-5 text-cyan-400" />
          <h2 className="font-bold text-white">Firewall Rules</h2>
          <span className="text-xs bg-gray-700 text-gray-300 px-2 py-0.5 rounded-full">{(rules ?? []).length} rules</span>
        </div>
        <div className="flex gap-3 items-center">
          <input value={filter} onChange={e => setFilter(e.target.value)} placeholder="Search rules…"
            className="bg-gray-700 border border-gray-600 text-white rounded-lg px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500 w-48" />
          <button onClick={() => setShowAdd(true)}
            className="flex items-center gap-2 bg-cyan-600 hover:bg-cyan-700 text-white px-4 py-1.5 rounded-lg text-sm font-medium transition-colors">
            <Plus className="w-4 h-4" /> Add Rule
          </button>
        </div>
      </div>

      <div className="space-y-2">
        {loading ? (
          Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="h-16 bg-gray-800 border border-gray-700 rounded-xl animate-pulse" />
          ))
        ) : filtered.length === 0 ? (
          <div className="text-center text-gray-500 py-12">
            <Shield className="w-10 h-10 mx-auto mb-2 opacity-30" />
            <p>No rules found</p>
          </div>
        ) : filtered.map(rule => (
          <div key={rule.rule_id}
            className={`flex items-center gap-4 p-4 rounded-xl border transition-all ${
              rule.is_active
                ? 'bg-gray-800 border-gray-700 hover:border-gray-600'
                : 'bg-gray-900/50 border-gray-800 opacity-60'
            }`}>
            {/* Priority badge */}
            <div className="text-center shrink-0">
              <div className="text-xs text-gray-500">Pri</div>
              <div className="text-white font-bold text-sm">{rule.priority}</div>
            </div>

            {/* Info */}
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <span className="text-white font-medium text-sm truncate">{rule.name}</span>
                <span className={`text-xs px-2 py-0.5 rounded-full border font-medium ${ACTION_STYLE[rule.action] ?? ''}`}>
                  {rule.action.toUpperCase()}
                </span>
              </div>
              <div className="flex items-center gap-3 text-xs text-gray-500">
                {rule.src_cidr && <span>src: {String(rule.src_cidr)}</span>}
                {rule.dst_cidr && <span>dst: {String(rule.dst_cidr)}</span>}
                {rule.dst_port && <span>port: {JSON.stringify(rule.dst_port)}</span>}
                <span>hits: {(rule.hit_count ?? 0).toLocaleString()}</span>
                {rule.expires_at && (
                  <span>expires: {new Date((rule.expires_at ?? 0) * 1000).toLocaleDateString()}</span>
                )}
              </div>
            </div>

            {/* Status */}
            <div className="shrink-0">
              {rule.is_active
                ? <CheckCircle className="w-4 h-4 text-green-400" />
                : <AlertCircle className="w-4 h-4 text-gray-500" />}
            </div>

            {/* Actions */}
            <div className="flex items-center gap-2 shrink-0">
              <button onClick={() => toggleRule(rule.rule_id)} title={rule.is_active ? 'Disable' : 'Enable'}
                className="p-1.5 rounded-lg hover:bg-gray-700 transition-colors">
                {rule.is_active
                  ? <ToggleRight className="w-5 h-5 text-cyan-400" />
                  : <ToggleLeft className="w-5 h-5 text-gray-500" />}
              </button>
              <button onClick={() => removeRule(rule.rule_id)} title="Delete rule"
                className="p-1.5 rounded-lg hover:bg-red-900/50 hover:text-red-400 text-gray-500 transition-colors">
                <Trash2 className="w-4 h-4" />
              </button>
            </div>
          </div>
        ))}
      </div>

      {showAdd && <AddRuleModal onClose={() => setShowAdd(false)} onAdd={handleAdd} />}
    </div>
  );
}
