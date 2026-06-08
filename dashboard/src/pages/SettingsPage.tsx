import React, { useState } from 'react';
import { Settings, Save, RefreshCw, Shield, Cpu, Bell, Database, Globe, Key, ToggleLeft, ToggleRight } from 'lucide-react';

// ────────────────────────────────────────────────────────────────────────────

function Section({ title, icon: Icon, children }: { title: string; icon: any; children: React.ReactNode }) {
  return (
    <div className="bg-gray-800 border border-gray-700 rounded-2xl overflow-hidden">
      <div className="flex items-center gap-3 px-6 py-4 border-b border-gray-700 bg-gray-900/40">
        <Icon className="w-5 h-5 text-cyan-400" />
        <h2 className="font-semibold text-white">{title}</h2>
      </div>
      <div className="p-6 space-y-5">{children}</div>
    </div>
  );
}

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-6">
      <div className="min-w-0">
        <label className="text-sm font-medium text-gray-200">{label}</label>
        {hint && <p className="text-xs text-gray-500 mt-0.5">{hint}</p>}
      </div>
      <div className="shrink-0">{children}</div>
    </div>
  );
}

function Toggle({ value, onChange }: { value: boolean; onChange: (v: boolean) => void }) {
  return (
    <button onClick={() => onChange(!value)} className="flex items-center gap-2">
      {value
        ? <ToggleRight className="w-10 h-6 text-cyan-400" />
        : <ToggleLeft className="w-10 h-6 text-gray-500" />}
      <span className={`text-sm font-medium ${value ? 'text-cyan-400' : 'text-gray-500'}`}>{value ? 'On' : 'Off'}</span>
    </button>
  );
}

function Slider({ value, onChange, min, max, unit }: { value: number; onChange: (v: number) => void; min: number; max: number; unit?: string }) {
  return (
    <div className="flex items-center gap-3">
      <input type="range" min={min} max={max} value={value} onChange={e => onChange(+e.target.value)}
        className="w-36 accent-cyan-500" />
      <span className="text-white text-sm w-16 text-right font-mono">{value.toLocaleString()}{unit}</span>
    </div>
  );
}

function Select({ value, onChange, options }: { value: string; onChange: (v: string) => void; options: string[] }) {
  return (
    <select value={value} onChange={e => onChange(e.target.value)}
      className="bg-gray-700 border border-gray-600 text-white rounded-lg px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500">
      {options.map(o => <option key={o} value={o}>{o}</option>)}
    </select>
  );
}

// ────────────────────────────────────────────────────────────────────────────

export default function SettingsPage() {
  const [saved, setSaved] = useState(false);

  // Network
  const [interface_, setInterface]   = useState('eth0');
  const [xdpMode,    setXdpMode]     = useState('skb');
  const [tcEgress,   setTcEgress]    = useState(true);
  const [lsmProbes,  setLsmProbes]   = useState(true);
  const [synLimit,   setSynLimit]    = useState(10000);

  // ML
  const [mlEnabled,    setMlEnabled]   = useState(true);
  const [batchSize,    setBatchSize]   = useState(64);
  const [modelPath,    setModelPath]   = useState('ml/checkpoints/latest');
  const [gpuEnabled,   setGpuEnabled]  = useState(false);
  const [onlineLearning, setOnlineLearning] = useState(true);
  const [autoRetrain,  setAutoRetrain] = useState(false);

  // Alerts
  const [alertEmail,   setAlertEmail]  = useState('');
  const [slackWebhook, setSlackWebhook] = useState('');
  const [critOnly,     setCritOnly]    = useState(false);
  const [alertDelay,   setAlertDelay]  = useState(30);

  // Storage
  const [clickhouseHost, setClickhouseHost] = useState('localhost');
  const [redisUrl,       setRedisUrl]       = useState('redis://localhost:6379/0');
  const [retentionDays,  setRetentionDays]  = useState(30);

  // Threat Intel
  const [tiEnabled,  setTiEnabled]  = useState(true);
  const [tiInterval, setTiInterval] = useState(900);
  const [otxKey,     setOtxKey]     = useState('');
  const [mispUrl,    setMispUrl]    = useState('');

  const handleSave = () => {
    setSaved(true);
    setTimeout(() => setSaved(false), 2500);
  };

  const Input = ({ value, onChange, type = 'text', placeholder = '' }: { value: string; onChange: (v: string) => void; type?: string; placeholder?: string }) => (
    <input type={type} value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder}
      className="bg-gray-700 border border-gray-600 text-white rounded-lg px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500 w-64" />
  );

  return (
    <div className="p-6 space-y-6 max-w-4xl">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Settings className="w-6 h-6 text-cyan-400" />
          <h1 className="text-2xl font-bold text-white">Settings</h1>
        </div>
        <button onClick={handleSave}
          className={`flex items-center gap-2 px-5 py-2 rounded-xl font-semibold transition-all ${
            saved ? 'bg-green-600 text-white' : 'bg-cyan-600 hover:bg-cyan-700 text-white'
          }`}>
          {saved ? <><RefreshCw className="w-4 h-4" /> Saved!</> : <><Save className="w-4 h-4" /> Save Changes</>}
        </button>
      </div>

      {/* Network & eBPF */}
      <Section title="Network & eBPF Enforcement" icon={Shield}>
        <Field label="Network Interface" hint="Linux: eth0, enp3s0 — Windows: ignored">
          <Input value={interface_} onChange={setInterface} placeholder="eth0" />
        </Field>
        <Field label="XDP Mode" hint="skb = any NIC, drv = native driver, hw = hardware offload">
          <Select value={xdpMode} onChange={setXdpMode} options={['skb', 'drv', 'hw']} />
        </Field>
        <Field label="SYN Rate Limit" hint="Max SYN packets per source IP per second">
          <Slider value={synLimit} onChange={setSynLimit} min={100} max={100000} unit="/s" />
        </Field>
        <Field label="TC Egress Inspection" hint="Monitor outbound traffic for data exfiltration">
          <Toggle value={tcEgress} onChange={setTcEgress} />
        </Field>
        <Field label="LSM Probes" hint="Linux Security Module hooks for agent self-protection">
          <Toggle value={lsmProbes} onChange={setLsmProbes} />
        </Field>
      </Section>

      {/* ML */}
      <Section title="Machine Learning" icon={Cpu}>
        <Field label="ML Enforcement" hint="Enable AI-powered flow analysis and blocking">
          <Toggle value={mlEnabled} onChange={setMlEnabled} />
        </Field>
        <Field label="Inference Batch Size" hint="Flows processed per ML call (higher = more throughput)">
          <Slider value={batchSize} onChange={setBatchSize} min={8} max={256} />
        </Field>
        <Field label="Model Checkpoint Path">
          <Input value={modelPath} onChange={setModelPath} placeholder="ml/checkpoints/latest" />
        </Field>
        <Field label="GPU Acceleration" hint="Requires CUDA-compatible GPU">
          <Toggle value={gpuEnabled} onChange={setGpuEnabled} />
        </Field>
        <Field label="Online Learning" hint="Continuously improve model from live traffic">
          <Toggle value={onlineLearning} onChange={setOnlineLearning} />
        </Field>
        <Field label="Auto-Retrain on Accuracy Drop" hint="Triggers full retrain if accuracy drops below 99%">
          <Toggle value={autoRetrain} onChange={setAutoRetrain} />
        </Field>
      </Section>

      {/* Alerts */}
      <Section title="Alerts & Notifications" icon={Bell}>
        <Field label="Alert Email">
          <Input value={alertEmail} onChange={setAlertEmail} type="email" placeholder="security@example.com" />
        </Field>
        <Field label="Slack Webhook">
          <Input value={slackWebhook} onChange={setSlackWebhook} placeholder="https://hooks.slack.com/..." />
        </Field>
        <Field label="Critical Threats Only" hint="Only notify for Critical severity events">
          <Toggle value={critOnly} onChange={setCritOnly} />
        </Field>
        <Field label="Alert Cooldown" hint="Minimum seconds between duplicate alerts">
          <Slider value={alertDelay} onChange={setAlertDelay} min={0} max={300} unit="s" />
        </Field>
      </Section>

      {/* Storage */}
      <Section title="Data Storage" icon={Database}>
        <Field label="ClickHouse Host">
          <Input value={clickhouseHost} onChange={setClickhouseHost} placeholder="localhost" />
        </Field>
        <Field label="Redis URL">
          <Input value={redisUrl} onChange={setRedisUrl} placeholder="redis://localhost:6379/0" />
        </Field>
        <Field label="Flow Retention" hint="Days to keep normal flow records">
          <Slider value={retentionDays} onChange={setRetentionDays} min={7} max={365} unit="d" />
        </Field>
      </Section>

      {/* Threat Intel */}
      <Section title="Threat Intelligence" icon={Globe}>
        <Field label="Enable Threat Intel Feeds">
          <Toggle value={tiEnabled} onChange={setTiEnabled} />
        </Field>
        <Field label="Update Interval">
          <Slider value={tiInterval} onChange={setTiInterval} min={60} max={3600} unit="s" />
        </Field>
        <Field label="AlienVault OTX API Key">
          <Input value={otxKey} onChange={setOtxKey} type="password" placeholder="••••••••••••••••" />
        </Field>
        <Field label="MISP Instance URL">
          <Input value={mispUrl} onChange={setMispUrl} placeholder="https://misp.example.com" />
        </Field>
      </Section>

      <div className="text-xs text-gray-600 text-center pb-4">
        Thor Firewall v0.2.0 • Build {new Date().toISOString().slice(0,10)}
      </div>
    </div>
  );
}
