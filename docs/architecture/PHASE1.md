# Thor Firewall — Phase 1 Architecture

## Overview

Phase 1 completes the **core enforcement pipeline** — turning the Phase 0 skeleton into a
working NGFW that can actually enforce policy at line rate.

```
┌─────────────────────────────────────────────────────────────────┐
│                    KERNEL SPACE (Linux)                          │
│                                                                  │
│  NIC ──► XDP xdp_main ──► xdp_conntrack ──► TC tc_egress       │
│              │                  │                  │             │
│         Whitelist/          TCP State          Data Exfil        │
│         Blacklist/          Machine            Detection         │
│         SYN Cookie          Port Scan          DNS Inspect       │
│              │                  │                                │
│         BPF Maps            RingBuf ──► User Space              │
│  LPM Trie / LRU Hash / PERCPU_ARRAY                             │
└─────────────────────────────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    USER SPACE (Rust Agent)                       │
│                                                                  │
│  RingConsumer ──► PacketParser ──► FlowManager                  │
│                        │               │                         │
│                   50 features    DashMap<FlowKey, FlowRecord>    │
│                        │               │                         │
│                        └──────┬────────┘                        │
│                               ▼                                  │
│                         RLCore (MARL)                            │
│                      PyO3 bridge to Python                       │
│                               │                                  │
│                         BPF Map Update ──► Block/Allow           │
│                               │                                  │
│                     gRPC Server ◄──► Control Plane               │
│                     Prometheus /metrics                          │
└─────────────────────────────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    ML LAYER (Python)                             │
│                                                                  │
│  MARL (PPO)          GNN (GraphSAGE+GATv2)    LLM (Mistral-7B) │
│  ├─ TCPAgent         ├─ NodeFeatureExtractor   ├─ ThreatRAG      │
│  ├─ UDPAgent         ├─ NetworkGraphBuilder    └─ SecurityExpl.  │
│  ├─ ICMPAgent        └─ ThorGNN                                  │
│  └─ MetaAgent                                                    │
│                                                                  │
│  Training Pipeline                                               │
│  ├─ CICIDS2017/2018 Dataset Loader                               │
│  ├─ NetworkEnv (Simulation)                                      │
│  └─ train_marl.py                                                │
│                                                                  │
│  Serving                                                         │
│  └─ inference_server.py (FastAPI + gzip + Prometheus)           │
└─────────────────────────────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────────────────────────┐
│                CONTROL PLANE (FastAPI)                           │
│                                                                  │
│  REST API:  /api/v1/{flows,rules,threats,analytics,query}        │
│  WebSocket: /ws/live  (1-second stats + event stream)            │
│  gRPC:      thor.v1.ThorAgent  (from agent/proto/thor.proto)     │
└─────────────────────────────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────────────────────────┐
│                DASHBOARD (React + TypeScript + Vite)             │
│                                                                  │
│  Pages: Overview / Flows / Threats / AI Query / Settings         │
│  Components:                                                     │
│  ├─ RealTimeStats  — 6 stat cards with live metrics              │
│  ├─ ThroughputChart — recharts AreaChart (120s window)           │
│  ├─ ThreatFeed  — color-coded live threat events                 │
│  └─ FlowTable  — sortable/filterable flow table                  │
│                                                                  │
│  Hooks: useWebSocket / useNetworkStats / useFlows / useRules     │
└─────────────────────────────────────────────────────────────────┘
```

## Performance Targets

| Metric | Target | Architecture |
|--------|--------|--------------|
| Packet throughput | 10 Mpps | XDP + LRU map |
| Per-packet latency | <100 ns | PERCPU maps, no locks |
| Flow capacity | 1M / core | LRU eviction |
| ML inference | <200 μs | PyO3 batch + GPU |
| Detection accuracy | >99.5% | MARL + GNN ensemble |
| False positive rate | <0.1% | Conservative thresholds |
| Zero-day detection | >85% | GNN anomaly + LLM RAG |

## eBPF Program Sequence

```
1. xdp_main.c       — Whitelist (LPM) → Blacklist (LPM) → SYN cookie
2. xdp_conntrack.c  — TCP state machine → Port scan detection
3. xdp_syn_flood.c  — Token bucket rate limiting per source IP
4. tc_egress.c      — Data exfiltration monitoring + DNS inspection
5. lsm_probe.c      — Agent self-protection (ptrace/kill)
```

## Windows (WFP)

```
1. thor_wfp.rs      — WFP callout driver (kernel-mode service)
2. Decision cache   — 30s TTL to avoid repeated ML calls
3. Named Pipe IPC   — \\.\pipe\thor_firewall ↔ user-mode agent
4. Fast classify    — Blocks dangerous ports instantly
5. Full ML path     — For flows not in cache
```

## Key Design Decisions

1. **Lock-free hot path**: All BPF maps are PERCPU, no spinlocks on the packet path.
2. **Async ML**: RLCore uses batch inference (64 flows/call) over PyO3 to amortize overhead.
3. **GNN as context**: 32-dim node embedding enriches MARL state without coupling their training.
4. **Defense in depth**: XDP blocks first (microseconds), ML confirms (milliseconds), LLM explains (seconds).
5. **Zero-copy ring buffer**: BPF_MAP_TYPE_RINGBUF avoids `perf_event_output` copying overhead.
