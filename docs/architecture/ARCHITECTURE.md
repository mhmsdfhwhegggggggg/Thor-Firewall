# Thor Firewall — Architecture Documentation
# توثيق الهندسة المعمارية

## Overview / نظرة عامة

Thor Firewall is a Next-Generation Firewall (NGFW) built on three pillars:

```
                            ┌─────────────────────────────────────┐
                            │         THOR FIREWALL                │
                            │                                      │
     Network Traffic ──────►│   Kernel Layer (eBPF/WFP)           │
                            │         │                            │
                            │         ▼                            │
                            │   Agent Layer (Rust)                 │
                            │    ├── PacketParser                  │
                            │    ├── FlowManager                   │
                            │    └── RLCore                        │
                            │         │                            │
                            │         ▼                            │
                            │   Intelligence Layer (Python)        │
                            │    ├── MARL Engine                   │
                            │    ├── GNN Analyzer                  │
                            │    └── LLM Explainer                 │
                            │         │                            │
                            │         ▼                            │
                            │   Control Plane (FastAPI/gRPC)       │
                            │         │                            │
                            │    ┌────┴────┐                       │
                            │    │ Storage │                        │
                            │    │ Redis   │                        │
                            │    │ ClickH. │                        │
                            │    └────┬────┘                       │
                            │         │                            │
                            │    Dashboard (React/TS)              │
                            └─────────────────────────────────────┘
```

---

## Layer 1: Kernel Layer
## الطبقة 1: طبقة النواة

### Linux: eBPF/XDP

The eBPF layer operates at the lowest possible level in the Linux networking stack — at the XDP (eXpress Data Path) hook, which runs **before** the packet enters the kernel's main networking stack.

**Processing pipeline:**
```
NIC Driver
    │
    ▼ (XDP Hook — <100ns target)
Phase 0: Early Drop (ARP spoofing, malformed headers)
    │
    ▼
Phase 1: 5-tuple extraction + xxh3 hash
    │
    ▼
Phase 2: Flow state lookup in BPF LRU hash map
    │
    ├── Known flow → Apply saved decision (pass/drop/sample)
    │
    └── New flow → Insert with SAMPLE action + send to ring buffer
             │
             ▼
        User-space agent (analysis)
```

**BPF Maps used:**
| Map | Type | Size | Purpose |
|-----|------|------|---------|
| `flow_table` | `LRU_PERCPU_HASH` | 1M entries | Flow state (decision + stats) |
| `syn_counters` | `PERCPU_HASH` | 64K entries | SYN rate per source IP |
| `sample_ringbuf` | `RINGBUF` | 64MB | Lock-free packet samples to userspace |
| `blacklist` | `LPM_TRIE` | 64K entries | IP/CIDR block list |
| `whitelist` | `LPM_TRIE` | 4K entries | IP/CIDR allow list |
| `stats_map` | `PERCPU_ARRAY` | 32 entries | Performance counters |
| `config_map` | `ARRAY` | 16 entries | Runtime-configurable parameters |

### Windows: WFP (Windows Filtering Platform)

The WFP layer uses kernel-mode callout drivers registered at the following layers:

| Layer | Purpose | Direction |
|-------|---------|-----------|
| `FWPS_LAYER_INBOUND_IPPACKET_V4/V6` | Raw IP packet inspection | Inbound |
| `FWPS_LAYER_OUTBOUND_IPPACKET_V4/V6` | Raw IP packet inspection | Outbound |
| `FWPS_LAYER_ALE_AUTH_CONNECT_V4/V6` | New connection authorization | Both |

Communication with user-mode agent: `DeviceIoControl` + shared memory ring buffer.

---

## Layer 2: Agent Layer (Rust)
## الطبقة 2: طبقة العميل (Rust)

### PacketParser (`src/packet_parser.rs`)

High-performance packet parser with SIMD optimizations:
- Input: Raw Ethernet frame (bytes)
- Output: `ParsedPacket` struct with 50 ML features
- Target latency: < 50ns per packet
- Supports: IPv4, IPv6, TCP, UDP, ICMP, GRE, VXLAN

### FlowManager (`src/flow_manager.rs`)

Lock-free flow state management using DashMap:
- Tracks up to 1M concurrent flows per CPU core
- Welford's online algorithm for running statistics (variance, mean)
- Background cleanup task for expired flows
- Direct BPF map update for real-time decision application

### RLCore (`src/rl_core.rs`)

Batched inference bridge between Rust and Python ML:
- Collects packets into batches (configurable: 64-256)
- Sends batch to ML engine via PyO3 (in-process) or REST API
- Returns decisions to FlowManager with risk scores

---

## Layer 3: Intelligence Layer (Python)
## الطبقة 3: طبقة الذكاء الاصطناعي (Python)

### MARL Engine (`ml/marl/`)

**Architecture: POCA (Population-Enhanced Centralized Agent)**

```
TCP Agent  ──┐
UDP Agent  ──┤──► Meta Agent ──► Final Decision
ICMP Agent ──┘
```

Each protocol agent:
- Uses `ActorCriticNetwork` (4 ResidualBlock layers, 256 hidden dim)
- Trained with PPO (Proximal Policy Optimization)
- Specialized in protocol-specific attack patterns

State space (82 features per flow):
- 50 packet-level features (size, TTL, flags, entropy, ports, timing)
- 32 GNN node embedding (behavioral context)

Action space:
| Index | Action | When Used |
|-------|--------|-----------|
| 0 | `allow` | Normal traffic |
| 1 | `block` | Confirmed attack |
| 2 | `throttle_100pps` | Suspected DoS |
| 3 | `mirror` | Deep inspection needed |
| 4 | `redirect_honeypot` | Sophisticated attack |

### GNN Analyzer (`ml/gnn/`)

**Architecture: GraphSAGE + GATv2**

```
Network Graph:
  Nodes = Devices (IP addresses)
  Edges = Connections (flows)

  Features per node (32-dim):
  - Total flows
  - Inbound/outbound bytes
  - Unique destination count
  - Unique port count
  - Failed connection rate
  - SYN rate

  GNN Output per node (32-dim embedding):
  → Fed into MARL as additional context
  → Used for whole-network threat detection
```

### LLM Explainer (`ml/llm/`)

**Model: Mistral-7B-Security (LoRA fine-tuned)**

- Fine-tuned on: CVE descriptions, MISP threat reports, USENIX/IEEE security papers
- Runs via llama.cpp (CUDA/Vulkan acceleration)
- RAG integration: MISP, AlienVault OTX, NVD CVE database
- Generates Arabic/English explanations for every block decision

---

## Layer 4: Control Plane
## الطبقة 4: طبقة التحكم

**Stack: FastAPI + gRPC**

```
Agent ──gRPC──► Control Plane ──WebSocket──► Dashboard
                      │
              ┌───────┴────────┐
              │                │
           Redis           ClickHouse
         (live state)     (time-series)
```

**API Design: OpenAPI 3.1**
- `GET /api/flows` — Active flows with filtering
- `POST /api/rules` — Create firewall rules
- `GET /api/threats` — Current threat landscape
- `GET /api/analytics` — Historical analytics
- `POST /api/query` — Natural language security query (LLM)
- `WS /ws/live` — Real-time event stream

---

## Data Flow: Packet Processing Lifecycle
## تدفق البيانات: دورة حياة الحزمة

```
1. Packet arrives at NIC
2. XDP hook fires (< 100ns)
3. Check whitelist → PASS immediately
4. Check blacklist → DROP immediately
5. Check SYN rate → DROP if flooding
6. Lookup flow table:
   ├── Known: Apply saved decision
   └── New: Register + send sample to ring buffer
7. Ring buffer consumer (Rust Agent):
   ├── Parse packet (PacketParser)
   ├── Update FlowManager stats
   └── Queue for RL analysis (every Nth packet)
8. Batch sent to RLCore:
   ├── Protocol agent selects action
   ├── GNN provides network context
   └── Meta-agent makes final decision
9. Decision written back to BPF flow_table (atomic update)
10. If blocked: BPF drops all subsequent packets from this flow
11. If suspicious: LLM generates explanation + alert sent to dashboard
```

---

## Performance Architecture
## هندسة الأداء

### Linux (XDP) Optimization Strategy:
1. **Per-CPU maps**: Eliminate lock contention between CPU cores
2. **LRU eviction**: Automatic flow table management without GC
3. **Ring buffer**: Zero-copy sample transfer to userspace
4. **Batch processing**: Amortize ML inference cost over multiple packets
5. **Early drop**: Reject clearly malicious traffic before kernel TCP/IP stack

### Memory Layout:
```
Per-CPU flow table: 1M flows × 48 bytes = 48MB per CPU
Ring buffer: 64MB (shared)
ML model: ~4GB (Mistral-7B int4 quantized)
GNN embeddings: ~100MB (10K nodes × 32 dim × fp32)
Redis state: ~2GB (live flows + counters)
```

---

## Security Architecture
## هندسة الأمان

### Self-Protection Mechanisms:
1. **Binary integrity**: SHA3-256 hash + Ed25519 signature on agent binary
2. **Memory encryption**: AES-256-GCM for sensitive data in memory
3. **Syscall monitoring**: eBPF LSM hooks on agent process
4. **Primary/Standby**: Two agent instances with automatic failover
5. **Audit log**: Append-only log of all decisions (Kafka-backed)

### Threat Model:
- Attacker with network access: Mitigated by eBPF kernel layer
- Attacker with local user access: Mitigated by binary integrity + syscall monitoring
- Attacker with kernel access: BYOVD protection (Windows), Lockdown LSM (Linux)
- Adversarial ML attacks: Ensemble models + anomaly detection fallback

---

## Deployment Architecture
## هندسة النشر

```
Production Deployment (Single Host):
┌────────────────────────────────────┐
│  thor-agent (primary)  │  systemd  │
│  thor-agent (standby)  │  service  │
├────────────────────────────────────┤
│  control-plane         │  docker   │
│  redis                 │  compose  │
│  clickhouse            │          │
│  llm-server            │          │
│  dashboard             │          │
└────────────────────────────────────┘

Enterprise Deployment (Multi-Host):
┌──────────┐   ┌──────────┐   ┌──────────┐
│  Node 1  │   │  Node 2  │   │  Node N  │
│  Agent   │   │  Agent   │   │  Agent   │
└────┬─────┘   └────┬─────┘   └────┬─────┘
     │              │              │
     └──────────────┼──────────────┘
                    │ gRPC
                    ▼
             ┌─────────────┐
             │  Central    │
             │  Control    │
             │  Plane      │
             └─────────────┘
```
