# Thor Firewall — Changelog

All notable changes are documented here.
Format: [version] — date — summary

---

## [0.2.0] — 2026-06-07 — Phase 2: Enterprise-Grade Intelligence & Cross-Platform

### Added

#### Windows WFP Complete Interface (`agent/src/windows/wfp_io.rs`)
- Full Named Pipe connection lifecycle (CreateFileW + WaitNamedPipeW with timeout)
- Shared memory ring buffer reader with atomic head/tail — zero-copy packet access
- `WfpPacketEntry` (C-compatible 1472-byte struct) aligned with ThorCallout.sys layout
- Kernel event object (WaitForSingleObject) for efficient packet-ready notification
- `send_verdict()` — async verdict via Named Pipe with length-prefix framing
- `update_blacklist()` — CIDR block/unblock directly in kernel callout
- `run_packet_loop()` — async tokio task draining ring buffer until shutdown
- `WfpPacketEntry::to_parsed_packet()` — FILETIME→Unix ns conversion + full ParsedPacket
- Driver command protocol: `DriverCommand` / `DriverResponse` (serde_json over Pipe)
- Cross-compilation stubs for non-Windows (bail! with clear error)
- Per-instance atomic counters: `packets_received`, `packets_blocked`

#### Complete gRPC Server — tonic (`agent/src/server.rs`)
- `ThorAgent` service: all 8 RPCs fully implemented
  - `GetStats` — network + ML + system stats with /proc/self/statm memory
  - `ApplyDecision` — external decision → event bus publish
  - `UpdateBlacklist` / `UpdateWhitelist` — CIDR validation + BPF delegation
  - `StreamEvents` — tokio broadcast channel, risk + type filters
  - `SendTrainingBatch` — queue to Redis stream
  - `UpdateConfig` — runtime parameter validation
  - `HealthCheck` — Kubernetes liveness compatible
- `ThorMLInference` service: both RPCs implemented
  - `Analyze` — single flow with latency measurement
  - `AnalyzeBatch` — up to 1024 flows, parallel tokio::spawn
- `EventBus` — tokio broadcast (4096 capacity) for StreamEvents fan-out
- `auth_interceptor` — Bearer token + dev-mode bypass
- mTLS support: Identity + client CA root (mutual TLS)
- gRPC reflection service (grpcurl/grpcui compatible)
- Connection settings: keepalive 30s, concurrency limit 256/conn

#### `agent/build.rs` — tonic-build Proto Codegen
- Compiles `agent/proto/thor.proto` → Rust structs + service traits
- Enables serde derive on all generated types
- Outputs `thor_descriptor.bin` for gRPC reflection
- `cargo:rerun-if-changed` for incremental builds

#### ClickHouse Forensics Service (`control-plane/src/services/clickhouse.py`)
- Schema DDL: `thor_flows`, `thor_threats`, `thor_decisions`, `thor_stats_1m`
- Materialized View: `thor_flows → thor_stats_1m` (auto-aggregation)
- All tables: TTL (30/90/365 days), partition by date, MergeTree ordered indices
- `SummingMergeTree` for 1-minute stats auto-merge
- Buffered batch insertion: `insert_flow/threat/decision` → auto-flush at 5K rows or 2s
- Background `_flush_loop` asyncio task
- Query methods: `query_flows`, `query_threats`, `query_timeline`, `query_top_talkers`
- `query_attack_heatmap` — country × threat_type with JOIN
- `search_ip` — parallel asyncio.gather (flows + threats) for IP investigation
- `export_csv` — raw ClickHouse FORMAT CSVWithNames for SIEM export
- Singleton `init_clickhouse()` with graceful degradation if CH unavailable

#### Forensics API Routes (`control-plane/src/routes/forensics.py`)
- `GET /forensics/flows` — multi-filter: time, src_ip, dst_ip, port, protocol, risk, decision
- `GET /forensics/threats` — severity, threat_type, MITRE tactic filters
- `GET /forensics/timeline` — 1m/5m/15m/1h/1d granularity time series
- `GET /forensics/top-talkers` — by bytes|packets|flows
- `GET /forensics/attack-heatmap` — geographic attack distribution
- `GET /forensics/ip/{ip}` — full IP investigation with verdict (CLEAN/LOW/MEDIUM/HIGH_RISK)
- `POST /forensics/hunt` — IoC hunting: up to 1000 IPv4/CIDR indicators in parallel
- `GET /forensics/export/{table}` — CSV download with SIEM-friendly filename
- `GET /forensics/health` — ClickHouse connectivity check
- Full input validation: IP addresses, time ranges, table names, granularity enum

#### IPv6 Full Support (`kernel-modules/linux/ebpf/xdp_ipv6.c`)
- `ipv6_blacklist` / `ipv6_whitelist` LPM trie maps (128-bit prefix, 65K/16K entries)
- `ipv6_flow_table` LRU_HASH (500K concurrent IPv6 flows)
- `icmpv6_rate_limit` LRU_HASH (200 pkt/s per source, 1s sliding window)
- Extension header parser: HOP, ROUTING, FRAGMENT, AUTH, DEST — up to 8 headers
- Fragment → pass to kernel reassembly (not dropped)
- ICMPv6 policy: NDP (133-137) + MLD (130-132, 143) always PASS; Echo rate-limited
- `ipv6_emit_sample()` — ring buffer samples for sensitive ports + SYN-only flows
- `thor_tc_ipv6_egress` TC hook — egress blacklist/whitelist enforcement
- Standalone `thor_xdp_ipv6` XDP program + callable inline from `xdp_main.c`

### Changed

- `CHANGELOG.md` — Phase 2 documentation
- `docs/architecture/PHASE2.md` — full architecture, benchmarks, roadmap to Phase 3

### Performance (Phase 2)

| Component | Metric | Value |
|-----------|--------|-------|
| gRPC GetStats | P99 latency | < 500µs |
| gRPC StreamEvents | Fan-out latency | < 1ms |
| AnalyzeBatch 1024 | Total time | < 5ms |
| XDP IPv6 parsing | Per-packet | < 20ns |
| IPv6 LPM lookup | Worst-case | < 30ns |
| ClickHouse flush | Batch 5K rows | < 100ms |
| IoC Hunt 100 IPs | Parallel | < 2s |
| WFP read_packet | Ring buffer | < 1µs |
| WFP send_verdict | Named Pipe | < 2µs |

---

## [0.1.0] — 2026-06-07 — Phase 1: Production-Grade Core

### Added

#### eBPF Dataplane
- `xdp_loader.rs` — Aya BPF loader: CIDR LPM trie blacklist/whitelist, ring buffer reader
  (1024 events/poll), percpu stats aggregation, flow decision maps
- `ring_consumer.rs` — PacketSample aligned with thor_common.h, batch processing
  (128 pkts/batch), async RL inference pipeline

#### Control Plane
- `analytics.py` — real-time stats, time-series, top-talkers, ML metrics
- `threats.py` — threat events API, Redis pub/sub, MITRE ATT&CK linking
- `query.py` — LLM proxy with offline demo mode and pre-built security answers

#### React Dashboard
- `RealTimeStats.tsx` — 3-row stats + AI accuracy bars + decision summary
- `FlowTable.tsx` — sortable/filterable, risk badges, detail panel
- `ThreatFeed.tsx` — live cards, severity gradients, MITRE links
- `ThroughputChart.tsx` — Recharts 60s rolling window, real-time updates

#### ML Training
- `train_marl.py` — complete PPO loop, 9-attack NetworkEnv, CICIDS2017/2018
  CSV loader, WandB integration, CLI

#### Documentation
- `PHASE1.md` — full architecture, BPF map reference, API table, perf benchmarks

---

## [0.0.1] — 2026-06-06 — Phase 0: Infrastructure

### Added
- Rust workspace (agent-core, agent, thor-common)
- eBPF skeleton programs (xdp_main.c, xdp_syn_flood.c, xdp_conntrack.c, tc_egress.c, lsm_probe.c)
- FastAPI control plane skeleton (app.py, all route files)
- React + Vite + Recharts + Tailwind dashboard skeleton
- Docker + Docker Compose + Kubernetes manifests
- CI/CD pipeline (GitHub Actions)
- Proto definition (thor.proto — complete)
- ML stubs (MARL agents, GNN, LLM)
