# Thor Firewall — CHANGELOG

All notable changes to this project are documented here.

---

## [0.2.0] — Phase 1 Production Core

### Added

#### eBPF / XDP Kernel Dataplane
- **`xdp_conntrack.c`** — Complete TCP state machine (RFC 793): NEW → SYN_SENT → ESTABLISHED → CLOSED, port scan detection, out-of-state packet detection
- **`tc_egress.c`** — TC egress filter: data exfiltration detection (100MB/min threshold), DNS inspection, traffic shaping marks
- **`lsm_probe.c`** — LSM self-protection hooks: ptrace blocked on agent PID, SIGKILL/SIGTERM monitoring, file access logging

#### Rust Agent
- **`linux/xdp_loader.rs`** — Complete XDP loader implementation: CIDR blacklist/whitelist via LPM trie (`aya`), flow decision BPF map updates, async ring buffer reader (up to 1024 events/poll), real-time `config_map` update API, `PerCpuArray` stats aggregation across all CPUs
- **`ring_consumer.rs`** — Complete ring buffer consumer: `PacketSample` aligned with `thor_common.h`, batch processing (128 pkts), async RL inference pipeline, `StatsPublisher` for Prometheus metrics

#### Control Plane (Python)
- **`routes/analytics.py`** — Full analytics API: real-time network stats, time-series endpoint, top-talkers ranking, ML model metrics — with Redis fallback to realistic demo data
- **`routes/threats.py`** — Threat events API: list/filter/create alerts, Redis pub/sub for real-time broadcast, `MITRE ATT&CK` technique linking
- **`routes/query.py`** — AI security query endpoint: LLM server proxy with offline demo mode, pre-built answers for common queries

#### React Dashboard
- **`components/dashboard/RealTimeStats.tsx`** — 3-row stats layout: core metrics (PPS, flows, blocked, Mbps), AI engine accuracy bars, system health bars, decision summary
- **`components/flows/FlowTable.tsx`** — Sortable/filterable flow table with state badges, risk bars, detail panel, manual block button
- **`components/threats/ThreatFeed.tsx`** — Live threat cards with severity gradients, MITRE links, auto-scroll, blocked/active status
- **`components/charts/ThroughputChart.tsx`** — Recharts AreaChart with 60-second rolling window, real-time updates, gradients for Mbps/blocked/suspicious

#### ML
- **`training/train_marl.py`** — Complete PPO training script: synthetic `NetworkEnv` (9 attack types with realistic feature distributions), CICIDS2017/2018 CSV loader, WandB integration, best-model checkpointing, CLI interface

#### Documentation
- **`docs/architecture/PHASE1.md`** — Full Phase 1 architecture: component table, BPF map reference, API table, performance benchmarks vs Checkpoint/PA, Phase 2 roadmap

---

## [0.1.0] — Phase 0 Infrastructure

### Added
- Rust workspace (`Cargo.toml`) with all production dependencies
- eBPF programs: `xdp_main.c`, `xdp_syn_flood.c`, `thor_common.h`
- Rust agent skeleton: `packet_parser.rs`, `flow_manager.rs`, `rl_core.rs`, `server.rs`, `main.rs`, `config.rs`, `telemetry.rs`
- Python ML stack: MARL (`agents.py`), GNN (`network_analyzer.py`), LLM (`explainer.py`)
- ML inference server (`inference_server.py`)
- Control plane FastAPI with WebSocket, Redis pub/sub
- React dashboard skeleton with TypeScript types
- CI/CD: GitHub Actions (Rust, Python, eBPF compilation, security audit)
- Docker Compose: agent + control-plane + ML server + Redis + ClickHouse + Prometheus + Grafana
- Makefile for eBPF build, Kubernetes manifests
