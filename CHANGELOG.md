# Changelog — Thor Firewall
# سجل التغييرات

All notable changes to Thor Firewall will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Phase 0 — Infrastructure (Months 1-3) 🔄

#### Added
- Complete project structure with monorepo layout
- Rust workspace (`Cargo.toml`) with all core dependencies pinned
- `thor-agent` binary crate with CLI interface (clap)
- `PacketParser` — high-performance packet parser with SIMD support
  - IPv4/IPv6/TCP/UDP/ICMP support
  - Shannon entropy calculation for payload analysis
  - 50-feature ML vector extraction
  - Canonical flow key normalization
- `FlowManager` — lock-free concurrent flow state management
  - DashMap-based hash table (1M flows per CPU core)
  - Welford's online algorithm for running statistics
  - Background cleanup for expired flows
  - Direct BPF map update interface
- `RLCore` — batched inference bridge (Rust → Python)
  - Configurable batch size and timeout
  - Support for: in-process (PyO3), REST API, and simulation modes
  - Async tokio-based request handling
- eBPF/XDP kernel programs:
  - `xdp_main.c` — main XDP entry point with multi-stage pipeline
  - `xdp_syn_flood.c` — advanced SYN flood protection with token bucket rate limiting
  - `thor_common.h` — shared kernel/userspace data structures
  - `Makefile` — automated build and BPF verifier check
- XDP Loader (`agent/src/linux/xdp_loader.rs`) using `aya` crate
- MARL Engine (`ml/marl/agents.py`):
  - `ActorCriticNetwork` with ResidualBlock layers
  - `ProtocolAgent` (TCP/UDP/ICMP specialization)
  - `MetaAgent` centralized coordinator
  - `ExperienceBuffer` with GAE advantage computation
  - PPO training loop with gradient clipping
- GNN Analyzer (`ml/gnn/network_analyzer.py`):
  - `NodeFeatureExtractor` — 32-dim per-device features
  - `ThorGNN` — GraphSAGE + GATv2 architecture
  - `NetworkGraphBuilder` — real-time graph updates
  - Whole-network threat detection
- LLM Explainer (`ml/llm/explainer.py`):
  - `SecurityExplainer` — Mistral-7B-Security interface
  - `ThreatIntelRAG` — MISP/OTX/CVE context retrieval
  - Arabic/English explanation generation
  - Fallback when LLM server unavailable
- Control Plane (FastAPI):
  - `/api/health` — health checks (Redis, ClickHouse, agents)
  - `/api/v1/flows` — flow listing with filtering and pagination
  - `/api/v1/rules` — CRUD for firewall rules
  - `/api/v1/threats` — threat event listing and summary
  - `/api/v1/analytics/network` — real-time network statistics
  - `/api/v1/analytics/system` — agent resource usage
  - `/api/v1/query` — natural language security queries (LLM)
  - `/ws/live` — WebSocket real-time event stream
  - ConnectionManager + EventBus for real-time updates
- Docker infrastructure:
  - `Dockerfile.agent` — multi-stage minimal runtime image
  - `docker-compose.yml` — full stack (Redis, ClickHouse, control-plane, dashboard, LLM, monitoring)
- CI/CD Pipelines:
  - `ci.yml` — Rust tests, Python tests, eBPF build, benchmarks, Docker push
  - `security.yml` — cargo-audit, pip-audit, CodeQL, Trivy container scan, Gitleaks
  - `dependabot.yml` — automated dependency updates (Cargo, pip, GitHub Actions)
- GitHub templates:
  - Bug report template (YAML)
  - Feature request template (YAML)
  - Pull request template with performance impact table
- Documentation:
  - `README.md` — comprehensive project overview with architecture diagram
  - `docs/architecture/ARCHITECTURE.md` — detailed architecture with data flow diagrams
  - `CONTRIBUTING.md` — full contributor guide with standards
  - `configs/agent.default.toml` — documented default configuration

---

## Roadmap

| Version | Phase | ETA |
|---------|-------|-----|
| 0.1.0 | Phase 0 — Infrastructure | Month 3 |
| 0.2.0 | Phase 1 — eBPF/WFP Core | Month 9 |
| 0.3.0 | Phase 2 — AI/ML Engine | Month 18 |
| 0.4.0 | Phase 3 — Self-Protection | Month 24 |
| 0.5.0 | Phase 4 — Dashboard | Month 28 |
| 1.0.0 | Phase 5 — Production Ready | Month 36 |
| 2.0.0 | Phase 6 — Enterprise | Month 48 |
