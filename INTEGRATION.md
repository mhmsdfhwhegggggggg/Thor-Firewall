# Thor Firewall — Open Source Integration Map
# ─────────────────────────────────────────────────────────────────────────────
# توثيق كيفية دمج 40+ مشروع مفتوح المصدر في نظام Thor
# ─────────────────────────────────────────────────────────────────────────────

## eBPF / XDP Stack

| المشروع | الدور في Thor | الموقع |
|---------|--------------|--------|
| **Aya** (github.com/aya-rs/aya) | eBPF loader من Rust — يُحمّل XDP programs | `agent/Cargo.toml`, `agent/src/` |
| **Cilium conntrack** (github.com/cilium/cilium) | نمط connection tracking → `conntrack.bpf.c` | `kernel-modules/linux/ebpf/conntrack.bpf.c` |
| **Katran** (github.com/facebookincubator/katran) | نمط XDP jump table (program array) | `kernel-modules/linux/ebpf/katran_xdp.bpf.c` |
| **Tetragon** (github.com/cilium/tetragon) | نمط ring buffer events للـ userspace | `kernel-modules/linux/ebpf/conntrack.bpf.c` |
| **Falco** (github.com/falcosecurity/falco) | نمط syscall tracing + rule engine | `control-plane/src/threat_intel/sigma_engine.py` |
| **Suricata** (github.com/OISF/suricata) | نمط rule-based detection + XDP integration | `configs/sigma/thor_network_threats.yml` |
| **WinDivert** (github.com/basil00/WinDivert) | Windows userspace packet capture | `kernel-modules/windows/windivert/windivert_capture.rs` |
| **eBPF-for-Windows** (github.com/microsoft/ebpf-for-windows) | Future: kernel-level on Windows | _(planned — Phase 2)_ |

## ML Platform

| المشروع | الدور في Thor | الموقع |
|---------|--------------|--------|
| **Ray RLlib** (github.com/ray-project/ray) | Distributed MARL training (MAPPO) | `ml/marl/ray_trainer.py` |
| **Stable-Baselines3** (github.com/DLR-RM/stable-baselines3) | RL baseline comparison | `ml/requirements.txt` |
| **Tianshou** (github.com/thu-ml/tianshou) | Fast PyTorch-native RL prototyping | `ml/requirements.txt` |
| **PyTorch Geometric** (github.com/pyg-team/pytorch_geometric) | GNN (GraphSAGE + GATv2) network analysis | `ml/gnn/pyg_model.py` |
| **DGL** (github.com/dmlc/dgl) | Heterogeneous graph (fallback) | `ml/requirements.txt` |
| **vLLM** (github.com/vllm-project/vllm) | LLM inference server (Mistral-7B) | `ml/serving/vllm_server.py`, `docker-compose.yml` |
| **BentoML** (github.com/bentoml/BentoML) | Model serving (HTTP + gRPC) | `ml/serving/bentoml_service.py`, `ml/Dockerfile.bentoml` |
| **MLflow** (github.com/mlflow/mlflow) | Experiment tracking + model registry | `docker-compose.yml`, `ml/requirements.txt` |

## API & Communication

| المشروع | الدور في Thor | الموقع |
|---------|--------------|--------|
| **FastAPI** (github.com/tiangolo/fastapi) | Control plane REST API | `control-plane/` |
| **Tonic** (github.com/hyperium/tonic) | Rust gRPC (Agent ↔ Control Plane) | `agent/src/grpc/server.rs`, `agent/Cargo.toml` |
| **Actix-web** (github.com/actix/actix-web) | Metrics HTTP endpoint in Rust | `agent/src/grpc/server.rs`, `agent/Cargo.toml` |

## Auth & Identity

| المشروع | الدور في Thor | الموقع |
|---------|--------------|--------|
| **Keycloak** (github.com/keycloak/keycloak) | JWT / OIDC / SAML / MFA | `docker-compose.yml`, `configs/keycloak/thor-realm.json` |
| **Casbin** (github.com/casbin/casbin) | RBAC/ABAC policy engine | `control-plane/src/auth/casbin_rbac.py`, `configs/casbin/` |

## Databases

| المشروع | الدور في Thor | الموقع |
|---------|--------------|--------|
| **ClickHouse** (github.com/ClickHouse) | Flow storage + analytics (10B events/day) | `docker-compose.yml` |
| **Redis** (redis.io) | State + cache + pub/sub | `docker-compose.yml`, `configs/redis/` |
| **TimescaleDB** (github.com/timescale/timescaledb) | Time-series metrics | `docker-compose.yml`, `configs/timescaledb/init.sql` |

## Observability

| المشروع | الدور في Thor | الموقع |
|---------|--------------|--------|
| **Prometheus** (github.com/prometheus) | Metrics collection | `docker-compose.yml`, `monitoring/prometheus/` |
| **Grafana** (github.com/grafana/grafana) | Dashboards + Keycloak SSO | `docker-compose.yml`, `monitoring/grafana/` |
| **Loki** (github.com/grafana/loki) | Log aggregation (JSON structured logs) | `docker-compose.yml`, `monitoring/loki/` |
| **Jaeger** (github.com/jaegertracing/jaeger) | Distributed tracing (OpenTelemetry) | `docker-compose.yml` |

## Threat Intelligence

| المشروع | الدور في Thor | الموقع |
|---------|--------------|--------|
| **MISP** (github.com/MISP/MISP) | IoC database + sharing | `docker-compose.yml`, `control-plane/src/threat_intel/threat_intel.py` |
| **Sigma** (github.com/SigmaHQ/sigma) | Detection rule engine | `control-plane/src/threat_intel/sigma_engine.py`, `configs/sigma/` |

## Kubernetes

| المشروع | الدور في Thor | الموقع |
|---------|--------------|--------|
| **Helm** (helm.sh) | Kubernetes packaging | `helm/thor-firewall/` |
| **Prometheus Operator** | K8s metrics collection | `k8s/` |
| **Loki Stack** | K8s log aggregation | `k8s/` |
| **Jaeger Operator** | K8s distributed tracing | `k8s/` |

## Architecture Summary

```
NIC → XDP Dispatcher (Katran pattern)
           │
           ├─ [TCP Handler]  ─┐
           ├─ [UDP Handler]   ├─ BPF Map Lookup → XDP_PASS | XDP_DROP
           └─ [ICMP Handler] ─┘         │
                                         │ (new flows)
                              Conntrack (Cilium pattern)
                                         │
                              Ring Buffer → Aya (Rust loader)
                                         │
                              PacketParser (50 SIMD features)
                                         │
                              GNN (PyG GraphSAGE) → 32-dim embedding
                                         │
                              MARL (Ray RLlib MAPPO) → decision
                                         │
                              BentoML serving ← vLLM explanation
                                         │
                              Tonic gRPC → Control Plane (FastAPI)
                                         │
                         Keycloak + Casbin (auth/RBAC)
                         Sigma rules (detection)
                         MISP (threat intel)
                         ClickHouse + TimescaleDB (storage)
                         Prometheus + Loki + Jaeger (observability)
                         Grafana + Cytoscape.js (visualization)
```
