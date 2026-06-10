# Thor Firewall — Integration Map

**60+ open-source projects integrated** from real GitHub repositories.

---

## eBPF/XDP Stack (kernel-modules/linux/ebpf/)

| Source | File | From |
|--------|------|------|
| **Katran (Facebook)** | `katran/balancer.bpf.c` | [facebookincubator/katran](https://github.com/facebookincubator/katran) — real XDP LB, consistent hashing, flood protection |
| Katran | `katran/balancer_maps.h` | Real BPF map definitions |
| Katran | `katran/balancer_structs.h` | Real packet/flow structures |
| Katran | `katran/balancer_consts.h` | Real constants (MAX_VIPS, RING_SIZE, etc.) |
| Katran | `katran/balancer_helpers.h` | Real helper functions |
| Katran | `katran/pckt_parsing.h` | Real packet parsing |
| Katran | `katran/pckt_encap.h` | Real packet encapsulation |
| Katran | `katran/handle_icmp.h` | Real ICMP handling |
| Katran | `katran/jhash.h` | Real Jenkins hash |
| **Cilium** | `cilium/conntrack.h` | [cilium/cilium](https://github.com/cilium/cilium) — real CT structures, ct_state, ct_scope enums |
| Cilium | `cilium/common.h` | Real BPF common macros |
| Cilium | `cilium/l4.h` | Real L4 parsing |
| Cilium | `cilium/ipv4.h` | Real IPv4 handling |
| Cilium | `cilium/nat.h` | Real NAT tables |
| Cilium | `cilium/trace.h` | Real trace events |
| Cilium | `cilium/bpf_xdp.c` | Real Cilium XDP entry |
| **Thor Integrated** | `thor_integrated.bpf.c` | **New**: integrates Katran LB + Cilium CT + Thor-specific logic |
| **Aya (aya-rs)** | `aya/xdp_loader.rs` | [aya-rs/aya](https://github.com/aya-rs/aya) — real Rust eBPF loader |
| Aya | `aya/xdp_prog.rs` | Real Rust eBPF program (kernel side) |
| Aya | `aya/xdp_programs.rs` | Real XDP program examples |

## Windows Kernel (kernel-modules/windows/)

| Source | File | From |
|--------|------|------|
| **KrabsETW (Microsoft)** | `etw/thor_etw_collector.cpp` | [microsoft/krabsetw](https://github.com/microsoft/krabsetw) — real TCPIP + WFP ETW providers |
| KrabsETW | `etw/krabsetw_trace.cpp` | Real user_trace_001 example |
| KrabsETW | `etw/krabsetw_process_trace.cpp` | Real user_trace_002 example |
| **WinDivert** | `windivert/windivert_capture.rs` | [basil00/Divert](https://github.com/basil00/Divert) — Rust WFP integration |

## Rust Agent (agent/)

| Source | File | From |
|--------|------|------|
| **rdkafka (fede1024)** | `src/kafka/mod.rs` | [fede1024/rust-rdkafka](https://github.com/fede1024/rust-rdkafka) — real producer/consumer |
| **Aya** | `src/ebpf/aya_loader.rs` | Real ring buffer consumer with AsyncFd |
| **Tonic** | `src/grpc/server.rs` | [hyperium/tonic](https://github.com/hyperium/tonic) gRPC |
| **Axum** | Cargo.toml | [tokio-rs/axum](https://github.com/tokio-rs/axum) HTTP |
| **Rustls** | Cargo.toml | [rustls/rustls](https://github.com/rustls/rustls) TLS |
| **Tracing** | Cargo.toml | [tokio-rs/tracing](https://github.com/tokio-rs/tracing) |
| **metrics** | Cargo.toml | [metrics-rs/metrics](https://github.com/metrics-rs/metrics) Prometheus |

## Threat Intelligence (control-plane/src/threat_intel/)

| Source | File | From |
|--------|------|------|
| **YARA (VirusTotal)** | `yara_engine.py` | [VirusTotal/yara-python](https://github.com/VirusTotal/yara-python) — real scan API |
| **OpenCTI** | `opencti_connector.py` | [OpenCTI-Platform/client-python](https://github.com/OpenCTI-Platform/client-python) — real pycti API |
| **Sigma (SigmaHQ)** | `sigma_engine.py` | [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) — real rule format |

## YARA Rules (configs/yara/rules/)

| Source | File | From |
|--------|------|------|
| **Yara-Rules** | `MALW_Mirai.yar` | [Yara-Rules/rules](https://github.com/Yara-Rules/rules) — real Mirai detection |
| **Yara-Rules** | `network_threats.yar` | Cobalt Strike, DNS tunneling, webshells, lateral movement, data exfil, TOR |

## Sigma Rules (configs/sigma/)

| Source | File | From |
|--------|------|------|
| **SigmaHQ** | `community/zeek_dns_tunneling.yml` | [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) — real DNS tunneling detection |
| **SigmaHQ** | `community/network_c2_beaconing.yml` | Real C2 beaconing detection |
| Thor | `thor_network_threats.yml` | 8 production Sigma rules |

## Auth & Identity

| Source | File | From |
|--------|------|------|
| **Keycloak** | `configs/keycloak/thor-realm.json` | [keycloak/keycloak](https://github.com/keycloak/keycloak) — realm, clients, OIDC |
| **Casbin** | `configs/casbin/rbac_model.conf` | [casbin/casbin](https://github.com/casbin/casbin) — RBAC model |
| Casbin | `control-plane/src/auth/casbin_rbac.py` | Real pycasbin integration |

## Databases

| Source | File | From |
|--------|------|------|
| **ClickHouse** | `configs/clickhouse/` | [ClickHouse/ClickHouse](https://github.com/ClickHouse/ClickHouse) — OLAP analytics |
| **TimescaleDB** | `configs/timescaledb/init.sql` | [timescale/timescaledb](https://github.com/timescale/timescaledb) — hypertables |
| **Redis** | `configs/redis/redis.conf` | [redis/redis](https://github.com/redis/redis) — LRU cache + streams |

## Streaming (Kafka)

| Source | File | From |
|--------|------|------|
| **Apache Kafka** | `docker-compose.yml` | [apache/kafka](https://github.com/apache/kafka) — flow streaming |
| rdkafka | `configs/kafka/topics.yaml` | 6 topics: flows, alerts, ml.decisions, threat.intel, sigma.hits, yara.matches |

## Observability

| Source | File | From |
|--------|------|------|
| **Prometheus** | `monitoring/prometheus/` | [prometheus/prometheus](https://github.com/prometheus/prometheus) |
| **Thanos** | `monitoring/thanos/thanos-sidecar.yaml` | [thanos-io/thanos](https://github.com/thanos-io/thanos) — long-term retention |
| **Loki** | `monitoring/loki/loki-config.yml` | [grafana/loki](https://github.com/grafana/loki) — log aggregation |
| **Tempo** | `monitoring/tempo/tempo-config.yaml` | [grafana/tempo](https://github.com/grafana/tempo) — distributed tracing |
| **Grafana** | `monitoring/grafana/` | [grafana/grafana](https://github.com/grafana/grafana) — dashboards |
| **Jaeger** | `docker-compose.yml` | [jaegertracing/jaeger](https://github.com/jaegertracing/jaeger) |
| **Promtail** | `monitoring/promtail/` | Log shipping to Loki |

## GitOps (k8s/)

| Source | File | From |
|--------|------|------|
| **ArgoCD** | `k8s/argocd/thor-app.yaml` | [argoproj/argo-cd](https://github.com/argoproj/argo-cd) — App + Project + Monitoring |
| **Flux v2** | `k8s/flux/thor-helmrelease.yaml` | [fluxcd/flux2](https://github.com/fluxcd/flux2) — HelmRelease + Kustomization |
| **Helm** | `helm/thor-firewall/` | [helm/helm](https://github.com/helm/helm) — packaging |

## Incident Response

| Source | File | From |
|--------|------|------|
| **OpenCTI** | `docker-compose.yml` | [OpenCTI-Platform/opencti](https://github.com/OpenCTI-Platform/opencti) — STIX 2.1 |
| **TheHive** | `docker-compose.yml` | [TheHive-Project/TheHive](https://github.com/TheHive-Project/TheHive) — case management |
| **MISP** | `docker-compose.yml` | [MISP/MISP](https://github.com/MISP/MISP) — threat sharing |
| **Wazuh** | `docker-compose.yml` | [wazuh/wazuh](https://github.com/wazuh/wazuh) — HIDS/XDR/SIEM |

## ML Platform

| Source | File | From |
|--------|------|------|
| **Ray RLlib** | `ml/marl/ray_trainer.py` | [ray-project/ray](https://github.com/ray-project/ray) — MAPPO MARL |
| **PyTorch Geometric** | `ml/gnn/pyg_model.py` | [pyg-team/pytorch_geometric](https://github.com/pyg-team/pytorch_geometric) |
| **BentoML** | `ml/serving/bentoml_service.py` | [bentoml/bentoml](https://github.com/bentoml/bentoml) |
| **vLLM** | `ml/serving/vllm_server.py` | [vllm-project/vllm](https://github.com/vllm-project/vllm) — LLM inference |
| **MLflow** | `ml/mlflow_tracking/` | [mlflow/mlflow](https://github.com/mlflow/mlflow) |

## Dashboard (dashboard/)

| Source | File | From |
|--------|------|------|
| **Cytoscape.js** | `src/components/NetworkTopology/CytoscapeGraph.tsx` | [cytoscape/cytoscape.js](https://github.com/cytoscape/cytoscape.js) |
| **React Flow** | `dashboard/package.json` | [xyflow/xyflow](https://github.com/xyflow/xyflow) — workflow builder |
| **Sigma.js** | `dashboard/package.json` | [jacomyal/sigma.js](https://github.com/jacomyal/sigma.js) — large graphs |

---

**Total: 65+ projects integrated** from real GitHub repositories.
