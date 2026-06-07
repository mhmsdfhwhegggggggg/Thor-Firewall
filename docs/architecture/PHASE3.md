# Thor Firewall — Phase 3: Operational Completeness & Global Intelligence

**Status:** Complete | **Target:** v0.3.0

---

## Executive Summary

Phase 3 closes the final gaps between a "working firewall" and a fully operational NGFW ready for enterprise deployment across thousands of nodes.

| Capability | Phase 2 | Phase 3 |
|---|---|---|
| Deployment | Manual scripts | **Docker Compose + Kubernetes DaemonSet** |
| Threat Intel | None | **MISP + OTX + ThreatFox + AbuseIPDB + STIX/TAXII** |
| ML Distribution | Single-node | **Federated Learning (FedAvg + DP + FedProx)** |
| Control Plane | Core routes | **+ Threat Intel + Forensics wired + ClickHouse init** |
| Kubernetes | None | **DaemonSet + HPA + StatefulSet + NetworkPolicy** |
| Privacy | None | **DP-SGD (ε, δ)-differential privacy** |

---

## 1. Federated Learning Architecture

### Problem Solved
Enterprise customers cannot send their network traffic to a central server.  
Solution: send only **model gradients** — never raw traffic data.

### Protocol (FedAvg + FedProx + DP-SGD)

```
Round k:
  Server → selected clients: global_model_state (weights)
  
  Each client i:
    1. Load global model
    2. Train locally for E epochs on local data
    3. Apply DP-SGD:
       - Clip gradients: ||g|| ≤ C (C = dp_max_grad_norm)
       - Add Gaussian noise: g += N(0, σ²C²I)
    4. Apply FedProx: loss += (μ/2)||w - w_global||²
    5. Compute delta_i = w_i - w_global
    6. Sparsify: keep only |delta_ij| > threshold
    7. Send delta_i to server
  
  Server:
    Aggregate: w_global = w_global + Σ(n_i/N) * delta_i
    Publish new model → round k+1
```

### Privacy Guarantees

| Parameter | Value | Meaning |
|-----------|-------|---------|
| ε (epsilon) | 1.0 | Each client's data is 1.0-private |
| δ (delta) | 1e-5 | Probability of privacy failure < 1e-5 |
| Noise multiplier σ | 1.1 | Standard DP-SGD tuning |
| Gradient clipping C | 1.0 | Max L2 norm per gradient |

### Communication Efficiency

| Optimization | Savings |
|---|---|
| Send deltas (not full weights) | 50-90% reduction |
| Sparsification (threshold=0.001) | Additional 70-95% |
| HTTP compression | 3-5x |
| Total vs. naive | **~100x less bandwidth** |

---

## 2. Threat Intelligence Architecture

### Data Sources (Priority Order)

| Source | Type | Update Frequency | Cost |
|--------|------|-----------------|------|
| Emerging Threats | IP blacklists | Every 6h | Free |
| Feodo Tracker | C2 IPs | Every 6h | Free |
| ThreatFox | IoCs + malware | Every 6h | Free |
| CINS Army | Scanners | Every 24h | Free |
| AlienVault OTX | Pulses + IPs | Live | Free (key) |
| AbuseIPDB | Abuse reports | Live | Free (key) |
| MISP | Full IoC platform | Live | Self-hosted |
| Cisco Talos | Enterprise IPs | Daily | Commercial |

### Lookup Performance

```
IP Lookup Path:
  Request
    │
    ├─ L1: In-memory dict (< 1µs)     ← recent lookups
    │       ↓ miss
    ├─ L2: Redis SISMEMBER (< 200µs)  ← feed_ips (100K+ IPs)
    │       ↓ miss
    ├─ L2: Redis HGET (< 200µs)       ← ip_scores
    │       ↓ miss
    └─ L3: Live API lookup (< 2s)     ← MISP / OTX / AbuseIPDB
           → Cache result in Redis (1h TTL)
```

### STIX 2.1 Export

```json
{
  "type": "bundle",
  "spec_version": "2.1",
  "objects": [
    {
      "type": "indicator",
      "pattern": "[ipv4-addr:value = '185.220.101.x']",
      "indicator_types": ["malicious-activity"],
      "confidence": 95,
      "kill_chain_phases": [
        {"kill_chain_name": "mitre-attack", "phase_name": "T1071"}
      ]
    }
  ]
}
```

---

## 3. Kubernetes Architecture

### Resource Layout

```
thor-system namespace
│
├── DaemonSet: thor-agent (1 pod per node)
│   ├── hostNetwork: true
│   ├── privileged capabilities: NET_ADMIN, SYS_ADMIN, IPC_LOCK
│   ├── BPF filesystem mount: /sys/fs/bpf
│   └── priorityClass: system-node-critical
│
├── Deployment: thor-control-plane (3 replicas → HPA 3-12)
│   ├── HPA: CPU > 70% → scale up
│   └── Ingress: api.thor-firewall.example.com (mTLS)
│
├── Deployment: thor-ml-inference (2 replicas, GPU node selector)
│   └── resources: 4 CPU, 4GB RAM (or GPU if available)
│
├── StatefulSet: thor-clickhouse (1 node, 500Gi SSD)
│   └── Upgrade path: ClickHouse Operator → 3-shard cluster
│
├── StatefulSet: thor-redis (6 nodes: 3 master + 3 replica)
│   └── Redis Cluster mode
│
└── NetworkPolicy: default-deny + allow-internal
```

### Node Affinity

```yaml
# thor-agent requires Linux (not Windows nodes)
nodeSelector:
  kubernetes.io/os: linux

# ml-inference prefers GPU nodes
affinity:
  nodeAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        preference:
          matchExpressions:
            - key: accelerator
              operator: In
              values: [nvidia-tesla-a100, nvidia-tesla-v100]
```

---

## 4. Complete Stack Services

### Docker Compose Services

| Service | Image | Port | Purpose |
|---------|-------|------|---------|
| thor-agent | thor-firewall/agent | 50051 (gRPC), 9090 (metrics) | Packet processing |
| control-plane | thor-firewall/control-plane | 8000 | API server |
| ml-inference | thor-firewall/ml-inference | 8082 | MARL+GNN inference |
| clickhouse | clickhouse/clickhouse-server:24.3 | 8123, 9000 | OLAP forensics |
| redis | redis:7.2-alpine | 6379 | Cache + Pub/Sub |
| dashboard | thor-firewall/dashboard | 3000 | React frontend |
| prometheus | prom/prometheus:2.51 | 9091 | Metrics scraping |
| grafana | grafana/grafana:10.3 | 3001 | Dashboards |

### Resource Requirements

| Profile | CPU | RAM | Storage | Network |
|---------|-----|-----|---------|---------|
| **Minimal** (lab) | 4 cores | 8 GB | 100 GB SSD | 1 Gbps |
| **Standard** (SMB) | 8 cores | 16 GB | 500 GB SSD | 10 Gbps |
| **Enterprise** (K8s) | 32+ cores | 64+ GB | 2+ TB NVMe | 25+ Gbps |
| **Carrier** (eBPF+DPDK) | 64+ cores | 256+ GB | 10+ TB | 100+ Gbps |

---

## 5. Security Architecture

### Secrets Management

| Secret | Storage | Access |
|--------|---------|--------|
| GRPC_TOKEN | K8s Secret / Docker secret | thor-agent, control-plane |
| CLICKHOUSE_PASSWORD | K8s Secret | control-plane, clickhouse |
| REDIS_PASSWORD | K8s Secret | all services |
| MISP_KEY | K8s Secret | control-plane only |
| OTX_KEY | K8s Secret | control-plane only |
| TLS certificates | K8s TLS Secret | ingress, gRPC |

### mTLS Everywhere

```
Control Plane → Agent:    gRPC + mTLS (mutual)
Client → Control Plane:  HTTPS + JWT
Agent → Redis:           TLS + AUTH password
Control Plane → CH:      Native protocol + password
```

---

## 6. Observability

### Prometheus Metrics (all services)

| Metric | Source | Alert |
|--------|--------|-------|
| `thor_packets_total` | Agent | — |
| `thor_flows_blocked_total` | Agent | Spike → alert |
| `thor_ml_inference_duration_seconds` | Agent | P99 > 10ms → alert |
| `thor_ml_accuracy` | Agent | < 0.90 → alert |
| `thor_grpc_requests_total` | Agent | — |
| `thor_cp_inprogress` | Control Plane | > 100 → alert |
| `clickhouse_rows_inserted_total` | ClickHouse | — |
| `redis_connected_clients` | Redis | > 1000 → warn |

### Grafana Dashboards (pre-built)

1. **Network Overview** — packets/s, flows, top-talkers map
2. **Threat Intelligence** — live threats, MITRE ATT&CK heatmap
3. **AI Performance** — accuracy, latency, false positives
4. **Forensics** — timeline, attack geography
5. **Infrastructure** — CPU, memory, BPF map utilization
6. **Federated Learning** — round progress, client participation

---

## 7. Phase 4 Roadmap

| Feature | Priority | ETA |
|---------|----------|-----|
| SmartNIC P4 offload (Mellanox Bluefield-3) | Critical | Q3 2026 |
| ZTNA (Zero-Trust Network Access) proxy | High | Q3 2026 |
| Encrypted Traffic Analysis (ML without decryption) | High | Q4 2026 |
| HSM key storage (PKCS#11) | Medium | Q4 2026 |
| DNS-over-HTTPS inspection | Medium | Q4 2026 |
| AI red-team continuous testing | High | Q1 2027 |
| Multi-cloud federation (AWS + Azure + GCP) | High | Q1 2027 |
| Quantum-safe cryptography (CRYSTALS-Kyber) | Low | Q2 2027 |

---

*Thor Firewall Phase 3 — From functional prototype to production-ready enterprise NGFW.*
