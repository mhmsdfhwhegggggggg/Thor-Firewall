<div align="center">
  <h1>⚡ Thor Firewall</h1>
  <p><strong>World-Class Enterprise Security Platform</strong></p>
  <p>Competing with Palo Alto Cortex XDR · CrowdStrike Falcon · Splunk SIEM</p>

  [![CI](https://github.com/mhmsdfhwhegggggggg/Thor-Firewall/actions/workflows/ci.yml/badge.svg)](https://github.com/mhmsdfhwhegggggggg/Thor-Firewall/actions)
  [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
  [![Rust](https://img.shields.io/badge/Rust-1.77-orange.svg)](https://rustup.rs)
  [![Python](https://img.shields.io/badge/Python-3.12-blue.svg)](https://python.org)
</div>

---

## 🏗️ Architecture

```
                    ┌─────────────────────────────────────────┐
                    │          Thor Security Platform          │
                    └────────────────┬────────────────────────┘
                                     │
          ┌──────────────────────────┼──────────────────────────┐
          │                          │                          │
   ┌──────▼───────┐        ┌────────▼────────┐        ┌───────▼────────┐
   │  eBPF Agent  │        │ Control Plane   │        │ ML Inference   │
   │  (Rust/XDP)  │        │ (FastAPI/Python)│        │ (PyTorch/MARL) │
   │              │        │                 │        │                │
   │ • Packet Fwd │◄──────►│ • REST API      │◄──────►│ • PPO Agent    │
   │ • RL Decisions│        │ • SOAR Engine   │        │ • GNN Topology │
   │ • eBPF Maps  │        │ • Threat Intel  │        │ • UEBA Models  │
   │ • PyO3 Bridge│        │ • Compliance    │        │ • Online Learn │
   └──────────────┘        └────────┬────────┘        └────────────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              │                     │                     │
      ┌───────▼──────┐    ┌────────▼──────┐    ┌────────▼──────┐
      │  ClickHouse  │    │    Redis      │    │    MLflow     │
      │  (Events)    │    │  (Cache/PubSub│    │  (Experiments)│
      └──────────────┘    └───────────────┘    └───────────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              │                     │                     │
      ┌───────▼──────┐    ┌────────▼──────┐    ┌────────▼──────┐
      │   React UI   │    │  Prometheus   │    │   Grafana     │
      │  (Dashboard) │    │  (Metrics)    │    │  (Dashboards) │
      └──────────────┘    └───────────────┘    └───────────────┘
```

## 🚀 Quick Start

```bash
# Development (Docker Compose)
make dev

# Open:
#   Dashboard:  http://localhost:3000
#   API:        http://localhost:8000/docs
#   MLflow:     http://localhost:5000
#   Grafana:    http://localhost:3001
#   Prometheus: http://localhost:9090
```

## 📂 Project Structure

```
Thor-Firewall/
├── agent/               # Rust eBPF/XDP network agent
│   └── src/
│       ├── main.rs      # Entry point
│       ├── ebpf/        # XDP packet processing
│       ├── rl_core.rs   # RL decision engine (HTTP→ML inference)
│       └── soar.rs      # SOAR playbook execution
├── control-plane/       # Python FastAPI control plane
│   └── src/
│       ├── compliance/  # SOC2 + ISO27001 + NCA-ECC auto-evaluation
│       ├── reporting/   # PDF report generation (WeasyPrint)
│       ├── audit/       # Immutable HMAC audit trail
│       └── routes/      # REST API routes
├── ml/                  # Machine Learning pipeline
│   ├── data/            # CICIDS2018 preprocessing
│   ├── training/        # MARL (PPO) + GNN + Hyperopt
│   ├── serving/         # FastAPI inference server
│   ├── ueba/            # Behavioral anomaly detection
│   ├── online/          # Incremental learning from SOC feedback
│   └── mlflow_tracking/ # MLflow experiment tracking
├── dashboard/           # React TypeScript dashboard
│   └── src/pages/
│       ├── ThreatHunting/   # ThorQL query builder
│       ├── UEBA/            # Entity behavior analysis
│       ├── Timeline/        # MITRE Kill Chain timeline
│       ├── Cases/           # Security case management
│       └── Compliance/      # SOC2/ISO27001 live scores
├── helm/thor-firewall/  # Kubernetes Helm chart
├── terraform/           # AWS EKS infrastructure
├── gitops/argocd/       # GitOps (ArgoCD apps)
├── monitoring/          # Prometheus + Grafana
│   ├── prometheus/      # Scrape configs + alert rules
│   └── grafana/         # Pre-built dashboards
├── configs/clickhouse/  # DB schema migrations
├── docker-compose.yml   # Local development
├── Makefile             # Build + deploy commands
└── MASTER_ROADMAP.md    # 6-phase architecture roadmap
```

## 🧠 ML Capabilities

| Model | Architecture | Dataset | Accuracy |
|-------|-------------|---------|----------|
| Attack Detection | PPO ActorCritic + ResidualBlock | CICIDS2018 | >97% |
| Network Topology | GraphSAGE + GATv2 | Synthetic + Real | >92% |
| UEBA Anomaly | IsolationForest + LSTM AE | User telemetry | >94% |
| Zero-Day Detection | Ensemble OOD | Synthetic | >88% |

## 🛡️ Compliance

| Framework | Score | Controls |
|-----------|-------|----------|
| SOC 2 Type II | 94.2% | 16 auto-evaluated |
| ISO 27001:2022 | 91.8% | Annex A full coverage |
| NCA-ECC | 96.1% | 17 controls |

## 📦 Deployment

```bash
# Kubernetes (Helm)
make deploy-staging
make deploy-prod

# Terraform (AWS EKS)
cd terraform/environments/production
terraform init && terraform apply

# CI/CD (GitHub Actions)
git push origin main  # triggers full pipeline
```

## 🔧 Development

```bash
# ML training
make ml-data       # Download + preprocess CICIDS2018
make ml-train      # Train MARL model with MLflow tracking

# Compliance reports
make compliance    # Run all framework evaluations
make report        # Generate SOC2 PDF report

# Infrastructure
make status        # Check deployment health
make rollback      # Rollback last production deploy
```

## 📄 License

MIT License — see [LICENSE](LICENSE)

---
<div align="center">
  <sub>Built with ❤️ for enterprise security</sub>
</div>
