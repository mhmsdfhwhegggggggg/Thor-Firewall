# Thor Firewall — Master Roadmap
# خارطة الطريق الشاملة لمنصة Thor الأمنية

> **الرؤية:** تحويل Thor من جدار ناري ذكي إلى منصة أمنية مؤسسية عالمية تنافس  
> Palo Alto Cortex XDR · CrowdStrike Falcon · Splunk SIEM · Microsoft Sentinel

**المرجعية:** هذا المستند هو مصدر الحقيقة الوحيد للمشروع.  
كل مطور/خبير يعمل على المشروع يجب أن يبدأ من هنا.

---

## 📊 حالة المشروع الحالية

| المكوّن | الحالة | الاكتمال |
|---------|--------|---------|
| PacketParser (Rust) | ✅ مكتمل | 100% |
| FlowManager (Rust) | ✅ مكتمل | 100% |
| RuleEngine (Rust) | ✅ مكتمل | 100% |
| RLCore (Rust→Python bridge) | ⚠️ Stubs فقط | 30% |
| eBPF/XDP Kernel | ⚠️ كود C موجود، تكامل ناقص | 40% |
| WFP Driver (Windows) | 🔴 Skeleton فارغ | 10% |
| MARL Engine (Python) | ⚠️ Architecture موجودة، تدريب ناقص | 35% |
| GNN Analyzer (Python) | ⚠️ Architecture موجودة، تدريب ناقص | 35% |
| LLM Explainer (Mistral-7B) | ⚠️ Interface موجودة، deploy ناقص | 40% |
| Control Plane (FastAPI) | ✅ مكتمل | 85% |
| ThreatIntel Service | ✅ MISP+OTX+AbuseIPDB | 90% |
| SOAR Engine | ✅ Playbooks كاملة | 85% |
| PolicyEngine (ABAC) | ✅ Zero-Trust | 90% |
| Dashboard (React/TS) | ✅ مكتمل | 80% |
| Docker Compose (Dev) | ✅ مكتمل | 95% |
| Kubernetes/Helm | 🔴 لم يبدأ | 0% |
| MLflow Tracking | 🔴 لم يبدأ | 0% |
| CICIDS2018 Pipeline | 🔴 لم يبدأ | 0% |
| Threat Hunting UI | 🔴 لم يبدأ | 0% |
| UEBA Engine | 🔴 لم يبدأ | 0% |
| Compliance Reports | 🔴 لم يبدأ | 0% |

---

## 🗺️ المراحل الكاملة

### المرحلة 0 — البنية التحتية (مكتملة) ✅
*الأشهر 1-3*

**المُنجز:**
- Rust workspace + thor-agent binary
- PacketParser (50-feature ML vector, SIMD, Shannon entropy)
- FlowManager (DashMap lock-free, 1M flows/core, Welford statistics)
- RuleEngine (CIDR, rate-based, TTL, priority chains)
- RLCore (batch infrastructure, PyO3/REST/Simulation modes)
- eBPF/XDP C programs (xdp_main, xdp_syn_flood, BPF maps)
- MARL Engine architecture (PPO, ActorCritic, ResidualBlock)
- GNN Analyzer architecture (GraphSAGE + GATv2)
- LLM Explainer interface (Mistral-7B + RAG)
- Control Plane (FastAPI, 12 endpoints)
- ThreatIntel (MISP + OTX + AbuseIPDB + STIX 2.1)
- SOAR Playbooks (block, quarantine, alert, IOC, ticket)
- PolicyEngine (ABAC + Zero-Trust + Threat Intel fast-path)
- Dashboard (React/TS, WebSocket, ThreatFeed, FlowTable)
- Docker Compose (8 services: agent, control-plane, ml, clickhouse, redis, dashboard, prometheus, grafana)

**المهام الباقية في المرحلة 0:**
- [ ] تفعيل RLCore REST API mode (استبدال stub بـ HTTP client حقيقي)
- [ ] ربط xdp_loader.rs بـ ring_consumer.rs
- [ ] ClickHouse schema migrations (tables: flows, threats, audit_log)

---

### المرحلة 1 — نواة eBPF/WFP فائقة السرعة
*الأشهر 4-9*

**الهدف:** تجاوز 10 Mpps على Linux، 5 Mpps على Windows

**Linux eBPF:**
- [ ] XDP multi-stage pipeline مكتمل (drop → parse → classify → sample)
- [ ] SYN cookies eBPF-level implementation
- [ ] Connection tracking BPF map مع TTL تلقائي
- [ ] TC egress hook لـ outbound inspection
- [ ] XDP hardware offload (للـ NIC التي تدعمه)
- [ ] BPF ring buffer → Rust consumer بالكامل

**Windows WFP:**
- [ ] WFP callout driver كامل (NDIS 6.x)
- [ ] Shared memory ring buffer (kernel ↔ usermode)
- [ ] Windows Service wrapper للـ thor-agent
- [ ] MSI installer مع Driver signing

**Benchmarks:**
- [ ] iperf3 throughput benchmarks
- [ ] pktgen latency benchmarks
- [ ] Comparison vs iptables/nftables

---

### المرحلة A — ML Training الحقيقي + MLflow + CICIDS2018 🆕
*الأشهر 4-9 بالتوازي مع المرحلة 1*

**الهدف:** نماذج ML مُدرَّبة حقيقية تعمل في production

#### A1. Data Pipeline — CICIDS2018
```
ml/
├── data/
│   ├── download_cicids.sh      # تحميل CICIDS2017/2018 من UNB
│   ├── preprocess.py           # تنظيف، normalisation، feature engineering
│   ├── label_encoder.py        # ترميز الهجمات (22 نوع)
│   └── dataset.py              # PyTorch Dataset class
```

**Datasets:**
- CICIDS2018 (Canadian Institute for Cybersecurity) — 10 أنواع هجوم
- UNSW-NB15 — 9 فئات هجوم
- CIC-IDS2017 — البيانات الأساسية
- NSL-KDD — للـ baseline comparison

**Feature Engineering (50→82 features):**
- 50 ميزة حزمة موجودة
- + 32 ميزة GNN node embedding
- Feature importance عبر SHAP values

#### A2. MLflow Tracking Server
```
ml/
├── mlflow/
│   ├── tracking_server.py      # MLflow server setup
│   ├── experiment_config.yaml  # hyperparameter spaces
│   └── model_registry.py       # versioning + promotion
```

**MLflow Components:**
- Experiment tracking لكل تجربة تدريب
- Model Registry (Staging → Production)
- Artifact Store (نماذج، charts، confusion matrices)
- Comparison عبر runs متعددة

#### A3. MARL Training Pipeline
```
ml/
├── training/
│   ├── train_marl.py           # MARL PPO training loop
│   ├── train_gnn.py            # GNN training loop
│   ├── train_llm_lora.py       # LoRA fine-tuning Mistral-7B
│   ├── evaluate.py             # evaluation + metrics
│   └── hyperopt.py             # Optuna hyperparameter search
```

**نماذج MARL:**
- `TcpAgent` — متخصص TCP (SYN flood, brute force, port scan)
- `UdpAgent` — متخصص UDP (DNS tunnel, amplification, NTP)
- `IcmpAgent` — متخصص ICMP (ping flood, smurf, redirect)
- `MetaAgent` — coordinator (weighted ensemble)

**مقاييس الأداء المستهدفة:**
- Accuracy ≥ 99.5% على CICIDS2018 test set
- F1-Score ≥ 0.99 لكل فئة هجوم
- False Positive Rate < 0.1%
- Inference latency < 1ms/batch (64 flows)

#### A4. Online Learning Loop
```
ml/
├── online/
│   ├── feedback_collector.py   # جمع قرارات SOC (FP/FN feedback)
│   ├── incremental_trainer.py  # تحديث تدريجي للنموذج
│   └── drift_detector.py       # كشف concept drift (ADWIN)
```

**الفكرة:** كل مرة يصحح SOC Analyst خطأً (FP/FN)، يدخل هذا التصحيح في دورة تدريب تدريجي — النموذج يتحسن مع الوقت.

#### A5. Model Serving (FastAPI → triton-like)
```
ml/
├── serving/
│   ├── inference_server.py     # FastAPI serving endpoint
│   ├── model_cache.py          # في‑الذاكرة model cache
│   ├── batching.py             # Dynamic batching (max 64, timeout 1ms)
│   └── health.py               # Model health + drift metrics
```

**الـ RLCore في Rust:** استبدال `call_rest_api` stub بـ HTTP client حقيقي يستدعي `http://ml-inference:8082/v1/analyze/batch`

---

### المرحلة B — Kubernetes + Helm + Terraform 🆕
*الأشهر 6-10*

**الهدف:** نشر production-grade على أي cloud/on-premise

#### B1. Helm Charts
```
helm/
├── thor-firewall/
│   ├── Chart.yaml
│   ├── values.yaml             # default values (overridable)
│   ├── values.production.yaml  # production overrides
│   ├── values.dev.yaml         # development overrides
│   └── templates/
│       ├── agent/              # DaemonSet (يعمل على كل node)
│       ├── control-plane/      # Deployment + HPA
│       ├── ml-inference/       # Deployment + GPU nodeSelector
│       ├── mlflow/             # Deployment + PVC
│       ├── clickhouse/         # StatefulSet + PVC
│       ├── redis/              # StatefulSet (Sentinel mode)
│       ├── dashboard/          # Deployment
│       ├── ingress.yaml        # NGINX Ingress + TLS
│       ├── hpa.yaml            # HorizontalPodAutoscaler
│       ├── pdb.yaml            # PodDisruptionBudget
│       ├── networkpolicies.yaml # Zero-trust pod isolation
│       ├── rbac.yaml           # ServiceAccount + RBAC
│       └── secrets.yaml        # ExternalSecrets (Vault/AWS SM)
```

**Thor Agent كـ DaemonSet:**
- يعمل على كل node تلقائياً
- hostNetwork: true لـ XDP
- Privileged container للـ eBPF
- Node affinity rules

**Auto-scaling:**
- Control Plane: HPA على CPU/memory (2→20 replicas)
- ML Inference: HPA على GPU utilization (1→8 replicas)
- KEDA للـ queue-based scaling (Redis queue depth)

#### B2. Terraform — Infrastructure as Code
```
terraform/
├── modules/
│   ├── aws/
│   │   ├── eks/                # EKS cluster + node groups
│   │   ├── rds/                # PostgreSQL (metadata)
│   │   ├── s3/                 # Model artifacts + logs
│   │   ├── vpc/                # VPC + subnets + security groups
│   │   └── iam/                # IAM roles + policies
│   ├── azure/
│   │   ├── aks/                # AKS cluster
│   │   ├── storage/            # Blob storage
│   │   └── network/            # VNet + NSG
│   └── gcp/
│       ├── gke/                # GKE cluster + GPU node pool
│       └── storage/            # GCS buckets
├── environments/
│   ├── dev/main.tf
│   ├── staging/main.tf
│   └── production/main.tf
└── README.md
```

**المزودون المدعومون:**
- AWS EKS (primary)
- Azure AKS
- GCP GKE
- On-premise (kubeadm)
- DigitalOcean DOKS

#### B3. GitOps — ArgoCD
```
gitops/
├── argocd/
│   ├── apps/
│   │   ├── thor-prod.yaml      # Production app
│   │   ├── thor-staging.yaml   # Staging app
│   │   └── thor-dev.yaml       # Dev app
│   └── projects/
│       └── thor-project.yaml
├── Makefile                    # deploy, rollback, status commands
└── README.md
```

**Pipeline CI/CD الكامل:**
```
Push to main
    ↓
GitHub Actions: test + build + scan
    ↓
Push image to ghcr.io
    ↓
ArgoCD detects new image
    ↓
Auto-deploy to staging
    ↓
Manual approval → Production
```

#### B4. Observability Stack
```
monitoring/
├── prometheus/
│   ├── alerts/
│   │   ├── thor_agent.yaml     # Agent health alerts
│   │   ├── ml_accuracy.yaml    # ML drift alerts
│   │   └── security.yaml       # Security event alerts
│   └── rules/
├── grafana/
│   ├── dashboards/
│   │   ├── overview.json       # Executive overview
│   │   ├── network_ops.json    # Network operations
│   │   ├── ml_performance.json # ML accuracy/drift
│   │   ├── threat_intel.json   # Threat intelligence
│   │   └── compliance.json     # Compliance status
│   └── provisioning/
├── jaeger/                     # Distributed tracing
│   └── deployment.yaml
└── loki/                       # Log aggregation
    └── deployment.yaml
```

---

### المرحلة C — Threat Hunting + UEBA + Timeline 🆕
*الأشهر 10-16*

**الهدف:** تجربة محقق أمني كاملة داخل المنصة

#### C1. Threat Hunting Interface
```
dashboard/src/
├── pages/
│   └── ThreatHunting/
│       ├── index.tsx           # Hunting workspace
│       ├── QueryBuilder.tsx    # Visual query builder
│       ├── HuntingNotepad.tsx  # Investigation notes (markdown)
│       ├── SavedHunts.tsx      # Library of hunting queries
│       └── HuntingResults.tsx  # Results + export
```

**Query Language (ThorQL):**
```
-- مثال: البحث عن DNS tunneling محتمل
flows
  WHERE protocol = "UDP"
    AND dst_port = 53
    AND payload_entropy > 7.0
    AND bytes_per_packet > 200
  LAST 4h
  GROUP BY src_ip
  HAVING count(*) > 100
  ORDER BY max(risk_score) DESC
```

**Saved Hunt Library (مدمج مسبقاً):**
- `hunt_dns_tunnel.thorql` — DNS tunneling
- `hunt_beaconing.thorql` — C2 beaconing (fixed intervals)
- `hunt_lateral_movement.thorql` — Lateral movement
- `hunt_data_exfil.thorql` — Data exfiltration
- `hunt_cryptominer.thorql` — Crypto mining
- `hunt_brute_force.thorql` — Multi-service brute force

#### C2. UEBA Engine
```
ml/
├── ueba/
│   ├── behavioral_baseline.py  # بناء baseline لكل entity
│   ├── anomaly_detector.py     # Isolation Forest + Autoencoder
│   ├── entity_scoring.py       # حساب risk score تراكمي
│   ├── peer_grouping.py        # تجميع entities بسلوك مشابه
│   └── alert_generator.py      # تنبيهات UEBA مُوزَّنة
```

**Entities المُراقَبة:**
- **User entities:** ساعات العمل، الأجهزة، التطبيقات، الأحجام، الأماكن الجغرافية
- **Device entities:** خدمات مفتوحة، اتصالات خارجية، عمليات، ملفات
- **Network entities:** IP addresses، ASNs، الدول، البروتوكولات

**نماذج UEBA:**
- `IsolationForest` — كشف الشذوذ غير المُصنَّف
- `LSTM Autoencoder` — أنماط زمنية غير طبيعية
- `Peer Group Analysis` — مقارنة entity بأقرانها
- `Cumulative Risk Score` — تراكم نقاط الخطر عبر الزمن

**UEBA Alerts:**
```
⚠️ UEBA Alert: User "john.doe" accessed 847 files in 2h
   Baseline: avg 23 files/day
   Peer group: avg 31 files/day
   Risk delta: +3.7 sigma
   MITRE: T1039 - Data from Local System
```

#### C3. Incident Timeline
```
dashboard/src/
├── components/
│   └── Timeline/
│       ├── IncidentTimeline.tsx  # زمن الحادثة بالكامل
│       ├── TimelineEvent.tsx     # حدث واحد مع تفاصيله
│       ├── AttackChain.tsx       # MITRE Kill Chain visualization
│       ├── EvidencePanel.tsx     # الأدلة المرتبطة (flows، logs، files)
│       └── ProcessTree.tsx       # شجرة العمليات للـ Endpoint
```

**مكونات الـ Timeline:**
- أحداث الشبكة (flows، DNS، HTTP)
- أحداث Endpoint (processes، files، registry)
- أحداث UEBA (behavioral anomalies)
- أحداث Threat Intel (IOC matches)
- قرارات SOAR (automated responses)
- تعليقات المحقق

**Attack Chain Mapping:**
```
Reconnaissance → Initial Access → Execution → Persistence
     T1595            T1190           T1059        T1547
       ↓                ↓               ↓            ↓
  [Port Scan]    [CVE-2024-xxx]  [PowerShell]  [Run Key]
  10:23:15        10:25:02         10:26:18      10:27:44
```

#### C4. Case Management
```
control-plane/src/
├── routes/
│   └── cases.py                # Case CRUD API
├── services/
│   └── case_manager.py         # Case lifecycle
└── models/
    └── case.py                 # Case schema
```

**Case Workflow:**
```
NEW → INVESTIGATING → ESCALATED → RESOLVED → CLOSED
```

**Case Fields:**
- ID + Title + Severity + Assignee
- Related Incidents (N-to-N)
- Evidence (flows, logs, screenshots)
- Investigation Notes (markdown)
- SLA Timer (تنبيه عند انتهاء الوقت)
- Closure Report + Root Cause

#### C5. Network Topology (Digital Twin)
```
dashboard/src/
├── components/
│   └── NetworkTopology/
│       ├── TopologyGraph.tsx    # D3.js/Sigma.js force graph
│       ├── NodeDetails.tsx      # تفاصيل device
│       ├── EdgeDetails.tsx      # تفاصيل connection
│       └── TopologyFilters.tsx  # فلترة حسب subnet/risk/protocol
```

**الخريطة الحية:**
- تحديث كل 30 ثانية
- Nodes = أجهزة (IP, hostname, OS)
- Edges = اتصالات نشطة (بروتوكول، حجم، خطر)
- ألوان: أخضر=آمن، برتقالي=مشبوه، أحمر=مُهاجَم
- كشف تغيير هيكل الشبكة (new device, new connection)

---

### المرحلة D — شهادات الامتثال + تقارير PDF 🆕
*الأشهر 14-20*

**الهدف:** اعتماد رسمي لـ SOC2 Type II + ISO 27001 + NCA-ECC

#### D1. Compliance Engine
```
control-plane/src/
├── compliance/
│   ├── frameworks/
│   │   ├── soc2.py             # SOC2 Type II controls
│   │   ├── iso27001.py         # ISO 27001:2022 controls
│   │   ├── nca_ecc.py          # NCA-ECC (سعودي)
│   │   ├── pci_dss.py          # PCI-DSS v4.0
│   │   ├── hipaa.py            # HIPAA Security Rule
│   │   └── gdpr.py             # GDPR Art. 32 controls
│   ├── evidence_collector.py   # جمع الأدلة تلقائياً
│   ├── gap_analyzer.py         # Gap analysis
│   └── remediation.py          # خطط المعالجة
```

**SOC2 Type II Controls المُتحقَّق منها تلقائياً:**
- CC6.1: Logical access controls ✓ (PolicyEngine logs)
- CC6.2: Network access restrictions ✓ (Firewall rules audit)
- CC6.6: Vulnerability management ✓ (CVE scanning logs)
- CC7.1: System monitoring ✓ (ClickHouse logs)
- CC7.2: Security incident response ✓ (SOAR audit trail)
- CC8.1: Change management ✓ (Rule change history)

**ISO 27001:2022 Controls:**
- A.8.16: Network monitoring ✓
- A.8.20: Networks security ✓
- A.8.22: Segregation of networks ✓
- A.8.23: Web filtering ✓
- A.5.28: Collection of evidence ✓

#### D2. Automated PDF Reports
```
control-plane/src/
├── reporting/
│   ├── report_engine.py        # WeasyPrint-based PDF generator
│   ├── templates/
│   │   ├── executive_summary.html
│   │   ├── soc2_report.html
│   │   ├── iso27001_report.html
│   │   ├── incident_report.html
│   │   ├── weekly_digest.html
│   │   └── threat_intelligence.html
│   ├── charts.py               # matplotlib charts embedded in PDF
│   └── scheduler.py            # تقارير مجدولة (يومي/أسبوعي/شهري)
```

**أنواع التقارير:**
1. **Executive Summary** — KPIs + threats + trends (للإدارة العليا)
2. **SOC2 Audit Report** — 100+ صفحة مع الأدلة الكاملة
3. **ISO 27001 Gap Analysis** — مع خطة المعالجة
4. **Incident Report** — تقرير حادثة كامل مع Timeline
5. **Weekly Digest** — ملخص أسبوعي للـ SOC team
6. **Threat Intelligence Report** — أبرز التهديدات + IOCs

**جدولة التقارير:**
```python
# تقرير أسبوعي تلقائي كل أحد 08:00
@scheduler.scheduled_job("cron", day_of_week="sun", hour=8)
async def weekly_report():
    report = await generate_report("weekly_digest")
    await email_report(report, recipients=["soc@company.com"])
    await upload_to_s3(report, bucket="thor-reports")
```

#### D3. Audit Trail الكامل
```
control-plane/src/
├── audit/
│   ├── audit_logger.py         # كل event يُسجَّل مع cryptographic hash
│   ├── immutable_log.py        # Write-once ClickHouse table
│   ├── log_integrity.py        # Merkle tree verification
│   └── forensics_export.py     # تصدير للـ legal/forensics
```

**Audit Trail Properties:**
- Immutable (append-only ClickHouse table)
- Cryptographically signed (HMAC-SHA256)
- Merkle tree للتحقق من التكامل
- تصدير EVTX/JSON/SYSLOG للـ SIEM خارجي

---

### المرحلة 2 — نظام الذكاء الاصطناعي الكامل
*الأشهر 10-18*

**المهام:**
- [ ] تدريب MARL على CICIDS2018 (مع MLflow tracking)
- [ ] تدريب GNN على real network graphs
- [ ] Fine-tuning Mistral-7B على CVE/MISP/USENIX (LoRA)
- [ ] Online learning loop (feedback → retrain)
- [ ] Model versioning + A/B testing
- [ ] Concept drift detection (ADWIN)

---

### المرحلة 3 — التحصين الذاتي
*الأشهر 19-24*

**المهام:**
- [ ] Syscall hooks للكشف عن محاولات تعطيل thor-agent
- [ ] Memory encryption للـ ML models في الذاكرة
- [ ] Binary integrity verification (TPM integration)
- [ ] Anti-tampering: restart تلقائي عند كشف تغيير
- [ ] Secure Boot chain verification
- [ ] Agent attestation (للـ zero-trust بين المكونات)

---

### المرحلة 4 — لوحة التحكم المتقدمة
*الأشهر 25-28*

**المهام (إضافة لما بُني):**
- [ ] Dark Mode + Multi-language (عربي/إنجليزي)
- [ ] Executive Dashboard (KPIs فقط للإدارة)
- [ ] Mobile App (React Native) للـ SOC on-the-go
- [ ] Slack/Teams/Telegram bot integration
- [ ] JIRA/ServiceNow automatic ticket creation
- [ ] Customizable alerts + noise reduction

---

### المرحلة 5 — Production Ready
*الأشهر 29-36*

**المهام:**
- [ ] Chaos Engineering (Chaos Monkey tests)
- [ ] Load testing (10M+ pps في environment حقيقي)
- [ ] Penetration testing (Red Team exercise)
- [ ] Common Criteria EAL4+ evaluation
- [ ] ICSA Labs NGFW certification
- [ ] FIPS 140-3 للمكونات التشفيرية
- [ ] NCA-ECC اعتماد (السوق السعودي)
- [ ] SOC2 Type II audit (external auditor)
- [ ] ISO 27001 certification

---

### المرحلة 6 — Enterprise & Commercial
*الأشهر 37-48*

**المهام:**
- [ ] Multi-tenant SaaS platform
- [ ] Managed Detection & Response (MDR) API
- [ ] Threat Intelligence Sharing Network (P2P STIX/TAXII)
- [ ] White-label partner program
- [ ] App Store / Marketplace
- [ ] Thor Intelligence Platform (TIP) — commercial feed
- [ ] Enterprise license server
- [ ] Professional Services offering

---

## 🏗️ Architecture القادمة (بعد المراحل A-D)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Thor Enterprise Security Platform                         │
│                                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │ Kernel Layer │  │ Agent Layer  │  │  ML/AI Layer │  │  Data Layer  │   │
│  │              │  │              │  │              │  │              │   │
│  │ eBPF/XDP     │  │ Rust Agent   │  │ MARL Engine  │  │ ClickHouse   │   │
│  │ WFP Driver   │◄─►│ Flow Manager │◄─►│ GNN Analyzer │  │ (OLAP)       │   │
│  │ Syscall Hooks│  │ Rule Engine  │  │ LLM Explainer│  │              │   │
│  │              │  │ UEBA Core    │  │ Online Learn │  │ Redis        │   │
│  └──────────────┘  └──────────────┘  │ MLflow       │  │ (State/Cache)│   │
│                                       └──────────────┘  │              │   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │ PostgreSQL   │   │
│  │ Control Plane│  │  Threat Intel│  │  Compliance  │  │ (Cases/Users)│   │
│  │              │  │              │  │              │  └──────────────┘   │
│  │ FastAPI/gRPC │  │ MISP+OTX     │  │ SOC2/ISO27001│                     │
│  │ SOAR Engine  │  │ STIX/TAXII   │  │ NCA-ECC      │                     │
│  │ Policy Engine│  │ P2P Sharing  │  │ PDF Reports  │                     │
│  │ Case Manager │  │ IOC Database │  │ Audit Trail  │                     │
│  └──────────────┘  └──────────────┘  └──────────────┘                     │
│                              │                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                    Dashboard (React/TypeScript)                       │  │
│  │  Overview│Flows│Threats│Hunting│UEBA│Cases│Timeline│Compliance│Query │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                              │                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │              Infrastructure (Kubernetes + Helm + Terraform)           │  │
│  │   AWS EKS │ Azure AKS │ GCP GKE │ On-Premise │ DigitalOcean DOKS     │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## ⚡ أولويات التنفيذ الفورية

### Sprint 1 (الأسبوع الحالي) — الأساسيات الحرجة
1. **ربط RLCore بـ ML Inference** — استبدال stub بـ HTTP client حقيقي
2. **MLflow Setup** — تثبيت + تهيئة tracking server
3. **CICIDS2018 Pipeline** — تحميل + معالجة البيانات
4. **ClickHouse Schema** — tables + migrations
5. **Kubernetes Helm Chart الأساسي** — DaemonSet + Deployment

### Sprint 2 (الأسبوع القادم)
1. **MARL Training** — تدريب أول نموذج على CICIDS2018
2. **GNN Training** — تدريب على network graphs
3. **Threat Hunting UI** — ThorQL + Query Builder
4. **Case Management API** — CRUD + workflow
5. **PDF Report Engine** — أول تقرير تلقائي

### Sprint 3 (الأسبوع الثالث)
1. **UEBA Engine** — Baseline + Isolation Forest
2. **Incident Timeline** — MITRE Kill Chain
3. **Network Topology** — D3.js graph
4. **SOC2 Controls Mapping** — automated evidence collection
5. **ArgoCD GitOps** — CI/CD pipeline كامل

---

## 📁 هيكل المشروع الكامل (المستهدف)

```
thor-firewall/
├── .github/
│   └── workflows/
│       ├── ci.yml              # Build + Test + Scan
│       ├── ml_train.yml        # Training pipeline trigger
│       ├── deploy.yml          # ArgoCD deploy trigger
│       └── security.yml        # Security scans
├── agent/                      # Rust eBPF agent ✅
├── agent-core/                 # Rust core library ✅
├── control-plane/              # FastAPI backend ✅
│   ├── src/
│   │   ├── compliance/         # 🆕 Compliance engine
│   │   ├── reporting/          # 🆕 PDF report engine
│   │   ├── audit/              # 🆕 Immutable audit trail
│   │   └── routes/
│   │       └── cases.py        # 🆕 Case management
├── dashboard/                  # React/TS frontend ✅
│   └── src/
│       └── pages/
│           ├── ThreatHunting/  # 🆕 Hunting workspace
│           ├── UEBA/           # 🆕 User behavior analytics
│           ├── Cases/          # 🆕 Case management
│           ├── Timeline/       # 🆕 Incident timeline
│           └── Compliance/     # 🆕 Compliance dashboard
├── ml/                         # ML/AI engines
│   ├── marl/                   # MARL (PPO) ✅
│   ├── gnn/                    # GNN (GraphSAGE+GATv2) ✅
│   ├── llm/                    # LLM (Mistral-7B) ✅
│   ├── ueba/                   # 🆕 UEBA engine
│   ├── data/                   # 🆕 CICIDS2018 pipeline
│   ├── training/               # 🆕 Training scripts
│   ├── serving/                # 🆕 Inference server
│   ├── online/                 # 🆕 Online learning
│   └── mlflow/                 # 🆕 MLflow tracking
├── helm/                       # 🆕 Kubernetes Helm Charts
│   └── thor-firewall/
├── terraform/                  # 🆕 Infrastructure as Code
│   ├── modules/aws/
│   ├── modules/azure/
│   └── modules/gcp/
├── gitops/                     # 🆕 ArgoCD GitOps
├── kernel-modules/             # eBPF/XDP + WFP
├── configs/                    # Configuration files
├── monitoring/                 # Prometheus + Grafana ✅
├── docs/                       # Documentation ✅
├── tests/                      # Test suites
├── scripts/                    # Utility scripts
├── docker-compose.yml          # Dev environment ✅
└── MASTER_ROADMAP.md           # هذا الملف — مصدر الحقيقة
```

---

## 🔧 للمطور/الخبير القادم

### كيف تبدأ العمل

```bash
# 1. استنساخ المستودع
git clone https://github.com/mhmsdfhwhegggggggg/Thor-Firewall.git
cd Thor-Firewall

# 2. قراءة هذا الملف بالكامل
cat MASTER_ROADMAP.md

# 3. تشغيل البيئة المحلية
docker-compose up -d

# 4. التحقق من حالة الخدمات
curl http://localhost:8000/api/health

# 5. فتح الـ Dashboard
open http://localhost:3000
```

### المكونات الحرجة التي تحتاج اهتماماً فورياً

1. **`agent/src/rl_core.rs`** — `call_rest_api()` و `call_python_model()` هما stubs تحتاج تنفيذ حقيقي
2. **`agent/src/linux/xdp_loader.rs`** — يحتاج ربط بـ `ring_consumer.rs`
3. **`ml/serving/inference_server.py`** — يحتاج بناء (لم يُنشأ بعد)
4. **`ml/data/`** — pipeline تحميل CICIDS2018 لم يُنشأ
5. **`helm/`** — Helm charts لم تُنشأ

### القواعد الصارمة
- **لا تعدّل الـ stubs بدون كتابة tests** أولاً
- **كل نموذج ML** يجب تسجيله في MLflow قبل الـ deployment
- **كل تغيير في PolicyEngine** يجب أن يُوثَّق في Audit Trail
- **لا تستخدم `console.log` في server code** — استخدم `req.log` أو `logger`
- **الـ Rust code** يجب أن يمر بـ `cargo clippy -- -D warnings`

---

## 📈 KPIs العالمية المستهدفة

| المقياس | الهدف | الطريقة |
|---------|-------|---------|
| Throughput (Linux XDP) | > 10 Mpps | pktgen benchmark |
| Throughput (Windows WFP) | > 5 Mpps | custom tool |
| Detection Accuracy | > 99.5% | CICIDS2018 test set |
| Zero-day Detection | > 85% | Custom adversarial set |
| False Positive Rate | < 0.1% | Production monitoring |
| ML Inference Latency | < 1ms/batch | perf profiling |
| SOAR Response Time | < 5s | P95 metric |
| Dashboard Load Time | < 2s | Lighthouse |
| API Response Time | < 100ms | P95 metric |
| Uptime | > 99.99% | SLA monitoring |

---

## 🌐 الشركاء والتكاملات المستهدفة

| الفئة | المنتج | الحالة |
|-------|--------|--------|
| Threat Intel | MISP | ✅ مُكتمل |
| Threat Intel | AlienVault OTX | ✅ مُكتمل |
| Threat Intel | AbuseIPDB | ✅ مُكتمل |
| Threat Intel | VirusTotal | 🔴 قادم |
| Threat Intel | Shodan | 🔴 قادم |
| SIEM | Splunk | 🔴 قادم |
| SIEM | QRadar | 🔴 قادم |
| Ticketing | JIRA | 🔴 قادم |
| Ticketing | ServiceNow | 🔴 قادم |
| Notification | Slack | 🔴 قادم |
| Notification | Microsoft Teams | 🔴 قادم |
| Cloud | AWS GuardDuty | 🔴 قادم |
| Cloud | Azure Defender | 🔴 قادم |
| Endpoint | CrowdStrike (import) | 🔴 قادم |
| Identity | Active Directory | 🔴 قادم |
| Identity | Okta | 🔴 قادم |

---

*آخر تحديث: 2026-06-08*  
*المرحلة الحالية: Phase 0 مكتملة → بدء Phases A+B+C+D*
