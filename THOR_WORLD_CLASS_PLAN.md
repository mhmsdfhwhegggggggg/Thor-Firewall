# خطة Thor العالمية — نحو منصة أمنية تنافس Cortex XDR + CrowdStrike Falcon + Splunk
# Thor World-Class Plan — Competing with the Global Security Giants

> **المؤلف:** Thor AI Architect  
> **التاريخ:** 2026-06-10  
> **الإصدار:** 1.0.0  
> **الحالة:** خطة تنفيذية نشطة — مصدر الحقيقة الوحيد للخبير القادم

---

## 📋 جدول المحتويات

1. [فهم المنصات المرجعية العالمية](#1-فهم-المنصات-المرجعية)
2. [تحليل الفجوات بين Thor والمنصات الثلاث](#2-تحليل-الفجوات)
3. [المعمارية المستهدفة النهائية](#3-المعمارية-المستهدفة)
4. [الخطة التنفيذية — 12 مرحلة](#4-الخطة-التنفيذية)
5. [Sprint Plan التفصيلية](#5-sprint-plan)
6. [الملفات المطلوب إنشاؤها أو تعديلها](#6-الملفات-المطلوبة)
7. [KPIs ومعايير النجاح](#7-kpis)
8. [تعليمات الخبير القادم](#8-تعليمات-الخبير)

---

## 1. فهم المنصات المرجعية

### 🏛️ Palo Alto Networks Cortex XDR

**الفلسفة الجوهرية:** "نظام المناعة الموحد" — يربط كل مصادر البيانات في رؤية واحدة.

| الميزة | كيف تعمل | ما يحتاجه Thor |
|--------|----------|--------------|
| **Unified Data Integration** | تجميع بيانات endpoint + network + cloud في data lake واحد | ClickHouse كـ unified lake + connectors لـ AWS/Azure/GCP |
| **Behavioral Analytics + ML** | نماذج ML تحلل الأنماط السلوكية في real-time | MARL + GNN + UEBA (موجود جزئياً) — يحتاج تدريب حقيقي |
| **Root Cause Analysis** | رسم تسلسل زمني مرئي للهجوم (attack chain visualization) | Timeline component + MITRE ATT&CK mapping (يحتاج بناء) |
| **Automated Response** | عزل جهاز / إنهاء عملية / حجب IP تلقائياً | SOAR engine موجود — يحتاج توسيع + endpoint agent |
| **WildFire Threat Intel** | قاعدة بيانات تهديدات حية مُحدَّثة باستمرار | MISP + OTX موجود — يحتاج VirusTotal + Shodan + ThreatFox |

**الميزة التنافسية الحاسمة لـ Cortex XDR:**
- **Causality Chain** — ربط كل event بـ "سبب جذري" واحد (RCA)
- **XDR Stitching** — ربط أحداث متفرقة عبر أجهزة مختلفة في incident واحد متماسك
- **MITRE ATT&CK Coverage** — تغطية 90%+ من تكتيكات وتقنيات MITRE

### 🚀 CrowdStrike Falcon

**الفلسفة الجوهرية:** "العقل السحابي الخفيف" — agent صغير جداً، ذكاء ضخم في السحابة.

| الميزة | كيف تعمل | ما يحتاجه Thor |
|--------|----------|--------------|
| **Single Lightweight Agent** | agent < 5MB يرسل telemetry للسحابة، القرارات تأتي من السحابة | تحسين thor-agent: تقليل حجمه + Cloud Decision Mode |
| **Threat Graph** | قاعدة بيانات AI تربط مليارات الأحداث عبر كل عملاء CrowdStrike | Thor Graph DB — Neo4j أو ClickHouse Graph queries |
| **OverWatch Threat Hunting** | خبراء بشريون + AI يصطادون التهديدات المخفية | ThorQL + Saved Hunts Library + AI-assisted hunting |
| **Falcon AIDR** | حماية تفاعلات AI (prompt injection, agent hijacking) | LLM Security layer + prompt sanitization |
| **Prevention-First** | الحجب يحدث قبل التنفيذ، ليس بعده | eBPF LSM hooks + pre-execution blocking |

**الميزة التنافسية الحاسمة لـ CrowdStrike:**
- **Process Tree** — رسم شجرة العمليات الكاملة لكل هجوم
- **Memory Scanning** — فحص الذاكرة مباشرةً (fileless malware detection)
- **Identity Protection** — كشف هجمات credential theft في Active Directory

### 🕵️ Splunk Enterprise Security

**الفلسفة الجوهرية:** "غرفة العمليات المركزية" — استيعاب وتحليل petabytes من أي مصدر.

| الميزة | كيف تعمل | ما يحتاجه Thor |
|--------|----------|--------------|
| **SPL (Search Processing Language)** | لغة استعلام مرنة وقوية تشبه SQL لكن للأمن | ThorQL (موجود skeleton) — يحتاج تنفيذ كامل مع backend |
| **Analyst Queue** | تجميع مئات التنبيهات في "incidents" مدمجة | Alert Correlation Engine — تجميع التنبيهات ذات الصلة |
| **UEBA** | نماذج سلوكية لكل user وdevice لكشف الشذوذ | UEBA Engine موجود skeleton — يحتاج تدريب وتكامل |
| **SOAR Playbooks** | كتب تشغيل تلقائية للاستجابة | SOAR موجود — يحتاج توسيع + visual playbook builder |
| **Data Ingestion** | connectors لأكثر من 2000 مصدر بيانات | Universal Log Ingestion (syslog, CEF, LEEF, JSON) |

**الميزة التنافسية الحاسمة لـ Splunk:**
- **Alert Fatigue Reduction** — تقليل 95% من التنبيهات عبر correlation
- **Risk-Based Alerting (RBA)** — تجميع risk scores بدلاً من تنبيهات فردية
- **Glass Table** — لوحة تحكم مخصصة لكل SOC team

---

## 2. تحليل الفجوات

### ما يمتلكه Thor الآن ✅

```
✅ PacketParser (Rust) — 50 features, <50ns
✅ FlowManager (Rust) — lock-free, 1M flows/core
✅ RuleEngine (Rust) — CIDR, rate, TTL
✅ eBPF/XDP Programs (C) — xdp_main, syn_flood, conntrack
✅ MARL Architecture (Python) — PPO, ActorCritic, ResidualBlock
✅ GNN Architecture (Python) — GraphSAGE + GATv2
✅ LLM Interface (Python) — Mistral-7B + RAG skeleton
✅ Control Plane (FastAPI) — 12 endpoints, 85% complete
✅ ThreatIntel (Python) — MISP + OTX + AbuseIPDB
✅ SOAR (Python) — 5 playbooks
✅ PolicyEngine (Python) — ABAC + Zero-Trust
✅ Dashboard (React/TS) — basic pages
✅ Docker Compose — 8+ services
✅ Keycloak IAM — JWT/OIDC
✅ ClickHouse Schema — basic tables
```

### الفجوات الحرجة التي تجعل Thor دون المستوى العالمي ❌

#### فجوات Cortex XDR:
```
❌ XDR Data Stitching — ربط أحداث متفرقة في incident واحد
❌ Causality Chain (RCA) — تتبع السبب الجذري تلقائياً
❌ Cloud Integration — AWS CloudTrail + Azure Sentinel + GCP Security Command Center
❌ Endpoint Agent (EDR) — مراقبة العمليات والملفات والـ registry
❌ Visual Attack Timeline — رسم بياني تفاعلي للهجوم
❌ MITRE ATT&CK Heatmap — تغطية التكتيكات والتقنيات
❌ Automated Forensics Collection — جمع الأدلة تلقائياً
```

#### فجوات CrowdStrike Falcon:
```
❌ Process Tree Visualization — شجرة العمليات
❌ Memory Scanning — fileless malware detection
❌ Threat Graph Database — graph queries عبر مليارات الأحداث
❌ Identity & AD Protection — كشف هجمات credential theft
❌ Prevention-First (Pre-execution blocking) — LSM hooks للحجب قبل التنفيذ
❌ Lightweight Agent Mode — cloud offload للقرارات الذكية
❌ AI-Assisted Threat Hunting — اقتراحات AI للصياد
```

#### فجوات Splunk:
```
❌ ThorQL Backend — لغة الاستعلام موجودة skeleton فقط، لا backend حقيقي
❌ Alert Correlation Engine — تجميع التنبيهات الذات صلة
❌ Risk-Based Alerting (RBA) — تجميع risk scores بدلاً من تنبيهات فردية
❌ Universal Log Ingestion — syslog, CEF, LEEF, JSON, Windows Event Log
❌ Saved Hunting Queries Library — مكتبة استعلامات جاهزة
❌ Custom Dashboard Builder — Glass Table مخصص لكل team
❌ Data Retention Policies — إدارة دورة حياة البيانات
```

#### فجوات البنية التحتية:
```
❌ Kubernetes Helm Charts — 0% (لم يبدأ)
❌ MLflow Tracking — 0% (لم يبدأ)
❌ CICIDS2018 Training Pipeline — 0% (لم يبدأ)
❌ CI/CD Pipeline — GitHub Actions + ArgoCD
❌ Multi-tenancy — عزل بيانات بين المستأجرين
❌ Compliance Reports (PDF) — تقارير SOC2/ISO27001/NCA-ECC
```

---

## 3. المعمارية المستهدفة النهائية

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                    THOR ENTERPRISE SECURITY PLATFORM v2.0                    ║
║           Competing with Cortex XDR · CrowdStrike Falcon · Splunk            ║
╚══════════════════════════════════════════════════════════════════════════════╝

┌─────────────────────────────────────────────────────────────────────────────┐
│                         DATA COLLECTION LAYER                                │
│                                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │ Network Agent │  │ Endpoint EDR │  │ Cloud Sensors│  │ Log Ingestion│   │
│  │ (Rust/eBPF)  │  │ (Rust/Linux  │  │ AWS + Azure  │  │ Syslog/CEF/  │   │
│  │ XDP + WFP    │  │  Windows)    │  │ + GCP + K8s  │  │ LEEF/JSON    │   │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘   │
│         └─────────────────┴─────────────────┴──────────────────┘           │
│                                    │                                         │
│                             Kafka Event Bus                                  │
│                         (Unified Streaming Layer)                            │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
┌─────────────────────────────────────────────────────────────────────────────┐
│                         AI / INTELLIGENCE LAYER                              │
│                                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │ MARL Engine  │  │ GNN Analyzer │  │ UEBA Engine  │  │ LLM Explainer│   │
│  │ (PPO/POCA)   │  │ (GraphSAGE   │  │ (IsoForest   │  │ (Mistral-7B  │   │
│  │ TCP/UDP/ICMP │  │  + GATv2)    │  │  + LSTM AE)  │  │  + LoRA)     │   │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘   │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │              XDR Correlation Engine (NEW — Critical)                  │   │
│  │  • Causality Chain Builder (RCA)                                      │   │
│  │  • Cross-Source Event Stitching                                       │   │
│  │  • MITRE ATT&CK Auto-Mapping                                          │   │
│  │  • Risk Score Aggregation (Risk-Based Alerting)                       │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │              Threat Intelligence Platform (TIP)                       │   │
│  │  MISP + OTX + ThreatFox + AbuseIPDB + VirusTotal + Shodan + STIX 2.1│   │
│  └──────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
┌─────────────────────────────────────────────────────────────────────────────┐
│                         DATA STORAGE LAYER                                   │
│                                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │  ClickHouse  │  │    Redis     │  │  PostgreSQL  │  │    MLflow    │   │
│  │ (Events/OLAP │  │ (State/Cache │  │ (Cases/Users │  │ (ML Models   │   │
│  │  10B rows/d) │  │  Pub/Sub)    │  │  Compliance) │  │  Registry)   │   │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘   │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │              Threat Graph (NEW — CrowdStrike Equivalent)              │   │
│  │  ClickHouse Graph Queries / Neo4j — مليارات العلاقات بين الأحداث     │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CONTROL PLANE (FastAPI)                              │
│                                                                              │
│  REST API + gRPC + WebSocket                                                 │
│  SOAR Engine + Policy Engine + Case Manager + Compliance Engine              │
│  ThorQL Backend + Alert Correlation + Forensics API                          │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SOC DASHBOARD (React/TypeScript)                     │
│                                                                              │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐ │
│  │ Overview │ │ XDR View │ │ Hunting  │ │  UEBA   │ │   Compliance     │ │
│  │ (KPIs)   │ │ (Timeline│ │ (ThorQL) │ │(Behavior│ │ SOC2/ISO/NCA-ECC │ │
│  │          │ │  Chain)  │ │          │ │ Scores) │ │                  │ │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────────────┘ │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐ │
│  │  Cases   │ │ Network  │ │ Process  │ │  Threat  │ │   Glass Table    │ │
│  │ Manager  │ │ Topology │ │  Tree    │ │   Map    │ │ (Custom Boards)  │ │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
┌─────────────────────────────────────────────────────────────────────────────┐
│                    INFRASTRUCTURE (Kubernetes + Helm + Terraform)            │
│  AWS EKS │ Azure AKS │ GCP GKE │ On-Premise │ DigitalOcean                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. الخطة التنفيذية — 12 مرحلة

### 🔴 المرحلة 0-FIX: إصلاح الأساسيات المكسورة (الأسبوع 1)
**الأولوية: حرجة جداً — لا يمكن المتابعة بدونها**

| المهمة | الملف | الوقت المقدر |
|--------|-------|-------------|
| ربط `RLCore` بـ ML Inference HTTP client حقيقي | `agent/src/rl_core.rs` | 2 يوم |
| ربط `xdp_loader.rs` بـ `ring_consumer.rs` | `agent/src/linux/xdp_loader.rs` | 1 يوم |
| إنشاء `ml/serving/inference_server.py` الكامل | `ml/serving/inference_server.py` | 2 يوم |
| ClickHouse schema migrations الكاملة | `configs/clickhouse/` | 1 يوم |

**تفاصيل التنفيذ:**

```rust
// agent/src/rl_core.rs — استبدل call_rest_api stub بـ:
pub async fn call_rest_api(&self, batch: &[FlowFeatures]) -> Result<Vec<Decision>> {
    let client = reqwest::Client::new();
    let response = client
        .post(&format!("{}/v1/analyze/batch", self.ml_url))
        .header("X-API-Key", &self.api_key)
        .json(&AnalyzeBatchRequest { flows: batch.to_vec() })
        .timeout(Duration::from_millis(50))
        .send()
        .await?;
    Ok(response.json::<AnalyzeBatchResponse>().await?.decisions)
}
```

```python
# ml/serving/inference_server.py — FastAPI inference server
from fastapi import FastAPI
from ml.marl.agents import MARLDecisionEngine
from ml.gnn.network_analyzer import ThorGNN

app = FastAPI(title="Thor ML Inference Server")
engine = MARLDecisionEngine.load("/models/thor_marl_best.pt")
gnn = ThorGNN.load("/models/thor_gnn_best.pt")

@app.post("/v1/analyze/batch")
async def analyze_batch(request: AnalyzeBatchRequest):
    # 1. GNN context for network-wide understanding
    embeddings = gnn.get_node_embeddings(request.flows)
    # 2. MARL decision with GNN context
    decisions = engine.decide_batch(request.flows, embeddings)
    return AnalyzeBatchResponse(decisions=decisions)
```

---

### 🟡 المرحلة A: ML Training الحقيقي (الأسابيع 2-4)
**الهدف: نماذج مُدرَّبة حقيقية بدقة >99%**

#### A1. CICIDS2018 Data Pipeline
```bash
# ml/data/download_cicids.sh
# تحميل من: https://www.unb.ca/cic/datasets/ids-2018.html
wget -r -np -nH --cut-dirs=3 -A "*.csv" \
  https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/Processed%20Traffic%20Data%20for%20ML%20Algorithms/
```

**الملفات المطلوبة:**
- `ml/data/download_cicids.sh` — تحميل dataset
- `ml/data/preprocess.py` — تنظيف + normalization + feature engineering
- `ml/data/dataset_loader.py` — PyTorch Dataset class
- `ml/data/label_encoder.py` — ترميز 15 نوع هجوم

**22 نوع هجوم في CICIDS2018:**
```
BENIGN, Bot, BruteForce, DoS attacks-SlowHTTPTest, DoS attacks-Hulk,
DoS attacks-GoldenEye, DoS attacks-Slowloris, DDoS attacks-LOIC-HTTP,
DDoS attacks-LOIC-UDP, FTP-BruteForce, SSH-Bruteforce, 
Infiltration, Infiltration-CoolWebSearch, SQL Injection,
XSS, DDOS attack-HOIC, Web Attack, Infilteration 
```

#### A2. MARL Training Pipeline
```python
# ml/training/train_marl.py

import mlflow
import optuna

def train_marl_full():
    with mlflow.start_run(run_name="marl_cicids2018_v1"):
        # Hyperparameter optimization via Optuna
        study = optuna.create_study(direction="maximize")
        study.optimize(objective_fn, n_trials=50)
        
        # Train with best params
        best_params = study.best_params
        agent = MARLSystem(
            tcp_agent=TcpAgent(hidden_dim=best_params["hidden_dim"]),
            udp_agent=UdpAgent(hidden_dim=best_params["hidden_dim"]),
            icmp_agent=IcmpAgent(hidden_dim=best_params["hidden_dim"]),
            meta_agent=MetaAgent()
        )
        
        # Log metrics to MLflow
        mlflow.log_params(best_params)
        mlflow.log_metric("accuracy", final_accuracy)
        mlflow.log_metric("f1_score", final_f1)
        mlflow.log_metric("fpr", false_positive_rate)
        
        # Register model
        mlflow.pytorch.log_model(agent, "thor_marl_model")
```

**أهداف الأداء:**
- Accuracy ≥ 99.5% على CICIDS2018 test set
- F1-Score ≥ 0.99 لكل فئة هجوم
- False Positive Rate < 0.1%
- Inference latency < 1ms/batch (64 flows)

#### A3. GNN Training
```python
# ml/training/train_gnn.py
# تدريب على real network graphs من CICIDS2018
# مع PyTorch Geometric
```

#### A4. Online Learning Loop
```python
# ml/online/feedback_collector.py
# كل مرة يصحح SOC Analyst خطأً → دورة تدريب تدريجي
# ADWIN drift detection
```

---

### 🟢 المرحلة B: XDR Correlation Engine — قلب Cortex XDR (الأسابيع 3-5)
**الهدف: ربط الأحداث المتفرقة في incidents مدمجة — أهم ميزة تنافسية**

#### B1. Causality Chain Builder (Root Cause Analysis)
```python
# control-plane/src/xdr/causality_builder.py

class CausalityChainBuilder:
    """
    يبني سلاسل سببية تلقائياً من الأحداث المتفرقة.
    
    مثال:
    Port Scan (10:23) → CVE Exploit (10:25) → Lateral Movement (10:27)
         ↓
    Single Incident: "APT29-style initial access via Log4j"
    """
    
    async def build_chain(self, seed_event: SecurityEvent) -> CausalityChain:
        # 1. ابحث عن أحداث مترابطة (نفس الـ src_ip، نفس الـ host، نفس الـ time window)
        related = await self._find_related_events(seed_event, window_minutes=30)
        
        # 2. رتّب زمنياً وابنِ العلاقات
        chain = self._build_temporal_chain(related)
        
        # 3. طبّق MITRE ATT&CK mapping
        chain.mitre_tactics = self._map_to_mitre(chain.events)
        
        # 4. احسب risk score مجمَّع
        chain.aggregate_risk = self._calculate_aggregate_risk(chain)
        
        return chain

    def _map_to_mitre(self, events: List[SecurityEvent]) -> List[MitreTactic]:
        """
        MITRE ATT&CK Mapping:
        T1046 (Port Scan) → T1190 (Exploit Public App) → T1059 (Command Execution)
        → T1021 (Lateral Movement) → T1486 (Data Encrypted for Impact)
        """
```

#### B2. Cross-Source Event Stitching
```python
# control-plane/src/xdr/event_stitcher.py

class XDREventStitcher:
    """
    يجمع أحداثاً من مصادر مختلفة تنتمي لنفس الهجوم.
    
    المصادر:
    - Network flows (eBPF agent)
    - Endpoint events (EDR agent — مستقبلاً)
    - Cloud logs (AWS CloudTrail, Azure Activity Log)
    - Auth logs (Active Directory, Keycloak)
    - DNS queries
    - File system events
    """
    
    CORRELATION_RULES = [
        # نفس source IP في نافذة 30 دقيقة
        CorrelationRule("same_source_ip", window=30*60, fields=["src_ip"]),
        # نفس الجهاز المستهدف
        CorrelationRule("same_target_host", window=60*60, fields=["dst_ip"]),
        # username مشترك
        CorrelationRule("same_user_identity", window=24*60*60, fields=["username"]),
        # IOC match (نفس الـ hash أو IP في threat intel)
        CorrelationRule("shared_ioc", window=7*24*60*60, fields=["ioc_hash"]),
    ]
```

#### B3. Risk-Based Alerting (مستوحى من Splunk RBA)
```python
# control-plane/src/xdr/risk_engine.py

class RiskBasedAlertingEngine:
    """
    بدلاً من إطلاق 500 تنبيه منفصل → تجميعها في risk score واحد.
    
    مثال:
    - Port Scan: +15 risk points
    - Failed Auth x10: +25 risk points
    - Sensitive File Access: +30 risk points
    - Unusual Hour: +10 risk points
    ─────────────────────────────
    Total: 80/100 → ALERT: "Possible Account Compromise"
    
    هذا يقلل Alert Fatigue بنسبة 95% (مثل Splunk RBA).
    """
    
    RISK_SCORES = {
        "port_scan": 15,
        "failed_auth": 5,           # per event, max 50
        "sensitive_file_access": 30,
        "unusual_hour_activity": 10,
        "large_data_transfer": 25,
        "new_external_connection": 20,
        "privilege_escalation": 50,
        "lateral_movement": 60,
        "c2_beacon": 80,
        "data_exfiltration": 90,
    }
    
    ALERT_THRESHOLD = 75  # إطلاق تنبيه عند تجاوز 75 نقطة
```

---

### 🔵 المرحلة C: Threat Graph — قلب CrowdStrike (الأسابيع 4-6)
**الهدف: قاعدة بيانات graph تربط مليارات الأحداث**

#### C1. Thor Threat Graph (ClickHouse Graph Implementation)
```sql
-- configs/clickhouse/003_threat_graph.sql

-- جدول الـ nodes (الكيانات)
CREATE TABLE thor_graph_nodes (
    node_id     String,           -- IP:port أو hostname أو hash
    node_type   Enum8('ip'=1, 'host'=2, 'user'=3, 'process'=4, 'file'=5, 'domain'=6),
    first_seen  DateTime,
    last_seen   DateTime,
    risk_score  Float32,
    threat_tags Array(String),    -- ['c2', 'scanner', 'botnet']
    ioc_match   Bool,
    country     LowCardinality(String),
    asn         String
) ENGINE = ReplacingMergeTree(last_seen)
ORDER BY (node_type, node_id);

-- جدول الـ edges (العلاقات)
CREATE TABLE thor_graph_edges (
    src_node    String,
    dst_node    String,
    edge_type   Enum8('connected'=1, 'authenticated'=2, 'transferred_data'=3, 'same_campaign'=4),
    first_seen  DateTime,
    last_seen   DateTime,
    flow_count  UInt64,
    bytes_total UInt64,
    risk_score  Float32
) ENGINE = ReplacingMergeTree(last_seen)
ORDER BY (src_node, dst_node, edge_type);

-- Materialized View: تحديث تلقائي عند ورود flows جديدة
CREATE MATERIALIZED VIEW thor_graph_auto_update TO thor_graph_edges
AS SELECT
    src_ip AS src_node,
    dst_ip AS dst_node,
    'connected' AS edge_type,
    now() AS last_seen,
    count() AS flow_count,
    sum(bytes) AS bytes_total
FROM thor_flows
GROUP BY src_ip, dst_ip;
```

#### C2. Graph Query API (ThreatGraph Hunting)
```python
# control-plane/src/routes/threat_graph.py

@router.get("/api/v1/graph/neighbors/{ip}")
async def get_ip_neighbors(ip: str, depth: int = 2):
    """
    BFS traversal في الـ graph — مثل CrowdStrike Threat Graph.
    "أعطني كل الكيانات التي تواصلت مع هذا الـ IP في آخر 7 أيام،
     وكل الكيانات التي تواصلت معها هي أيضاً."
    """
    query = f"""
    WITH RECURSIVE neighbors AS (
        SELECT dst_node as node, 1 as depth FROM thor_graph_edges WHERE src_node = '{ip}'
        UNION ALL
        SELECT e.dst_node, n.depth + 1
        FROM thor_graph_edges e
        JOIN neighbors n ON e.src_node = n.node
        WHERE n.depth < {depth}
    )
    SELECT DISTINCT node, depth FROM neighbors
    """
    return await clickhouse.execute(query)

@router.get("/api/v1/graph/campaign/{campaign_ioc}")
async def trace_campaign(campaign_ioc: str):
    """
    تتبع حملة هجومية كاملة من IOC واحد — مثل CrowdStrike Campaign Intelligence.
    """
```

---

### 🟣 المرحلة D: ThorQL — قلب Splunk (الأسابيع 5-7)
**الهدف: لغة استعلام حقيقية تنافس Splunk SPL**

#### D1. ThorQL Parser & Executor
```python
# control-plane/src/thorql/parser.py

"""
ThorQL — Thor Query Language (مستوحى من Splunk SPL + ClickHouse SQL)

أمثلة:
  flows WHERE protocol = "TCP" AND dst_port IN [22,3389,5900] LAST 24h
    | WHERE risk_score > 0.8
    | GROUP BY src_ip
    | SORT BY count DESC
    | LIMIT 100

  threats WHERE severity = "critical" LAST 7d
    | CORRELATE WITH flows ON src_ip
    | ENRICH WITH threat_intel
    | EXPORT CSV

  users WHERE login_failures > 5 IN 1h
    | ALERT "BruteForce Suspected"
    | SOAR block_ip
"""

from lark import Lark, Transformer

THORQL_GRAMMAR = r"""
    query: source filters? pipes* time_range? limit?
    source: "flows" | "threats" | "users" | "processes" | "files" | "dns"
    filters: "WHERE" condition ("AND" condition)*
    condition: field OP value
    pipes: "|" pipe_cmd
    pipe_cmd: group_by | sort_by | enrich | alert | soar | export | correlate
    time_range: "LAST" NUMBER time_unit
    time_unit: "m" | "h" | "d" | "w"
    ...
"""

class ThorQLExecutor:
    async def execute(self, query: str) -> QueryResult:
        ast = self.parser.parse(query)
        ch_query = self.transpiler.to_clickhouse_sql(ast)
        result = await self.clickhouse.execute(ch_query)
        if ast.has_enrich:
            result = await self.enricher.enrich_with_threat_intel(result)
        if ast.has_alert:
            await self.alerter.create_alert(ast.alert_config, result)
        if ast.has_soar:
            await self.soar.execute_playbook(ast.soar_action, result)
        return result
```

#### D2. Saved Hunting Queries Library
```python
# control-plane/src/thorql/saved_hunts.py

BUILT_IN_HUNTS = {
    "dns_tunneling": ThorQLHunt(
        name="DNS Tunneling Detection",
        description="كشف نفق DNS لنقل البيانات المخفي",
        mitre_id="T1071.004",
        query="""
        flows WHERE protocol = "UDP" AND dst_port = 53
            AND payload_entropy > 7.0
            AND bytes_per_packet > 200
        LAST 4h
        GROUP BY src_ip
        HAVING count(*) > 100
        ORDER BY max(risk_score) DESC
        """,
        severity="high"
    ),
    
    "c2_beaconing": ThorQLHunt(
        name="C2 Beaconing Detection",
        description="كشف التواصل المنتظم مع خادم C2",
        mitre_id="T1071",
        query="""
        flows WHERE dst_port NOT IN [80, 443, 53, 22]
            AND connection_interval_stddev < 5.0
        LAST 24h
        GROUP BY src_ip, dst_ip
        HAVING count(*) > 50 AND stddev(interval_seconds) < 10
        ENRICH WITH threat_intel
        ALERT "C2 Beaconing Suspected" SEVERITY high
        """,
        severity="critical"
    ),
    
    "lateral_movement": ThorQLHunt(
        name="Lateral Movement Detection",
        description="كشف الحركة الجانبية داخل الشبكة",
        mitre_id="T1021",
        query="""
        flows WHERE dst_port IN [22, 3389, 445, 5985, 5986]
            AND src_ip LIKE "10.%" AND dst_ip LIKE "10.%"
        LAST 1h
        GROUP BY src_ip
        HAVING count(DISTINCT dst_ip) > 5
        CORRELATE WITH auth_logs ON src_ip
        SORT BY unique_destinations DESC
        """,
        severity="high"
    ),
    
    "data_exfiltration": ThorQLHunt(
        name="Data Exfiltration Detection",
        description="كشف تسريب البيانات للخارج",
        mitre_id="T1048",
        query="""
        flows WHERE direction = "outbound"
            AND bytes_out > 100MB
            AND dst_country NOT IN ["SA", "AE", "US", "GB"]
        LAST 24h
        GROUP BY src_ip, dst_ip
        ORDER BY bytes_out DESC
        ALERT "Potential Data Exfiltration" SEVERITY critical
        SOAR quarantine_host
        """,
        severity="critical"
    ),
    
    "brute_force": ThorQLHunt(
        name="Multi-Service Brute Force",
        description="كشف هجوم القوة الغاشمة متعدد الخدمات",
        mitre_id="T1110",
        query="""
        flows WHERE dst_port IN [22, 21, 3389, 5900, 23, 25]
            AND tcp_flags CONTAINS "SYN"
        LAST 15m
        GROUP BY src_ip
        HAVING count(*) > 100
        ENRICH WITH threat_intel
        ALERT "Brute Force Attack" SEVERITY high
        SOAR block_ip DURATION 24h
        """,
        severity="high"
    ),
    
    "crypto_mining": ThorQLHunt(
        name="Cryptomining Detection",
        description="كشف تعدين العملات المشفرة",
        mitre_id="T1496",
        query="""
        flows WHERE dst_port IN [3333, 4444, 5555, 9999, 14444, 45700]
            OR (dst_port = 443 AND payload_entropy > 7.5 AND packet_size_variance < 10)
        LAST 1h
        ENRICH WITH threat_intel
        GROUP BY src_ip, dst_ip
        """,
        severity="medium"
    ),
}
```

---

### 🟤 المرحلة E: UEBA Engine — كشف التهديدات الداخلية (الأسابيع 6-8)
**الهدف: مطابقة قدرات Splunk UEBA + CrowdStrike Identity Protection**

#### E1. Behavioral Baseline Builder
```python
# ml/ueba/behavioral_baseline.py

class UserBehaviorBaseline:
    """
    يبني نموذجاً سلوكياً لكل مستخدم بناءً على:
    - ساعات العمل الاعتيادية (working hours pattern)
    - الأجهزة المستخدمة عادةً (device fingerprints)
    - الأماكن الجغرافية (geo-locations)
    - الخدمات المستخدمة (service access patterns)
    - حجم البيانات المعتاد (data volume baseline)
    - معدل تسجيل الدخول (login frequency)
    """
    
    BASELINE_FEATURES = [
        "login_hour_distribution",      # توزيع ساعات تسجيل الدخول
        "active_days_pattern",          # أيام النشاط
        "unique_destinations_per_day",  # عدد الوجهات الفريدة
        "bytes_transferred_daily",      # حجم البيانات اليومي
        "failed_auth_rate",             # معدل الفشل في المصادقة
        "privileged_access_frequency",  # تكرار الوصول المميز
        "device_count",                 # عدد الأجهزة المستخدمة
        "geo_location_spread",          # انتشار المواقع الجغرافية
        "after_hours_access_rate",      # معدل الوصول خارج ساعات العمل
        "sensitive_resource_access",    # الوصول للموارد الحساسة
    ]
    
    def build_baseline(self, user_id: str, history_days: int = 90):
        """
        يحتاج 90 يوم من البيانات التاريخية لبناء baseline موثوق.
        """
```

#### E2. Anomaly Detector (Isolation Forest + LSTM Autoencoder)
```python
# ml/ueba/anomaly_detector.py

class UEBAnomalyDetector:
    """
    نموذج مزدوج:
    1. Isolation Forest — كشف النقاط الشاذة (outliers)
    2. LSTM Autoencoder — كشف الأنماط الزمنية غير الطبيعية
    
    كلا النموذجين يعطي risk delta، والنتيجة النهائية هي:
    risk_score = 0.6 * isolation_score + 0.4 * lstm_reconstruction_error
    """
    
    def detect_anomaly(self, current_behavior: UserBehavior, baseline: UserBehaviorBaseline):
        isolation_score = self.isolation_forest.score_samples([current_behavior.features])
        lstm_error = self.lstm_ae.reconstruction_error(current_behavior.time_series)
        
        combined_risk = 0.6 * isolation_score + 0.4 * lstm_error
        
        if combined_risk > self.ALERT_THRESHOLD:
            return UEBAAlert(
                user_id=current_behavior.user_id,
                risk_score=combined_risk,
                anomalies=self._explain_anomalies(current_behavior, baseline),
                mitre_id=self._infer_mitre_tactic(anomalies),
                peer_comparison=self._compare_with_peers(current_behavior)
            )
```

#### E3. Peer Group Analysis
```python
# ml/ueba/peer_grouping.py

class PeerGroupAnalyzer:
    """
    يجمع المستخدمين في مجموعات متشابهة السلوك (peer groups)
    ثم يقارن كل مستخدم بأقرانه.
    
    مثال تنبيه:
    ⚠️ UEBA Alert: User "ahmed.ali" accessed 847 files in 2h
       Baseline: avg 23 files/day
       Peer group (Accounting): avg 31 files/day  
       Risk delta: +3.7 sigma → ALERT
       MITRE: T1039 - Data from Local System
    """
    
    def cluster_users_by_behavior(self, all_users: List[UserBaseline]) -> Dict[str, PeerGroup]:
        """K-Means clustering على behavioral features"""
        from sklearn.cluster import KMeans
        features = np.array([u.feature_vector for u in all_users])
        kmeans = KMeans(n_clusters=10, random_state=42)
        labels = kmeans.fit_predict(features)
        return self._build_peer_groups(all_users, labels)
```

---

### 🔶 المرحلة F: Endpoint EDR Agent (الأسابيع 8-12)
**الهدف: مطابقة قدرات CrowdStrike Falcon EDR**

#### F1. Linux EDR Agent (eBPF-based)
```rust
// agent/src/edr/linux_edr.rs

/// EDR Agent للـ Linux — يراقب:
/// 1. Process Events (execve, fork, exit)
/// 2. File Events (open, write, unlink on sensitive paths)
/// 3. Network Events (socket connect, accept)
/// 4. Memory Events (mmap with EXEC, ptrace)
/// 5. Auth Events (sudo, su, PAM)

pub struct LinuxEDRAgent {
    process_tracer: ProcessTracer,    // eBPF tracepoint sys_enter_execve
    file_monitor: FileMonitor,        // eBPF kprobe vfs_open على /etc, /bin, /lib
    memory_scanner: MemoryScanner,    // scan for injected shellcode
    process_tree: ProcessTree,        // شجرة العمليات الكاملة
}
```

#### F2. Process Tree Visualization (مستوحى من CrowdStrike)
```typescript
// dashboard/src/components/ProcessTree/index.tsx

/**
 * Process Tree مثل CrowdStrike Falcon:
 * 
 * bash (pid: 1234)
 *   └── python (pid: 5678)
 *         └── curl (pid: 9012) [SUSPICIOUS: connecting to 185.220.101.x]
 *               └── sh (pid: 1357) [BLOCKED: executing payload]
 * 
 * كل node يُظهر:
 * - اسم العملية + PID + PPID
 * - Command line كامل
 * - User + permissions
 * - Network connections
 * - Files accessed
 * - Risk score
 * - MITRE ATT&CK mapping
 */
```

---

### 🔷 المرحلة G: Cloud Integration (الأسابيع 10-14)
**الهدف: مطابقة قدرات Cortex XDR Cloud Integration**

```python
# control-plane/src/cloud/aws_collector.py

class AWSSecurityCollector:
    """
    يجمع أحداث أمنية من:
    - AWS CloudTrail (API calls + changes)
    - AWS GuardDuty (threat detection)
    - AWS VPC Flow Logs (network flows)
    - AWS Security Hub (aggregated findings)
    - AWS WAF Logs (web attacks)
    - S3 Access Logs
    - EKS Audit Logs
    """
    
    async def stream_cloudtrail(self, sqs_queue_url: str):
        """Consume CloudTrail events via SQS → ClickHouse"""
```

```python
# control-plane/src/cloud/azure_collector.py

class AzureSecurityCollector:
    """
    - Azure Sentinel (Microsoft Defender XDR)
    - Azure Activity Log
    - Azure AD Sign-in Logs (Identity attacks)
    - Network Watcher Flow Logs
    - Microsoft Defender for Cloud
    """
```

---

### 🟦 المرحلة H: Universal Log Ingestion — Splunk-like (الأسابيع 9-11)
**الهدف: استيعاب أي log من أي مصدر**

```python
# control-plane/src/ingestion/universal_ingester.py

class UniversalLogIngester:
    """
    يستقبل logs من أي مصدر بأي تنسيق:
    
    المنافذ:
    - UDP 514: Syslog (RFC 5424)
    - TCP 514/6514: Syslog over TLS  
    - TCP 5044: Beats/Logstash
    - HTTP 8088: HTTP Event Collector (HEC — مثل Splunk HEC)
    - Kafka: streaming events
    - gRPC 50051: native Thor agents
    
    التنسيقات المدعومة:
    - Syslog (RFC 5424)
    - CEF (Common Event Format) — ArcSight
    - LEEF (Log Event Extended Format) — QRadar
    - JSON (أي هيكل)
    - Windows Event Log (XML)
    - NetFlow/IPFIX
    - Apache/Nginx access logs
    - AWS CloudTrail JSON
    """
    
    async def ingest(self, raw_log: bytes, source_type: LogSourceType) -> NormalizedEvent:
        parser = self.parser_registry[source_type]
        event = parser.parse(raw_log)
        normalized = self.normalizer.normalize(event)  # ECS (Elastic Common Schema)
        await self.clickhouse.insert("thor_raw_logs", [normalized])
        await self.redis.publish("new_event", normalized)
        return normalized
```

---

### 🟧 المرحلة I: Kubernetes + Helm + Terraform (الأسابيع 8-12)
**الهدف: نشر production-grade على أي cloud**

**الملفات المطلوبة:**

```yaml
# helm/thor-firewall/templates/agent/daemonset.yaml
# thor-agent كـ DaemonSet — يعمل على كل node تلقائياً
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: thor-agent
  namespace: thor-system
spec:
  selector:
    matchLabels:
      app: thor-agent
  template:
    spec:
      hostNetwork: true      # لـ XDP
      hostPID: true          # لـ EDR process monitoring
      priorityClassName: system-node-critical
      containers:
      - name: thor-agent
        image: ghcr.io/mhmsdfhwhegggggggg/thor-firewall/agent:latest
        securityContext:
          privileged: false
          capabilities:
            add: [NET_ADMIN, SYS_ADMIN, BPF, PERFMON]
        volumeMounts:
        - name: bpf-fs
          mountPath: /sys/fs/bpf
        - name: host-proc
          mountPath: /host/proc
          readOnly: true
      volumes:
      - name: bpf-fs
        hostPath:
          path: /sys/fs/bpf
          type: Directory
      - name: host-proc
        hostPath:
          path: /proc
```

```yaml
# helm/thor-firewall/templates/control-plane/deployment.yaml
# Control Plane مع HPA (auto-scaling)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: thor-control-plane
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: control-plane
        image: ghcr.io/mhmsdfhwhegggggggg/thor-firewall/control-plane:latest
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "2000m"
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: thor-cp-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: thor-control-plane
  minReplicas: 3
  maxReplicas: 20
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```

```hcl
# terraform/environments/production/main.tf
# AWS EKS Infrastructure

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.0"

  cluster_name    = "thor-firewall-prod"
  cluster_version = "1.30"

  # Node Groups
  eks_managed_node_groups = {
    thor_system = {
      instance_types = ["c6i.4xlarge"]  # 16 vCPU, 32 GB RAM
      min_size       = 3
      max_size       = 20
      desired_size   = 5
    }
    thor_ml_gpu = {
      instance_types = ["g4dn.xlarge"]  # GPU للـ ML inference
      min_size       = 1
      max_size       = 8
      desired_size   = 2
    }
  }
}
```

---

### 🟨 المرحلة J: Compliance Engine — SOC2 + ISO27001 + NCA-ECC (الأسابيع 11-14)
**الهدف: اعتماد رسمي تلقائي للمتطلبات التنظيمية**

```python
# control-plane/src/compliance/auto_evaluator.py

class ComplianceAutoEvaluator:
    """
    يقيّم الامتثال تلقائياً بناءً على بيانات النظام الفعلية.
    لا يحتاج إدخال يدوي.
    """
    
    async def evaluate_soc2(self) -> SOC2Report:
        controls = {
            "CC6.1": await self._check_logical_access_controls(),
            "CC6.2": await self._check_network_access_restrictions(),
            "CC6.6": await self._check_vulnerability_management(),
            "CC7.1": await self._check_system_monitoring(),
            "CC7.2": await self._check_incident_response(),
            "CC8.1": await self._check_change_management(),
        }
        score = sum(c.score for c in controls.values()) / len(controls)
        return SOC2Report(controls=controls, overall_score=score)
    
    async def _check_system_monitoring(self) -> ControlResult:
        """
        CC7.1: The entity uses detection and monitoring procedures
        → تحقق: هل ClickHouse يستقبل logs؟ هل Prometheus يعمل؟
        """
        ch_rows_24h = await clickhouse.execute("SELECT count() FROM thor_flows WHERE timestamp > now() - INTERVAL 24 HOUR")
        prometheus_up = await prometheus.query("up{job='thor-agent'}")
        
        score = 1.0 if ch_rows_24h > 0 and prometheus_up else 0.5
        evidence = f"Received {ch_rows_24h} events in last 24h. Prometheus: {'UP' if prometheus_up else 'DOWN'}"
        
        return ControlResult(control_id="CC7.1", score=score, evidence=evidence)
```

---

### 🟩 المرحلة K: Dashboard الشامل — SOC المتكامل (الأسابيع 10-14)
**الهدف: تجربة SOC analyst كاملة**

```typescript
// dashboard/src/pages/XDRView/index.tsx — الجديدة (مستوحاة من Cortex XDR)

/**
 * XDR Investigation View — يعرض:
 * 
 * ┌─────────────────────────────────────────────────────┐
 * │  INCIDENT #INC-2847: APT-style Lateral Movement     │
 * │  Severity: CRITICAL | Risk Score: 94/100            │
 * │  MITRE: T1190 → T1059 → T1021 → T1486              │
 * ├─────────────────────────────────────────────────────┤
 * │  Attack Timeline (Causality Chain)                  │
 * │  10:23 [Port Scan] ──► 10:25 [CVE Exploit]         │
 * │       ──► 10:26 [Cmd Exec] ──► 10:27 [Lateral Mvt] │
 * │       ──► 10:31 [Data Exfil BLOCKED]               │
 * ├─────────────────────────────────────────────────────┤
 * │  Affected Assets: 3 hosts, 1 user account           │
 * │  Network Graph: [Interactive D3 visualization]      │
 * ├─────────────────────────────────────────────────────┤
 * │  [Isolate Host] [Block IP] [Run Playbook] [Close]  │
 * └─────────────────────────────────────────────────────┘
 */
```

```typescript
// dashboard/src/pages/GlassTable/index.tsx — مستوحى من Splunk Glass Table

/**
 * Glass Table — لوحة تحكم مخصصة قابلة للبناء بالـ drag-and-drop
 * 
 * الـ widgets المتاحة:
 * - Threat Counter (العداد الحي للتهديدات)
 * - Risk Gauge (مقياس الخطر)
 * - ThreatMap (خريطة جغرافية)
 * - ThorQL Results Table
 * - UEBA Risk Chart
 * - Compliance Score
 * - Agent Status Grid
 */
```

---

### 🟥 المرحلة L: Integrations اعتماد عالمي (الأسابيع 12-18)
**الهدف: التكامل مع النظام البيئي الأمني العالمي**

```python
# control-plane/src/integrations/

# SIEM Integrations
integrations/splunk_forwarder.py      # تصدير events لـ Splunk HEC
integrations/qradar_syslog.py         # تصدير لـ IBM QRadar LEEF
integrations/sentinel_connector.py    # Microsoft Sentinel API
integrations/elastic_forwarder.py     # Elasticsearch/OpenSearch

# Ticketing
integrations/jira_connector.py        # Auto-create Jira issues
integrations/servicenow_connector.py  # ServiceNow incident creation
integrations/pagerduty.py             # PagerDuty alerts

# Notification
integrations/slack_bot.py             # Slack threat notifications
integrations/teams_webhook.py         # Microsoft Teams alerts
integrations/telegram_bot.py          # Telegram SOC bot

# Threat Intelligence
integrations/virustotal.py            # VirusTotal file/URL/IP lookup
integrations/shodan_api.py            # Shodan asset intelligence
integrations/recordedfuture.py        # Recorded Future threat intel
integrations/mandiant.py              # Mandiant Advantage

# Identity
integrations/active_directory.py      # AD event collection + protection
integrations/okta_connector.py        # Okta identity events
integrations/crowdstrike_import.py    # استيراد alerts من CrowdStrike

# Cloud
integrations/aws_guardduty.py         # AWS GuardDuty findings
integrations/azure_defender.py        # Azure Defender alerts
integrations/gcp_scc.py               # GCP Security Command Center
```

---

## 5. Sprint Plan التفصيلية

### Sprint 1 (الأسبوع 1-2) — Phase 0-FIX: إصلاح الأساسيات
```
المهام:
[ ] 1. rl_core.rs: استبدال call_rest_api stub بـ reqwest HTTP client حقيقي
[ ] 2. xdp_loader.rs: ربط بـ ring_consumer.rs (drain_events implementation)
[ ] 3. ml/serving/inference_server.py: FastAPI server كامل
[ ] 4. ClickHouse migrations: flows + threats + decisions + audit_log tables
[ ] 5. MLflow setup: tracking server + experiment configuration
[ ] 6. CICIDS2018 download + preprocess pipeline
[ ] 7. docker-compose smoke test: جميع الـ 8 خدمات تعمل معاً

الملفات المتأثرة:
- agent/src/rl_core.rs (تعديل)
- agent/src/linux/xdp_loader.rs (تعديل)
- ml/serving/inference_server.py (إنشاء)
- configs/clickhouse/002_flows_schema.sql (إنشاء)
- configs/clickhouse/003_threat_graph.sql (إنشاء)
- ml/data/download_cicids.sh (إنشاء)
- ml/data/preprocess.py (تعديل)

معايير القبول:
✓ curl http://localhost:8082/health → {"status": "ok"}
✓ curl http://localhost:8000/api/health → {"status": "healthy"}
✓ ClickHouse SELECT count() FROM thor_flows → 0 (جاهز)
✓ Thor agent يرسل events وتصل للـ ML server
```

### Sprint 2 (الأسبوع 2-3) — Phase A: ML Training
```
المهام:
[ ] 1. train_marl.py: حلقة تدريب MARL كاملة مع MLflow tracking
[ ] 2. train_gnn.py: تدريب GNN على network graphs
[ ] 3. MLflow Model Registry: تسجيل + promote النماذج
[ ] 4. inference_server.py: dynamic batching + model hot-swap
[ ] 5. Online learning: feedback_collector.py + incremental_trainer.py

معايير القبول:
✓ MLflow UI: run مسجّل مع accuracy ≥ 95%
✓ Inference server: POST /v1/analyze/batch → response < 5ms
✓ Model Registry: نموذج في "Production" stage
```

### Sprint 3 (الأسبوع 3-5) — Phase B: XDR Correlation Engine
```
المهام:
[ ] 1. causality_builder.py: بناء causality chains تلقائياً
[ ] 2. event_stitcher.py: ربط أحداث من مصادر مختلفة
[ ] 3. risk_engine.py: Risk-Based Alerting (RBA) محرك كامل
[ ] 4. mitre_mapper.py: خريطة MITRE ATT&CK تلقائية
[ ] 5. incident API: POST /api/v1/incidents (create from chain)
[ ] 6. Dashboard: XDR Investigation View

معايير القبول:
✓ حدثان من نفس src_ip في 30 دقيقة → incident واحد مدمج
✓ Risk score تراكمي يُطلق تنبيهاً عند تجاوز 75 نقطة
✓ MITRE mapping: port scan → T1046
```

### Sprint 4 (الأسبوع 4-6) — Phase C: Threat Graph
```
المهام:
[ ] 1. ClickHouse graph tables: nodes + edges + materialized views
[ ] 2. graph_builder.py: بناء الـ graph من flows
[ ] 3. graph API: GET /api/v1/graph/neighbors/{ip}
[ ] 4. campaign_tracer.py: تتبع الحملات الهجومية
[ ] 5. Dashboard: Network Topology + Graph View

معايير القبول:
✓ IP جديد يظهر في الـ graph خلال < 10 ثوانٍ
✓ Graph query: neighbors depth=2 في < 500ms
```

### Sprint 5 (الأسبوع 5-7) — Phase D: ThorQL
```
المهام:
[ ] 1. thorql/grammar.py: Lark grammar كامل
[ ] 2. thorql/parser.py: AST builder
[ ] 3. thorql/transpiler.py: ThorQL → ClickHouse SQL
[ ] 4. thorql/executor.py: execution engine مع enrichment + SOAR
[ ] 5. saved_hunts.py: 10 hunts مدمجة
[ ] 6. Dashboard: ThorQL query builder UI

معايير القبول:
✓ "flows WHERE dst_port = 22 LAST 24h" → نتيجة من ClickHouse
✓ "| ALERT" → ينشئ تنبيهاً حقيقياً
✓ "| SOAR block_ip" → ينفذ SOAR playbook
```

### Sprint 6 (الأسبوع 6-8) — Phase E: UEBA Engine
```
المهام:
[ ] 1. behavioral_baseline.py: بناء baseline لكل entity
[ ] 2. anomaly_detector.py: IsolationForest + LSTM Autoencoder
[ ] 3. peer_grouping.py: K-Means clustering
[ ] 4. entity_scoring.py: cumulative risk score
[ ] 5. ueba_api.py: endpoints لـ UEBA data
[ ] 6. Dashboard: UEBA page

معايير القبول:
✓ Baseline يُبنى بعد 7 أيام من البيانات
✓ Anomaly detection: latency < 100ms
✓ UEBA page: قائمة entities مرتبة حسب risk
```

### Sprint 7 (الأسبوع 7-9) — Phase F+G: EDR + Cloud
```
المهام:
[ ] 1. linux_edr.rs: eBPF process + file monitoring
[ ] 2. process_tree.py: بناء شجرة العمليات
[ ] 3. aws_collector.py: CloudTrail + GuardDuty collector
[ ] 4. azure_collector.py: Azure Sentinel connector
[ ] 5. Dashboard: Process Tree + Cloud Events

معايير القبول:
✓ EDR يكتشف execve للـ python/bash
✓ CloudTrail events تصل لـ ClickHouse
```

### Sprint 8 (الأسبوع 8-11) — Phase I: Kubernetes
```
المهام:
[ ] 1. Helm chart كامل: agent DaemonSet + control-plane + ml + clickhouse + redis
[ ] 2. HPA: auto-scaling للـ control-plane
[ ] 3. NetworkPolicy: zero-trust pod isolation
[ ] 4. Terraform: AWS EKS module
[ ] 5. ArgoCD: GitOps pipeline
[ ] 6. GitHub Actions: CI/CD pipeline

معايير القبول:
✓ helm install thor-firewall ينجح على Kind/Minikube
✓ DaemonSet: pod يعمل على كل node
✓ GitHub push → ArgoCD deploy في < 5 دقائق
```

### Sprint 9 (الأسبوع 11-13) — Phase J: Compliance
```
المهام:
[ ] 1. auto_evaluator.py: تقييم SOC2 + ISO27001 + NCA-ECC تلقائي
[ ] 2. evidence_collector.py: جمع الأدلة من ClickHouse/Redis/logs
[ ] 3. report_engine.py: PDF reports (WeasyPrint)
[ ] 4. report_scheduler.py: جدولة تقارير أسبوعية تلقائية
[ ] 5. Dashboard: Compliance page

معايير القبول:
✓ GET /api/v1/compliance/soc2 → score > 80%
✓ PDF report يُولَّد في < 30 ثانية
```

### Sprint 10 (الأسبوع 12-15) — Phase K+L: Dashboard + Integrations
```
المهام:
[ ] 1. XDR Investigation View: attack timeline + causality chain
[ ] 2. Glass Table: drag-and-drop dashboard builder
[ ] 3. Process Tree visualization
[ ] 4. MITRE ATT&CK Coverage Heatmap
[ ] 5. Slack bot + Microsoft Teams webhook
[ ] 6. JIRA integration
[ ] 7. VirusTotal + Shodan connectors

معايير القبول:
✓ XDR View: incident مع causality chain مرئية
✓ Slack notification عند critical alert
✓ JIRA issue يُفتح تلقائياً عند incident
```

---

## 6. الملفات المطلوبة

### ملفات جديدة يجب إنشاؤها (مرتبة حسب الأولوية):

```
PRIORITY 1 — حرجة فورية:
├── ml/serving/inference_server.py          [FastAPI ML inference server]
├── configs/clickhouse/002_flows_schema.sql  [جداول ClickHouse الكاملة]
├── configs/clickhouse/003_threat_graph.sql  [graph nodes + edges]
├── ml/data/preprocess_cicids.py            [CICIDS2018 pipeline]
├── ml/training/train_marl_full.py          [MARL training مع MLflow]
├── ml/training/train_gnn_full.py           [GNN training]

PRIORITY 2 — XDR Core:
├── control-plane/src/xdr/causality_builder.py
├── control-plane/src/xdr/event_stitcher.py
├── control-plane/src/xdr/risk_engine.py
├── control-plane/src/xdr/mitre_mapper.py
├── control-plane/src/xdr/__init__.py

PRIORITY 3 — Threat Graph:
├── configs/clickhouse/004_graph_schema.sql
├── control-plane/src/routes/threat_graph.py
├── control-plane/src/services/graph_builder.py

PRIORITY 4 — ThorQL:
├── control-plane/src/thorql/grammar.py
├── control-plane/src/thorql/parser.py
├── control-plane/src/thorql/transpiler.py
├── control-plane/src/thorql/executor.py
├── control-plane/src/thorql/saved_hunts.py
├── control-plane/src/routes/query.py        [تعديل: ربط بـ ThorQL]

PRIORITY 5 — UEBA:
├── ml/ueba/behavioral_baseline.py           [تعديل: تنفيذ كامل]
├── ml/ueba/anomaly_detector.py              [تعديل: تنفيذ كامل]
├── ml/ueba/peer_grouping.py
├── ml/ueba/entity_scoring.py
├── control-plane/src/routes/ueba.py

PRIORITY 6 — Kubernetes:
├── helm/thor-firewall/Chart.yaml            [تعديل]
├── helm/thor-firewall/values.yaml           [تعديل]
├── helm/thor-firewall/templates/agent/daemonset.yaml [تعديل]
├── helm/thor-firewall/templates/control-plane/deployment.yaml [تعديل]
├── helm/thor-firewall/templates/ml-inference/deployment.yaml [جديد]
├── helm/thor-firewall/templates/hpa.yaml    [تعديل]
├── terraform/environments/production/main.tf [تعديل]
├── .github/workflows/ci.yml                 [تعديل]
├── .github/workflows/deploy.yml             [جديد]

PRIORITY 7 — Dashboard Pages:
├── dashboard/src/pages/XDRView/index.tsx    [جديد]
├── dashboard/src/pages/GlassTable/index.tsx [جديد]
├── dashboard/src/components/ProcessTree/index.tsx [جديد]
├── dashboard/src/components/MitreHeatmap/index.tsx [جديد]
├── dashboard/src/components/Timeline/AttackChain.tsx [تعديل]

PRIORITY 8 — Compliance:
├── control-plane/src/compliance/auto_evaluator.py [تعديل]
├── control-plane/src/compliance/evidence_collector.py [جديد]
├── control-plane/src/reporting/report_engine.py [تعديل]
├── control-plane/src/reporting/templates/soc2_report.html [تعديل]

PRIORITY 9 — Integrations:
├── control-plane/src/integrations/slack_bot.py
├── control-plane/src/integrations/jira_connector.py
├── control-plane/src/integrations/virustotal.py
├── control-plane/src/integrations/shodan_api.py
├── control-plane/src/integrations/aws_collector.py
├── control-plane/src/integrations/azure_collector.py
```

### ملفات تحتاج تعديلاً جوهرياً:

```
agent/src/rl_core.rs                   → استبدل stub بـ HTTP client حقيقي
agent/src/linux/xdp_loader.rs          → اربط بـ ring_consumer
control-plane/src/main.py              → أضف جميع الـ routers الجديدة
dashboard/src/App.tsx                  → أضف XDR + Glass Table + UEBA routes
docker-compose.yml                     → أضف mlflow + bentoml
```

---

## 7. KPIs ومعايير النجاح

### أداء النظام (مستوى عالمي):

| المقياس | الهدف | المرجع | طريقة القياس |
|---------|-------|--------|-------------|
| Packet Throughput (Linux XDP) | > 10 Mpps | Palo Alto PA-5450: 15 Mpps | pktgen benchmark |
| Packet Throughput (Windows WFP) | > 5 Mpps | Fortinet FG-3000F | custom tool |
| Per-packet Latency | < 100ns | Juniper SRX: 200ns | hardware timestamps |
| ML Inference Latency | < 1ms/batch(64) | N/A (our target) | Prometheus histogram |
| Detection Accuracy | > 99.5% | CrowdStrike: ~99% | CICIDS2018 test set |
| Zero-Day Detection | > 85% | Cortex XDR: ~80% | adversarial test set |
| False Positive Rate | < 0.1% | Enterprise standard | production monitoring |
| SOAR Response Time | < 5s (P95) | Splunk SOAR: ~10s | Prometheus |
| API Latency | < 100ms (P95) | Industry standard | Prometheus |
| Dashboard Load | < 2s | Google Lighthouse | Lighthouse CI |
| Uptime SLA | > 99.99% | Enterprise SLA | monitoring |

### جودة الكشف:

| نوع الهجوم | الهدف | المقاييس |
|-----------|-------|---------|
| Port Scan | 99.9% detection | < 1% FPR |
| DDoS (SYN Flood) | 99.99% detection (in kernel) | 0% FPR |
| Brute Force | 99.5% detection | < 0.5% FPR |
| C2 Beaconing | 95% detection | < 2% FPR |
| DNS Tunneling | 90% detection | < 1% FPR |
| Lateral Movement | 90% detection | < 1% FPR |
| Data Exfiltration | 85% detection | < 2% FPR |
| Zero-Day | > 80% detection | < 5% FPR |
| Insider Threat (UEBA) | > 85% detection | < 3% FPR |

### الامتثال:

| الإطار | الهدف | الملاحظة |
|-------|-------|---------|
| SOC 2 Type II | ≥ 95% | 16 controls تقييم تلقائي |
| ISO 27001:2022 | ≥ 92% | Annex A full coverage |
| NCA-ECC (سعودي) | ≥ 96% | الاعتماد السعودي |
| PCI-DSS v4.0 | ≥ 90% | للمؤسسات المالية |

### مؤشرات التوسع:

| المقياس | الهدف |
|---------|-------|
| Concurrent agents | > 10,000 |
| Events per second (ingestion) | > 1,000,000 |
| ClickHouse storage | > 10 billion rows |
| ThorQL query time (7 days data) | < 2 seconds |

---

## 8. تعليمات الخبير القادم

### 🚀 كيف تبدأ العمل — خطوة بخطوة

```bash
# الخطوة 1: استنساخ المستودع
git clone https://github.com/mhmsdfhwhegggggggg/Thor-Firewall.git
cd Thor-Firewall

# الخطوة 2: اقرأ هذا الملف كاملاً أولاً!
cat THOR_WORLD_CLASS_PLAN.md

# الخطوة 3: افهم الحالة الحالية
cat MASTER_ROADMAP.md  # الخارطة الأصلية

# الخطوة 4: تشغيل البيئة المحلية
cp .env.example .env  # أو أنشئ .env من القيم الافتراضية
docker-compose up -d clickhouse redis

# الخطوة 5: ابدأ بـ Sprint 1 (أهم الأشياء أولاً)
# ← ابدأ بإصلاح agent/src/rl_core.rs

# الخطوة 6: ابنِ ونشغّل inference server
cd ml && pip install -r requirements.txt
python -m serving.inference_server --port 8082

# الخطوة 7: ابنِ الـ agent
cd agent && cargo build --release

# الخطوة 8: شغّل الـ agent مع الـ ML server
./target/release/thor-agent \
  --ml-url http://localhost:8082 \
  --api-url http://localhost:8000 \
  --api-key dev_key \
  --batch-size 64
```

### 📌 أهم القواعد التي لا تُخرق

```
1. ابدأ دائماً من Sprint 1 — الـ stubs المكسورة تمنع كل شيء
2. كل نموذج ML → يجب أن يُسجَّل في MLflow قبل الـ deployment
3. كل تغيير في PolicyEngine → يجب أن يُوثَّق في Audit Trail
4. لا console.log في server code → استخدم req.log أو logger
5. الـ Rust code يجب أن يمر بـ cargo clippy -- -D warnings
6. كل endpoint جديد → يجب أن يُوثَّق في docs/api/openapi.yaml
7. كل feature جديدة → يجب أن تُكتَب tests لها أولاً (TDD)
8. لا secrets في الكود → env vars فقط
```

### 🗂️ خريطة الكود الأساسية

```
الجزء الأهم (ابدأ هنا):
├── agent/src/rl_core.rs           ← الجسر بين Rust وML — stubs تحتاج تنفيذ
├── ml/serving/inference_server.py ← ML server — يحتاج إنشاء من الصفر
├── control-plane/src/main.py      ← نقطة الدخول — أضف الـ routers الجديدة
├── dashboard/src/App.tsx          ← نقطة الدخول للـ UI

المكونات الجاهزة (لا تعدّل بدون فهم):
├── agent/src/packet_parser.rs     ✅ مكتمل 100%
├── agent/src/flow_manager.rs      ✅ مكتمل 100%
├── agent/src/rule_engine.rs       ✅ مكتمل 100%
├── control-plane/src/services/    ✅ threat_intel + soar + policy
├── ml/marl/                       ✅ architecture جاهزة — تحتاج تدريب
├── ml/gnn/                        ✅ architecture جاهزة — تحتاج تدريب

الجديد — يحتاج بناء من الصفر:
├── control-plane/src/xdr/         ❌ يجب إنشاء
├── control-plane/src/thorql/      ❌ يجب إنشاء
├── helm/                          ❌ يجب اكتمال
├── terraform/                     ❌ يجب اكتمال
```

### ⚡ أولويات المهام الحرجة (افعلها أولاً)

```
1. [CRITICAL] rl_core.rs → HTTP client حقيقي (بدونه: لا ML decisions)
2. [CRITICAL] inference_server.py → FastAPI server (بدونه: لا ML inference)
3. [CRITICAL] ClickHouse tables → migrations (بدونه: لا storage)
4. [HIGH] MARL training → دقة > 99% (بدونه: الـ ML لا يعمل بكفاءة)
5. [HIGH] XDR causality_builder.py (أهم ميزة تنافسية)
6. [HIGH] ThorQL backend (المحقق الأمني يحتاجه فوراً)
7. [MEDIUM] UEBA engine (للتهديدات الداخلية)
8. [MEDIUM] Kubernetes Helm charts (للنشر الإنتاجي)
9. [LOW] Cloud integration (يمكن تأجيله للمرحلة اللاحقة)
```

### 🔗 الروابط المرجعية للمطور

```
CICIDS2018 Dataset:
  https://www.unb.ca/cic/datasets/ids-2018.html
  https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/

MITRE ATT&CK Framework:
  https://attack.mitre.org/
  https://github.com/mitre-attack/attack-stix-data

eBPF/XDP Resources:
  https://docs.ebpf.io/
  https://www.kernel.org/doc/html/latest/bpf/index.html
  https://aya-rs.dev/book/

Aya (Rust eBPF):
  https://github.com/aya-rs/aya

Cortex XDR Docs:
  https://docs-cortex.paloaltonetworks.com/

CrowdStrike Falcon Docs:
  https://falcon.crowdstrike.com/documentation/

Splunk SPL Reference:
  https://docs.splunk.com/Documentation/Splunk/latest/SearchReference

PyTorch Geometric (GNN):
  https://pytorch-geometric.readthedocs.io/

STIX 2.1 Standard:
  https://oasis-open.github.io/cti-documentation/stix/intro
```

---

## 9. خلاصة المقارنة النهائية

### بعد تنفيذ هذه الخطة الكاملة، سيمتلك Thor:

| الميزة | Cortex XDR | CrowdStrike | Splunk | Thor (الهدف) |
|--------|-----------|-------------|--------|-------------|
| XDR Data Integration | ✅ | ⚠️ | ⚠️ | ✅ (Phase B) |
| Causality Chain / RCA | ✅ | ⚠️ | ❌ | ✅ (Phase B) |
| Threat Graph | ❌ | ✅ | ❌ | ✅ (Phase C) |
| Process Tree | ⚠️ | ✅ | ❌ | ✅ (Phase F) |
| UEBA | ✅ | ✅ | ✅ | ✅ (Phase E) |
| Query Language | ⚠️ | ❌ | ✅ SPL | ✅ ThorQL (Phase D) |
| SOAR Playbooks | ✅ | ✅ | ✅ | ✅ (موجود + توسيع) |
| Alert Correlation | ✅ | ✅ | ✅ | ✅ (Phase B) |
| Cloud Integration | ✅ | ✅ | ✅ | ✅ (Phase G) |
| Kernel-level Protection | ✅ | ✅ | ❌ | ✅ (eBPF/WFP موجود) |
| Compliance Automation | ⚠️ | ❌ | ⚠️ | ✅ (Phase J) |
| Open Source / On-Prem | ❌ | ❌ | ❌ | ✅ (ميزة حصرية!) |
| Arabic Language Support | ❌ | ❌ | ❌ | ✅ (ميزة حصرية!) |
| NCA-ECC Compliance | ❌ | ❌ | ❌ | ✅ (ميزة حصرية!) |

### 🏆 الميزة التنافسية الحاسمة لـ Thor:
1. **المصدر المفتوح** — لا vendor lock-in، يمكن للعملاء التخصيص
2. **On-Premise حقيقي** — لا سحابة إجبارية، مناسب للحكومات والبنوك
3. **دعم اللغة العربية** — LLM يشرح التهديدات بالعربية
4. **NCA-ECC Compliance** — الاعتماد السعودي الذي لا تمتلكه المنافسون
5. **السعر** — أرخص بكثير من Palo Alto/CrowdStrike/Splunk

---

*آخر تحديث: 2026-06-10*  
*الخبير الذي كتب هذه الخطة: Thor AI Architect*  
*للأسئلة والاستفسارات: راجع ARCHITECTURE.md + MASTER_ROADMAP.md*  
*ابدأ دائماً من Sprint 1 — لا تتخطاه!*
