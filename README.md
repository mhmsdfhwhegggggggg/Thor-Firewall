# 🔥 Thor Firewall — الحصن السيبراني من الجيل التالي

<div align="center">

![Thor Firewall](https://img.shields.io/badge/Thor%20Firewall-NGFW-red?style=for-the-badge&logo=shield&logoColor=white)
![Version](https://img.shields.io/badge/version-0.1.0--alpha-blue?style=for-the-badge)
![License](https://img.shields.io/badge/license-GPLv3-green?style=for-the-badge)
![Rust](https://img.shields.io/badge/Rust-1.79%2B-orange?style=for-the-badge&logo=rust)
![Python](https://img.shields.io/badge/Python-3.12%2B-blue?style=for-the-badge&logo=python)
![eBPF](https://img.shields.io/badge/eBPF-XDP-purple?style=for-the-badge)

**نظام جدار ناري من الجيل التالي (NGFW) يعمل على Linux و Windows**  
**مدعوم بذكاء اصطناعي هجين وسرعة فائقة تنافس أكبر الشركات العالمية**

[التوثيق](./docs) · [الهندسة المعمارية](./docs/architecture) · [تقرير الأداء](./docs/benchmarks) · [الإسهام](./CONTRIBUTING.md)

</div>

---

## 🎯 الرؤية

Thor Firewall ليس مجرد جدار ناري — إنه **نظام دفاع سيبراني حي** يفكر، يتعلم، ويتطور في الزمن الحقيقي. ثلاث ركائز تجعله فريدًا من نوعه:

| الركيزة | التقنية | الهدف |
|---------|---------|-------|
| ⚡ **السرعة الفائقة** | eBPF/XDP (Linux) · WFP Driver (Windows) | > 10M حزمة/ثانية · < 100ns زمن وصول |
| 🧠 **الذكاء الهجين** | MARL + GNN + LLM (LoRA Fine-tuned) | 99.5% دقة · 85% كشف Zero-day |
| 🛡️ **التحصين الذاتي** | Syscall hooks · Memory encryption · Binary integrity | صفر توقف · استرداد تلقائي |

---

## 🏗️ الهندسة المعمارية العامة

```
┌─────────────────────────────────────────────────────────────────┐
│                        Thor Firewall                            │
│                                                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │  Kernel Layer│    │  Agent Layer │    │  Intelligence    │  │
│  │              │    │              │    │  Layer           │  │
│  │  eBPF/XDP    │◄──►│  Rust Agent  │◄──►│  MARL Engine     │  │
│  │  WFP Driver  │    │  Flow Mgr    │    │  GNN Analyzer    │  │
│  │  XDP Maps    │    │  RL Core     │    │  LLM Explainer   │  │
│  └──────────────┘    └──────────────┘    └──────────────────┘  │
│           │                  │                     │            │
│           └──────────────────┼─────────────────────┘            │
│                              ▼                                  │
│                   ┌──────────────────┐                          │
│                   │  Control Plane   │                          │
│                   │  (FastAPI/gRPC)  │                          │
│                   └────────┬─────────┘                          │
│                            │                                    │
│              ┌─────────────┼─────────────┐                     │
│              ▼             ▼             ▼                     │
│          [Redis]      [ClickHouse]   [Dashboard]               │
│          State          Analytics     React/TS                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📁 هيكل المشروع

```
thor-firewall/
├── .github/                    # CI/CD، قوالب، CodeQL، Dependabot
│   ├── workflows/              # GitHub Actions
│   └── ISSUE_TEMPLATE/         # قوالب التقارير
├── docs/                       # التوثيق الشامل
│   ├── architecture/           # مخططات UML والهندسة المعمارية
│   ├── api/                    # OpenAPI/gRPC specs
│   └── threat-intelligence/    # قاعدة معرفة التهديدات
├── kernel-modules/             # كود النواة
│   ├── linux/ebpf/             # برامج eBPF/XDP بلغة C
│   └── windows/wfp/            # WFP Driver بلغة Rust
├── agent/                      # العميل الموحد (Rust)
│   └── src/
│       ├── packet_parser.rs    # محلل الحزم فائق السرعة (SIMD)
│       ├── flow_manager.rs     # إدارة تدفقات الشبكة
│       ├── rl_core.rs          # نواة التعلم المعزز
│       ├── linux/              # واجهة eBPF
│       └── windows/            # واجهة WFP
├── ml/                         # نظام الذكاء الاصطناعي (Python)
│   ├── marl/                   # Multi-Agent Reinforcement Learning
│   ├── gnn/                    # Graph Neural Networks
│   ├── llm/                    # LLM مع LoRA Fine-tuning
│   └── training/               # بنية التدريب الموزع
├── control-plane/              # FastAPI backend
├── dashboard/                  # React + TypeScript frontend
├── scripts/                    # أدوات التطوير والنشر
└── tests/                      # اختبارات شاملة
```

---

## 🚀 البدء السريع

### المتطلبات

**Linux (eBPF/XDP):**
```bash
# Ubuntu/Debian
sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r)
cargo install bpf-linker

# التحقق من دعم eBPF
uname -r  # يجب أن يكون >= 5.15
```

**Windows (WFP Driver):**
```powershell
# تثبيت Windows Driver Kit (WDK)
winget install Microsoft.WindowsDriverKit
cargo install cargo-make
```

**Python (ML):**
```bash
pip install -r ml/requirements.txt
# أو باستخدام uv (موصى به)
uv pip install -r ml/requirements.txt
```

### البناء

```bash
# بناء العميل (Linux)
cargo build --release --package thor-agent

# بناء برامج eBPF
cd kernel-modules/linux/ebpf && make

# بناء لوحة التحكم
cd dashboard && pnpm install && pnpm build

# تشغيل control plane
cd control-plane && uvicorn src.main:app --host 0.0.0.0 --port 8080
```

---

## 📊 مقاييس الأداء المستهدفة

| المقياس | القيمة المستهدفة | الوضع الحالي |
|---------|----------------|-------------|
| الإنتاجية (Linux XDP) | 10 Mpps | 🔄 قيد التطوير |
| الإنتاجية (Windows WFP) | 5 Mpps | 🔄 قيد التطوير |
| زمن الوصول (Linux) | < 100 ns | 🔄 قيد التطوير |
| زمن الوصول (Windows) | < 500 ns | 🔄 قيد التطوير |
| دقة كشف الهجمات المعروفة | 99.5% | 🔄 قيد التطوير |
| كشف Zero-day | 85% | 🔄 قيد التطوير |
| إيجابيات كاذبة | < 0.1% | 🔄 قيد التطوير |
| استهلاك الذاكرة | < 1GB/M تدفق | 🔄 قيد التطوير |

---

## 🗺️ خارطة الطريق

- [x] **المرحلة 0** (الأشهر 1-3): البنية التحتية وإعداد CI/CD
- [ ] **المرحلة 1** (الأشهر 4-9): نواة eBPF/WFP فائقة السرعة
- [ ] **المرحلة 2** (الأشهر 10-18): نظام الذكاء الاصطناعي (MARL + GNN + LLM)
- [ ] **المرحلة 3** (الأشهر 19-24): التحصين الذاتي
- [ ] **المرحلة 4** (الأشهر 25-28): لوحة التحكم والتحليلات
- [ ] **المرحلة 5** (الأشهر 29-36): الاختبارات والمقاييس العالمية
- [ ] **المرحلة 6** (الأشهر 37-48): النشر التجاري والمجتمعي

---

## 🤝 المساهمة

نرحب بكل مساهمة! اقرأ [CONTRIBUTING.md](./CONTRIBUTING.md) قبل البدء.

---

## 📄 الترخيص

Thor Firewall مرخص بموجب [GPLv3](./LICENSE) للاستخدام مفتوح المصدر.  
للاستخدام المؤسسي، تواصل معنا للحصول على ترخيص تجاري.

---

<div align="center">

**"نظام عالمي حقيقي ينافس أكبر الشركات — أو نفنى دون ذلك"**

</div>
