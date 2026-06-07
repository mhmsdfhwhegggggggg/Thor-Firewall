# Contributing to Thor Firewall
# دليل المساهمة في نظام Thor Firewall

شكراً لاهتمامك بالمساهمة في Thor Firewall. هذا المشروع يهدف إلى بناء نظام جدار ناري عالمي المستوى، ومساهمتك قيّمة.

---

## 📋 قبل أن تبدأ

### قرأ أولاً
- [ARCHITECTURE.md](docs/architecture/ARCHITECTURE.md) — فهم الهندسة المعمارية
- [README.md](README.md) — نظرة عامة على المشروع
- [الخارطة الزمنية](README.md#خارطة-الطريق) — أين نحن الآن

### بيئة التطوير

**Linux (موصى به):**
```bash
# المتطلبات الأساسية
sudo apt-get install -y \
    curl git clang llvm libbpf-dev \
    linux-headers-$(uname -r) \
    python3.12 python3-pip

# Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
rustup component add clippy rustfmt

# Python
pip install uv
uv pip install -r ml/requirements.txt

# Pre-commit hooks
pip install pre-commit
pre-commit install
```

---

## 🔄 عملية المساهمة (Workflow)

### 1. Fork وClone
```bash
git clone https://github.com/<your-username>/thor-firewall.git
cd thor-firewall
git remote add upstream https://github.com/mhmsdfhwhegggggggg/Thor-Firewall.git
```

### 2. إنشاء فرع
```bash
# اتبع نمط التسمية:
git checkout -b feat/ebpf-connection-tracking    # ميزة جديدة
git checkout -b fix/syn-flood-false-positive     # إصلاح خطأ
git checkout -b perf/packet-parser-simd          # تحسين الأداء
git checkout -b docs/architecture-update         # توثيق
git checkout -b test/marl-unit-tests             # اختبارات
```

### 3. كتابة الكود

**قواعد Rust:**
- لا `unwrap()` في كود الإنتاج — استخدم `?` أو معالجة صريحة للأخطاء
- لا `expect()` في كود الإنتاج
- لا `panic!()` في كود الإنتاج
- كل دالة عامة يجب أن تحتوي على doc comment
- التعليقات باللغة الإنجليزية في الكود (للتوافق العالمي)

```bash
# تحقق قبل الإرسال
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test --all
```

**قواعد Python:**
- Type hints إلزامية في كل الدوال
- Docstrings للدوال العامة
- لا `print()` — استخدم `logging`

```bash
ruff check ml/ --fix
black ml/ control-plane/
mypy ml/ --strict
pytest ml/tests/ -v
```

### 4. الاختبارات

كل كود جديد **يجب** أن يكون مصحوباً باختبارات:

```bash
# اختبارات Rust
cargo test --all -- --test-threads=4

# اختبارات Python
pytest ml/tests/ control-plane/tests/ -v --cov

# Benchmarks (إذا كان التغيير يؤثر على الأداء)
cargo bench --package thor-agent
```

### 5. Commit

اتبع [Conventional Commits](https://conventionalcommits.org/):

```
feat(ebpf): add IPv6 flow tracking in XDP program
fix(marl): correct reward calculation for false positives
perf(parser): use SIMD for entropy calculation
docs(arch): update GNN architecture diagram
test(flow-manager): add tests for LRU eviction
chore(deps): bump tokio to 1.39
```

### 6. Pull Request

- املأ قالب PR بالكامل
- تأكد من اجتياز جميع CI checks
- اطلب مراجعة من أحد المساهمين الأساسيين

---

## 📐 معايير الجودة

### الأداء
أي تغيير يؤثر على مسار المعالجة الحرج (hot path) **يجب** أن يُثبت عدم انخفاض الأداء:

| المكوّن | الحد الأدنى المقبول |
|---------|-------------------|
| XDP packet processing | > 8M pps |
| PacketParser | < 75ns/packet |
| FlowManager lookup | < 200ns |
| RL inference (batch of 64) | < 5ms |

### الأمان
- لا secrets في الكود أبداً
- كل مدخلات المستخدم يجب التحقق منها
- استخدم `anyhow` أو `thiserror` للأخطاء، لا `panic!`
- مراجعة أمنية إضافية لأي تعديل على كود kernel

---

## 🏗️ هيكل المساهمات الشائعة

### إضافة برنامج eBPF جديد
1. أنشئ `kernel-modules/linux/ebpf/<name>.c`
2. أضف `#include "thor_common.h"` في البداية
3. أضف الهدف في `kernel-modules/linux/ebpf/Makefile`
4. أضف loader في `agent/src/linux/<name>_loader.rs`
5. أضف اختبارات في `tests/ebpf/`

### إضافة نموذج ML جديد
1. أنشئ الملف في `ml/<component>/`
2. أضف اختبارات في `ml/tests/`
3. وثّق الأداء في `docs/ml/`
4. أضف endpoint في control-plane إذا لزم

### إضافة API endpoint
1. أضف route في `control-plane/src/routes/`
2. أضف Pydantic models
3. أضف اختبارات في `control-plane/tests/`
4. وثّق في OpenAPI (يُولَّد تلقائياً)

---

## ❓ للأسئلة

- افتح Discussion في GitHub
- راسلنا على Discord (قريباً)
- اقرأ الوثائق في `docs/`

---

**"كل سطر كود يُكتب بجودة عالية هو خطوة نحو نظام عالمي حقيقي."**
