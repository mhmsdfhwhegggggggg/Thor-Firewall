# درع المستقبل - Thor Firewall
**جيل جديد من جدران الحماية الذكية المدعومة بالتعلم المعزز والنماذج اللغوية الكبيرة**

## الرؤية
نظام أمني موحد يعمل على Linux و Windows بسرعة استثنائية وذكاء تكيفي، ينافس كبرى الشركات العالمية.

## الميزات الرئيسية
- 🚀 **سرعة فائقة**: Linux (eBPF/XDP) + Windows (WFP)
- 🧠 **ذكاء تكيفي**: Multi-Agent Reinforcement Learning
- 🧬 **فهم سياقي**: Local LLM + RAG لهجمات اليوم صفر
- 🔒 **تحصين ذاتي**: حماية ضد هجمات BYOVD و Syscall hooking
- 🌍 **متعدد المنصات**: نفس الكود الأساسي بلغة Rust

## الهيكل
- `kernel-modules/`: وحدات النواة (Linux eBPF / Windows WFP)
- `agent-core/`: الوكيل الموحد بلغة Rust
- `control-plane/`: العقل المفكر (RL, LLM, dashboard)
- `scripts/`: أدوات التثبيت والاختبار
- `tests/`: اختبارات متكاملة

## متطلبات البناء
- Rust (latest)
- LLVM/clang (لـ eBPF)
- Visual Studio + WDK (لـ Windows)
- Python 3.10+ (للـ control-plane)

## البدء السريع (Linux)
```bash
git clone https://github.com/yourname/Thor-Firewall.git
cd Thor-Firewall
./scripts/install_linux.sh
cargo run --bin thor-agent
```

## البدء السريع (Windows)
```powershell
.\scripts\install_windows.ps1
cargo run --bin thor-agent
```

## المساهمة
نرحب بأي خبير في eBPF, WFP, Rust, RL, LLM. راجع CONTRIBUTING.md

## الترخيص
GPLv3 أو Apache 2.0 (مفتوح المصدر للتطوير الأكاديمي والتجاري)
