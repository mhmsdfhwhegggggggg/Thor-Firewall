# Thor Firewall — Integration Guide
# دليل التكامل الشامل لمنصة Thor الأمنية

## نظرة عامة

يصف هذا الدليل كيفية تشغيل وإدارة الأدوات الأمنية المدمجة في Thor Firewall:

| الأداة | الغرض | المنفذ الافتراضي |
|--------|--------|-----------------|
| Wazuh | XDR + SIEM | 55000 (API), 443 (Dashboard) |
| Elasticsearch + Kibana | تخزين وتحليل السجلات | 9200, 5601 |
| Logstash | معالجة وتوجيه السجلات | 5044, 5045 |
| TheHive | إدارة الحوادث والاستجابة | 9000 |
| Shuffle | أتمتة SOAR | 3001 |
| MISP | استخبارات التهديدات | 8081 |
| Suricata | كشف اختراق الشبكة (NIDS) | — (host network) |
| OSSEC | مراقبة سلامة الملفات (HIDS) | 1516 |
| Coraza WAF | حماية تطبيقات الويب | 8088, 8443 |
| Hayabusa | صيد التهديدات من سجلات Windows | — (on-demand) |

---

## المتطلبات الأساسية

```bash
# Ubuntu 22.04+
sudo apt update && sudo apt install -y docker.io docker-compose-plugin curl jq git make

# تفعيل Docker بدون sudo
sudo usermod -aG docker $USER && newgrp docker

# التحقق من المتطلبات
docker --version    # >= 24.0
docker compose version  # >= 2.20
```

---

## التشغيل السريع

```bash
# 1. استنساخ المستودع
git clone https://github.com/mhmsdfhwhegggggggg/Thor-Firewall.git
cd Thor-Firewall

# 2. إعداد ملف البيئة
cp .env.example .env
# عدّل .env حسب بيئتك (كلمات المرور، عناوين IP...)

# 3. تشغيل سكريبت التهيئة الشامل
bash scripts/integration_setup.sh

# أو يدوياً:
docker compose -f docker-compose.yml -f docker-compose.integrations.yml \
  --profile integration up -d
```

---

## تفاصيل التكامل

### 1. Wazuh + ELK Stack (الأولوية القصوى)

```
┌──────────────┐     Filebeat      ┌─────────────┐     ┌─────────┐
│ Wazuh Manager│ ──────────────▶  │  Logstash   │ ──▶ │  Kibana │
│  (SIEM/XDR)  │                  │  :5044/5045 │     │  :5601  │
└──────────────┘                  └─────────────┘     └─────────┘
       │                                │
       ▼                                ▼
  Wazuh Indexer                  Elasticsearch
  (OpenSearch)                      :9200
```

**إضافة Wazuh كـ data source في Kibana:**

```bash
# بعد بدء التشغيل
curl -X POST "http://localhost:5601/api/saved_objects/index-pattern" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  -u "elastic:${ELASTIC_PASSWORD}" \
  -d '{"attributes":{"title":"wazuh-alerts-*","timeFieldName":"@timestamp"}}'
```

**ملف Logstash Pipeline لاستقبال Wazuh alerts:**

الملف: `configs/logstash/pipeline/wazuh.conf`

```ruby
input {
  tcp {
    port => 5045
    codec => json_lines
    tags => ["wazuh"]
  }
}
filter {
  if "wazuh" in [tags] {
    date { match => ["timestamp", "ISO8601"] }
    mutate { add_field => { "thor_source" => "wazuh" } }
  }
}
output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    user => "elastic"
    password => "${ELASTIC_PASSWORD}"
    index => "wazuh-alerts-%{+YYYY.MM.dd}"
  }
}
```

---

### 2. Wazuh → TheHive (إرسال التنبيهات تلقائياً)

```
Wazuh Manager
     │
     │ (custom integration)
     ▼
TheHive :9000  ──▶  فريق الاستجابة
```

**تفعيل التكامل في Wazuh:**

```xml
<!-- أضف في /var/ossec/etc/ossec.conf داخل <ossec_config> -->
<integration>
  <name>custom-thehive</name>
  <level>7</level>   <!-- level 7+ فقط -->
  <alert_format>json</alert_format>
</integration>
```

السكريبت `custom-thehive` يُنشأ تلقائياً بواسطة `integration_setup.sh`.

**اختبار التكامل يدوياً:**

```bash
# محاكاة تنبيه Wazuh → TheHive
curl -X POST "http://localhost:9000/api/v1/alert" \
  -H "Authorization: Bearer ${THEHIVE_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "test",
    "source": "wazuh-manual-test",
    "sourceRef": "test-001",
    "title": "Test Alert from Wazuh",
    "severity": 2,
    "tags": ["test", "wazuh"]
  }'
```

---

### 3. MISP + Shuffle (تحديث التهديدات تلقائياً)

```
MISP (IoC feed)
     │
     │ Webhook → Shuffle workflow
     ▼
Shuffle Playbook:
  1. استقبال IoC جديد
  2. إرسال إلى Wazuh لإضافة rule
  3. حظر IP في Coraza WAF
  4. إنشاء تنبيه في TheHive
```

**إعداد Shuffle Workflow للحظر التلقائي:**

```bash
# استيراد workflow أساسي
curl -X POST "http://localhost:3001/api/v1/workflows/import" \
  -H "Authorization: Bearer ${SHUFFLE_API_KEY}" \
  -F "file=@configs/shuffle/workflow.json"
```

ملف `configs/shuffle/workflow.json` يحتوي على workflow أساسي.

---

### 4. Suricata (NIDS)

**التحقق من أن Suricata تعمل:**

```bash
# مشاهدة السجلات في الوقت الفعلي
docker compose exec suricata tail -f /var/log/suricata/fast.log

# تحديث قواعد Suricata (Emerging Threats)
docker compose exec suricata suricata-update
```

**ربط Suricata بـ Logstash:**

```bash
# تأكد أن eve.json يُرسل إلى Logstash
docker compose exec suricata bash -c \
  'echo "output:
  - eve-log:
      enabled: yes
      filetype: unix_stream
      filename: /tmp/suricata.sock" >> /etc/suricata/suricata.yaml'
```

---

### 5. Coraza WAF

**اختبار WAF:**

```bash
# طلب عادي - يجب أن يمر
curl http://localhost:8088/api/health

# هجوم SQL Injection محاكى - يجب أن يُحظر
curl "http://localhost:8088/api/search?q=1' OR '1'='1"
# المتوقع: HTTP 403

# هجوم XSS محاكى - يجب أن يُحظر
curl "http://localhost:8088/api/search?q=<script>alert(1)</script>"
# المتوقع: HTTP 403
```

---

### 6. Hayabusa (تحليل سجلات Windows)

```bash
# تشغيل تحليل على ملفات EVTX
mkdir -p hayabusa-data/evtx hayabusa-data/results

# ضع ملفات .evtx في hayabusa-data/evtx/
# ثم شغّل:
docker compose -f docker-compose.yml -f docker-compose.integrations.yml \
  --profile integration run hayabusa

# النتائج في: hayabusa-data/results/timeline.csv
```

---

## محاكاة هجوم بسيط (اختبار التكامل)

```bash
# 1. تثبيت أدوات الاختبار (على جهاز منفصل أو container)
docker run --rm --network thor-net alpine sh -c \
  "apk add --no-cache nmap && nmap -sV -O 172.30.0.1/24"

# 2. توقع رؤية:
#    - Suricata: تنبيه port scan في fast.log
#    - Wazuh: تنبيه level 6+ في /var/ossec/logs/alerts/alerts.json
#    - TheHive: case جديد تلقائياً (إذا level >= 7)
#    - Kibana: الأحداث في index wazuh-alerts-*

# 3. فحص النتائج
docker logs thor-suricata 2>&1 | grep -i "ET SCAN"
curl -s "http://localhost:9000/api/v1/alert" \
  -H "Authorization: Bearer ${THEHIVE_API_KEY}" | jq '.total'
```

---

## استكشاف الأخطاء

### الخدمة لا تبدأ

```bash
docker compose -f docker-compose.yml -f docker-compose.integrations.yml logs [service-name]
```

### Elasticsearch يرفض الاتصال

```bash
# تحقق من vm.max_map_count
sysctl vm.max_map_count
# إذا < 262144:
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

### Wazuh لا يرسل تنبيهات إلى TheHive

```bash
# تحقق من integration script
docker exec thor-wazuh ls -la /var/ossec/integrations/custom-thehive
docker exec thor-wazuh cat /var/ossec/logs/integrations.log
```

### إعادة تعيين كاملة

```bash
docker compose -f docker-compose.yml -f docker-compose.integrations.yml \
  --profile integration down -v
bash scripts/integration_setup.sh
```

---

## روابط مفيدة

- [Wazuh Documentation](https://documentation.wazuh.com)
- [TheHive Documentation](https://docs.thehive-project.org)
- [Shuffle Documentation](https://shuffler.io/docs)
- [Suricata Documentation](https://suricata.readthedocs.io)
- [Coraza WAF](https://coraza.io/docs)
- [Elasticsearch Guide](https://www.elastic.co/guide/en/elasticsearch/reference/current/index.html)
