// Thor Firewall — Stateful Rule Engine
// محرك القواعد ذو الحالة
//
// يُنفّذ:
//   - تقييم سلاسل القواعد (Chains) بترتيب الأولوية
//   - مطابقة CIDR، المنافذ، البروتوكولات
//   - قواعد مع انتهاء صلاحية (TTL)
//   - قواعد تُفعَّل بعد عتبة (rate-based rules)
//   - تكامل مع BPF maps للتطبيق الفوري
//
// SPDX-License-Identifier: MIT

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use ipnet::Ipv4Net;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::flow_manager::Decision;
use crate::packet_parser::PacketMeta;

// ============================================================================
// Rule Definition
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub rule_id:    String,
    pub name:       String,
    pub description: Option<String>,

    // Match conditions (None = match any)
    pub src_cidr:  Option<Ipv4Net>,
    pub dst_cidr:  Option<Ipv4Net>,
    pub src_port:  Option<PortMatch>,
    pub dst_port:  Option<PortMatch>,
    pub protocol:  Option<u8>,      // 6=TCP, 17=UDP, 1=ICMP
    pub tcp_flags: Option<TcpFlagMatch>,

    // Action
    pub action:    RuleAction,
    pub priority:  i32,       // أعلى رقم = أعلى أولوية
    pub is_active: bool,

    // Rate-based trigger
    pub rate_match: Option<RateMatch>,

    // Lifecycle
    pub created_at: u64,      // Unix timestamp
    pub expires_at: Option<u64>,

    // Statistics
    pub hit_count:  u64,
    pub last_hit:   Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PortMatch {
    Single(u16),
    Range(u16, u16),
    List(Vec<u16>),
}

impl PortMatch {
    pub fn matches(&self, port: u16) -> bool {
        match self {
            Self::Single(p)    => *p == port,
            Self::Range(lo, hi) => port >= *lo && port <= *hi,
            Self::List(ports)  => ports.contains(&port),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpFlagMatch {
    pub mask:  u8,  // أقنعة الأعلام المعنية
    pub value: u8,  // القيمة المطلوبة
}

impl TcpFlagMatch {
    pub fn matches(&self, flags: u8) -> bool {
        (flags & self.mask) == self.value
    }

    /// SYN فقط (لا ACK)
    pub fn syn_only() -> Self {
        Self { mask: 0x12, value: 0x02 }
    }

    /// RST
    pub fn rst() -> Self {
        Self { mask: 0x04, value: 0x04 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateMatch {
    pub threshold:   u64,    // حد الحزم في النافذة
    pub window_secs: u64,    // حجم نافذة القياس
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RuleAction {
    Allow,
    Block,
    Throttle { rate_pps: u32 },
    Mirror,
    Log,     // تسجيل فقط، لا إجراء
}

impl From<RuleAction> for Decision {
    fn from(action: RuleAction) -> Self {
        match action {
            RuleAction::Allow              => Decision::Allow,
            RuleAction::Block              => Decision::Block,
            RuleAction::Throttle { .. }    => Decision::Throttle,
            RuleAction::Mirror             => Decision::Mirror,
            RuleAction::Log                => Decision::Allow,
        }
    }
}

// ============================================================================
// Rule Chain
// ============================================================================

#[derive(Debug, Clone)]
pub struct RuleChain {
    /// القواعد مرتبة تنازلياً حسب الأولوية
    rules: Vec<FirewallRule>,
}

impl RuleChain {
    pub fn new() -> Self {
        Self { rules: vec![] }
    }

    pub fn insert(&mut self, rule: FirewallRule) {
        let pos = self.rules.partition_point(|r| r.priority > rule.priority);
        self.rules.insert(pos, rule);
    }

    pub fn remove(&mut self, rule_id: &str) -> bool {
        let before = self.rules.len();
        self.rules.retain(|r| r.rule_id != rule_id);
        self.rules.len() < before
    }

    pub fn get_active(&self) -> impl Iterator<Item = &FirewallRule> {
        let now = unix_now();
        self.rules.iter().filter(move |r| {
            r.is_active &&
            r.expires_at.map_or(true, |exp| exp > now)
        })
    }
}

// ============================================================================
// Rule Engine
// ============================================================================

pub struct RuleEngine {
    chain: RwLock<RuleChain>,
    /// عدادات معدل لكل (rule_id, src_ip)
    rate_counters: RwLock<HashMap<String, RateCounter>>,
}

struct RateCounter {
    count:       u64,
    window_start: Instant,
    window_secs:  u64,
}

impl RateCounter {
    fn increment(&mut self) -> u64 {
        let now = Instant::now();
        if now.duration_since(self.window_start).as_secs() >= self.window_secs {
            self.count = 1;
            self.window_start = now;
        } else {
            self.count += 1;
        }
        self.count
    }
}

impl RuleEngine {
    pub fn new() -> Self {
        Self {
            chain: RwLock::new(RuleChain::new()),
            rate_counters: RwLock::new(HashMap::new()),
        }
    }

    /// تقييم القواعد على حزمة واحدة
    /// يُعيد None إذا لم تنطبق أي قاعدة (→ يُحال للـ ML)
    pub fn evaluate(&self, meta: &PacketMeta) -> Option<Decision> {
        let chain = self.chain.read();

        for rule in chain.get_active() {
            if self.matches_rule(rule, meta) {
                // تحديث الإحصاءات (لا نحتاج write lock كاملة)
                debug!(
                    rule_id = %rule.rule_id,
                    rule_name = %rule.name,
                    src = ?meta.src_ip,
                    dst = ?meta.dst_ip,
                    "Rule matched"
                );

                return Some(rule.action.clone().into());
            }
        }

        None
    }

    /// فحص هل الحزمة تطابق القاعدة
    fn matches_rule(&self, rule: &FirewallRule, meta: &PacketMeta) -> bool {
        // CIDR source
        if let Some(ref cidr) = rule.src_cidr {
            let src = Ipv4Addr::from(meta.src_ip);
            if !cidr.contains(&src) {
                return false;
            }
        }

        // CIDR destination
        if let Some(ref cidr) = rule.dst_cidr {
            let dst = Ipv4Addr::from(meta.dst_ip);
            if !cidr.contains(&dst) {
                return false;
            }
        }

        // Protocol
        if let Some(proto) = rule.protocol {
            if meta.proto != proto {
                return false;
            }
        }

        // Source port
        if let Some(ref pm) = rule.src_port {
            if !pm.matches(meta.sport) {
                return false;
            }
        }

        // Destination port
        if let Some(ref pm) = rule.dst_port {
            if !pm.matches(meta.dport) {
                return false;
            }
        }

        // TCP flags
        if let Some(ref fm) = rule.tcp_flags {
            if !fm.matches(meta.tcp_flags) {
                return false;
            }
        }

        // Rate-based check
        if let Some(ref rate) = rule.rate_match {
            let key = format!("{}-{}", rule.rule_id, meta.src_ip);
            let mut counters = self.rate_counters.write();
            let counter = counters.entry(key).or_insert_with(|| RateCounter {
                count: 0,
                window_start: Instant::now(),
                window_secs: rate.window_secs,
            });
            let count = counter.increment();
            if count < rate.threshold {
                return false;
            }
        }

        true
    }

    // ============================================================================
    // Rule Management API
    // ============================================================================

    pub fn add_rule(&self, rule: FirewallRule) -> String {
        let id = rule.rule_id.clone();
        info!(rule_id = %id, name = %rule.name, action = ?rule.action, "Adding firewall rule");
        self.chain.write().insert(rule);
        id
    }

    pub fn remove_rule(&self, rule_id: &str) -> bool {
        let removed = self.chain.write().remove(rule_id);
        if removed {
            info!(rule_id = %rule_id, "Firewall rule removed");
        }
        removed
    }

    pub fn toggle_rule(&self, rule_id: &str) -> bool {
        let mut chain = self.chain.write();
        if let Some(rule) = chain.rules.iter_mut().find(|r| r.rule_id == rule_id) {
            rule.is_active = !rule.is_active;
            info!(rule_id = %rule_id, active = rule.is_active, "Rule toggled");
            return true;
        }
        false
    }

    pub fn list_rules(&self) -> Vec<FirewallRule> {
        self.chain.read().rules.clone()
    }

    pub fn rule_count(&self) -> usize {
        self.chain.read().rules.len()
    }

    /// تنظيف القواعد المنتهية
    pub fn evict_expired(&self) -> usize {
        let now = unix_now();
        let mut chain = self.chain.write();
        let before = chain.rules.len();
        chain.rules.retain(|r| r.expires_at.map_or(true, |exp| exp > now));
        let removed = before - chain.rules.len();
        if removed > 0 {
            info!(removed, "Evicted expired firewall rules");
        }
        removed
    }

    // ============================================================================
    // Preset Rules
    // ============================================================================

    /// تحميل القواعد الافتراضية لأمن الشبكة
    pub fn load_default_rules(&self) {
        let rules = vec![
            // حظر محاولات الوصول لقواعد البيانات من الخارج
            FirewallRule {
                rule_id:    Uuid::new_v4().to_string(),
                name:       "Block external DB access".to_string(),
                description: Some("Block MySQL, PostgreSQL, Redis, MongoDB from internet".to_string()),
                src_cidr:  None,
                dst_cidr:  None,
                src_port:  None,
                dst_port:  Some(PortMatch::List(vec![1433, 3306, 5432, 6379, 27017, 9200, 11211])),
                protocol:  Some(6),
                tcp_flags: None,
                action:    RuleAction::Block,
                priority:  1000,
                is_active: true,
                rate_match: None,
                created_at: unix_now(),
                expires_at: None,
                hit_count:  0,
                last_hit:   None,
            },
            // حظر Docker API من الخارج
            FirewallRule {
                rule_id:    Uuid::new_v4().to_string(),
                name:       "Block Docker API external".to_string(),
                description: Some("Block Docker daemon API port".to_string()),
                src_cidr:  None,
                dst_cidr:  None,
                src_port:  None,
                dst_port:  Some(PortMatch::List(vec![2375, 2376, 2377])),
                protocol:  Some(6),
                tcp_flags: None,
                action:    RuleAction::Block,
                priority:  950,
                is_active: true,
                rate_match: None,
                created_at: unix_now(),
                expires_at: None,
                hit_count:  0,
                last_hit:   None,
            },
            // تسجيل محاولات SSH
            FirewallRule {
                rule_id:    Uuid::new_v4().to_string(),
                name:       "Log SSH attempts".to_string(),
                description: Some("Log all SSH connection attempts for monitoring".to_string()),
                src_cidr:  None,
                dst_cidr:  None,
                src_port:  None,
                dst_port:  Some(PortMatch::Single(22)),
                protocol:  Some(6),
                tcp_flags: Some(TcpFlagMatch::syn_only()),
                action:    RuleAction::Log,
                priority:  100,
                is_active: true,
                rate_match: None,
                created_at: unix_now(),
                expires_at: None,
                hit_count:  0,
                last_hit:   None,
            },
        ];

        for rule in rules {
            self.add_rule(rule);
        }

        info!("Default security rules loaded ({})", self.rule_count());
    }
}

// ============================================================================

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
