// Thor Firewall — Common Definitions
// تعريفات مشتركة بين kernel space و user space
//
// SPDX-License-Identifier: GPL-2.0

#pragma once

#include <linux/types.h>

// ========================================================================
// Constants — الثوابت
// ========================================================================

#define THOR_MAX_FLOWS       (1 << 20)   // 1M تدفق
#define THOR_RINGBUF_SIZE    (64 << 20)  // 64MB ring buffer
#define THOR_BLACKLIST_MAX   (1 << 16)   // 65536 شبكة
#define THOR_WHITELIST_MAX   (1 << 12)   // 4096 شبكة
#define THOR_SAMPLE_RATE     100         // إرسال عينة كل 100 حزمة
#define THOR_STATS_MAX       32
#define THOR_CONFIG_MAX      16

// ========================================================================
// Action Codes — رموز القرارات
// ========================================================================

#define THOR_ACTION_PASS     0   // السماح بمرور الحزمة
#define THOR_ACTION_DROP     1   // حظر الحزمة
#define THOR_ACTION_SAMPLE   2   // السماح + إرسال عينة لـ ML
#define THOR_ACTION_REDIR    3   // إعادة توجيه (honeypot)
#define THOR_ACTION_THROTTLE 4   // تقليل معدل الحزم

// ========================================================================
// Statistics Indices — مؤشرات الإحصاءات
// ========================================================================

#define THOR_STAT_TOTAL      0   // إجمالي الحزم المعالجة
#define THOR_STAT_DROPPED    1   // الحزم المحظورة
#define THOR_STAT_WHITELIST  2   // السماح بسبب whitelist
#define THOR_STAT_BLACKLIST  3   // الحظر بسبب blacklist
#define THOR_STAT_SYN_FLOOD  4   // الحظر بسبب SYN flood
#define THOR_STAT_NEW_FLOWS  5   // تدفقات جديدة
#define THOR_STAT_MALFORMED  6   // حزم مشوهة

// ========================================================================
// Config Keys — مفاتيح الإعدادات
// ========================================================================

#define THOR_CONFIG_SYN_LIMIT    0  // الحد الأقصى لـ SYN/s
#define THOR_CONFIG_SAMPLE_RATE  1  // معدل أخذ العينات
#define THOR_CONFIG_MODE         2  // وضع التشغيل

// ========================================================================
// Sample Reasons — أسباب إرسال العينات
// ========================================================================

#define SAMPLE_REASON_NEW_FLOW   0  // تدفق جديد
#define SAMPLE_REASON_PERIODIC   1  // عينة دورية
#define SAMPLE_REASON_SYN_FLOOD  2  // محاولة SYN flood
#define SAMPLE_REASON_ANOMALY    3  // شذوذ مكتشف
#define SAMPLE_REASON_HIGH_RISK  4  // درجة خطر عالية

// ========================================================================
// Data Structures — هياكل البيانات
// ========================================================================

/// مفتاح التدفق (5-tuple)
struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 sport;
    __u16 dport;
    __u8  proto;
    __u8  is_ipv6;
    __u8  pad[2];   // محاذاة 8 بايت
} __attribute__((packed));

/// حالة التدفق المحفوظة في BPF map
struct flow_state {
    __u8  action;         // THOR_ACTION_*
    __u8  flags;          // أعلام إضافية
    __u16 pad;
    __u32 packets;        // عدد الحزم
    __u64 bytes;          // إجمالي البايتات
    __u64 first_seen_ns;  // أول حزمة (نانوثانية)
    __u64 last_seen_ns;   // آخر حزمة
    __u32 risk_score_x100; // نقاط الخطر × 100 (بدون float)
} __attribute__((packed));

/// عداد SYN لكشف الفيضان
struct syn_counter {
    __u32 count;
    __u64 window_start_ns;
} __attribute__((packed));

/// عينة حزمة مرسلة إلى user-space
struct packet_sample {
    struct flow_key flow_key;
    __u64 timestamp_ns;
    __u16 pkt_len;
    __u8  reason;        // SAMPLE_REASON_*
    __u8  tcp_flags;
    __u32 risk_score_x100;
} __attribute__((packed));

/// مفتاح LPM Trie لـ blacklist/whitelist
struct lpm_key {
    __u32 prefixlen;
    __u32 ip;
} __attribute__((packed));

/// رأس VLAN
struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};
