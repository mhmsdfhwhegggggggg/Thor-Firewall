// Thor Firewall — XDP Main Program
// برنامج XDP الرئيسي — المرحلة الأولى من الفلترة
//
// يعمل في مساحة النواة (kernel space) بأقصى سرعة ممكنة
// الهدف: معالجة > 10M حزمة/ثانية مع زمن < 100ns
//
// الترجمة:
//   clang -O2 -target bpf -D__TARGET_ARCH_x86 -I./headers \
//     -c xdp_main.c -o xdp_main.o
//
// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include "thor_common.h"

// ========================================================================
// BPF Maps — هياكل البيانات المشتركة مع user-space
// ========================================================================

/// جدول حالة التدفقات (Flow State Table)
/// يحتوي على قرار كل تدفق معروف
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, THOR_MAX_FLOWS);
    __type(key, struct flow_key);
    __type(value, struct flow_state);
} flow_table SEC(".maps");

/// عداد SYN لكل IP مصدر (للكشف عن SYN flood)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 1 << 16); // 65536 IPs
    __type(key, __u32);           // IPv4 src
    __type(value, struct syn_counter);
} syn_counters SEC(".maps");

/// Ring buffer لإرسال العينات إلى user-space بدون حذف
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, THOR_RINGBUF_SIZE); // 64MB
} sample_ringbuf SEC(".maps");

/// إحصاءات عامة (لوحة التحكم)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, THOR_STATS_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

/// قائمة الحظر السريع (IP blacklist) — O(1) lookup
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, THOR_BLACKLIST_MAX);
    __type(key, struct lpm_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} blacklist SEC(".maps");

/// قائمة السماح السريعة (IP whitelist) — bypass كل الفلترة
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, THOR_WHITELIST_MAX);
    __type(key, struct lpm_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} whitelist SEC(".maps");

/// إعدادات قابلة للتعديل في الزمن الحقيقي
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, THOR_CONFIG_MAX);
    __type(key, __u32);
    __type(value, __u64);
} config_map SEC(".maps");

// ========================================================================
// Helper Functions — دوال مساعدة مضمّنة
// ========================================================================

/// تحديث إحصاء معين
static __always_inline void inc_stat(__u32 idx) {
    __u64 *val = bpf_map_lookup_elem(&stats_map, &idx);
    if (val)
        __sync_fetch_and_add(val, 1);
}

/// التحقق من blacklist (IPv4)
static __always_inline int is_blacklisted(__u32 src_ip) {
    struct lpm_key key = {
        .prefixlen = 32,
        .ip = src_ip,
    };
    return bpf_map_lookup_elem(&blacklist, &key) != NULL;
}

/// التحقق من whitelist (IPv4)
static __always_inline int is_whitelisted(__u32 src_ip) {
    struct lpm_key key = {
        .prefixlen = 32,
        .ip = src_ip,
    };
    return bpf_map_lookup_elem(&whitelist, &key) != NULL;
}

/// إرسال عينة إلى user-space عبر ring buffer
static __always_inline void send_sample(
    struct xdp_md *ctx,
    struct flow_key *key,
    __u16 pkt_len,
    __u8 reason
) {
    struct packet_sample *sample;
    sample = bpf_ringbuf_reserve(&sample_ringbuf, sizeof(*sample), 0);
    if (!sample)
        return;

    sample->flow_key = *key;
    sample->timestamp_ns = bpf_ktime_get_ns();
    sample->pkt_len = pkt_len;
    sample->reason = reason;

    bpf_ringbuf_submit(sample, 0);
}

// ========================================================================
// SYN Flood Detection — كشف هجمات SYN flood
// ========================================================================

/// التحقق مما إذا كان IP يرسل SYN packets بمعدل مفرط
/// يُعيد 1 إذا تجاوز الحد المسموح به
static __always_inline int check_syn_rate(__u32 src_ip) {
    struct syn_counter *cnt;
    struct syn_counter new_cnt = {};
    __u64 now = bpf_ktime_get_ns();
    __u64 *syn_limit_ptr;
    __u32 config_key = THOR_CONFIG_SYN_LIMIT;
    __u64 syn_limit = 1000; // default: 1000 SYN/s

    syn_limit_ptr = bpf_map_lookup_elem(&config_map, &config_key);
    if (syn_limit_ptr)
        syn_limit = *syn_limit_ptr;

    cnt = bpf_map_lookup_elem(&syn_counters, &src_ip);
    if (!cnt) {
        new_cnt.count = 1;
        new_cnt.window_start_ns = now;
        bpf_map_update_elem(&syn_counters, &src_ip, &new_cnt, BPF_ANY);
        return 0;
    }

    // إعادة تعيين النافذة كل ثانية
    if (now - cnt->window_start_ns > 1000000000ULL) {
        cnt->count = 1;
        cnt->window_start_ns = now;
        return 0;
    }

    __sync_fetch_and_add(&cnt->count, 1);

    if (cnt->count > syn_limit) {
        inc_stat(THOR_STAT_SYN_FLOOD);
        return 1; // تجاوز الحد
    }

    return 0;
}

// ========================================================================
// Packet Parser — محلل الحزم داخل النواة
// ========================================================================

/// استخراج Flow Key من حزمة Ethernet
/// يُعيد XDP_ABORTED في حالة وجود حزمة مشوهة
static __always_inline int parse_packet(
    struct xdp_md *ctx,
    struct flow_key *key,
    __u8 *tcp_flags,
    __u16 *pkt_len
) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    *pkt_len = data_end - data;

    // ===== Ethernet Header =====
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_ABORTED;

    __u16 eth_type = bpf_ntohs(eth->h_proto);

    // تخطي VLAN tags
    if (eth_type == ETH_P_8021Q) {
        struct vlan_hdr *vlan = (void *)(eth + 1);
        if ((void *)(vlan + 1) > data_end)
            return XDP_ABORTED;
        eth_type = bpf_ntohs(vlan->h_vlan_encapsulated_proto);
        data += sizeof(struct vlan_hdr);
    }

    // نتعامل فقط مع IPv4 و IPv6
    if (eth_type != ETH_P_IP && eth_type != ETH_P_IPV6)
        return XDP_PASS; // PASS غير IP traffic

    // ===== IPv4 Header =====
    if (eth_type == ETH_P_IP) {
        struct iphdr *ip = data + sizeof(struct ethhdr);
        if ((void *)(ip + 1) > data_end)
            return XDP_ABORTED;

        key->src_ip = ip->saddr;
        key->dst_ip = ip->daddr;
        key->proto = ip->protocol;
        key->is_ipv6 = 0;

        __u8 ihl = ip->ihl * 4;
        void *l4 = (void *)ip + ihl;

        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = l4;
            if ((void *)(tcp + 1) > data_end)
                return XDP_ABORTED;
            key->sport = bpf_ntohs(tcp->source);
            key->dport = bpf_ntohs(tcp->dest);
            *tcp_flags = ((__u8 *)tcp)[13]; // TCP flags byte
        } else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = l4;
            if ((void *)(udp + 1) > data_end)
                return XDP_ABORTED;
            key->sport = bpf_ntohs(udp->source);
            key->dport = bpf_ntohs(udp->dest);
        } else {
            key->sport = 0;
            key->dport = 0;
        }
    }

    return 0; // نجاح
}

// ========================================================================
// XDP Main Program — نقطة الدخول الرئيسية
// ========================================================================

SEC("xdp")
int thor_xdp_main(struct xdp_md *ctx)
{
    struct flow_key key = {};
    __u8 tcp_flags = 0;
    __u16 pkt_len = 0;
    int parse_ret;

    // ===== المرحلة 1: تحليل الحزمة =====
    parse_ret = parse_packet(ctx, &key, &tcp_flags, &pkt_len);
    if (parse_ret == XDP_ABORTED) {
        inc_stat(THOR_STAT_MALFORMED);
        return XDP_DROP;
    }
    if (parse_ret == XDP_PASS) {
        return XDP_PASS; // pass غير IP
    }

    inc_stat(THOR_STAT_TOTAL);

    // ===== المرحلة 2: فحص Whitelist (مسار سريع) =====
    if (is_whitelisted(key.src_ip)) {
        inc_stat(THOR_STAT_WHITELIST);
        return XDP_PASS;
    }

    // ===== المرحلة 3: فحص Blacklist (مسار سريع) =====
    if (is_blacklisted(key.src_ip)) {
        inc_stat(THOR_STAT_BLACKLIST);
        return XDP_DROP;
    }

    // ===== المرحلة 4: كشف SYN Flood =====
    if (key.proto == IPPROTO_TCP) {
        __u8 is_syn = (tcp_flags & 0x02) && !(tcp_flags & 0x10);
        if (is_syn) {
            if (check_syn_rate(key.src_ip)) {
                // تجاوز حد SYN — حظر فوري
                inc_stat(THOR_STAT_DROPPED);
                send_sample(ctx, &key, pkt_len, SAMPLE_REASON_SYN_FLOOD);
                return XDP_DROP;
            }
        }
    }

    // ===== المرحلة 5: استعلام حالة التدفق =====
    struct flow_state *state = bpf_map_lookup_elem(&flow_table, &key);

    if (state) {
        // تدفق معروف — تطبيق القرار المحفوظ
        __sync_fetch_and_add(&state->packets, 1);
        __sync_fetch_and_add(&state->bytes, pkt_len);

        switch (state->action) {
        case THOR_ACTION_PASS:
            return XDP_PASS;
        case THOR_ACTION_DROP:
            inc_stat(THOR_STAT_DROPPED);
            return XDP_DROP;
        case THOR_ACTION_SAMPLE:
            // إرسال عينة لكل N حزمة
            if ((state->packets % THOR_SAMPLE_RATE) == 0) {
                send_sample(ctx, &key, pkt_len, SAMPLE_REASON_PERIODIC);
            }
            return XDP_PASS;
        default:
            return XDP_PASS;
        }
    }

    // ===== المرحلة 6: تدفق جديد — إرسال للتحليل =====
    // إنشاء حالة أولية: PASS مع طلب تحليل
    struct flow_state new_state = {
        .action = THOR_ACTION_SAMPLE,
        .packets = 1,
        .bytes = pkt_len,
        .first_seen_ns = bpf_ktime_get_ns(),
    };
    bpf_map_update_elem(&flow_table, &key, &new_state, BPF_NOEXIST);

    inc_stat(THOR_STAT_NEW_FLOWS);
    send_sample(ctx, &key, pkt_len, SAMPLE_REASON_NEW_FLOW);

    return XDP_PASS; // السماح بالحزمة الأولى دائماً
}

char _license[] SEC("license") = "GPL";
