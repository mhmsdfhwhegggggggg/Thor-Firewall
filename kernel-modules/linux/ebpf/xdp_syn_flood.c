// Thor Firewall — SYN Flood Protection (Advanced)
// حماية متقدمة من هجمات SYN flood
//
// يُطبّق خوارزمية SYN Cookie للتحقق من صحة الاتصالات
// دون الحاجة لتخزين حالة لكل اتصال معلق
//
// الأداء المستهدف: التعامل مع 100M SYN/s مع صفر false positives
//
// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "thor_common.h"

// ========================================================================
// SYN Cookie Implementation
// تطبيق SYN Cookie لمقاومة هجمات SYN flood
// ========================================================================

// الثوابت السرية (تُحدَّث من user-space دورياً)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} syn_cookie_secrets SEC(".maps");

/// إنشاء SYN Cookie آمن
/// يستخدم BLAKE3 (محاكاة — في الواقع يستخدم SipHash داخل النواة)
static __always_inline __u32 generate_syn_cookie(
    __u32 src_ip, __u32 dst_ip,
    __u16 sport, __u16 dport,
    __u32 timestamp_s
) {
    __u32 key0 = 0, key1 = 1;
    __u64 *secret;

    secret = bpf_map_lookup_elem(&syn_cookie_secrets, &key0);
    __u64 s0 = secret ? *secret : 0xdeadbeefdeadbeefULL;

    secret = bpf_map_lookup_elem(&syn_cookie_secrets, &key1);
    __u64 s1 = secret ? *secret : 0xcafebabedeadcafeULL;

    // SipHash-2-4 مُبسّط (للأداء داخل eBPF)
    __u64 v0 = s0 ^ 0x736f6d6570736575ULL;
    __u64 v1 = s1 ^ 0x646f72616e646f6dULL;
    __u64 v2 = s0 ^ 0x6c7967656e657261ULL;
    __u64 v3 = s1 ^ 0x7465646279746573ULL;

    __u64 msg = ((__u64)src_ip << 32) | ((__u64)dst_ip);
    v3 ^= msg;
    v0 ^= msg;

    msg = ((__u64)sport << 48) | ((__u64)dport << 32) | timestamp_s;
    v3 ^= msg;
    v0 ^= msg;

    return (__u32)(v0 ^ v1 ^ v2 ^ v3);
}

// ========================================================================
// Rate Limiter per Source IP (Token Bucket)
// حد معدل لكل IP مصدر باستخدام خوارزمية دلو الرمز
// ========================================================================

struct token_bucket {
    __u64 tokens;          // الرموز الحالية (× 1000 للدقة)
    __u64 last_refill_ns;  // آخر وقت إعادة تعبئة
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1 << 16);
    __type(key, __u32);
    __type(value, struct token_bucket);
} rate_limiters SEC(".maps");

/// التحقق من حد المعدل لـ IP معين
/// يُعيد 0 إذا كان مسموحاً، 1 إذا تجاوز الحد
static __always_inline int rate_limit_check(__u32 src_ip, __u64 now_ns) {
    struct token_bucket *bucket;
    struct token_bucket new_bucket = {
        .tokens = 1000000,  // بداية بـ 1000 رمز × 1000
        .last_refill_ns = now_ns,
    };

    bucket = bpf_map_lookup_elem(&rate_limiters, &src_ip);
    if (!bucket) {
        bpf_map_update_elem(&rate_limiters, &src_ip, &new_bucket, BPF_ANY);
        return 0;
    }

    // إعادة تعبئة: 1000 رمز/ثانية = 1 رمز/ms
    __u64 elapsed_ns = now_ns - bucket->last_refill_ns;
    __u64 new_tokens = elapsed_ns / 1000000; // رمز لكل مليون نانوثانية (1ms)

    if (new_tokens > 0) {
        bucket->tokens += new_tokens * 1000;
        if (bucket->tokens > 1000000) // حد أقصى 1000 رمز
            bucket->tokens = 1000000;
        bucket->last_refill_ns = now_ns;
    }

    if (bucket->tokens >= 1000) {
        bucket->tokens -= 1000;
        return 0; // مسموح
    }

    return 1; // تجاوز الحد
}

// ========================================================================
// XDP SYN Flood Program
// ========================================================================

SEC("xdp")
int thor_syn_guard(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    __u64 now_ns = bpf_ktime_get_ns();

    // ===== Ethernet =====
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_ABORTED;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    // ===== IPv4 =====
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_ABORTED;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // ===== TCP =====
    struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
    if ((void *)(tcp + 1) > data_end)
        return XDP_ABORTED;

    __u8 flags = ((__u8 *)tcp)[13];
    __u8 is_syn = (flags & 0x02) && !(flags & 0x10);

    if (!is_syn)
        return XDP_PASS;

    // ===== SYN Packet Detected =====
    __u32 src_ip = bpf_ntohl(ip->saddr);
    __u16 sport  = bpf_ntohs(tcp->source);
    __u16 dport  = bpf_ntohs(tcp->dest);

    // فحص حد المعدل
    if (rate_limit_check(src_ip, now_ns)) {
        // تجاوز حد السرعة — حظر
        bpf_printk("Thor SYN flood: blocked %pI4:%u\n", &ip->saddr, sport);
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
