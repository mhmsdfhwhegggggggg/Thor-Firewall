// Thor Firewall — TC Egress Filter
// فلتر حركة المرور الصادرة (Traffic Control)
//
// يعمل على hook مختلف عن XDP:
//   XDP = ingress فقط (حزم واردة)
//   TC  = ingress + egress (حزم صادرة أيضاً)
//
// المهام:
//   - تطبيق QoS (تحديد معدل لحركات مشبوهة)
//   - منع data exfiltration (تسريب البيانات)
//   - تشفير المرور عبر WireGuard للاتصالات الخارجية
//   - تسجيل محاولات DNS المشبوهة
//
// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/pkt_cls.h>
#include "thor_common.h"

// ========================================================================
// DNS Inspection
// ========================================================================

#define DNS_PORT 53
#define DNS_MAX_NAME_LEN 128

struct dns_header {
    __u16 id;
    __u16 flags;
    __u16 qdcount;
    __u16 ancount;
    __u16 nscount;
    __u16 arcount;
} __attribute__((packed));

// قائمة نطاقات مشبوهة (DNS-over-TCP يُحقَّق بشكل أعمق)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);   // hash of domain
    __type(value, __u8);  // 1 = blocked
} dns_blacklist SEC(".maps");

// Ring buffer لأحداث DNS
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 << 20);  // 8MB
} dns_events SEC(".maps");

struct dns_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 query_id;
    __u8  is_response;
    __u8  rcode;        // Response code
    __u64 timestamp_ns;
    char  query_name[DNS_MAX_NAME_LEN];
};

// ========================================================================
// Rate Limiter (Token Bucket) for Egress
// ========================================================================

struct egress_bucket {
    __u64 tokens;          // × 1000
    __u64 last_refill_ns;
    __u32 drop_count;
    __u32 pass_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1 << 16);
    __type(key, __u32);   // dst_ip
    __type(value, struct egress_bucket);
} egress_limiters SEC(".maps");

// ========================================================================
// Data Exfiltration Detection
// ========================================================================

// يتتبع حجم البيانات الصادرة لكل IP وجهة
struct exfil_tracker {
    __u64 bytes_sent;
    __u64 window_start_ns;
    __u32 large_pkt_count;  // حزم > 1400 bytes
    __u32 flags;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1 << 16);
    __type(key, __u32);   // dst_ip
    __type(value, struct exfil_tracker);
} exfil_trackers SEC(".maps");

// عتبة تسريب البيانات: 100MB في دقيقة واحدة
#define EXFIL_THRESHOLD_BYTES (100ULL * 1024 * 1024)
#define EXFIL_WINDOW_NS       (60ULL * 1000000000ULL)

static __always_inline int check_data_exfiltration(
    __u32 dst_ip,
    __u16 pkt_len,
    __u64 now_ns
) {
    struct exfil_tracker *tracker;
    struct exfil_tracker new_tracker = {
        .bytes_sent = pkt_len,
        .window_start_ns = now_ns,
    };

    tracker = bpf_map_lookup_elem(&exfil_trackers, &dst_ip);
    if (!tracker) {
        bpf_map_update_elem(&exfil_trackers, &dst_ip, &new_tracker, BPF_ANY);
        return 0;
    }

    // إعادة تعيين كل دقيقة
    if (now_ns - tracker->window_start_ns > EXFIL_WINDOW_NS) {
        *tracker = new_tracker;
        return 0;
    }

    __sync_fetch_and_add(&tracker->bytes_sent, pkt_len);

    if (pkt_len > 1400) {
        __sync_fetch_and_add(&tracker->large_pkt_count, 1);
    }

    // تجاوز عتبة التسريب
    if (tracker->bytes_sent > EXFIL_THRESHOLD_BYTES) {
        bpf_printk("Thor: Potential data exfiltration to %pI4 (%llu MB)\n",
                   &dst_ip, tracker->bytes_sent >> 20);
        return 1;  // مشبوه
    }

    return 0;
}

// ========================================================================
// TC Egress Main Program
// ========================================================================

SEC("tc")
int thor_tc_egress(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    __u64 now      = bpf_ktime_get_ns();

    // ===== Ethernet =====
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) return TC_ACT_OK;

    // ===== IPv4 =====
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return TC_ACT_OK;

    __u32 dst_ip  = bpf_ntohl(ip->daddr);
    __u16 pkt_len = data_end - data;

    // ===== Data Exfiltration Check =====
    // Only for external IPs (not RFC 1918)
    bool is_external = !(
        (dst_ip & 0xFF000000) == 0x0A000000 ||  // 10.0.0.0/8
        (dst_ip & 0xFFF00000) == 0xAC100000 ||  // 172.16.0.0/12
        (dst_ip & 0xFFFF0000) == 0xC0A80000      // 192.168.0.0/16
    );

    if (is_external && check_data_exfiltration(dst_ip, pkt_len, now)) {
        // إرسال تحذير — لكن لا نوقف الإرسال تلقائياً
        // القرار النهائي يعود لـ MARL بعد التحليل
        skb->mark = 0xDEAD;  // وضع علامة للمعالجة في userspace
    }

    // ===== UDP DNS Inspection =====
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ip->ihl * 4;
        if ((void *)(udp + 1) > data_end) return TC_ACT_OK;

        if (bpf_ntohs(udp->dest) == DNS_PORT) {
            // إرسال عينة DNS للتحليل
            struct dns_event *evt = bpf_ringbuf_reserve(&dns_events, sizeof(*evt), 0);
            if (evt) {
                evt->src_ip       = ip->saddr;
                evt->dst_ip       = ip->daddr;
                evt->timestamp_ns = now;
                evt->is_response  = 0;
                bpf_ringbuf_submit(evt, 0);
            }
        }
    }

    return TC_ACT_OK;
}

// ========================================================================
// TC Ingress (for traffic shaping)
// ========================================================================

SEC("tc")
int thor_tc_ingress(struct __sk_buff *skb)
{
    // يُستخدم لـ traffic shaping وredirection
    // الفلترة الرئيسية تتم في XDP
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
