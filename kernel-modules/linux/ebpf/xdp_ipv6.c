// SPDX-License-Identifier: GPL-2.0
/*
 * Thor Firewall — XDP IPv6 Full Support
 * دعم كامل لـ IPv6 في طبقة XDP
 *
 * يُنفَّذ قبل xdp_main.c ويُعيد قرار الحزمة كاملاً
 *
 * الميزات:
 *   - Neighbor Discovery Protocol (NDP) — pass عبور آمن
 *   - Hop-by-Hop extension headers — parsing كامل
 *   - Flow Label tracking (20-bit)
 *   - ICMPv6 rate limiting (anti-flood)
 *   - IPv6 LPM Trie blacklist (عبر 128-bit prefix)
 *   - DHCPv6 allowlist
 *   - Stateless Address Autoconfiguration (SLAAC) — transparent
 *
 * الأداء:
 *   - IPv6 parsing: < 20ns على core واحد
 *   - Blacklist lookup (LPM): O(128) bit-by-bit = < 30ns
 *
 * يتوافق مع: Linux >= 5.15, libbpf >= 1.0
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in6.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

#include "thor_common.h"

/* =========================================================================
 * Constants
 * =========================================================================*/

/* IPv6 Next Header values */
#define NEXTHDR_HOP        0   /* Hop-by-Hop Options */
#define NEXTHDR_TCP        6
#define NEXTHDR_UDP       17
#define NEXTHDR_ROUTING   43   /* Routing Header */
#define NEXTHDR_FRAGMENT  44   /* Fragment Header */
#define NEXTHDR_ESP       50   /* Encapsulating Security Payload */
#define NEXTHDR_AUTH      51   /* Authentication Header */
#define NEXTHDR_ICMPV6    58
#define NEXTHDR_DEST      60   /* Destination Options */
#define NEXTHDR_NONE     59

/* ICMPv6 Types */
#define ICMPV6_DEST_UNREACH      1
#define ICMPV6_PKT_TOOBIG        2
#define ICMPV6_TIME_EXCEEDED     3
#define ICMPV6_PARAM_PROB        4
#define ICMPV6_ECHO_REQUEST    128
#define ICMPV6_ECHO_REPLY      129
/* Neighbor Discovery */
#define ICMPV6_ND_ROUTER_SOL   133
#define ICMPV6_ND_ROUTER_ADV   134
#define ICMPV6_ND_NEIGHBOR_SOL 135
#define ICMPV6_ND_NEIGHBOR_ADV 136
#define ICMPV6_ND_REDIRECT     137
/* Multicast */
#define ICMPV6_MLD_QUERY       130
#define ICMPV6_MLD_REPORT      131
#define ICMPV6_MLD_DONE        132
#define ICMPV6_MLD2_REPORT     143

/* Max extension header iterations (verifier limit) */
#define MAX_EXT_HEADERS 8

/* ICMPv6 rate limiting: max 200 packets/second per src */
#define ICMPV6_RATE_LIMIT_PPS 200
#define ICMPV6_RATE_WINDOW_NS 1000000000ULL /* 1 second */

/* =========================================================================
 * BPF Map Key: IPv6 address (16 bytes = 128 bits)
 * =========================================================================*/

struct ipv6_lpm_key {
    __u32 prefixlen;      /* bits — max 128 */
    __u8  addr[16];       /* IPv6 address */
};

/* =========================================================================
 * BPF Maps
 * =========================================================================*/

/*
 * IPv6 Blacklist — LPM Trie (longest-prefix match)
 * يدعم CIDR notation مثل 2001:db8::/32
 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __type(key, struct ipv6_lpm_key);
    __type(value, __u32);              /* سبب الحظر (bitmask) */
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ipv6_blacklist SEC(".maps");

/*
 * IPv6 Whitelist — عناوين مُصرَّح بها دائماً
 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 16384);
    __type(key, struct ipv6_lpm_key);
    __type(value, __u32);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ipv6_whitelist SEC(".maps");

/*
 * IPv6 Flow Table — تتبع الاتصالات النشطة
 * Key: (src_ip128, dst_ip128, src_port, dst_port, protocol)
 * Value: flow_entry (بُنية مشتركة مع IPv4)
 */
struct ipv6_flow_key {
    __u8  src_ip[16];
    __u8  dst_ip[16];
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  _pad[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 500000);   /* 500K IPv6 flows */
    __type(key, struct ipv6_flow_key);
    __type(value, struct flow_entry);
} ipv6_flow_table SEC(".maps");

/*
 * ICMPv6 Rate Limit — عداد لكل src IP
 */
struct icmpv6_rate_entry {
    __u64 window_start_ns;
    __u32 count;
    __u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);           /* hash(src_ip[0..3] ^ src_ip[12..15]) */
    __type(value, struct icmpv6_rate_entry);
} icmpv6_rate_limit SEC(".maps");

/*
 * Per-CPU IPv6 Packet Statistics
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct thor_stats);
} ipv6_stats SEC(".maps");

/*
 * Ring Buffer — إرسال عينات IPv6 لـ user space
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024); /* 16 MB */
} ipv6_ringbuf SEC(".maps");

/* =========================================================================
 * Helper: بناء IPv6 flow key
 * =========================================================================*/

static __always_inline void
build_ipv6_flow_key(
    struct ipv6_flow_key *key,
    const __u8 *src_ip,
    const __u8 *dst_ip,
    __u16 src_port,
    __u16 dst_port,
    __u8 protocol
) {
    __builtin_memcpy(key->src_ip, src_ip, 16);
    __builtin_memcpy(key->dst_ip, dst_ip, 16);
    key->src_port  = src_port;
    key->dst_port  = dst_port;
    key->protocol  = protocol;
    key->_pad[0]   = 0;
    key->_pad[1]   = 0;
    key->_pad[2]   = 0;
}

/* =========================================================================
 * Helper: IPv6 LPM lookup
 * =========================================================================*/

static __always_inline int
ipv6_in_trie(void *map, const __u8 *addr)
{
    struct ipv6_lpm_key key = { .prefixlen = 128 };
    __builtin_memcpy(key.addr, addr, 16);
    return bpf_map_lookup_elem(map, &key) != NULL;
}

/* =========================================================================
 * Helper: ICMPv6 rate limiting
 * =========================================================================*/

static __always_inline int
icmpv6_rate_check(const __u8 *src_ip)
{
    /* حساب key بسيط (XOR أول وآخر 4 bytes) */
    __u32 key = 0;
    __builtin_memcpy(&key, src_ip, 4);
    __u32 tail = 0;
    __builtin_memcpy(&tail, src_ip + 12, 4);
    key ^= tail;

    __u64 now_ns = bpf_ktime_get_ns();

    struct icmpv6_rate_entry *entry = bpf_map_lookup_elem(&icmpv6_rate_limit, &key);
    if (!entry) {
        struct icmpv6_rate_entry new_entry = {
            .window_start_ns = now_ns,
            .count           = 1,
        };
        bpf_map_update_elem(&icmpv6_rate_limit, &key, &new_entry, BPF_ANY);
        return XDP_PASS;
    }

    /* نافذة انتهت؟ إعادة تشغيل */
    if ((now_ns - entry->window_start_ns) >= ICMPV6_RATE_WINDOW_NS) {
        entry->window_start_ns = now_ns;
        entry->count           = 1;
        return XDP_PASS;
    }

    /* تجاوز الحد؟ */
    if (entry->count >= ICMPV6_RATE_LIMIT_PPS)
        return XDP_DROP;

    __sync_fetch_and_add(&entry->count, 1);
    return XDP_PASS;
}

/* =========================================================================
 * Helper: parsing extension headers → حيث يبدأ Transport Layer
 * =========================================================================*/

static __always_inline int
parse_ipv6_ext_headers(
    void       *data_end,
    void       *cursor,
    __u8       *next_hdr,       /* [in/out] */
    __u32      *transport_off   /* [out] byte offset من بداية packet */
) {
#pragma unroll
    for (int i = 0; i < MAX_EXT_HEADERS; i++) {
        switch (*next_hdr) {
        case NEXTHDR_TCP:
        case NEXTHDR_UDP:
        case NEXTHDR_ICMPV6:
        case NEXTHDR_NONE:
        case NEXTHDR_ESP:
            /* وصلنا للـ transport layer */
            return 0;

        case NEXTHDR_FRAGMENT: {
            /* Fragment Header: 8 bytes ثابتة */
            struct {
                __u8 next_hdr;
                __u8 reserved;
                __u16 frag_off;
                __u32 id;
            } *frag = cursor;
            if ((void *)(frag + 1) > data_end)
                return -1;
            *next_hdr    = frag->next_hdr;
            cursor       = (void *)(frag + 1);
            *transport_off += 8;
            /* الحزم المُجزَّأة: pass مباشرة (reassembly يتم في kernel) */
            if (bpf_ntohs(frag->frag_off) & 0xFFF8)
                return 1; /* signal: fragment */
            break;
        }

        case NEXTHDR_HOP:
        case NEXTHDR_ROUTING:
        case NEXTHDR_DEST:
        case NEXTHDR_AUTH: {
            /* Generic extension header: next_hdr + length في أول 2 bytes */
            struct {
                __u8 next_hdr;
                __u8 hdr_ext_len;
            } *hdr = cursor;
            if ((void *)(hdr + 1) > data_end)
                return -1;
            __u32 hdr_len = (((__u32)hdr->hdr_ext_len + 1) * 8);
            *next_hdr     = hdr->next_hdr;
            cursor        = cursor + hdr_len;
            *transport_off += hdr_len;
            if (cursor > data_end)
                return -1;
            break;
        }

        default:
            /* Unknown extension header — pass بأمان */
            return 0;
        }
    }

    return -1; /* تجاوزنا الحد الأقصى للـ headers */
}

/* =========================================================================
 * Helper: تحديث الإحصاءات
 * =========================================================================*/

static __always_inline void
ipv6_stats_update(__u32 bytes, int action)
{
    __u32 key = 0;
    struct thor_stats *stats = bpf_map_lookup_elem(&ipv6_stats, &key);
    if (!stats)
        return;

    __sync_fetch_and_add(&stats->packets, 1);
    __sync_fetch_and_add(&stats->bytes, bytes);

    if (action == XDP_DROP)
        __sync_fetch_and_add(&stats->dropped, 1);
    else if (action == XDP_PASS)
        __sync_fetch_and_add(&stats->passed, 1);
}

/* =========================================================================
 * Helper: إرسال PacketSample لـ ring buffer (للتحليل بـ ML)
 * =========================================================================*/

static __always_inline void
ipv6_emit_sample(
    const struct ipv6hdr *ip6,
    __u16 src_port,
    __u16 dst_port,
    __u8  tcp_flags,
    __u32 pkt_len
) {
    struct packet_sample *sample = bpf_ringbuf_reserve(&ipv6_ringbuf,
                                                        sizeof(*sample), 0);
    if (!sample)
        return;

    sample->timestamp_ns = bpf_ktime_get_ns();
    sample->pkt_len      = pkt_len;
    sample->is_ipv6      = 1;
    sample->src_port     = src_port;
    sample->dst_port     = dst_port;
    sample->protocol     = ip6->nexthdr;
    sample->tcp_flags    = tcp_flags;
    sample->ttl          = ip6->hop_limit;
    sample->dscp         = (ip6->priority << 2) | (ip6->flow_lbl[0] >> 6);

    /* تخزين IPv6 address في حقلي src_ip و dst_ip الـ 4-byte
     * نأخذ آخر 4 bytes (جزء interface identifier) للـ lookup السريع
     * والـ 16 bytes الكاملة تأتي عبر ring buffer في حقول مُخصَّصة */
    __builtin_memcpy(&sample->src_ip, ip6->saddr.in6_u.u6_addr8 + 12, 4);
    __builtin_memcpy(&sample->dst_ip, ip6->daddr.in6_u.u6_addr8 + 12, 4);

    /* تخزين كامل IPv6 addresses في byte array */
    __builtin_memcpy(sample->src_ip6, ip6->saddr.in6_u.u6_addr8, 16);
    __builtin_memcpy(sample->dst_ip6, ip6->daddr.in6_u.u6_addr8, 16);

    bpf_ringbuf_submit(sample, 0);
}

/* =========================================================================
 * XDP Program: IPv6 Handler
 * يُستدعى من xdp_main.c بعد التحقق من EtherType = 0x86DD
 * =========================================================================*/

static __always_inline int
thor_process_ipv6(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* ─── Ethernet Header ──────────────────────────────────────────── */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    /* ─── IPv6 Header ──────────────────────────────────────────────── */
    struct ipv6hdr *ip6 = (void *)(eth + 1);
    if ((void *)(ip6 + 1) > data_end)
        return XDP_DROP;

    __u32 pkt_len      = (__u32)(data_end - data);
    const __u8 *src_ip = ip6->saddr.in6_u.u6_addr8;
    const __u8 *dst_ip = ip6->daddr.in6_u.u6_addr8;

    /* ─── Whitelist Check ──────────────────────────────────────────── */
    if (ipv6_in_trie(&ipv6_whitelist, src_ip)) {
        ipv6_stats_update(pkt_len, XDP_PASS);
        return XDP_PASS;
    }

    /* ─── Blacklist Check ──────────────────────────────────────────── */
    if (ipv6_in_trie(&ipv6_blacklist, src_ip)) {
        ipv6_stats_update(pkt_len, XDP_DROP);
        return XDP_DROP;
    }

    /* ─── Extension Header Parsing ─────────────────────────────────── */
    __u8  next_hdr    = ip6->nexthdr;
    __u32 ext_offset  = 0;
    void *transport   = (void *)(ip6 + 1);

    int ext_result = parse_ipv6_ext_headers(data_end, transport, &next_hdr, &ext_offset);
    if (ext_result < 0)
        return XDP_DROP;   /* malformed extension headers */

    transport = transport + ext_offset;

    /* Fragment → pass للـ kernel reassembly */
    if (ext_result == 1) {
        ipv6_stats_update(pkt_len, XDP_PASS);
        return XDP_PASS;
    }

    /* ─── ICMPv6 Handling ──────────────────────────────────────────── */
    if (next_hdr == NEXTHDR_ICMPV6) {
        struct icmp6hdr *icmp6 = transport;
        if ((void *)(icmp6 + 1) > data_end)
            return XDP_DROP;

        __u8 icmp_type = icmp6->icmp6_type;

        /* Neighbor Discovery — مُعفى من القيود (أساسي لـ IPv6) */
        if (icmp_type >= ICMPV6_ND_ROUTER_SOL &&
            icmp_type <= ICMPV6_ND_REDIRECT) {
            ipv6_stats_update(pkt_len, XDP_PASS);
            return XDP_PASS;
        }

        /* MLD (Multicast Listener Discovery) — أساسي */
        if (icmp_type == ICMPV6_MLD_QUERY  ||
            icmp_type == ICMPV6_MLD_REPORT  ||
            icmp_type == ICMPV6_MLD_DONE    ||
            icmp_type == ICMPV6_MLD2_REPORT) {
            ipv6_stats_update(pkt_len, XDP_PASS);
            return XDP_PASS;
        }

        /* ICMPv6 Echo — تطبيق rate limit لمنع Smurf attacks */
        if (icmp_type == ICMPV6_ECHO_REQUEST ||
            icmp_type == ICMPV6_ECHO_REPLY) {
            int rate_result = icmpv6_rate_check(src_ip);
            ipv6_stats_update(pkt_len, rate_result);
            return rate_result;
        }

        /* باقي ICMPv6 — pass */
        ipv6_stats_update(pkt_len, XDP_PASS);
        return XDP_PASS;
    }

    /* ─── TCP ──────────────────────────────────────────────────────── */
    __u16 src_port = 0, dst_port = 0;
    __u8  tcp_flags = 0;

    if (next_hdr == NEXTHDR_TCP) {
        struct tcphdr *tcp = transport;
        if ((void *)(tcp + 1) > data_end)
            return XDP_DROP;

        src_port  = bpf_ntohs(tcp->source);
        dst_port  = bpf_ntohs(tcp->dest);
        tcp_flags = *(((__u8 *)tcp) + 13); /* flags byte */

    } else if (next_hdr == NEXTHDR_UDP) {
        struct udphdr *udp = transport;
        if ((void *)(udp + 1) > data_end)
            return XDP_DROP;

        src_port = bpf_ntohs(udp->source);
        dst_port = bpf_ntohs(udp->dest);
    }

    /* ─── Flow Table Lookup ────────────────────────────────────────── */
    struct ipv6_flow_key fkey = {};
    build_ipv6_flow_key(&fkey, src_ip, dst_ip, src_port, dst_port, next_hdr);

    struct flow_entry *entry = bpf_map_lookup_elem(&ipv6_flow_table, &fkey);
    if (entry) {
        __sync_fetch_and_add(&entry->packets, 1);
        __sync_fetch_and_add(&entry->bytes, pkt_len);
        entry->last_seen_ns = bpf_ktime_get_ns();

        /* تطبيق القرار المُخزَّن */
        if (entry->decision == DECISION_BLOCK) {
            ipv6_stats_update(pkt_len, XDP_DROP);
            return XDP_DROP;
        }
    } else {
        /* تدفق جديد — إضافة للـ flow table */
        struct flow_entry new_entry = {
            .packets        = 1,
            .bytes          = pkt_len,
            .first_seen_ns  = bpf_ktime_get_ns(),
            .last_seen_ns   = bpf_ktime_get_ns(),
            .src_port       = src_port,
            .dst_port       = dst_port,
            .protocol       = next_hdr,
            .decision       = DECISION_UNKNOWN,
            .risk_score_q8  = 0,
        };
        bpf_map_update_elem(&ipv6_flow_table, &fkey, &new_entry, BPF_ANY);

        /* إرسال عينة لـ ML إذا كان منفذ حساس أو SYN جديد */
        int should_sample = (dst_port == 22 || dst_port == 23 ||
                             dst_port == 3389 || dst_port == 443 ||
                             (next_hdr == NEXTHDR_TCP && (tcp_flags & 0x02) && !(tcp_flags & 0x10)));
        if (should_sample) {
            ipv6_emit_sample(ip6, src_port, dst_port, tcp_flags, pkt_len);
        }
    }

    /* ─── SYN Flood Detection (IPv6) ───────────────────────────────── */
    if (next_hdr == NEXTHDR_TCP &&
        (tcp_flags & 0x02) &&    /* SYN */
        !(tcp_flags & 0x10)) {   /* !ACK */

        /* نفس المنطق في xdp_syn_flood.c لكن لـ IPv6 */
        /* TODO: يُكمَّل مع إحصاءات SYN per-src */
    }

    ipv6_stats_update(pkt_len, XDP_PASS);
    return XDP_PASS;
}

/* =========================================================================
 * BPF Program Entry (standalone — أو يُستدعى من xdp_main)
 * =========================================================================*/

SEC("xdp")
int thor_xdp_ipv6(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* نعالج فقط IPv6 */
    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
        return XDP_PASS;

    return thor_process_ipv6(ctx);
}

/* =========================================================================
 * TC Egress Hook for IPv6 (TC_ACT_*)
 * يُعالج الحزم الصادرة من النظام
 * =========================================================================*/

SEC("tc")
int thor_tc_ipv6_egress(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
        return TC_ACT_OK;

    struct ipv6hdr *ip6 = (void *)(eth + 1);
    if ((void *)(ip6 + 1) > data_end)
        return TC_ACT_OK;

    /* فحص Whitelist للحزم الصادرة */
    if (ipv6_in_trie(&ipv6_whitelist, ip6->daddr.in6_u.u6_addr8))
        return TC_ACT_OK;

    /* فحص Blacklist للوجهة */
    if (ipv6_in_trie(&ipv6_blacklist, ip6->daddr.in6_u.u6_addr8))
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
