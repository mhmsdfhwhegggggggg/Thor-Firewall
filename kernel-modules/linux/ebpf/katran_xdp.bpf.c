// Thor Firewall — XDP Jump Table (Katran-inspired)
// =================================================
// مستوحى من: https://github.com/facebookincubator/katran
//            (L4 Load Balancer — 10+ Tbps at Meta)
//
// يُطبّق نمط Katran: Program Array (Jump Table) لتوزيع XDP programs
// على أنواع حركة المرور دون الحاجة لـ BPF tail calls overhead.
//
// البنية:
//   xdp_dispatcher → [TCP handler] | [UDP handler] | [ICMP handler]
//                                                   ↓
//                                          [ML verdict lookup]
//                                                   ↓
//                                      XDP_PASS | XDP_DROP | XDP_TX
//
// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Program array indices
#define PROG_TCP   0
#define PROG_UDP   1
#define PROG_ICMP  2
#define PROG_IPV6  3
#define PROG_MAX   4

#define MAX_FLOWS       1000000
#define MAX_BLACKLIST   100000
#define SAMPLE_RATE     100     // 1:100 sampling for ML

// ─────────────────────────────────────────────────────────────────────────────
// BPF Maps
// ─────────────────────────────────────────────────────────────────────────────

// Jump table (Katran pattern) — array of XDP programs
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, PROG_MAX);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} thor_xdp_progs SEC(".maps");

// Flow verdict table (written by ML inference userspace)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_FLOWS);
    __type(key, __u64);     // flow hash
    __type(value, __u32);   // 0=allow, 1=block, 2=throttle, 3=mirror, 4=redirect
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} thor_flow_verdicts SEC(".maps");

// IP Blacklist (LPM TRIE for O(1) CIDR lookup)
struct lpm_key {
    __u32 prefixlen;
    __u32 data;
};
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_BLACKLIST);
    __type(key, struct lpm_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} thor_blacklist SEC(".maps");

// IP Whitelist (LPM TRIE)
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 10000);
    __type(key, struct lpm_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} thor_whitelist SEC(".maps");

// Per-CPU statistics (lockless)
struct xdp_stats {
    __u64 total;
    __u64 passed;
    __u64 dropped;
    __u64 sampled;
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xdp_stats);
} thor_xdp_stats SEC(".maps");

// Sample ring buffer → userspace ML pipeline (64MB, lockless)
struct sample_event {
    __u64   flow_hash;
    __u32   src_ip;
    __u32   dst_ip;
    __u16   src_port;
    __u16   dst_port;
    __u8    protocol;
    __u8    _pad[3];
    __u32   pkt_len;
    __u64   timestamp_ns;
    __u8    payload_head[32];   // first 32 bytes of payload
};
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024 * 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} thor_sample_ringbuf SEC(".maps");

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

// FNV-1a hash (fast, good distribution for flow keys)
static __always_inline __u64
flow_hash(__u32 src_ip, __u32 dst_ip, __u16 src_port, __u16 dst_port, __u8 proto)
{
    __u64 h = 14695981039346656037ULL;  // FNV offset basis
    h ^= src_ip;  h *= 1099511628211ULL;
    h ^= dst_ip;  h *= 1099511628211ULL;
    h ^= ((__u32)src_port << 16) | dst_port;
    h *= 1099511628211ULL;
    h ^= proto;   h *= 1099511628211ULL;
    return h;
}

static __always_inline int
check_blacklist(__u32 ip)
{
    struct lpm_key k = { .prefixlen = 32, .data = bpf_ntohl(ip) };
    return bpf_map_lookup_elem(&thor_blacklist, &k) != NULL;
}

static __always_inline int
check_whitelist(__u32 ip)
{
    struct lpm_key k = { .prefixlen = 32, .data = bpf_ntohl(ip) };
    return bpf_map_lookup_elem(&thor_whitelist, &k) != NULL;
}

// ─────────────────────────────────────────────────────────────────────────────
// XDP Dispatcher (Katran-style program array dispatch)
// ─────────────────────────────────────────────────────────────────────────────

SEC("xdp/dispatcher")
int thor_xdp_dispatcher(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 eth_proto = bpf_ntohs(eth->h_proto);

    // IPv6 → separate handler
    if (eth_proto == ETH_P_IPV6) {
        bpf_tail_call(ctx, &thor_xdp_progs, PROG_IPV6);
        return XDP_PASS;
    }

    if (eth_proto != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;

    // ── Fast path: Whitelist check ────────────────────────────────────────────
    if (check_whitelist(src_ip))
        return XDP_PASS;

    // ── Fast path: Blacklist check (< 50ns) ───────────────────────────────────
    if (check_blacklist(src_ip))
        return XDP_DROP;

    // ── Dispatch to protocol-specific handler ─────────────────────────────────
    switch (ip->protocol) {
    case IPPROTO_TCP:
        bpf_tail_call(ctx, &thor_xdp_progs, PROG_TCP);
        break;
    case IPPROTO_UDP:
        bpf_tail_call(ctx, &thor_xdp_progs, PROG_UDP);
        break;
    case IPPROTO_ICMP:
        bpf_tail_call(ctx, &thor_xdp_progs, PROG_ICMP);
        break;
    }

    return XDP_PASS;
}

// ─────────────────────────────────────────────────────────────────────────────
// TCP Handler
// ─────────────────────────────────────────────────────────────────────────────

SEC("xdp/tcp")
int thor_xdp_tcp(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    struct iphdr  *ip  = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    struct tcphdr *tcp = (void *)(ip + 1);
    if ((void *)(tcp + 1) > data_end) return XDP_PASS;

    __u64 fhash = flow_hash(
        ip->saddr, ip->daddr,
        tcp->source, tcp->dest,
        IPPROTO_TCP
    );

    // Check ML verdict
    __u32 *verdict = bpf_map_lookup_elem(&thor_flow_verdicts, &fhash);
    if (verdict) {
        if (*verdict == 1) return XDP_DROP;    // BLOCK
        if (*verdict == 0) return XDP_PASS;    // ALLOW (fast path)
    }

    // Sample for ML (1:SAMPLE_RATE)
    __u32 key = 0;
    struct xdp_stats *stats = bpf_map_lookup_elem(&thor_xdp_stats, &key);
    if (stats) {
        stats->total++;
        if (stats->total % SAMPLE_RATE == 0) {
            stats->sampled++;
            struct sample_event *ev = bpf_ringbuf_reserve(
                &thor_sample_ringbuf, sizeof(*ev), 0
            );
            if (ev) {
                ev->flow_hash    = fhash;
                ev->src_ip       = ip->saddr;
                ev->dst_ip       = ip->daddr;
                ev->src_port     = tcp->source;
                ev->dst_port     = tcp->dest;
                ev->protocol     = IPPROTO_TCP;
                ev->pkt_len      = ctx->data_end - ctx->data;
                ev->timestamp_ns = bpf_ktime_get_ns();
                // Copy first 32 bytes of TCP payload
                __u8 *payload = (void *)(tcp + 1);
                if ((void *)(payload + 32) <= data_end) {
                    __builtin_memcpy(ev->payload_head, payload, 32);
                }
                bpf_ringbuf_submit(ev, 0);
            }
        }
        stats->passed++;
    }

    return XDP_PASS;
}

// ─────────────────────────────────────────────────────────────────────────────
// UDP Handler
// ─────────────────────────────────────────────────────────────────────────────

SEC("xdp/udp")
int thor_xdp_udp(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    struct iphdr  *ip  = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    struct udphdr *udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > data_end) return XDP_PASS;

    __u64 fhash = flow_hash(
        ip->saddr, ip->daddr,
        udp->source, udp->dest,
        IPPROTO_UDP
    );

    __u32 *verdict = bpf_map_lookup_elem(&thor_flow_verdicts, &fhash);
    if (verdict && *verdict == 1)
        return XDP_DROP;

    return XDP_PASS;
}

// ─────────────────────────────────────────────────────────────────────────────
// ICMP Handler
// ─────────────────────────────────────────────────────────────────────────────

SEC("xdp/icmp")
int thor_xdp_icmp(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth  = data;
    struct iphdr  *ip   = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    struct icmphdr *icmp = (void *)(ip + 1);
    if ((void *)(icmp + 1) > data_end) return XDP_PASS;

    // Drop ICMP flood (> threshold handled by SYN flood map in xdp_filter)
    // Large ICMP → possible ping-of-death
    __u32 pkt_len = ctx->data_end - ctx->data;
    if (pkt_len > 1500)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
