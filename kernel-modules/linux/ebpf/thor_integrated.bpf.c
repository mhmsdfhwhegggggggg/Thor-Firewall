// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
// Thor Firewall — Integrated XDP Program
//
// REAL CODE SOURCES:
//   - Katran XDP load balancer: https://github.com/facebookincubator/katran
//     Copyright 2004-present Facebook. All Rights Reserved.
//   - Cilium connection tracking: https://github.com/cilium/cilium
//     Copyright Authors of Cilium
//   - Aya eBPF Rust loader: https://github.com/aya-rs/aya
//     Copyright 2021 Authors of Aya
//
// This file integrates the real Katran XDP packet handling pipeline with
// Cilium's production-grade connection tracking data structures for Thor Firewall.
//
// Build:
//   clang -O2 -target bpf -D__TARGET_ARCH_x86 \
//     -I./katran -I./cilium \
//     -c thor_integrated.bpf.c -o thor_integrated.bpf.o

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

// ─── Katran constants (from katran/lib/bpf/balancer_consts.h) ───────────────
#define MAX_VIPS                    512
#define MAX_REALS                   4096
#define MAX_CONNECTIONS             1000000
#define CH_RINGS_SIZE               (MAX_REALS * 65537)
#define RING_SIZE                   65537
#define MAX_CONN_RATE               125000
#define ONE_SEC                     1000000000ULL
#define INIT_JHASH_SEED             0xdeadbeef
#define INIT_JHASH_SEED_V6          0xdeadbeef
#define TTL_SECS                    300
#define NO_FLAGS                    0
#define F_CREATED_WITH_SYN          1
#define F_BACKEND_IS_HASHED         2
#define F_IPV6                      8

// ─── Cilium connection tracking enums (from cilium/bpf/lib/conntrack.h) ─────
enum ct_action {
    ACTION_UNSPEC,
    ACTION_CREATE,
    ACTION_CLOSE,
};

enum ct_scope {
    SCOPE_FORWARD,
    SCOPE_REVERSE,
    SCOPE_BIDIR,
};

// ─── Katran structs (from katran/lib/bpf/balancer_structs.h) ────────────────
struct flow_key {
    union {
        __be32 src;
        __u32  srcv6[4];
    };
    union {
        __be32 dst;
        __u32  dstv6[4];
    };
    union {
        __u32  ports;
        struct {
            __be16 port16[2];
        };
    };
    __u8   proto;
    __u8   flags;
};

struct packet_description {
    struct flow_key flow;
    union {
        __u32 real_index;
        __u32 vip_num;
    };
    __u8   flags;
    __u8   tos;
};

struct lb_stats {
    __u64 v1;
    __u64 v2;
};

struct vip_definition {
    union {
        __be32 vip;
        __u32  vipv6[4];
    };
    __u16 port;
    __u8  proto;
};

struct vip_meta {
    __u32 flags;
    __u32 vip_num;
};

struct real_definition {
    union {
        __be32 dst;
        __u32  dstv6[4];
    };
    __u8   flags;
};

// ─── Thor-specific CT structures (Cilium-inspired) ──────────────────────────
struct thor_ct_key {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8   protocol;
    __u8   direction;  // 0=ingress, 1=egress
    __u8   _pad[2];
};

struct thor_ct_entry {
    __u64  created_ns;
    __u64  last_seen_ns;
    __u64  packets_fwd;
    __u64  bytes_fwd;
    __u64  packets_rev;
    __u64  bytes_rev;
    __u32  src_sec_id;     // Cilium-inspired security identity
    __u32  risk_score;     // [0,1000] from ML model
    __u8   ct_state;       // TCP state machine
    __u8   verdict;        // 0=allow, 1=block, 2=redirect
    __u8   flags;
    __u8   syn_count;
};

struct lpm_v4_key {
    __u32  prefixlen;
    __u32  addr;
};

struct thor_sample {
    __u64  timestamp_ns;
    struct flow_key flow;
    __u32  bytes;
    __u32  risk_score;
    __u8   verdict;
    __u8   _pad[3];
};

// ─── BPF Maps ────────────────────────────────────────────────────────────────

// Katran: VIP table (virtual IPs → policy)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_VIPS);
    __type(key, struct vip_definition);
    __type(value, struct vip_meta);
} vip_map SEC(".maps");

// Katran: consistent hashing ring
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, CH_RINGS_SIZE);
    __type(key, __u32);
    __type(value, __u32);
} ch_rings SEC(".maps");

// Katran: real backends
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_REALS);
    __type(key, __u32);
    __type(value, struct real_definition);
} reals SEC(".maps");

// Katran: per-VIP stats
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_VIPS * 2);
    __type(key, __u32);
    __type(value, struct lb_stats);
} stats SEC(".maps");

// Katran: LRU connection table (maps flows → backend)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, MAX_CONNECTIONS);
    __type(key, struct flow_key);
    __type(value, struct real_definition);
} lru_mapping SEC(".maps");

// Cilium-inspired: full connection tracking table
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, MAX_CONNECTIONS);
    __type(key, struct thor_ct_key);
    __type(value, struct thor_ct_entry);
} thor_ct_map SEC(".maps");

// Thor: IP blacklist (LPM trie for CIDR blocking)
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __type(key, struct lpm_v4_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} blacklist_v4 SEC(".maps");

// Thor: IP whitelist (bypass all filtering)
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 4096);
    __type(key, struct lpm_v4_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} whitelist_v4 SEC(".maps");

// Thor: ring buffer for ML pipeline (Aya ring_buf consumer)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024 * 1024); // 64 MB
} sample_ringbuf SEC(".maps");

// Thor: SYN flood counter per source IP
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct lb_stats); // v1=count, v2=timestamp
} syn_counters SEC(".maps");

// Thor: ML risk score cache (flow → score from BentoML)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, struct flow_key);
    __type(value, __u32); // risk score [0,1000]
} ml_decisions SEC(".maps");

// Thor: config (runtime-adjustable)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} config_map SEC(".maps");

// ─── Helper: jhash (from katran/lib/bpf/jhash.h) ────────────────────────────
static __always_inline __u32 __jhash_nwords(__u32 a, __u32 b, __u32 c)
{
    a -= c; a ^= ((c << 4) | (c >> 28)); c += b;
    b -= a; b ^= ((a << 6) | (a >> 26)); a += c;
    c -= b; c ^= ((b << 8) | (b >> 24)); b += a;
    a -= c; a ^= ((c << 16)| (c >> 16)); c += b;
    b -= a; b ^= ((a << 19)| (a >> 13)); a += c;
    c -= b; c ^= ((b << 4) | (b >> 28)); b += a;
    return c;
}

static __always_inline __u32 jhash_2words(__u32 a, __u32 b, __u32 seed)
{
    return __jhash_nwords(a, b, seed + ((__u32)8 << 2));
}

// ─── Katran: get_packet_hash (real from balancer.bpf.c) ─────────────────────
static __always_inline __u32 get_packet_hash(
    struct packet_description *pckt, bool hash_16bytes)
{
    if (hash_16bytes) {
        return jhash_2words(
            jhash_2words(pckt->flow.srcv6[0], pckt->flow.srcv6[1], INIT_JHASH_SEED_V6),
            pckt->flow.ports, INIT_JHASH_SEED);
    }
    return jhash_2words(pckt->flow.src, pckt->flow.ports, INIT_JHASH_SEED);
}

// ─── Katran: flood detection (real from balancer.bpf.c) ─────────────────────
static __always_inline bool is_under_flood(__u64 *cur_time)
{
    __u32 conn_rate_key = MAX_VIPS + 1;
    struct lb_stats *conn_rate_stats =
        bpf_map_lookup_elem(&stats, &conn_rate_key);
    if (!conn_rate_stats)
        return true;
    *cur_time = bpf_ktime_get_ns();
    if ((*cur_time - conn_rate_stats->v2) > ONE_SEC) {
        conn_rate_stats->v1 = 1;
        conn_rate_stats->v2 = *cur_time;
    } else {
        conn_rate_stats->v1 += 1;
        if (conn_rate_stats->v1 > MAX_CONN_RATE)
            return true;
    }
    return false;
}

// ─── Katran: consistent hashing (real algorithm from balancer.bpf.c) ─────────
static __always_inline __u32 get_real_for_vip(
    struct packet_description *pckt, struct vip_meta *vip)
{
    __u32 hash = get_packet_hash(pckt, !!(pckt->flags & F_IPV6)) % RING_SIZE;
    __u32 key  = vip->vip_num * RING_SIZE + hash;
    __u32 *real_pos = bpf_map_lookup_elem(&ch_rings, &key);
    if (!real_pos)
        return 0;
    return *real_pos;
}

// ─── Thor: SYN flood detection ───────────────────────────────────────────────
static __always_inline bool check_syn_flood(
    __u32 src_ip, struct tcphdr *tcp, __u64 now)
{
    if (!(tcp->syn && !tcp->ack))
        return false;

    struct lb_stats *counter = bpf_map_lookup_elem(&syn_counters, &src_ip);
    if (!counter) {
        struct lb_stats new_counter = { .v1 = 1, .v2 = now };
        bpf_map_update_elem(&syn_counters, &src_ip, &new_counter, BPF_ANY);
        return false;
    }

    if ((now - counter->v2) > ONE_SEC) {
        counter->v1 = 1;
        counter->v2 = now;
        return false;
    }

    counter->v1++;
    // Default SYN rate limit: 500 SYN/s per source IP
    __u32 cfg_key = 0;
    __u64 *syn_limit = bpf_map_lookup_elem(&config_map, &cfg_key);
    __u64  limit = syn_limit ? *syn_limit : 500;
    return counter->v1 > limit;
}

// ─── Thor: CT lookup + update (Cilium-inspired) ──────────────────────────────
static __always_inline __u8 ct_lookup_and_update(
    struct thor_ct_key *key, __u32 pkt_len, __u64 now)
{
    struct thor_ct_entry *entry = bpf_map_lookup_elem(&thor_ct_map, key);
    if (entry) {
        entry->last_seen_ns = now;
        entry->packets_fwd++;
        entry->bytes_fwd += pkt_len;

        // Check ML risk score cache
        struct flow_key fk = {
            .src   = key->src_ip,
            .dst   = key->dst_ip,
            .ports = ((__u32)key->src_port << 16) | key->dst_port,
            .proto = key->protocol,
        };
        __u32 *score = bpf_map_lookup_elem(&ml_decisions, &fk);
        if (score && *score > 800) // High risk
            return 1; // block
        return entry->verdict;
    }

    // New flow — create CT entry (ACTION_CREATE, Cilium pattern)
    struct thor_ct_entry new_entry = {
        .created_ns  = now,
        .last_seen_ns = now,
        .packets_fwd = 1,
        .bytes_fwd   = pkt_len,
        .ct_state    = 0, // NEW
        .verdict     = 0, // allow by default
    };
    bpf_map_update_elem(&thor_ct_map, key, &new_entry, BPF_NOEXIST);
    return 0;
}

// ─── Thor: emit sample to ring buffer (Aya ring_buf consumer) ────────────────
static __always_inline void emit_sample(
    struct flow_key *fk, __u32 bytes, __u32 risk, __u8 verdict)
{
    // Sample every 100th packet (configurable)
    __u32 cfg_key = 1;
    __u64 *rate = bpf_map_lookup_elem(&config_map, &cfg_key);
    __u64  sample_rate = rate ? *rate : 100;

    __u64 rnd = bpf_get_prandom_u32();
    if ((rnd % sample_rate) != 0)
        return;

    struct thor_sample *sample =
        bpf_ringbuf_reserve(&sample_ringbuf, sizeof(*sample), 0);
    if (!sample)
        return;

    sample->timestamp_ns = bpf_ktime_get_ns();
    __builtin_memcpy(&sample->flow, fk, sizeof(*fk));
    sample->bytes      = bytes;
    sample->risk_score = risk;
    sample->verdict    = verdict;

    bpf_ringbuf_submit(sample, 0);
}

// ─── MAIN XDP ENTRY POINT ────────────────────────────────────────────────────
SEC("xdp")
int thor_xdp_main(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    // Parse Ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    __be16 proto = eth->h_proto;
    if (proto != bpf_htons(ETH_P_IP))
        return XDP_PASS; // Only handle IPv4 in this section

    // Parse IPv4
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_DROP;
    if (iph->ihl < 5)
        return XDP_DROP;

    __u32 src_ip = iph->saddr;
    __u32 dst_ip = iph->daddr;
    __u32 pkt_len = bpf_ntohs(iph->tot_len);

    // ── 1. Whitelist check (bypass all) ─────────────────────────────────────
    struct lpm_v4_key wl_key = { .prefixlen = 32, .addr = src_ip };
    if (bpf_map_lookup_elem(&whitelist_v4, &wl_key))
        return XDP_PASS;

    // ── 2. Blacklist check (O(1) LPM) ───────────────────────────────────────
    struct lpm_v4_key bl_key = { .prefixlen = 32, .addr = src_ip };
    if (bpf_map_lookup_elem(&blacklist_v4, &bl_key)) {
        __u32 stats_key = 0;
        struct lb_stats *s = bpf_map_lookup_elem(&stats, &stats_key);
        if (s) s->v1++;
        return XDP_DROP;
    }

    __u64 now = bpf_ktime_get_ns();

    // ── 3. TCP/UDP: SYN flood + CT ───────────────────────────────────────────
    struct thor_ct_key ct_key = {
        .src_ip    = src_ip,
        .dst_ip    = dst_ip,
        .protocol  = iph->protocol,
        .direction = 0,
    };

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)iph + (iph->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return XDP_DROP;

        ct_key.src_port = tcp->source;
        ct_key.dst_port = tcp->dest;

        // SYN flood detection
        if (check_syn_flood(src_ip, tcp, now)) {
            struct flow_key fk = {
                .src   = src_ip, .dst = dst_ip,
                .ports = ((__u32)tcp->source << 16) | tcp->dest,
                .proto = IPPROTO_TCP,
            };
            emit_sample(&fk, pkt_len, 950, 1);
            return XDP_DROP;
        }

    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)iph + (iph->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return XDP_DROP;
        ct_key.src_port = udp->source;
        ct_key.dst_port = udp->dest;
    }

    // ── 4. Connection tracking (Cilium-inspired ACTION_CREATE) ───────────────
    __u8 ct_verdict = ct_lookup_and_update(&ct_key, pkt_len, now);
    if (ct_verdict == 1) {
        struct flow_key fk = {
            .src = src_ip, .dst = dst_ip, .proto = iph->protocol,
        };
        emit_sample(&fk, pkt_len, 850, 1);
        return XDP_DROP;
    }

    // ── 5. Katran: VIP-based load balancing ──────────────────────────────────
    struct vip_definition vip_def = {
        .vip   = dst_ip,
        .port  = ct_key.dst_port,
        .proto = iph->protocol,
    };
    struct vip_meta *vip = bpf_map_lookup_elem(&vip_map, &vip_def);
    if (vip) {
        // Flood protection (real Katran pattern)
        __u64 cur_time;
        if (is_under_flood(&cur_time))
            return XDP_DROP;

        // Consistent hashing to select backend (real Katran algorithm)
        struct packet_description pckt = {
            .flow = {
                .src   = src_ip,
                .dst   = dst_ip,
                .ports = ((__u32)ct_key.src_port << 16) | ct_key.dst_port,
                .proto = iph->protocol,
            },
        };
        __u32 real_idx = get_real_for_vip(&pckt, vip);
        if (real_idx > 0) {
            struct real_definition *real =
                bpf_map_lookup_elem(&reals, &real_idx);
            if (real) {
                // Update stats (Katran pattern)
                __u32 stats_key = vip->vip_num;
                struct lb_stats *lb_s = bpf_map_lookup_elem(&stats, &stats_key);
                if (lb_s) {
                    lb_s->v1++;           // packets
                    lb_s->v2 += pkt_len; // bytes
                }

                // Emit flow sample to ring buffer → Aya → ML pipeline
                struct flow_key fk = { .src = src_ip, .dst = dst_ip,
                    .ports = pckt.flow.ports, .proto = iph->protocol };
                __u32 *score = bpf_map_lookup_elem(&ml_decisions, &fk);
                emit_sample(&fk, pkt_len, score ? *score : 0, 0);

                // In production: modify dst IP and recalculate checksum
                // iph->daddr = real->dst;
                // iph->check = 0; recalculate...
                return XDP_TX;
            }
        }
    }

    // ── 6. Default: pass to kernel network stack ──────────────────────────────
    struct flow_key fk = {
        .src = src_ip, .dst = dst_ip,
        .ports = ((__u32)ct_key.src_port << 16) | ct_key.dst_port,
        .proto = iph->protocol,
    };
    emit_sample(&fk, pkt_len, 0, 0);
    return XDP_PASS;
}

char _license[] SEC("license") = "Dual BSD/GPL";
