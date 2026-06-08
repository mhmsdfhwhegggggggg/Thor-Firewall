// Thor Firewall — eBPF Connection Tracking
// ==========================================
// مستوحى من: https://github.com/cilium/cilium (connection tracking)
// مستوحى من: https://github.com/cilium/tetragon (process tracing)
//
// يُتابع حالة كل TCP connection في BPF maps:
//   NEW → SYN_SENT → ESTABLISHED → FIN_WAIT → CLOSED
//
// يتكامل مع:
//   - xdp_filter.bpf.c (تشترك في نفس flow_table map)
//   - thor-agent (Rust, Aya loader)
//   - control-plane (يقرأ حالات التدفقات)
//
// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_ENTRIES     1000000
#define TCP_TIMEOUT_NS  (120ULL * 1000000000)  // 120 seconds
#define UDP_TIMEOUT_NS  (30ULL  * 1000000000)  // 30 seconds
#define ICMP_TIMEOUT_NS (10ULL  * 1000000000)  // 10 seconds

// ─────────────────────────────────────────────────────────────────────────────
// Connection States (مستوحى من Cilium conntrack)
// ─────────────────────────────────────────────────────────────────────────────

enum ct_state {
    CT_NEW          = 0,
    CT_SYN_SENT     = 1,
    CT_SYN_RECV     = 2,
    CT_ESTABLISHED  = 3,
    CT_FIN_WAIT1    = 4,
    CT_FIN_WAIT2    = 5,
    CT_TIME_WAIT    = 6,
    CT_CLOSE_WAIT   = 7,
    CT_CLOSING      = 8,
    CT_CLOSED       = 9,
    CT_RELATED      = 10,   // ICMP error packets
    CT_INVALID      = 255,
};

enum ct_direction {
    CT_DIR_REQUEST  = 0,    // client → server
    CT_DIR_REPLY    = 1,    // server → client
};

// ─────────────────────────────────────────────────────────────────────────────
// Data Structures
// ─────────────────────────────────────────────────────────────────────────────

struct ct_key {
    __be32  src_ip;
    __be32  dst_ip;
    __be16  src_port;
    __be16  dst_port;
    __u8    protocol;
    __u8    _pad[3];
};

struct ct_entry {
    __u64   created_ns;         // creation timestamp
    __u64   last_seen_ns;       // last packet timestamp
    __u64   packets_fwd;        // forward direction packets
    __u64   bytes_fwd;          // forward direction bytes
    __u64   packets_rev;        // reverse direction packets
    __u64   bytes_rev;          // reverse direction bytes
    __u32   flags;              // TCP flags seen
    __u8    state;              // ct_state
    __u8    direction;          // ct_direction
    __u8    syn_count;          // SYN retransmissions (DDoS detection)
    __u8    verdict;            // 0=allow, 1=block, 2=pending
    __u32   risk_score;         // [0, 1000] from ML (scaled)
    __u32   agent_id;           // which ML agent decided
};

// ─────────────────────────────────────────────────────────────────────────────
// BPF Maps
// ─────────────────────────────────────────────────────────────────────────────

// Main connection tracking table (shared with xdp_filter.bpf.c)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct ct_key);
    __type(value, struct ct_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);  // pin for userspace access (Aya)
} thor_conntrack_table SEC(".maps");

// Reverse lookup (reply → request mapping)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct ct_key);
    __type(value, struct ct_key);
} thor_conntrack_rev SEC(".maps");

// Per-CPU packet counters (lockless)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} thor_ct_stats SEC(".maps");

// Ring buffer for new connection events → userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 32 * 1024 * 1024);  // 32MB
} thor_ct_events SEC(".maps");

// ─────────────────────────────────────────────────────────────────────────────
// CT Events (for userspace consumption via Aya)
// ─────────────────────────────────────────────────────────────────────────────

struct ct_event {
    __u64           timestamp_ns;
    struct ct_key   key;
    __u8            event_type;   // 0=new, 1=update, 2=destroy
    __u8            old_state;
    __u8            new_state;
    __u8            _pad;
    struct ct_entry entry;
};

// ─────────────────────────────────────────────────────────────────────────────
// Helper: Create reverse key (reply direction)
// ─────────────────────────────────────────────────────────────────────────────

static __always_inline void
make_rev_key(const struct ct_key *fwd, struct ct_key *rev)
{
    rev->src_ip   = fwd->dst_ip;
    rev->dst_ip   = fwd->src_ip;
    rev->src_port = fwd->dst_port;
    rev->dst_port = fwd->src_port;
    rev->protocol = fwd->protocol;
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: Emit event to ring buffer
// ─────────────────────────────────────────────────────────────────────────────

static __always_inline void
emit_ct_event(
    const struct ct_key   *key,
    const struct ct_entry *entry,
    __u8  event_type,
    __u8  old_state,
    __u8  new_state
)
{
    struct ct_event *ev = bpf_ringbuf_reserve(&thor_ct_events, sizeof(*ev), 0);
    if (!ev)
        return;

    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->key          = *key;
    ev->event_type   = event_type;
    ev->old_state    = old_state;
    ev->new_state    = new_state;
    ev->entry        = *entry;

    bpf_ringbuf_submit(ev, 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// TCP State Machine (مستوحى من Cilium ct.h)
// ─────────────────────────────────────────────────────────────────────────────

static __always_inline __u8
tcp_ct_transition(__u8 state, __u32 tcp_flags, __u8 direction)
{
    __u8 syn = (tcp_flags & 0x02) != 0;
    __u8 ack = (tcp_flags & 0x10) != 0;
    __u8 fin = (tcp_flags & 0x01) != 0;
    __u8 rst = (tcp_flags & 0x04) != 0;

    if (rst)
        return CT_CLOSED;

    switch (state) {
    case CT_NEW:
    case CT_CLOSED:
        if (syn && !ack)         return CT_SYN_SENT;
        break;
    case CT_SYN_SENT:
        if (syn && ack)          return CT_SYN_RECV;
        if (syn)                 return CT_SYN_SENT;  // retransmission
        break;
    case CT_SYN_RECV:
        if (ack && !syn && !fin) return CT_ESTABLISHED;
        break;
    case CT_ESTABLISHED:
        if (fin)                 return (direction == CT_DIR_REQUEST) ?
                                        CT_FIN_WAIT1 : CT_CLOSE_WAIT;
        break;
    case CT_FIN_WAIT1:
        if (fin && ack)          return CT_TIME_WAIT;
        if (ack)                 return CT_FIN_WAIT2;
        break;
    case CT_FIN_WAIT2:
        if (fin)                 return CT_TIME_WAIT;
        break;
    case CT_CLOSE_WAIT:
        if (fin)                 return CT_CLOSING;
        break;
    }
    return state;  // no transition
}

// ─────────────────────────────────────────────────────────────────────────────
// Main TC Classifier Program (TC_ACT_OK / TC_ACT_SHOT)
// ─────────────────────────────────────────────────────────────────────────────

SEC("tc/conntrack")
int thor_conntrack(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    struct ct_key key  = {};
    __u32  tcp_flags   = 0;

    if (bpf_ntohs(eth->h_proto) == ETH_P_IP) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return TC_ACT_OK;

        key.src_ip   = ip->saddr;
        key.dst_ip   = ip->daddr;
        key.protocol = ip->protocol;

        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)(ip + 1);
            if ((void *)(tcp + 1) > data_end)
                return TC_ACT_OK;
            key.src_port = tcp->source;
            key.dst_port = tcp->dest;
            tcp_flags    = ((__u32)tcp->fin) | ((__u32)tcp->syn << 1) |
                           ((__u32)tcp->rst << 2) | ((__u32)tcp->psh << 3) |
                           ((__u32)tcp->ack << 4) | ((__u32)tcp->urg << 5);
        } else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (void *)(ip + 1);
            if ((void *)(udp + 1) > data_end)
                return TC_ACT_OK;
            key.src_port = udp->source;
            key.dst_port = udp->dest;
        }
    } else {
        return TC_ACT_OK;  // IPv6 handled separately
    }

    __u64 now = bpf_ktime_get_ns();

    // Lookup forward entry
    struct ct_entry *entry = bpf_map_lookup_elem(&thor_conntrack_table, &key);
    if (entry) {
        // Existing connection — update
        __u8 old_state = entry->state;

        entry->last_seen_ns = now;
        entry->packets_fwd++;
        entry->bytes_fwd += skb->len;
        entry->flags     |= tcp_flags;

        if (key.protocol == IPPROTO_TCP) {
            __u8 new_state = tcp_ct_transition(old_state, tcp_flags, CT_DIR_REQUEST);
            entry->state = new_state;

            if (new_state != old_state)
                emit_ct_event(&key, entry, 1, old_state, new_state);

            if (new_state == CT_CLOSED) {
                bpf_map_delete_elem(&thor_conntrack_table, &key);
                return TC_ACT_OK;
            }
        }

        // Check verdict (set by ML inference in userspace)
        if (entry->verdict == 1)
            return TC_ACT_SHOT;  // BLOCK

        return TC_ACT_OK;  // ALLOW
    }

    // Check reply direction
    struct ct_key rev_key;
    make_rev_key(&key, &rev_key);
    struct ct_entry *rev_entry = bpf_map_lookup_elem(&thor_conntrack_table, &rev_key);
    if (rev_entry) {
        rev_entry->last_seen_ns = now;
        rev_entry->packets_rev++;
        rev_entry->bytes_rev += skb->len;

        if (key.protocol == IPPROTO_TCP) {
            __u8 old_state = rev_entry->state;
            __u8 new_state = tcp_ct_transition(old_state, tcp_flags, CT_DIR_REPLY);
            rev_entry->state = new_state;
            if (new_state != old_state)
                emit_ct_event(&rev_key, rev_entry, 1, old_state, new_state);
        }

        if (rev_entry->verdict == 1)
            return TC_ACT_SHOT;

        return TC_ACT_OK;
    }

    // New connection — create entry
    struct ct_entry new_entry = {
        .created_ns  = now,
        .last_seen_ns = now,
        .packets_fwd = 1,
        .bytes_fwd   = skb->len,
        .flags       = tcp_flags,
        .state       = (key.protocol == IPPROTO_TCP && (tcp_flags & 0x02)) ?
                       CT_SYN_SENT : CT_NEW,
        .direction   = CT_DIR_REQUEST,
        .verdict     = 2,  // 2 = pending (ML decision needed)
    };

    bpf_map_update_elem(&thor_conntrack_table, &key, &new_entry, BPF_ANY);

    // Also insert reverse entry for reply tracking
    struct ct_entry rev_new = new_entry;
    rev_new.direction = CT_DIR_REPLY;
    bpf_map_update_elem(&thor_conntrack_table, &rev_key, &rev_new, BPF_ANY);

    // Emit NEW event to userspace (Aya ring buffer consumer)
    emit_ct_event(&key, &new_entry, 0, CT_NEW, new_entry.state);

    // Stats update (per-CPU, lockless)
    __u32 idx = 0;
    __u64 *counter = bpf_map_lookup_elem(&thor_ct_stats, &idx);
    if (counter)
        __sync_fetch_and_add(counter, 1);

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
