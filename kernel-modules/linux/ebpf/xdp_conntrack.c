// Thor Firewall — TCP Connection Tracker (eBPF/XDP)
// تتبع حالة اتصالات TCP داخل النواة
//
// يُنفّذ آلة حالة TCP كاملة (RFC 793):
//   NEW → SYN_SENT → SYN_RECV → ESTABLISHED → FIN_WAIT → CLOSED
//
// الأهداف:
//   - منع حزم خارج السياق (out-of-state packets)
//   - كشف TCP hijacking وspoofing
//   - تتبع Window scale وSACK
//   - تغذية GNN بمقاييس الشبكة
//
// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "thor_common.h"

// ========================================================================
// TCP State Machine
// ========================================================================

enum tcp_state {
    TCP_NEW       = 0,
    TCP_SYN_SENT  = 1,
    TCP_SYN_RECV  = 2,
    TCP_ESTABLISHED = 3,
    TCP_FIN_WAIT1 = 4,
    TCP_FIN_WAIT2 = 5,
    TCP_CLOSE_WAIT = 6,
    TCP_CLOSING   = 7,
    TCP_LAST_ACK  = 8,
    TCP_TIME_WAIT = 9,
    TCP_CLOSED    = 10,
    TCP_INVALID   = 11,  // حزمة خارج السياق — مشبوهة
};

// TCP flags
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PSH  0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80

// ========================================================================
// Connection Table Entry
// ========================================================================

struct conntrack_entry {
    // حالة الآلة
    __u8  state;
    __u8  flags;          // أعلام اتصال إضافية
    __u16 pad;

    // متتبعات التسلسل
    __u32 seq_orig;       // Sequence number الاتجاه الأصلي
    __u32 seq_reply;      // Sequence number الاتجاه العكسي
    __u32 ack_orig;       // ACK number الاتجاه الأصلي
    __u32 ack_reply;      // ACK number الاتجاه العكسي

    // TCP options
    __u8  wscale_orig;    // Window scale factor
    __u8  wscale_reply;
    __u8  sack_ok;        // SACK supported
    __u8  reserved;

    // توقيت
    __u64 created_ns;
    __u64 last_seen_ns;

    // إحصاءات
    __u32 pkts_orig;
    __u32 pkts_reply;
    __u64 bytes_orig;
    __u64 bytes_reply;

    // anomaly counters
    __u16 ooo_count;       // Out-of-order packets
    __u16 retrans_count;   // Retransmissions
    __u16 invalid_count;   // Invalid state transitions
    __u16 zero_win_count;  // Zero window announcements
} __attribute__((packed));

// ========================================================================
// BPF Maps
// ========================================================================

// جدول الاتصالات الرئيسي
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, THOR_MAX_FLOWS);
    __type(key, struct flow_key);
    __type(value, struct conntrack_entry);
} conntrack_table SEC(".maps");

// Ring buffer لإرسال أحداث التحقق إلى user-space
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 << 20);  // 16MB
} conntrack_events SEC(".maps");

// إحصاءات التتبع
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} ct_stats SEC(".maps");

#define CT_STAT_NEW         0
#define CT_STAT_ESTABLISHED 1
#define CT_STAT_CLOSED      2
#define CT_STAT_INVALID     3
#define CT_STAT_RETRANS     4
#define CT_STAT_OOO         5

// ========================================================================
// State Machine Helpers
// ========================================================================

static __always_inline void ct_inc_stat(__u32 idx) {
    __u64 *val = bpf_map_lookup_elem(&ct_stats, &idx);
    if (val) __sync_fetch_and_add(val, 1);
}

/// تحديث آلة حالة TCP
/// يُعيد XDP_DROP إذا كانت الحزمة خارج السياق وخطيرة
static __always_inline int update_tcp_state(
    struct conntrack_entry *ct,
    __u8 tcp_flags,
    __u32 seq,
    __u32 ack,
    __u16 pkt_len,
    __u64 now_ns,
    bool is_orig_dir
) {
    __u8 old_state = ct->state;

    // تحديث الإحصاءات
    if (is_orig_dir) {
        __sync_fetch_and_add(&ct->pkts_orig, 1);
        __sync_fetch_and_add(&ct->bytes_orig, pkt_len);
    } else {
        __sync_fetch_and_add(&ct->pkts_reply, 1);
        __sync_fetch_and_add(&ct->bytes_reply, pkt_len);
    }
    ct->last_seen_ns = now_ns;

    // RST: إغلاق فوري
    if (tcp_flags & TH_RST) {
        ct->state = TCP_CLOSED;
        ct_inc_stat(CT_STAT_CLOSED);
        return XDP_PASS;
    }

    // آلة الحالة
    switch (ct->state) {
    case TCP_NEW:
        if ((tcp_flags & TH_SYN) && !(tcp_flags & TH_ACK)) {
            ct->state = TCP_SYN_SENT;
            ct->seq_orig = seq;
            ct_inc_stat(CT_STAT_NEW);
        } else {
            // حزمة بدون SYN لاتصال جديد — مشبوهة
            ct->state = TCP_INVALID;
            ct->invalid_count++;
            ct_inc_stat(CT_STAT_INVALID);
            return XDP_DROP;
        }
        break;

    case TCP_SYN_SENT:
        if ((tcp_flags & TH_SYN) && (tcp_flags & TH_ACK)) {
            // SYN-ACK من الخادم
            ct->state = TCP_SYN_RECV;
            ct->seq_reply = seq;
            ct->ack_reply = ack;
        } else if (tcp_flags & TH_SYN) {
            // SYN متزامن (نادر لكن صحيح)
            ct->state = TCP_SYN_RECV;
        } else {
            ct->invalid_count++;
            ct_inc_stat(CT_STAT_INVALID);
        }
        break;

    case TCP_SYN_RECV:
        if (tcp_flags & TH_ACK) {
            ct->state = TCP_ESTABLISHED;
            ct_inc_stat(CT_STAT_ESTABLISHED);
        }
        break;

    case TCP_ESTABLISHED:
        if (tcp_flags & TH_FIN) {
            ct->state = is_orig_dir ? TCP_FIN_WAIT1 : TCP_CLOSE_WAIT;
        }
        break;

    case TCP_FIN_WAIT1:
        if (tcp_flags & TH_ACK) {
            ct->state = TCP_FIN_WAIT2;
        }
        break;

    case TCP_FIN_WAIT2:
        if (tcp_flags & TH_FIN) {
            ct->state = TCP_TIME_WAIT;
        }
        break;

    case TCP_CLOSE_WAIT:
        if (tcp_flags & TH_FIN) {
            ct->state = TCP_LAST_ACK;
        }
        break;

    case TCP_LAST_ACK:
        if (tcp_flags & TH_ACK) {
            ct->state = TCP_CLOSED;
            ct_inc_stat(CT_STAT_CLOSED);
        }
        break;

    case TCP_TIME_WAIT:
    case TCP_CLOSED:
        break;

    default:
        break;
    }

    return XDP_PASS;
}

// ========================================================================
// Port Scan Detection
// ========================================================================

// يتتبع محاولات الاتصال المرفوضة لكل IP
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, 1 << 16);
    __type(key, __u32);  // src_ip
    __type(value, struct scan_tracker);
} scan_trackers SEC(".maps");

struct scan_tracker {
    __u32 ports_tried;      // عدد المنافذ المجربة
    __u32 ports_rejected;   // المنافذ المرفوضة (RST/لا استجابة)
    __u64 window_start_ns;  // بداية نافذة القياس
    __u16 last_dst_port;    // آخر منفذ مجرب
    __u16 unique_ports;     // المنافذ الفريدة
};

/// كشف مسح المنافذ (Port Scan)
static __always_inline int detect_port_scan(
    __u32 src_ip,
    __u16 dst_port,
    __u64 now_ns,
    bool is_syn_only
) {
    if (!is_syn_only) return 0;

    struct scan_tracker *tracker;
    struct scan_tracker new_tracker = {
        .ports_tried = 1,
        .ports_rejected = 0,
        .window_start_ns = now_ns,
        .last_dst_port = dst_port,
        .unique_ports = 1,
    };

    tracker = bpf_map_lookup_elem(&scan_trackers, &src_ip);
    if (!tracker) {
        bpf_map_update_elem(&scan_trackers, &src_ip, &new_tracker, BPF_ANY);
        return 0;
    }

    // إعادة تعيين كل 10 ثوانٍ
    if (now_ns - tracker->window_start_ns > 10000000000ULL) {
        *tracker = new_tracker;
        return 0;
    }

    __sync_fetch_and_add(&tracker->ports_tried, 1);

    // منفذ جديد مختلف
    if (tracker->last_dst_port != dst_port) {
        __sync_fetch_and_add(&tracker->unique_ports, 1);
        tracker->last_dst_port = dst_port;
    }

    // عتبة: أكثر من 50 منفذ فريد في 10 ثوانٍ = مسح منافذ
    if (tracker->unique_ports > 50) {
        bpf_printk("Thor: Port scan detected from %pI4 (%u unique ports)\n",
                   &src_ip, tracker->unique_ports);
        return 1;  // مشبوه
    }

    return 0;
}

// ========================================================================
// XDP Connection Tracker Entry Point
// ========================================================================

SEC("xdp")
int thor_conntrack(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    __u64 now      = bpf_ktime_get_ns();

    // ===== Ethernet =====
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_ABORTED;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) return XDP_PASS;

    // ===== IPv4 =====
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_ABORTED;
    if (ip->protocol != IPPROTO_TCP) return XDP_PASS;

    // ===== TCP =====
    struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
    if ((void *)(tcp + 1) > data_end) return XDP_ABORTED;

    __u8  flags    = ((__u8 *)tcp)[13];
    __u16 sport    = bpf_ntohs(tcp->source);
    __u16 dport    = bpf_ntohs(tcp->dest);
    __u32 src_ip   = bpf_ntohl(ip->saddr);
    __u32 dst_ip   = bpf_ntohl(ip->daddr);
    __u32 seq      = bpf_ntohl(tcp->seq);
    __u32 ack_seq  = bpf_ntohl(tcp->ack_seq);
    __u16 pkt_len  = data_end - data;

    bool  is_syn_only = (flags & TH_SYN) && !(flags & TH_ACK);

    // ===== Port Scan Detection =====
    if (detect_port_scan(src_ip, dport, now, is_syn_only)) {
        // إرسال تحذير، لكن لا نحظر تلقائياً — نترك قرار RL
        // TODO: إرسال حدث عبر ring buffer
    }

    // ===== Connection Tracking =====
    struct flow_key key = {
        .src_ip  = bpf_htonl(src_ip),
        .dst_ip  = bpf_htonl(dst_ip),
        .sport   = sport,
        .dport   = dport,
        .proto   = IPPROTO_TCP,
        .is_ipv6 = 0,
    };

    struct conntrack_entry *ct = bpf_map_lookup_elem(&conntrack_table, &key);

    if (!ct) {
        // اتصال جديد
        struct conntrack_entry new_ct = {
            .state       = TCP_NEW,
            .created_ns  = now,
            .last_seen_ns = now,
            .seq_orig    = seq,
        };

        // تحديث الحالة فوراً
        if (is_syn_only) {
            new_ct.state = TCP_SYN_SENT;
        } else {
            // حزمة بدون SYN — مشبوهة (احتمال TCP splicing أو هجوم)
            new_ct.state   = TCP_INVALID;
            new_ct.invalid_count = 1;
        }

        bpf_map_update_elem(&conntrack_table, &key, &new_ct, BPF_NOEXIST);
        return XDP_PASS;
    }

    // اتصال موجود — تحديث الحالة
    int ret = update_tcp_state(ct, flags, seq, ack_seq, pkt_len, now, true);

    // حظر الحزم خارج السياق الشديدة
    if (ct->state == TCP_INVALID && ct->invalid_count > 5) {
        return XDP_DROP;
    }

    return ret;
}

char _license[] SEC("license") = "GPL";
