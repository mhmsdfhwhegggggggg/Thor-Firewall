// SPDX-License-Identifier: GPL-2.0
// Minimal XDP filter for Thor Firewall

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

SEC("xdp")
int thor_xdp_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    if (eth->h_proto == __constant_htons(ETH_P_ARP))
        return XDP_DROP;
    
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
