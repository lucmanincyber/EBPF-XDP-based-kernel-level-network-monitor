#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include "common.h"

// Bulletproof byte-swapping macro fallbacks for Clang LLVM BPF compilation
#ifndef bpf_htons
#define bpf_htons(x) __builtin_bswap16(x)
#endif

#ifndef bpf_ntohs
#define bpf_ntohs(x) __builtin_bswap16(x)
#endif

// Define the ring buffer map to pass packet metadata to user-space
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16); // 64KB buffer allocation
} pkt_ringbuf SEC(".maps");

SEC("xdp")
int xdp_monitor_func(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Parse Ethernet Frame header boundaries
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Isolate IP Packets (Ignore IPv6 / ARP for this sequence)
if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Reserve space within the ring buffer for safe asynchronous tracking
    struct pkt_meta *meta;
    meta = bpf_ringbuf_reserve(&pkt_ringbuf, sizeof(*meta), 0);
    if (!meta)
        return XDP_PASS; // Pass along if buffer pipeline is saturated

    // Harvest core structural markers
    meta->src_ip   = ip->saddr;
    meta->dst_ip   = ip->daddr;
    meta->protocol = ip->protocol;
    meta->pkt_len  = data_end - data;
    meta->src_port = 0;
    meta->dst_port = 0;

    // Deep inspect payload maps for Layer 4 validation metrics
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) <= data_end) {
            meta->src_port = bpf_ntohs(tcp->source);
            meta->dst_port = bpf_ntohs(tcp->dest);
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) <= data_end) {
            meta->src_port = bpf_ntohs(udp->source);
            meta->dst_port = bpf_ntohs(udp->dest);
        }
    }

    // Push telemetry up to the user-space daemon
    bpf_ringbuf_submit(meta, 0);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
