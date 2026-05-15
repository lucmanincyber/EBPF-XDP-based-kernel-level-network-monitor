#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
// For XDP flags definition
#include <linux/if_link.h>
#include "common.h"
#include "xdp_monitor.skel.h"

static volatile bool keep_running = true;
static void sig_handler(int signo) { keep_running = false; }

// Cyberdeck Monospaced Terminal Palettes
#define CLR_SCR()      printf("\033[H\033[J")
#define AMBER          "\033[38;5;214m"
#define AMBER_BLINK    "\033[38;5;214;5m"
#define CRIMSON        "\033[38;5;196m"
#define BRUTAL_INV     "\033[7;38;5;196m" 
#define WARN_BG        "\033[48;5;214;30m" 
#define RESET          "\033[0m"

void print_header(const char* ifname) {
    CLR_SCR();
    printf(CRIMSON "◆=============================================================================◆\n" RESET);
    printf(BRUTAL_INV " NET-SCAN SUB-ROUTINE ACTIVE " RESET AMBER " // SYS_DECK_MODE: ONLINE // NODE: %s \n" RESET, ifname);
    printf(CRIMSON "◆=============================================================================◆\n" RESET);
    printf(AMBER " %-8s │ %-15s │ %-5s │ %-15s │ %-5s │ %-8s\n" RESET, 
           "TAG", "SRC_ADDR", "PORT", "DST_ADDR", "PORT", "LEN_BYTES");
    printf(CRIMSON "-------------------------------------------------------------------------------\n" RESET);
}
static int handle_packet(void *ctx, void *data, size_t data_sz) {
    const struct pkt_meta *meta = data;
    struct in_addr src_addr = { .s_addr = meta->src_ip };
    struct in_addr dst_addr = { .s_addr = meta->dst_ip };
    
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &src_addr, src_ip_str, sizeof(src_ip_str));
    inet_ntop(AF_INET, &dst_addr, dst_ip_str, sizeof(dst_ip_str));

    char proto_tag[32]; 
    char sport_str[10] = "----", dport_str[10] = "----";

    if (meta->protocol == IPPROTO_TCP) {
        snprintf(proto_tag, sizeof(proto_tag), AMBER "[TCP]");
        snprintf(sport_str, sizeof(sport_str), "%d", meta->src_port);
        snprintf(dport_str, sizeof(dport_str), "%d", meta->dst_port);
    } else if (meta->protocol == IPPROTO_UDP) {
        snprintf(proto_tag, sizeof(proto_tag), CRIMSON "[UDP]");
        snprintf(sport_str, sizeof(sport_str), "%d", meta->src_port);
        snprintf(dport_str, sizeof(dport_str), "%d", meta->dst_port);
    } else if (meta->protocol == IPPROTO_ICMP) {
        snprintf(proto_tag, sizeof(proto_tag), WARN_BG " ICMP " RESET);
    } else {
        snprintf(proto_tag, sizeof(proto_tag), AMBER "UNK_%02X", meta->protocol);
    }

    printf(" %-17s │ %-15s │ %-5s │ %-15s │ %-5s │ %-8u\n", 
           proto_tag, src_ip_str, sport_str, dst_ip_str, dport_str, meta->pkt_len);

    return 0;
}
nt main(int argc, char **argv) {
    struct xdp_monitor_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err = 0, ifindex;
    
    if (argc < 2) {
        fprintf(stderr, CRIMSON "ERR: OPERATOR MUST SPECIFY INTERFACE LINK\n" RESET);
        return 1;
    }

    char *ifname = *(argv + 1);

    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, CRIMSON "ERR: LINK SPECIFICATION CORRUPTED (%s)\n" RESET, ifname);
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    struct rlimit rlim = { .rlim_cur = RLIM_INFINITY, .rlim_max = RLIM_INFINITY };
    setrlimit(RLIMIT_MEMLOCK, &rlim);

    skel = xdp_monitor_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, CRIMSON "ERR: KERNEL BPF LOADING FAULT\n" RESET);
        return 1;
    }

    int prog_fd = bpf_program__fd(skel->progs.xdp_monitor_func);
    
    // Using DECLARE_LIBBPF_OPTS macro safely inside main
    DECLARE_LIBBPF_OPTS(bpf_xdp_attach_opts, opts, .old_prog_fd = 0);
    
    // Force generic SKB mode to sweep away existing locks or driver conflicts
    err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, &opts);
    if (err < 0) {
 // Clear any orphaned interface references and try a hot retry
        bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
        err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, &opts);
        if (err < 0) {
            fprintf(stderr, CRIMSON "ERR: KERNEL REJECTED XDP INTERCEPT ATTACH [%d]\n" RESET, err);
            goto cleanup;
        }
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.pkt_ringbuf), handle_packet, NULL, NULL);
    if (!rb) {
        fprintf(stderr, CRIMSON "ERR: DATA_RING INITIALIZATION VOID\n" RESET);
        goto cleanup;
    }

    print_header(ifname);

    while (keep_running) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            err = 0;
            continue;
        }
        if (err < 0) break;
    }

cleanup:
    bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
    printf("\n" AMBER_BLINK ">> DE-COUPLING CORRUPT HOOKS... EXECUTION HALTED.\n" RESET);
    if (rb) ring_buffer__free(rb);
    xdp_monitor_bpf__destroy(skel);
    return err ? 1 : 0;
}


static int handle_packet(void *ctx, void *data, size_t data_sz) {
