#ifndef __COMMON_H
#define __COMMON_H

#include <linux/types.h>

struct pkt_meta {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u32 pkt_len;
    __u8  protocol;
};

#endif
