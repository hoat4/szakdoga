#include <stdint.h>
#include <stdlib.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/stddef.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdbool.h>

#define IP_OFF		(sizeof(struct ethhdr))

inline bool is_ip_packet(struct __sk_buff * skb) {
    return skb->protocol == bpf_htons(ETH_P_IP);
}

/* Get the source port of a TCP or UDP flow.
 * Returning -1 if the packet is malformed or protocol not IP+TCP/UDP
 * */
inline int32_t get_dest_port(struct __sk_buff *skb)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;

	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		if (data + sizeof(struct ethhdr) > data_end)
			return -1;
        struct iphdr *iph = (struct iphdr *)(data + sizeof(struct ethhdr));
		if ((void *)(iph + 1) > data_end)
			return -1;
        uint32_t ihl = iph->ihl * 4;
		if (((void *)iph) + ihl > data_end)
			return -1;

		if (iph->protocol == IPPROTO_TCP) {
			struct tcphdr *tcp = (struct tcphdr *)(((void *)iph) + ihl);
			if ((void *)(tcp + 1) > data_end)
				return -1;
			return bpf_htons(tcp->dest);
		} else if(iph->protocol == IPPROTO_UDP) {
			struct udphdr *udp = (struct udphdr *)(((void *)iph) + ihl);
			if ((void *)(udp + 1) > data_end)
				return -1;
			return bpf_htons(udp->dest);
		}
	}
	return -1;
}

static inline int32_t get_flow_length(struct __sk_buff *skb) {  
    int32_t port = get_dest_port(skb);
    switch (port) {
        case 50001: return 100;
        case 50002: return 500;
        case 50003: return 1000;
        case 50004: return 5000;
        case 50005: return 10000;
        case 50006: return 50000;
        case 50007: return 100000;
        case 50008: return 500000;
        case 50009: return 1000000;
        case 50010: return 5000000;
        case 50011: return 10000000;
        case 50012: return 50000000;
        case 50013: return 100000000;
        case 50014: return 500000000;
        case 50015: return 1000000000;
        default: return -1;
    }
}

static inline void set_rank(struct __sk_buff *skb, __u16 rank) {
    __u16 rank_to_mark = bpf_htons(rank);
    __u16 old_id;
    bpf_skb_load_bytes(skb, IP_OFF + offsetof(struct iphdr, id), &old_id, 2);
    bpf_l3_csum_replace(skb, IP_OFF + offsetof(struct iphdr, check), old_id, rank_to_mark, 2);

    /* put the rank into the id field if the IPv4 */
    int ret = bpf_skb_store_bytes(skb, IP_OFF + offsetof(struct iphdr, id), &rank_to_mark, 2, 0);
    if(ret < 0)
        bpf_printk("bpf_skb_store_bytes vacak");
}

// https://stackoverflow.com/questions/65986056/is-there-a-non-looping-unsigned-32-bit-integer-square-root-function-c
static const uint8_t clz_tab[32] = 
{
    31, 22, 30, 21, 18, 10, 29,  2, 20, 17, 15, 13, 9,  6, 28, 1,
    23, 19, 11,  3, 16, 14,  7, 24, 12,  4,  8, 25, 5, 26, 27, 0
};
uint8_t clz32 (uint32_t a)
{
    a |= a >> 16;
    a |= a >> 8;
    a |= a >> 4;
    a |= a >> 2;
    a |= a >> 1;
    return clz_tab [0x07c4acdd * a >> 27];
}
uint16_t isqrt32(uint32_t x)
{
    int lz = clz32(x | 1) & 30;
    x <<= lz;
    uint32_t y = 1 + (x >> 30);
    y = (y << 1) + (x >> 27) / y;
    y = (y << 3) + (x >> 21) / y;
    y = (y << 7) + (x >> 9) / y;
    y -= x < (uint32_t)y * y;
    return y >> (lz >> 1);
}
