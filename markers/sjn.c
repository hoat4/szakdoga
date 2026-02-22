#include "marker_common.h"

SEC("classifier")
int marker_func(struct __sk_buff *skb)
{
    if (is_ip_packet(skb)) {
        int32_t flow_length = get_flow_length(skb);
        __u16 rank = 0;
        if (flow_length != -1) {
            rank = (__u16) isqrt32(flow_length); // sqrt azért kell csak, hogy hogy beleférjen u16-ba
        }

		//bpf_printk("rank: %d, flow length: %d", rank, flow_length);

		set_rank(skb, rank);
    }
	return TC_ACT_OK;
}

char __license[] SEC("license") = "Dual BSD/GPL";
