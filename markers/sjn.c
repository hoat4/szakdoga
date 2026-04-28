#include "marker_common.h"

SEC("classifier")
int marker_func(struct __sk_buff *skb)
{
    if (is_ip_packet(skb)) { 
        if (bpf_skb_pull_data(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr)) < 0)
            return TC_ACT_OK;

        //int32_t dstp = get_dest_port(skb);
        int32_t flow_length = get_flow_length(skb);
        __u16 rank = 0;
        if (flow_length != -1) {
            rank = (__u16) isqrt32(flow_length); // sqrt azért kell csak, hogy hogy beleférjen u16-ba
        }

		//bpf_printk("rank: %d, flow length: %d, dst port: %d", rank, flow_length, dstp);
        //bpf_printk("packet size: %d, %d\n", (long)skb->data_end-(long)skb->data, skb->len);
        //bpf_printk("dstp: %d\n", get_dest_port(skb));

		set_rank(skb, rank);
    }
	return TC_ACT_OK;
}

char __license[] SEC("license") = "Dual BSD/GPL";
