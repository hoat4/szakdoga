#include "marker_common.h"
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ip.h>

struct flow_id {
    __u32 source_addr;
    __u32 source_port;
    __u32 dest_addr;
    __u32 dest_port;
};

struct flow_data {
    __u32 length;
    __u32 sent_bytes;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct flow_id);
	__type(value, struct flow_data);
} flows SEC(".maps");

SEC("classifier")
int marker_func(struct __sk_buff *skb)
{
    if (is_ip_packet(skb)) {        
        int32_t flow_length = get_flow_length(skb);
        __u16 rank = 0;
        if (flow_length != -1) {
            void *data_end = (void *)(long)skb->data_end;
            void *data = (void *)(long)skb->data;
            struct iphdr *iph = (struct iphdr *)(data + sizeof(struct ethhdr));
            uint32_t ihl = iph->ihl * 4;
            // portok TCP és UDP packetek esetén is ugyanott vannak
            struct tcphdr * tcph = (struct tcphdr *)(((void*)iph) + ihl); 

            if ((void*) (&tcph->dest + 1) > data_end || 
                (void*) (&tcph->source + 1) > data_end) {
                bpf_printk("hiba1");
                return TC_ACT_OK;
            }
        
            struct flow_id flowID = {
                .source_addr = iph->saddr, 
                .source_port = tcph->source, 
                .dest_addr = iph->daddr, 
                .dest_port = tcph->dest, 
            };
            __u32 payloadLen;
            switch (iph->protocol) {
                case IPPROTO_TCP: 
                    if ((void*) (&tcph->window /* doff */) > data_end) {
                        bpf_printk("hiba3");
                        return TC_ACT_OK;
                    }
                    payloadLen = bpf_htons(iph->tot_len) - sizeof(struct iphdr) - (tcph->doff * 4);
                    break;
                case IPPROTO_UDP:
                    payloadLen = bpf_htons(iph->tot_len) - sizeof(struct iphdr) - sizeof(struct udphdr);
                    break;
                default:
                    bpf_printk("hiba4");
                    return TC_ACT_OK;
            }

            //bpf_printk("payloadlen: %d, ip len: %d, tcp header len: %d", payloadLen, bpf_htons(iph->tot_len), tcph->doff * 4);
            bpf_printk("payloadlen: %d", payloadLen);

            struct flow_data* flowData = bpf_map_lookup_elem(&flows, &flowID);
            if (!flowData) {
                struct flow_data newFlowData = { 
                    .length = (__u32) flow_length,
                    .sent_bytes = 0
                };

                bpf_map_update_elem(&flows, &flowID, &newFlowData, BPF_NOEXIST);
                flowData = bpf_map_lookup_elem(&flows, &flowID);
                if (!flowData) {
                    // ez akkor lehet, ha kikerült a hashmapből az update és lookup hívás között, 
                    // de ahhoz rengeteg új packet párhuzamos feldolgozása kéne, ezért ez lehetetlen
                    bpf_printk("hiba2");
                    return TC_ACT_OK;
                }
            }
            
            int32_t remainingBytes = ((int32_t)flowData->length) - ((int32_t)flowData->sent_bytes);
            bpf_printk("remaining bytes: %d - %d = %d", flowData->length, flowData->sent_bytes, remainingBytes);
            if (remainingBytes < 0) {
                rank = 0;
            } else {
                rank = (__u16) isqrt32(remainingBytes); // sqrt azért kell, hogy hogy beleférjen u16-ba
            }    

            __sync_fetch_and_add(&flowData->sent_bytes, payloadLen);
        }
        
		bpf_printk("rank: %d", rank);

        set_rank(skb, rank);
    }
	return TC_ACT_OK;
}

char __license[] SEC("license") = "Dual BSD/GPL";
