#include "marker_common.h"
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ip.h>

// minden packetnél kiírja hogy mennyi a flowsize, remaining bytes, rank
#define SRTF_VERBOSE 0

struct flow_id {
    __u32 source_addr;
    __u32 source_port;
    __u32 dest_addr;
    __u32 dest_port;
};

struct flow_data {
    bool is_tcp;

    // UDP:
    __u32 sent_bytes;

    // TCP:
    __u32 initial_sequence_number;
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
        if (bpf_skb_pull_data(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr)) < 0)
            return TC_ACT_OK;
       
        void *data = (void *)(long)skb->data;
        struct iphdr *iph = (struct iphdr *)(data + sizeof(struct ethhdr));
       
        void *data_end = (void *)(long)skb->data_end;

        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
            bpf_printk("no full IP packet header (1)");
            return TC_ACT_OK;
        }

        if (iph->protocol == IPPROTO_TCP) {
            uint32_t ihl_in_bytes = iph->ihl * 4;
            if (bpf_skb_pull_data(skb, sizeof(struct ethhdr) + ihl_in_bytes + sizeof(struct tcphdr)) < 0) {
                bpf_printk("failed to pull TCP header");
                return TC_ACT_OK;
            }
        }

        //bpf_printk("dstport %d\n", get_dest_port(skb));
        int32_t flow_length = get_flow_length(skb);
        __u16 rank = 0;
        if (flow_length != -1) {
            // lehet hogy bpf_skb_pull_data által megváltozott
            data = (void *)(long)skb->data;
            iph = (struct iphdr *)(data + sizeof(struct ethhdr));
            data_end = (void *)(long)skb->data_end;

            if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
                bpf_printk("no full IP packet header (2)");
                return TC_ACT_OK;
            }

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
            //bpf_printk("payloadlen: %d", payloadLen);
            //bpf_printk("flowid: %d, %d -> %d, %d\n", 
            //    flowID.source_addr, flowID.source_port, 
            //    flowID.dest_addr, flowID.dest_port);

            struct flow_data* flowData = bpf_map_lookup_elem(&flows, &flowID);
            if (!flowData) {
                bool is_tcp = false;
                __u32 initial_sequence_number = 0;

                if (iph->protocol == IPPROTO_TCP && (void*) (&tcph->window /* doff */) <= data_end) {
                    initial_sequence_number = bpf_ntohl(tcph->seq);
                    is_tcp = true;
                }

                struct flow_data newFlowData = { 
                    .initial_sequence_number = initial_sequence_number,
                    .sent_bytes = 0, 
                    .is_tcp = is_tcp
                };

                if (!bpf_map_update_elem(&flows, &flowID, &newFlowData, BPF_NOEXIST)) {
                    bpf_printk("bpf_map_update_elem failed");
                }
                flowData = bpf_map_lookup_elem(&flows, &flowID);
                if (!flowData) {
                    // ez akkor lehet, ha kikerült a hashmapből az update és lookup hívás között, 
                    // de ahhoz rengeteg új packet párhuzamos feldolgozása kéne, ezért ez lehetetlen
                    bpf_printk("hiba2");
                    return TC_ACT_OK;
                }
            }
            
            int32_t sent_bytes;

            if (flowData->is_tcp) {
		        //bpf_printk("flow is tcp");
                if (iph->protocol == IPPROTO_TCP && (void*) (&tcph->window /* doff */) <= data_end) {
                    // ez így nem pontos, mert pl. a SYN is asszem 1-gyel növeli a sequence numbert, de nem baj ha csak kicsit pontatlan
                    sent_bytes = bpf_ntohl(tcph->seq) - flowData->initial_sequence_number;
    		        //bpf_printk("seq is %d", tcph->seq);
    		        //bpf_printk("sent_bytes %d", sent_bytes);
                } else {
                    sent_bytes = 0;
                    //bpf_printk("was TCP but currently not");
                }
            } else {
		        //bpf_printk("flow is udp");
                sent_bytes = (int32_t) flowData->sent_bytes;
            }

            int32_t remainingBytes = flow_length - sent_bytes;
            if (remainingBytes < 0) {
                rank = 0;
            } else {
                rank = (__u16) isqrt32(remainingBytes); // sqrt azért kell, hogy hogy beleférjen u16-ba
            }    

            if (SRTF_VERBOSE)
                bpf_printk("[SRTF] %d:%d->%d:%d Remaining bytes: %d - %d = %d; rank = %d", 
                    bpf_ntohl(flowID.source_addr), bpf_ntohs(flowID.source_port), 
                    bpf_ntohl(flowID.dest_addr), bpf_ntohs(flowID.dest_port), 
                    flow_length, sent_bytes, remainingBytes, 
                    rank);
            
            if (!flowData->is_tcp)
                __sync_fetch_and_add(&flowData->sent_bytes, payloadLen);
        }
        
		//bpf_printk("rank: %d", rank);

        set_rank(skb, rank);
    }
	return TC_ACT_OK;
}

char __license[] SEC("license") = "Dual BSD/GPL";
