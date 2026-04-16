#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/if_arp.h>
#include <net/pkt_sched.h>
#include <net/pkt_cls.h>
#include <linux/math64.h>
#include <linux/types.h>
#include "depq.h"


#define UINT32_MAX 4294967295

#ifdef DEBUG
#define PIFO_QUEUE_LENGTH_BYTES 10000
#else
#define PIFO_QUEUE_LENGTH_BYTES 100000
#endif

struct pifo_params {
    /**
     * max queue length in bytes ("B")
     */
	u32 limit;			

};

struct pifo_stats {
    u64 latency_sum;
    u64 latency_count;
    u64 dropped_new_packet;
    u64 dropped_old_packet;
};

struct pifo_vars {
    heap_t depq;
    u64 packetCounter; // ld. skb_and_rank.order
};

struct pifo_sched_data {
	struct Qdisc *sch;
	struct pifo_params params;
	struct pifo_stats stats;
	struct pifo_vars vars;
};

static int pifo_init(struct Qdisc *sch, struct nlattr *arg,
    struct netlink_ext_ack *extack)
{
    struct pifo_sched_data *q = qdisc_priv(sch);
    memset(q, 0, sizeof(struct pifo_sched_data));
    sch->limit = q->params.limit = PIFO_QUEUE_LENGTH_BYTES;
    q->sch = sch;

    int max_packets = q->params.limit / 28;

    q->vars.depq.data = vmalloc((max_packets+1) * sizeof(struct sk_buff*));
    q->vars.depq.count = 0;
    q->vars.depq.size = max_packets+1;
    q->vars.packetCounter = 0;
    pr_debug("vmalloc result %p", q->vars.depq.data);

    return 0;
}

static int pifo_enqueue(struct sk_buff *skb, struct Qdisc *sch,
			 struct sk_buff **to_free)
{
	struct pifo_sched_data *q = qdisc_priv(sch);
	const struct iphdr *iph;
	//u32 len = qdisc_pkt_len(skb);
	//q->vars.bytes += len;

    u32 rank = 0;
    //pr_debug("micsoda: %d", skb_protocol(skb, true));
    //pr_debug("skb 1: %p", skb);

    /*
	if (skb_protocol(skb, true) == htons(ETH_P_ARP)) {
        struct arphdr* arphdr = arp_hdr(skb);
        //pr_debug("arp op: %d", arphdr->ar_op);
    }
    */

    bool nonIP = true;
	if (skb_protocol(skb, true) == htons(ETH_P_IP)) {
        iph = ip_hdr(skb);
        //pr_warn("protocol: %d", iph->protocol);
    	if(iph != NULL) {
            rank = ntohs(iph->id);
            nonIP = false;
        }
    }

    // TODO mi legyen ha túl rövid? megtelik a queue


    skb_and_rank s = {
        .skb = skb, 
        .rank = rank, 
        .order = q->vars.packetCounter++
    };
    
    //pr_debug("push %p, %p", q->vars.depq.data, s);
    if (sch->qstats.backlog + qdisc_pkt_len(skb) <= q->params.limit &&
            mmh_insert(&q->vars.depq, s)) {
        sch->qstats.backlog += qdisc_pkt_len(skb);
        sch->q.qlen++; // sch_htb enélkül nem megy
        // sch_api.c-ben írják is:
        // "For complicated disciplines with multiple queues q->q is not
        //  real packet queue, but however q->q.qlen must be valid."

        if (nonIP) {
            pr_debug("[PIFO] Enqueue non-IP (used bytes: %d/%d)", sch->qstats.backlog, q->params.limit);
        } else {
	        pr_debug("[PIFO] Enqueue rank %d (used bytes: %d/%d)", rank, sch->qstats.backlog, q->params.limit);
        }

        if (skb->tstamp == 0)
            skb->tstamp = ktime_get();
        else
            printk(KERN_WARNING "[PIFO] skb->tstamp already used, latency statistics will be wrong");

        return NET_XMIT_SUCCESS;
    } else {
        // PIFO paperben nem találtam semmit limitekről, így droppolásról sem.

        if (nonIP) {
            pr_debug("[PIFO] Drop non-IP packet (used bytes: %d/%d, used packets: %d/%d)", 
                sch->qstats.backlog, q->params.limit, q->vars.depq.count, mmh_capacity(&q->vars.depq));
        } else {
            pr_debug("[PIFO] Drop with rank %d (used bytes: %d/%d, used packets: %d/%d)", 
                rank, sch->qstats.backlog, q->params.limit, q->vars.depq.count, mmh_capacity(&q->vars.depq));
        }
        q->stats.dropped_new_packet++;
        return qdisc_drop(skb, sch, to_free);
    }
}

//if (skb_protocol(skb, true) != htons(ETH_P_IP))
static struct sk_buff *pifo_dequeue(struct Qdisc *sch)
{
    pr_debug("[PIFO] dequeue begin");
	struct pifo_sched_data *q = qdisc_priv(sch);
    skb_and_rank s;
    if (mmh_pop_min(&q->vars.depq, &s)) {
        //pr_debug("deq success (%d elements)", q->vars.depq.count);
        struct sk_buff* skb = s.skb;
        //pr_debug("deq result %p, rank %d", skb, s->rank);
        sch->q.qlen--;
        sch->qstats.backlog -= qdisc_pkt_len(skb);
        
    	if (skb_protocol(skb, true) != htons(ETH_P_IP))
	    	pr_debug("[PIFO] Dequeue non-IP");
        else {
	        const struct iphdr *iph = ip_hdr(skb);
	        if(iph == NULL)
        		pr_debug("[PIFO] Dequeue non-IP");
            else {
                u32 rank = iph == NULL ? 0 : ntohs(iph->id);
                pr_debug("[PIFO] Dequeue with rank %d", rank); 
            }
        }

        ktime_t now = ktime_get();
        ktime_t latency = now - skb->tstamp;
        q->stats.latency_sum += latency;
        q->stats.latency_count++;
        pr_debug("[PIFO] dequeue latency %lld", latency);
        skb->tstamp = 0;

        return skb;
    } else {
        pr_debug("[PIFO] Can't dequeue because empty");
        return NULL;
    }
}

static struct sk_buff *pifo_peek(struct Qdisc *sch)
{
	struct pifo_sched_data *q = qdisc_priv(sch);
    skb_and_rank s;
    if (mmh_peek_min(&q->vars.depq, &s)) {
        pr_debug("peek succ");
        return s.skb;
    } else {
        pr_debug("peek fail");
        return NULL;
    }
}

static void pifo_reset(struct Qdisc *sch)
{
	struct pifo_sched_data *q = qdisc_priv(sch);
    pr_debug("[PIFO] Free %d items from minheap", q->vars.depq.count);
    if (q->vars.depq.count != sch->q.qlen)
        printk(KERN_ERR "q->vars.depq.count != sch->q.qlen: %d vs %d", q->vars.depq.count, sch->q.qlen);
    if (q->vars.depq.count > 0) {
        skb_and_rank* arr = q->vars.depq.data;
        for (int i = 1; i <= q->vars.depq.count - 1; i++) {
            arr[i].skb->next = arr[i + 1].skb;
        }
        rtnl_kfree_skbs(arr[1].skb, arr[q->vars.depq.count].skb);
        q->vars.depq.count = 0;
        sch->q.qlen = 0;
    }
    sch->qstats.backlog = 0;
    q->vars.packetCounter = 0;
    
    q->stats.latency_sum = 0;
    q->stats.latency_count = 0;
    q->stats.dropped_new_packet = 0;
    q->stats.dropped_old_packet = 0;
}


static void pifo_destroy(struct Qdisc *sch)
{
    pr_debug("[PIFO] destroy");
    pifo_reset(sch);

    struct pifo_sched_data *q = qdisc_priv(sch);
    vfree(q->vars.depq.data);
    pr_debug("[PIFO] destroy done");
}




static int pifo_dump(struct Qdisc *sch, struct sk_buff *skb)
{
    struct pifo_sched_data *q = qdisc_priv(sch);
    printk(KERN_INFO "[PIFO] Statistics: latency: %llu / %llu = %llu, drop old: %llu, drop new: %llu", 
        q->stats.latency_sum, q->stats.latency_count, 
        q->stats.latency_sum / (q->stats.latency_count == 0 ? 1 : q->stats.latency_count), 
        q->stats.dropped_old_packet, q->stats.dropped_new_packet);
    q->stats.latency_sum = 0;
    q->stats.latency_count = 0;
	return -1;
}


struct Qdisc_ops pifo_qdisc_ops __read_mostly = {
#ifdef DEBUG
	.id		=	"pifo_debug",
#else
	.id		=	"pifo",
#endif
	.priv_size	=	sizeof(struct pifo_sched_data),
	.enqueue	=	pifo_enqueue,
	.dequeue	=	pifo_dequeue,
//	.dequeue	=	qdisc_dequeue_head,
	.peek		=	pifo_peek,
	.init		=	pifo_init,
	.destroy	=	pifo_destroy,
	.reset		=	pifo_reset,
	.change		=	pifo_init,
	.dump		=	pifo_dump,
	.owner		=	THIS_MODULE,
};

static int __init pifo_module_init(void)
{
	return register_qdisc(&pifo_qdisc_ops);
}

static void __exit pifo_module_exit(void)
{
	unregister_qdisc(&pifo_qdisc_ops);
}

module_init(pifo_module_init);
module_exit(pifo_module_exit);

MODULE_DESCRIPTION("Push-In First Out packet scheduler");
MODULE_AUTHOR("Hontvári Attila");
MODULE_LICENSE("Dual BSD/GPL");
