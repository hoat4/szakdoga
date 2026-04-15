#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/pkt_sched.h>
#include <net/pkt_cls.h>
#include <linux/math64.h>

#define QUEUE_COUNT 8

struct sp_pifo_sched_data {
	struct Qdisc *sch;
    
	struct sk_buff_head qdiscs[QUEUE_COUNT];
    int bounds[QUEUE_COUNT];
	struct gnet_stats_queue qstats[QUEUE_COUNT];

    u64 latency_sum;
    u64 latency_count;
    u64 drop_because_queue_full;
};


static int sp_pifo_init(struct Qdisc *sch, struct nlattr *arg,
    struct netlink_ext_ack *extack)
{
    struct sp_pifo_sched_data *q = qdisc_priv(sch);
    memset(q, 0, sizeof(struct sp_pifo_sched_data));

    sch->limit = 50; // packetek maximális száma
    
	for (int i = 0; i < QUEUE_COUNT; i++)
        __skb_queue_head_init(&q->qdiscs[i]);

    return 0;
}

static int sp_pifo_enqueue(struct sk_buff *skb, struct Qdisc *sch,
			 struct sk_buff **to_free)
{
	struct sp_pifo_sched_data *q = qdisc_priv(sch);
    
    u32 rank = 0;
    bool nonIP = true;
    if (skb_protocol(skb, true) == htons(ETH_P_IP)) {
	    const struct iphdr* iph = ip_hdr(skb);
	    if(iph != NULL) {
            rank = ntohs(iph->id);
            nonIP = false;
        }
    }

    int queueIndex = QUEUE_COUNT - 1;
    while (queueIndex > 0 && q->bounds[queueIndex] > rank)
        queueIndex--;
    
    if (queueIndex == 0 && rank < q->bounds[queueIndex]) {
        int dec = q->bounds[queueIndex] - rank;
        pr_debug("[SP-PIFO] Push down because rank %d < %d: decrement %d from all queues", rank, q->bounds[queueIndex], dec);
        for (int i = 0; i < QUEUE_COUNT; i++) {
            q->bounds[i] -= dec;
        }
    } else {
        q->bounds[queueIndex] = rank;
    }

	struct sk_buff_head* qdisc = &q->qdiscs[queueIndex];

	if (sch->q.qlen < sch->limit) {
        if (nonIP) {
            pr_debug("[SP-PIFO] Enqueue non-IP to queue #%d (used %d/%d)", 
                queueIndex, sch->q.qlen, sch->limit);
        } else {
	        pr_debug("[SP-PIFO] Enqueue rank %d to queue #%d (used %d/%d)", 
                rank, queueIndex, sch->q.qlen, sch->limit);
        }

		__skb_queue_tail(qdisc, skb);
		qdisc_qstats_backlog_inc(sch, skb);
		q->qstats[queueIndex].backlog += qdisc_pkt_len(skb);
		sch->q.qlen++;

        if (skb->tstamp == 0)
            skb->tstamp = ktime_get();
        else
            printk(KERN_WARNING "[SP-PIFO] skb->tstamp already used, latency statistics will be wrong");

        return NET_XMIT_SUCCESS;
	}

    q->drop_because_queue_full++;
    if (nonIP) {
        pr_debug("[SP-PIFO] Drop non-IP packet; used: %d, limit: %d", sch->q.qlen, sch->limit);
    } else {
        pr_debug("[SP-PIFO] Drop with rank %d; used: %d, limit: %d", rank, sch->q.qlen, sch->limit);
    }
	return qdisc_drop(skb, sch, to_free);
}

static struct sk_buff *sp_pifo_dequeue(struct Qdisc *sch)
{
	struct sp_pifo_sched_data *q = qdisc_priv(sch);

    //pr_debug("[SP-PIFO] dequeue begin");
    for (int i = 0; i < QUEUE_COUNT; i++) {
        struct sk_buff *skb = __skb_dequeue(&q->qdiscs[i]);
    
        if (skb) {
    	    if (skb_protocol(skb, true) != htons(ETH_P_IP))
    	    	pr_debug("[SP-PIFO] Dequeue non-IP from queue #%d", i);
            else {
    	        const struct iphdr *iph = ip_hdr(skb);
	            if(iph == NULL)
            		pr_debug("[SP-PIFO] Dequeue non-IP from queue #%d", i);
                else {
                    u32 rank = iph == NULL ? 0 : ntohs(iph->id);
                    pr_debug("[SP-PIFO] Dequeue with rank %d from queue #%d", rank, i); 
                }
            }

            sch->q.qlen--;
            qdisc_qstats_backlog_dec(sch, skb);
            qdisc_bstats_update(sch, skb);
        
            q->qstats[i].backlog -= qdisc_pkt_len(skb);

            ktime_t now = ktime_get();
            ktime_t latency = now - skb->tstamp;
            q->latency_sum += latency;
            q->latency_count++;
            printk("[SP-PIFO] dequeue latency %lld", latency);
            skb->tstamp = 0;

            return skb;
        }
    }
    pr_debug("[SP-PIFO] Can't dequeue because empty");
    return NULL;
}


static void sp_pifo_destroy(struct Qdisc *sch)
{
    struct sp_pifo_sched_data *q = qdisc_priv(sch);

	for (int i = 0; i < QUEUE_COUNT; i++)
		__skb_queue_purge(&q->qdiscs[i]);
}


static void sp_pifo_reset(struct Qdisc *sch)
{
    struct sp_pifo_sched_data *q = qdisc_priv(sch);

    for (int i = 0; i < QUEUE_COUNT; i++)
		__skb_queue_purge(&q->qdiscs[i]);

	memset(&q->qstats, 0, sizeof(q->qstats));

    q->drop_because_queue_full = 0;
    q->latency_sum = 0;
    q->latency_count = 0;
}


static int sp_pifo_dump(struct Qdisc *sch, struct sk_buff *skb)
{
    struct sp_pifo_sched_data *q = qdisc_priv(sch);
    printk(KERN_INFO "[SP-PIFO] Statistics: latency: %llu / %llu = %llu, drop because full: %llu", 
        q->latency_sum, q->latency_count, 
        q->latency_sum / (q->latency_count == 0 ? 1 : q->latency_count), 
        q->drop_because_queue_full);
    q->latency_sum = 0;
    q->latency_count = 0;
	return -1;
}


struct Qdisc_ops sp_pifo_qdisc_ops __read_mostly = {
	.id		=	"sp_pifo",
	.priv_size	=	sizeof(struct sp_pifo_sched_data),
	.enqueue	=	sp_pifo_enqueue,
	.dequeue	=	sp_pifo_dequeue,
	.peek		=	qdisc_peek_head,
	.init		=	sp_pifo_init,
	.destroy	=	sp_pifo_destroy,
	.reset		=	sp_pifo_reset,
	.change		=	sp_pifo_init,
	.dump		=	sp_pifo_dump,
	.owner		=	THIS_MODULE,
};
EXPORT_SYMBOL(sp_pifo_qdisc_ops);

static int __init sp_pifo_module_init(void)
{
	return register_qdisc(&sp_pifo_qdisc_ops);
}

static void __exit sp_pifo_module_exit(void)
{
	unregister_qdisc(&sp_pifo_qdisc_ops);
}

module_init(sp_pifo_module_init);
module_exit(sp_pifo_module_exit);

MODULE_DESCRIPTION("Strict-Priority Push-In First-Out packet scheduler");
MODULE_AUTHOR("Hontvári Attila");
MODULE_LICENSE("Dual BSD/GPL");
