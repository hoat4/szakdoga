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

#ifdef DEBUG
#define SP_PIFO_SUBQUEUE_LENGTH_BYTES 10000
#else
#define SP_PIFO_SUBQUEUE_LENGTH_BYTES 50000
#endif

// Ez a queue hossz nem jó sehogy se. 
// Ha 100k, akkor a queue telítettség lesz túl alacsony (megfogja a forgalmat
// valami még azelőtt hogy elérne ehhez a qdischez) ezáltal nem annyira veszi
// figyelembe a rankokat. 
// Ha viszont 50k, akkor meg a flow completion time rontódik.

// ez nincs használva sehol, csak reportolva a statban
#define SP_PIFO_QUEUE_LENGTH_BYTES (SP_PIFO_SUBQUEUE_LENGTH_BYTES * QUEUE_COUNT)

struct sp_pifo_sched_data {
	struct Qdisc *sch;
    
	struct sk_buff_head queues[QUEUE_COUNT];
    int bounds[QUEUE_COUNT];
	struct gnet_stats_queue qstats[QUEUE_COUNT];

    u64 latency_sum;
    u64 latency_count;
    u64 drop_because_full;
    u64 drop_because_subqueue_full;
};


static int sp_pifo_init(struct Qdisc *sch, struct nlattr *arg,
    struct netlink_ext_ack *extack)
{
    struct sp_pifo_sched_data *q = qdisc_priv(sch);
    memset(q, 0, sizeof(struct sp_pifo_sched_data));

    sch->limit = SP_PIFO_QUEUE_LENGTH_BYTES;
    
	for (int i = 0; i < QUEUE_COUNT; i++)
        __skb_queue_head_init(&q->queues[i]);

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

	struct sk_buff_head* qdisc = &q->queues[queueIndex];

	if (q->qstats[queueIndex].backlog + qdisc_pkt_len(skb) <= SP_PIFO_SUBQUEUE_LENGTH_BYTES) {
        if (nonIP) {
            pr_debug("[SP-PIFO] Enqueue non-IP to queue #%d (used %d/%d bytes)", 
                queueIndex, q->qstats[queueIndex].backlog, SP_PIFO_SUBQUEUE_LENGTH_BYTES);
        } else {
	        pr_debug("[SP-PIFO] Enqueue rank %d to queue #%d (used %d/%d bytes)", 
                rank, queueIndex, q->qstats[queueIndex].backlog, SP_PIFO_SUBQUEUE_LENGTH_BYTES);
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

    if (sch->qstats.backlog + qdisc_pkt_len(skb) <= sch->limit) {
        // másik queue-ba még belefért volna.
        // valójában nem biztos hogy befért volna, mert lehet hogy megoszlik az üres hely a sok queue-ban, 
        // de nem okoz jelentős problémát, ha néha feleslegesen adunk NET_XMIT_SUCCESS-t droppolt packetre 
        // NET_XMIT_DROP helyett.
        
        q->drop_because_subqueue_full++;
        if (nonIP) {
            pr_debug("[SP-PIFO] Drop non-IP packet because queue #%d is full; used: %d, limit: %d", 
                queueIndex, sch->q.qlen, sch->limit);
        } else {
            pr_debug("[SP-PIFO] Drop with rank %d because queue #%d is full; used: %d, limit: %d", 
                rank, queueIndex, sch->q.qlen, sch->limit);
        }
	    qdisc_drop(skb, sch, to_free);
        return NET_XMIT_SUCCESS;
    } else {
        // másik queue-ba se fért volna már bele.
        
        q->drop_because_full++;
        if (nonIP) {
            pr_debug("[SP-PIFO] Drop non-IP packet because all queues are full; used: %d, limit: %d", 
                sch->q.qlen, sch->limit);
        } else {
            pr_debug("[SP-PIFO] Drop with rank %d because all queues are full; used: %d, limit: %d", 
                rank, sch->q.qlen, sch->limit);
        }
	    return qdisc_drop(skb, sch, to_free);
    }
}

static struct sk_buff *sp_pifo_dequeue(struct Qdisc *sch)
{
	struct sp_pifo_sched_data *q = qdisc_priv(sch);

    //pr_debug("[SP-PIFO] dequeue begin");
    for (int i = 0; i < QUEUE_COUNT; i++) {
        struct sk_buff *skb = __skb_dequeue(&q->queues[i]);
    
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
            pr_debug("[SP-PIFO] dequeue latency %lld", latency);

            return skb;
        }
    }
    pr_debug("[SP-PIFO] Can't dequeue because empty");
    return NULL;
}

// TODO ez nincs tesztelve, de lehet hogy nem is hívódik meg a mérések során
static struct sk_buff *sp_pifo_peek(struct Qdisc *sch)
{
	struct sp_pifo_sched_data *q = qdisc_priv(sch);

    //pr_debug("[SP-PIFO] dequeue begin");
    for (int i = 0; i < QUEUE_COUNT; i++) {
        struct sk_buff *skb = __skb_peek(&q->queues[i]);
    
        if (skb) {
    	    if (skb_protocol(skb, true) != htons(ETH_P_IP))
    	    	pr_debug("[SP-PIFO] Peek result: non-IP from queue #%d", i);
            else {
    	        const struct iphdr *iph = ip_hdr(skb);
	            if(iph == NULL)
            		pr_debug("[SP-PIFO] Peek result: non-IP from queue #%d", i);
                else {
                    u32 rank = iph == NULL ? 0 : ntohs(iph->id);
                    pr_debug("[SP-PIFO] Peek result: packet with rank %d from queue #%d", rank, i); 
                }
            }

            return skb;
        }
    }
    pr_debug("[SP-PIFO] Can't peek because empty");
    return NULL;
}


static void sp_pifo_destroy(struct Qdisc *sch)
{
    struct sp_pifo_sched_data *q = qdisc_priv(sch);

	for (int i = 0; i < QUEUE_COUNT; i++)
		__skb_queue_purge(&q->queues[i]);
}


static void sp_pifo_reset(struct Qdisc *sch)
{
    struct sp_pifo_sched_data *q = qdisc_priv(sch);

    for (int i = 0; i < QUEUE_COUNT; i++)
		__skb_queue_purge(&q->queues[i]);

	memset(&q->qstats, 0, sizeof(q->qstats));

    q->drop_because_full = 0;
    q->drop_because_subqueue_full = 0;
    q->latency_sum = 0;
    q->latency_count = 0;
}


static int sp_pifo_dump(struct Qdisc *sch, struct sk_buff *skb)
{
    struct sp_pifo_sched_data *q = qdisc_priv(sch);

    printk(KERN_INFO "[SP-PIFO] Statistics: latency: %llu / %llu = %llu, queue usage: %u / %u, drop because full: %llu, drop because subqueue full: %llu", 
        q->latency_sum, q->latency_count, 
        q->latency_sum / (q->latency_count == 0 ? 1 : q->latency_count), 
        sch->qstats.backlog, SP_PIFO_QUEUE_LENGTH_BYTES, 
        q->drop_because_full, q->drop_because_subqueue_full);
    q->latency_sum = 0;
    q->latency_count = 0;
	return -1;
}


struct Qdisc_ops sp_pifo_qdisc_ops __read_mostly = {
#ifdef DEBUG
	.id		=	"sp_pifo_debug",
#else
	.id		=	"sp_pifo",
#endif
	.priv_size	=	sizeof(struct sp_pifo_sched_data),
	.enqueue	=	sp_pifo_enqueue,
	.dequeue	=	sp_pifo_dequeue,
	.peek		=	sp_pifo_peek,
	.init		=	sp_pifo_init,
	.destroy	=	sp_pifo_destroy,
	.reset		=	sp_pifo_reset,
	.change		=	sp_pifo_init,
	.dump		=	sp_pifo_dump,
	.owner		=	THIS_MODULE,
};

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
