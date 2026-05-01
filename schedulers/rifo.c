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

#define UINT32_MAX 4294967295

// queue length byte-okban van mérve
#ifdef DEBUG
#define RIFO_QUEUE_LENGTH 10000
#define RIFO_UPDATE_INTERVAL 5
#else
#define RIFO_QUEUE_LENGTH 100000
#define RIFO_UPDATE_INTERVAL 100
#endif

// 100K-nál nagyobbra nem érdemes tenni a queue-t, mert nem töltődik meg (legalábbis a htb-s tesztek során nem)

struct rifo_params {
    /**
     * max queue length in bytes ("B")
     */
	u32 limit;			

    /**
     * B * k
     */
	u32 guaranteed_admission_limit;

    /**
     * reset min/max after every ... packets
     */
	u32 update_interval;
};

struct rifo_stats {
    u64 latency_sum;
    u64 latency_count;
    u64 drop_because_priority_too_low;
    u64 drop_because_queue_full;
};

struct rifo_vars {
    u32 min;
    u32 counter;
    u32 max;
};

struct rifo_sched_data {
	struct Qdisc *sch;
	struct rifo_params params;
	struct rifo_stats stats;
	struct rifo_vars vars;
};


static int rifo_init(struct Qdisc *sch, struct nlattr *arg,
    struct netlink_ext_ack *extack)
{
    struct rifo_sched_data *q = qdisc_priv(sch);
    memset(q, 0, sizeof(struct rifo_sched_data));
    sch->limit = q->params.limit = RIFO_QUEUE_LENGTH;
    q->sch = sch;
    q->params.guaranteed_admission_limit = q->params.limit / 10;
    q->params.update_interval = RIFO_UPDATE_INTERVAL;
    q->vars.min = UINT32_MAX;

    return 0;
}

static int rifo_enqueue(struct sk_buff *skb, struct Qdisc *sch,
			 struct sk_buff **to_free)
{
	struct rifo_sched_data *q = qdisc_priv(sch);
	const struct iphdr *iph;
	//u32 len = qdisc_pkt_len(skb);
	//q->vars.bytes += len;

	if (skb_protocol(skb, true) != htons(ETH_P_IP))
		goto enqueue;

	iph = ip_hdr(skb);
	u32 rank = iph == NULL ? 0 : ntohs(iph->id);
	if(iph == NULL)
		goto enqueue;


    if (q->vars.counter == q->params.update_interval) {
        q->vars.min = q->vars.max = rank;
        q->vars.counter = 1;
	} else {
        q->vars.min = rank < q->vars.min ? rank : q->vars.min;
        q->vars.max = rank > q->vars.max ? rank : q->vars.max;
        q->vars.counter++;
    }

    if (q->vars.max == q->vars.min)
        goto enqueue;
    else {
        u32 l = sch->qstats.backlog;
	    if (l <= q->params.guaranteed_admission_limit ||
            (rank - q->vars.min) * q->params.limit <= 
            (q->params.limit - l) * (q->vars.max - q->vars.min)) {

            goto enqueue;
        } else {
            pr_debug("[RIFO] rank %d drop because priority too low (used %d, limit %d: current rank range: %d-%d)", rank, sch->qstats.backlog, q->params.limit, 
                q->vars.min, q->vars.max);
            q->stats.drop_because_priority_too_low++;
            qdisc_drop(skb, sch, to_free);
            return NET_XMIT_SUCCESS;
        }
    }

enqueue:
    if (sch->qstats.backlog + qdisc_pkt_len(skb) <= q->params.limit) {
		pr_debug("[RIFO] rank %d enqueue (used %d, limit %d: current rank range: %d-%d)", rank, sch->qstats.backlog, q->params.limit, 
            q->vars.min, q->vars.max);

        if (skb->tstamp == 0)
            skb->tstamp = ktime_get();
        else
            printk(KERN_WARNING "[RIFO] skb->tstamp already used, latency statistics will be wrong");

        return qdisc_enqueue_tail(skb, sch);
    }

    pr_debug("[RIFO] rank %d drop because queue is full", rank);
	q->stats.drop_because_queue_full++;
	return qdisc_drop(skb, sch, to_free);

}

//if (skb_protocol(skb, true) != htons(ETH_P_IP))
static struct sk_buff *rifo_dequeue(struct Qdisc *sch)
{
	struct rifo_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb = qdisc_dequeue_head(sch);
    if (skb) {
    	if (skb_protocol(skb, true) != htons(ETH_P_IP))
	    	pr_debug("[RIFO] Dequeue non-IP");
        else {
	        const struct iphdr *iph = ip_hdr(skb);
	        if(iph == NULL)
        		pr_debug("[RIFO] Dequeue non-IP");
            else {
                u32 rank = iph == NULL ? 0 : ntohs(iph->id);
                pr_debug("[RIFO] Dequeue with rank %d", rank); 
            }
        }

        ktime_t now = ktime_get();
        ktime_t latency = now - skb->tstamp;
        q->stats.latency_sum += latency;
        q->stats.latency_count++;
        pr_debug("[RIFO] dequeue latency %lld", latency);
    } else {
        pr_debug("[RIFO] No packet to be dequeued");
    }
	//const struct iphdr *iph;
	return skb;
}


static void rifo_destroy(struct Qdisc *sch)
{
}


static void rifo_reset(struct Qdisc *sch)
{
	struct rifo_sched_data *q = qdisc_priv(sch);
    q->stats.latency_sum = 0;
    q->stats.latency_count = 0;
    q->stats.drop_because_priority_too_low = 0;
    q->stats.drop_because_queue_full = 0;

    qdisc_reset_queue(sch);
}


static int rifo_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct rifo_sched_data *q = qdisc_priv(sch);
    printk(KERN_INFO "[RIFO] Statistics: latency: %llu / %llu = %llu, queue usage: %u / %u, drop because full: %llu, drop because priority too low: %llu", 
        q->stats.latency_sum, q->stats.latency_count, 
        q->stats.latency_sum / (q->stats.latency_count == 0 ? 1 : q->stats.latency_count), 
        sch->qstats.backlog, RIFO_QUEUE_LENGTH, 
        q->stats.drop_because_queue_full, q->stats.drop_because_priority_too_low);
    q->stats.latency_sum = 0;
    q->stats.latency_count = 0;
	return -1;
}


struct Qdisc_ops rifo_qdisc_ops __read_mostly = {
#ifdef DEBUG
	.id		=	"rifo_debug",
#else
	.id		=	"rifo",
#endif
	.priv_size	=	sizeof(struct rifo_sched_data),
	.enqueue	=	rifo_enqueue,
	.dequeue	=	rifo_dequeue,
//	.dequeue	=	qdisc_dequeue_head,
	.peek		=	qdisc_peek_head,
	.init		=	rifo_init,
	.destroy	=	rifo_destroy,
	.reset		=	rifo_reset,
	.change		=	rifo_init,
	.dump		=	rifo_dump,
	.owner		=	THIS_MODULE,
};

static int __init rifo_module_init(void)
{
	return register_qdisc(&rifo_qdisc_ops);
}

static void __exit rifo_module_exit(void)
{
	unregister_qdisc(&rifo_qdisc_ops);
}

module_init(rifo_module_init);
module_exit(rifo_module_exit);

MODULE_DESCRIPTION("Range-In First Out packet scheduler");
MODULE_AUTHOR("Hontvári Attila");
MODULE_LICENSE("Dual BSD/GPL");
