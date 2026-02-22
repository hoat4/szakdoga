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
	u32 ecn_marked;
	u32 tail_drop;
	u32 ctv_drop;
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
    sch->limit = q->params.limit = 2500000;
    q->sch = sch;
    q->params.guaranteed_admission_limit = q->params.limit / 10;
    q->params.update_interval = 100;
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
            pr_debug("rank %d drop because priority too low (range: %d - %d)", rank, q->vars.min, q->vars.max);
            ++q->stats.ctv_drop;
            return qdisc_drop(skb, sch, to_free);
        }
    }

enqueue:
    if (sch->qstats.backlog + qdisc_pkt_len(skb) <= q->params.limit) {
		pr_debug("rank %d enqueue (used %d, limit %d)", rank, sch->qstats.backlog, q->params.limit);
        return qdisc_enqueue_tail(skb, sch);
    }

    pr_debug("rank %d drop because queue is full", rank);
	++q->stats.tail_drop;
	return qdisc_drop(skb, sch, to_free);

}

//if (skb_protocol(skb, true) != htons(ETH_P_IP))
static struct sk_buff *rifo_dequeue(struct Qdisc *sch)
{
	//struct rifo_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb = qdisc_dequeue_head(sch);
	//const struct iphdr *iph;
	return skb;
}


static void rifo_destroy(struct Qdisc *sch)
{
}


static void rifo_reset(struct Qdisc *sch)
{
	qdisc_reset_queue(sch);
}


static int rifo_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	return -1;
}


struct Qdisc_ops rifo_qdisc_ops __read_mostly = {
	.id		=	"rifo",
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
EXPORT_SYMBOL(rifo_qdisc_ops);

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
