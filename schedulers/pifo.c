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
#include <linux/min_heap.h>
#include <linux/types.h>


#define UINT32_MAX 4294967295

struct pifo_params {
    /**
     * max queue length in bytes ("B")
     */
	u32 limit;			

};

struct pifo_stats {
	u32 droppedNewPacket;
    u32 droppedOldPacket;
};

struct pifo_vars {
    struct min_heap min_heap;
};

struct pifo_sched_data {
	struct Qdisc *sch;
	struct pifo_params params;
	struct pifo_stats stats;
	struct pifo_vars vars;
};


typedef struct skb_and_rank {
    struct sk_buff* skb;
    u32 rank;
} skb_and_rank;

bool rank_less_than(const void *lhs, const void *rhs);

bool rank_less_than(const void *lhs, const void *rhs) {
    return ((skb_and_rank *)lhs)->rank < ((skb_and_rank *)rhs)->rank;
}

void skb_and_rank_swap(void *a, void *b);

void skb_and_rank_swap(void *a, void *b) {
    skb_and_rank *a0 = (skb_and_rank*) a, *b0 = (skb_and_rank*) b;
    skb_and_rank tmp = *a0;
    *a0 = *b0;
    *b0 = tmp;
}

struct min_heap_callbacks min_heap_callbacks = {
    .elem_size = sizeof(skb_and_rank),
    .less = rank_less_than, 
    .swp  = skb_and_rank_swap,
};

static int pifo_init(struct Qdisc *sch, struct nlattr *arg,
    struct netlink_ext_ack *extack)
{
    struct pifo_sched_data *q = qdisc_priv(sch);
    memset(q, 0, sizeof(struct pifo_sched_data));
    sch->limit = q->params.limit = 2500000;
    q->sch = sch;

    int max_packets = q->params.limit / 28;

    q->vars.min_heap.data = vmalloc(max_packets * sizeof(struct sk_buff*));
    q->vars.min_heap.nr = 0;
    q->vars.min_heap.size = max_packets;
    pr_debug("vmalloc result %p", q->vars.min_heap.data);

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

	if (skb_protocol(skb, true) == htons(ETH_P_ARP)) {
        struct arphdr* arphdr = arp_hdr(skb);
        //pr_debug("arp op: %d", arphdr->ar_op);
    }

	if (skb_protocol(skb, true) == htons(ETH_P_IP)) {
        iph = ip_hdr(skb);
        //pr_warn("protocol: %d", iph->protocol);
    	if(iph != NULL)
            rank = ntohs(iph->id);
    }

    // TODO mi legyen ha túl rövid? megtelik a queue


    skb_and_rank s = {
        .skb = skb, 
        .rank = rank
    };
    
    if (sch->qstats.backlog + qdisc_pkt_len(skb) > q->params.limit) {
        pr_debug("drop");
        q->stats.droppedNewPacket++;
        return qdisc_drop(skb, sch, to_free);
    } else {
        //pr_debug("push %p, %p", q->vars.min_heap.data, &min_heap_callbacks);
        min_heap_push(&(q->vars.min_heap), &s, &min_heap_callbacks);
        sch->qstats.backlog += qdisc_pkt_len(skb);
        sch->q.qlen++; // sch_htb enélkül nem megy

        
        //pr_warn("enq success (%d elements)", q->vars.min_heap.nr);
        skb_and_rank* s = (skb_and_rank*) q->vars.min_heap.data;
        //pr_warn("read from %p", s);
        skb = s->skb;
        //pr_warn("enq result %p, rank %d", skb, s->rank);
        

        return NET_XMIT_SUCCESS;
    }
}

//if (skb_protocol(skb, true) != htons(ETH_P_IP))
static struct sk_buff *pifo_dequeue(struct Qdisc *sch)
{
	struct pifo_sched_data *q = qdisc_priv(sch);
    if (q->vars.min_heap.nr > 0) {
        //pr_debug("deq success (%d elements)", q->vars.min_heap.nr);
        skb_and_rank* s = (skb_and_rank*) q->vars.min_heap.data;
        struct sk_buff* skb = s->skb;
        //pr_debug("deq result %p, rank %d", skb, s->rank);
        min_heap_pop(&q->vars.min_heap, &min_heap_callbacks);
        sch->q.qlen--;
        sch->qstats.backlog -= qdisc_pkt_len(skb);
        //pr_debug("deq success p: %d", skb_protocol(skb, true));
        return skb;
    } else {
        pr_debug("deq fail");
        return NULL;
    }
}

static struct sk_buff *pifo_peek(struct Qdisc *sch)
{
	struct pifo_sched_data *q = qdisc_priv(sch);
    if (q->vars.min_heap.nr > 0) {
        pr_debug("peek succ");
        skb_and_rank* s = (skb_and_rank*) q->vars.min_heap.data;
        return s->skb;
    } else {
        pr_debug("peek fail");
        return NULL;
    }
}

static void pifo_reset(struct Qdisc *sch)
{
	struct pifo_sched_data *q = qdisc_priv(sch);
    if (q->vars.min_heap.nr > 0) {
        skb_and_rank* arr = (skb_and_rank*) q->vars.min_heap.data;
        for (int i = 0; i < q->vars.min_heap.nr - 1; i++) {
            arr[i].skb->next = arr[i + 1].skb;
        }
        rtnl_kfree_skbs(arr[0].skb, arr[q->vars.min_heap.nr - 1].skb);
    }
    sch->qstats.backlog = 0;
}


static void pifo_destroy(struct Qdisc *sch)
{
    pifo_reset(sch);

    struct pifo_sched_data *q = qdisc_priv(sch);
    vfree(q->vars.min_heap.data);
}




static int pifo_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	return -1;
}


struct Qdisc_ops pifo_qdisc_ops __read_mostly = {
	.id		=	"pifo",
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
EXPORT_SYMBOL(pifo_qdisc_ops);

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
