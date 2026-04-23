#ifndef DEPQ_H_
#define DEPQ_H_

#include <linux/types.h>

typedef struct skb_and_rank {
    struct sk_buff* skb;
    u32 rank;
    bool non_ip; // ha ez true, akkor rank legyen 0
    u64 order; // ld. pifo_sched_data.packetCounter
} skb_and_rank;

static inline bool less_than(skb_and_rank a, skb_and_rank b) {
    return a.rank < b.rank || (a.rank == b.rank && a.order < b.order);
}

static inline bool greater_than(skb_and_rank a, skb_and_rank b) {
    return a.rank > b.rank || (a.rank == b.rank && a.order > b.order);
}

typedef struct heap {
  skb_and_rank* data;
  int count;
  int size;
} heap_t;

bool mmh_insert(heap_t* h, skb_and_rank value);
bool mmh_peek_min(heap_t* h, skb_and_rank* out);
bool mmh_peek_max(heap_t* h, skb_and_rank* out);
bool mmh_pop_min(heap_t* h, skb_and_rank* out);
bool mmh_pop_max(heap_t* h, skb_and_rank* out);

static inline int mmh_capacity(heap_t* h) {
    return h->size - 1;
}

#endif  // DEPQ_H_
