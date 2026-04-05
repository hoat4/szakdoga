#ifndef DEPQ_H_
#define DEPQ_H_

#include <linux/types.h>

typedef struct skb_and_rank {
    struct sk_buff* skb;
    u32 rank;
    u64 order; // ld. pifo_sched_data.packetCounter
} skb_and_rank;

typedef struct heap {
  skb_and_rank* data;
  int count;
  int size;
} heap_t;

bool mmh_insert(heap_t* h, skb_and_rank value);
bool mmh_pop_min(heap_t* h, skb_and_rank* out);
bool mmh_pop_max(heap_t* h, skb_and_rank* out);

#endif  // DEPQ_H_
