// https://github.com/ilbanshee/min-max-heap/blob/master/src/minmax_heap.c

#include "depq.h"

#define is_min(n) ((log2_32(n) & 1) == 0)
#define parent(n) (n / 2)
#define first_child(n) (n * 2)
#define second_child(n) ((n * 2) + 1)

const int tab32[32] = {0,  9,  1,  10, 13, 21, 2,  29, 11, 14, 16,
                       18, 22, 25, 3,  30, 8,  12, 20, 28, 15, 17,
                       24, 7,  19, 27, 23, 6,  26, 5,  4,  31};

static int log2_32(uint32_t value) {
  value |= value >> 1;
  value |= value >> 2;
  value |= value >> 4;
  value |= value >> 8;
  value |= value >> 16;
  return tab32[(uint32_t)(value * 0x07C4ACDD) >> 27];
}

static void swap(heap_t* h, int i, int j) {
  skb_and_rank tmp = h->data[i];
  h->data[i] = h->data[j];
  h->data[j] = tmp;
}

static void bubbleup_min(heap_t* h, int i) {
  int pp_idx = parent(parent(i));
  if (pp_idx <= 0) return;

  if (less_than(h->data[i], h->data[pp_idx])) {
    swap(h, i, pp_idx);
    bubbleup_min(h, pp_idx);
  }
}

static void bubbleup_max(heap_t* h, int i) {
  int pp_idx = parent(parent(i));
  if (pp_idx <= 0) return;

  if (greater_than(h->data[i], h->data[pp_idx])) {
    swap(h, i, pp_idx);
    bubbleup_max(h, pp_idx);
  }
}

static void bubbleup(heap_t* h, int i) {
  int p_idx = parent(i);
  if (p_idx <= 0) return;

  if (is_min(i)) {
    if (greater_than(h->data[i], h->data[p_idx])) {
      swap(h, i, p_idx);
      bubbleup_max(h, p_idx);
    } else {
      bubbleup_min(h, i);
    }
  } else {
    if (less_than(h->data[i], h->data[p_idx])) {
      swap(h, i, p_idx);
      bubbleup_min(h, p_idx);
    } else {
      bubbleup_max(h, i);
    }
  }
}

static int index_max_child_grandchild(heap_t* h, int i) {
  int a = first_child(i);
  int b = second_child(i);
  int d = second_child(a);
  int c = first_child(a);
  int f = second_child(b);
  int e = first_child(b);

  int min_idx = -1;
  if (a <= h->count) min_idx = a;
  if (b <= h->count && greater_than(h->data[b], h->data[min_idx])) min_idx = b;
  if (c <= h->count && greater_than(h->data[c], h->data[min_idx])) min_idx = c;
  if (d <= h->count && greater_than(h->data[d], h->data[min_idx])) min_idx = d;
  if (e <= h->count && greater_than(h->data[e], h->data[min_idx])) min_idx = e;
  if (f <= h->count && greater_than(h->data[f], h->data[min_idx])) min_idx = f;

  return min_idx;
}

static int index_min_child_grandchild(heap_t* h, int i) {
  int a = first_child(i);
  int b = second_child(i);
  int c = first_child(a);
  int d = second_child(a);
  int e = first_child(b);
  int f = second_child(b);

  int min_idx = -1;
  if (a <= h->count) min_idx = a;
  if (b <= h->count && less_than(h->data[b], h->data[min_idx])) min_idx = b;
  if (c <= h->count && less_than(h->data[c], h->data[min_idx])) min_idx = c;
  if (d <= h->count && less_than(h->data[d], h->data[min_idx])) min_idx = d;
  if (e <= h->count && less_than(h->data[e], h->data[min_idx])) min_idx = e;
  if (f <= h->count && less_than(h->data[f], h->data[min_idx])) min_idx = f;

  return min_idx;
}

static void trickledown_max(heap_t* h, int i) {
  int m = index_max_child_grandchild(h, i);
  if (m <= -1) return;
  if (m > second_child(i)) {
    // m is a grandchild
    if (greater_than(h->data[m], h->data[i])) {
      swap(h, i, m);
      if (less_than(h->data[m], h->data[parent(m)])) {
        swap(h, m, parent(m));
      }
      trickledown_max(h, m);
    }
  } else {
    // m is a child
    if (greater_than(h->data[m], h->data[i])) swap(h, i, m);
  }
}

static void trickledown_min(heap_t* h, int i) {
  int m = index_min_child_grandchild(h, i);
  if (m <= -1) return;
  if (m > second_child(i)) {
    // m is a grandchild
    if (less_than(h->data[m], h->data[i])) {
      swap(h, i, m);
      if (greater_than(h->data[m], h->data[parent(m)])) {
        swap(h, m, parent(m));
      }
      trickledown_min(h, m);
    }
  } else {
    // m is a child
    if (less_than(h->data[m], h->data[i])) swap(h, i, m);
  }
}

static void trickledown(heap_t* h, int i) {
  if (is_min(i)) {
    trickledown_min(h, i);
  } else {
    trickledown_max(h, i);
  }
}

bool mmh_insert(heap_t* h, skb_and_rank value) {
  h->count++;
  if (h->count + 1 == h->size) {
    h->count--;
    return false;
  }
  h->data[h->count] = value;
  bubbleup(h, h->count);
  return true;
}

bool mmh_pop_min(heap_t* h, skb_and_rank* out) {
  if (h->count > 1) {
    skb_and_rank d = h->data[1];
    h->data[1] = h->data[h->count--];
    trickledown(h, 1);
    *out = d;
    return true;
  }

  if (h->count == 1) {
    h->count--;
    *out = h->data[1];
    return true;
  }
  return false;
}

bool mmh_pop_max(heap_t* h, skb_and_rank* out) {
  if (h->count > 2) {
    int idx = 2;
    if (less_than(h->data[2], h->data[3])) idx = 3;
    skb_and_rank d = h->data[idx];
    h->data[idx] = h->data[h->count--];
    trickledown(h, idx);
    *out = d;
    return true;
  }

  if (h->count == 2) {
    h->count--;
    *out = h->data[2];
    return true;
  }

  if (h->count == 1) {
    h->count--;
    *out = h->data[1];
    return true;
  }
  return false;
}


bool mmh_peek_min(heap_t* h, skb_and_rank* out) {
  if (h->count > 0) {
    *out = h->data[1];
    return true;
  }
  return false;
}

bool mmh_peek_max(heap_t* h, skb_and_rank* out) {
  if (h->count > 2) {
    skb_and_rank a = h->data[2], b = h->data[3];
    *out = greater_than(a, b) ? a : b;
    return true;
  }
  if (h->count == 2) {
    *out = h->data[2];
    return true;
  }
  if (h->count == 1) {
    *out = h->data[1];
    return true;
  }
  return false;
}
