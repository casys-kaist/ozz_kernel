#ifndef __KSSB_H
#define __KSSB_H

#include <linux/kernel.h>
#include <linux/list.h>

#ifdef __DEBUG
#define printk_debug(...) printk(__VA_ARGS__)
#else
#define printk_debug(...)                                                      \
	do {                                                                   \
	} while (0)
#endif

#define _BITS(val) ((val)*8)
#define BYTES_PER_WORD (uint64_t)(sizeof(void *))
#define _BIT_MASK(_BITS)                                                       \
	((_BITS) == 64 ? 0xffffffffffffffff : (1ULL << (_BITS)) - 1)

struct buffer_entry {
	struct hlist_node hlist;
	struct list_head list;
	uint64_t *addr;
	uint64_t val;
	size_t size;
	uint64_t *aligned_addr;
	uint64_t aligned_val;
	uint64_t mask;
} __attribute__((aligned(128)));

struct buffer_entry *new_entry(void);
void reclaim_entry(struct buffer_entry *entry);
int flush_vector_next(void);

#endif // __KSSB_H
