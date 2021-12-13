#ifndef __KSSB_H
#define __KSSB_H

#include <linux/kernel.h>
#include <linux/llist.h>

// XXX: We really don't want to leave any of API calls as they may use
// atomic operations. Enabling debugging possibly change the bahavior
// of store buffer.
// TODO: Use Linux APIs
#ifdef __DEBUG
#define printk_debug(...) printk(__VA_ARGS__)
#else
#define printk_debug(...)                                                      \
	do {                                                                   \
	} while (0)
#endif

enum kssb_access_t { kssb_load, kssb_store };

struct kssb_access {
	enum kssb_access_t type;
	// Original access
	unsigned long inst;
	uint64_t *addr;
	size_t size;
	uint64_t val;
	// Aligned to be fit into the store buffer
	bool aligned;
	uint64_t aligned_addr;
	uint64_t aligned_val;
	uint64_t mask;
	loff_t offset;
};

struct kssb_buffer_entry {
	struct hlist_node hlist;
	struct llist_node llist;
	struct kssb_access access;
	pid_t pid;
	int cpu;
} __attribute__((aligned(128)));

struct kssb_buffer_entry *new_entry(void);
void reclaim_entry(struct kssb_buffer_entry *entry);

struct kssb_flush_vector {
	struct rcu_head rcu;
	int *vector;
	size_t size;
	atomic_t index;
};

int flush_vector_next(unsigned long);

void assert_context(struct task_struct *);
void reset_context(void);

#include "kssb_util.h"

extern bool kssb_initialized;

#endif // __KSSB_H
