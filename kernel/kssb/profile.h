#ifndef __KSSB_PROFILE_H
#define __KSSB_PROFILE_H

#ifdef CONFIG_KSSB_PROFILE
#include <linux/atomic.h>

#include "kssb.h"

struct kssb_stat_t {
	atomic64_t load_count;
	atomic64_t store_count;
	atomic64_t flush_count;
};

extern struct kssb_stat_t kssb_stat;

void profile_load(struct kssb_access *);
void profile_store(struct kssb_access *);
void profile_flush(uint64_t);
void profile_reset(void);
#else
#define profile_load(...) \
	do {              \
	} while (0)
#define profile_store(...) \
	do {               \
	} while (0)
#define profile_flush(...) \
	do {               \
	} while (0)
#define profile_reset(...) \
	do {               \
	} while (0)
#endif

#endif /* __KSSB_PROFILE_H */
