#define NO_INSTRUMENT_ATOMIC

#include <linux/kernel.h>
#include <linux/atomic.h>

#include "kssb.h"

typedef atomic64_t kssb_stat;

kssb_stat stat_load;
kssb_stat stat_store;
kssb_stat stat_flush;

bool kssb_do_profile = false;

void profile_load(struct kssb_access *acc)
{
	if (kssb_do_profile)
		return;
	atomic64_add(1, &stat_load);
}

void profile_store(struct kssb_access *acc)
{
	if (kssb_do_profile)
		return;
	atomic64_add(1, &stat_store);
}

void profile_flush(uint64_t aligned_addr)
{
	if (kssb_do_profile)
		return;
	atomic64_add(1, &stat_flush);
}

void profile_reset(void)
{
	atomic64_set(&stat_load, 0);
	atomic64_set(&stat_store, 0);
	atomic64_set(&stat_flush, 0);
}
