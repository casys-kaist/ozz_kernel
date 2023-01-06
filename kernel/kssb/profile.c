#define NO_INSTRUMENT_ATOMIC

#include <linux/kernel.h>
#include <linux/atomic.h>

#include "kssb.h"

struct kssb_stat_t kssb_stat;

bool kssb_do_profile = false;

void profile_load(struct kssb_access *acc)
{
	if (kssb_do_profile)
		return;
	atomic64_add(1, &kssb_stat.load_count);
}

void profile_store(struct kssb_access *acc)
{
	if (kssb_do_profile)
		return;
	atomic64_add(1, &kssb_stat.store_count);
}

void profile_flush(uint64_t aligned_addr)
{
	if (kssb_do_profile)
		return;
	atomic64_add(1, &kssb_stat.flush_count);
}

void profile_reset(void)
{
	memset(&kssb_stat, 0, sizeof(struct kssb_stat_t));
}
