#ifndef __KMEMCOV_LOCK_H
#define __KMEMCOV_LOCK_H

#include <linux/kmemcov.h>

extern bool kmemcov_trace_lock;

static void sanitize_memcov_trace_lock_acquire(void *lockdep)
{
	if (kmemcov_trace_lock)
		__sanitize_memcov_trace_lock(lockdep, true);
}
static void sanitize_memcov_trace_lock_release(void *lockdep)
{
	if (kmemcov_trace_lock)
		__sanitize_memcov_trace_lock(lockdep, false);
}

#endif
