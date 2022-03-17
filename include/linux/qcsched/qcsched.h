#ifndef _QCSCHED_H
#define _QCSCHED_H

#include <linux/qcsched/hcall.h>
#include <linux/lockdep.h>

#include "hcall.h"

void qcsched_hook_entry(void);
void qcsched_hook_exit(void);

static inline void qcsched_vmi_hint_lock_acquire(struct lockdep_map *lock,
						 int trylock, int read)
{
	hypercall(HCALL_VMI_HINT, VMI_LOCK_ACQUIRE, (unsigned long)lock,
		  (trylock << 2) | read);
}

static inline void qcsched_vmi_hint_lock_release(struct lockdep_map *lock)
{
	hypercall(HCALL_VMI_HINT, VMI_LOCK_RELEASE, (unsigned long)lock, 0);
}

#endif
