#define NO_INSTRUMENT_ATOMIC

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/percpu.h>

#include "kssb.h"

// The software store buffer should always work in the same
// context. If otherwise, it will cause a problem that does not exist
// in the real world. Let's check this invariant at the beginning of
// load/store callbacks to early detect if the store buffer emulation
// goes wrong.

static bool assert_failed = false;

static DEFINE_PER_CPU(struct task_struct *, prev_ctx);

static bool is_same_context(struct task_struct *running_ctx,
			    struct task_struct *prev_ctx)
{
	// TODO: We are currently support the task context only.
	BUG_ON(!in_task());
	return running_ctx == prev_ctx;
}

// Called with interrupts disabled
void assert_context(struct task_struct *ctx)
{
	struct task_struct *prev = this_cpu_read(prev_ctx);
	if (unlikely(READ_ONCE(assert_failed)))
		return;

	if (unlikely(prev && !is_same_context(prev, ctx))) {
		WRITE_ONCE(assert_failed, true);
		WARN_ONCE(1,
			"The context invariant is violated prev: %px, running: %px",
			prev, current);
	}
	this_cpu_write(prev_ctx, current);
}

// Called with interrupts disabled
void reset_context(void)
{
	this_cpu_write(prev_ctx, NULL);
}
