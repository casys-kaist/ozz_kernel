#define NO_INSTRUMENT_ATOMIC

#include <linux/kernel.h>
#include <linux/atomic.h>
#include <linux/printk.h>
#include <linux/debugfs.h>
#include <linux/hash.h>

#include "kssb.h"

static void __record_emulated_inst(struct kssb_access *acc);

struct kssb_stat_t kssb_stat;

bool kssb_do_profile = false;

void profile_load(struct kssb_access *acc)
{
	if (likely(!kssb_do_profile))
		return;
	atomic64_add(1, &kssb_stat.load_count);
	__record_emulated_inst(acc);
}

void profile_store(struct kssb_access *acc)
{
	if (likely(!kssb_do_profile))
		return;
	atomic64_add(1, &kssb_stat.store_count);
	__record_emulated_inst(acc);
}

void profile_flush(uint64_t aligned_addr)
{
	if (likely(!kssb_do_profile))
		return;
	atomic64_add(1, &kssb_stat.flush_count);
}

void profile_retchk(void *ret)
{
	if (likely(!kssb_do_profile))
		return;
	atomic64_add(1, &kssb_stat.retchk_count);
}

void profile_lfence(void)
{
	if (likely(!kssb_do_profile))
		return;
	atomic64_add(1, &kssb_stat.lfence_count);
}

void profile_funcentry(void *ret)
{
	if (likely(!kssb_do_profile))
		return;
	atomic64_add(1, &kssb_stat.funcentry_count);
}

void profile_reset(void)
{
	memset(&kssb_stat, 0, sizeof(struct kssb_stat_t));
}

// XXX: want to make these per-cpu. I'm lazy so instead of properly
// using pcpu, just make them array.
#define ____NR_CPU 4
#define MAX_EMULATED_INST 10 * 1024
static unsigned long emulated_inst_count[____NR_CPU] = {
	0,
};
static struct kssb_access emulated_inst[____NR_CPU][MAX_EMULATED_INST];
extern volatile char __ssb_do_emulate;
extern struct kssb_flush_vector *flush_vector;

int profile_emulated_inst_show(struct seq_file *m, void *v)
{
	struct kssb_flush_vector *vector;
	int size = 0;

	if (!kssb_do_profile)
		return 0;

	if (__ssb_do_emulate)
		return -EBUSY;

	rcu_read_lock();
	vector = smp_load_acquire(&flush_vector);
	if (vector != NULL)
		size = vector->size;
	rcu_read_unlock();

	seq_printf(m, "hash size: %d\n", size);
	for (int i = 0; i < ____NR_CPU; i++) {
		int count = emulated_inst_count[i];
		for (int j = 0; j < count; j++) {
			struct kssb_access *acc = &emulated_inst[i][j];
			int hash_index = hash_64_generic(acc->inst, 64) % size;
			seq_printf(m, "%lx %px %d %c %d %d\n", acc->inst,
				   acc->addr, acc->size,
				   (acc->type == kssb_load ? 'R' : 'W'),
				   hash_index, flush_vector_next(acc->inst));
		}
	}
	return 0;
}

void profile_reset_emulated_inst(void)
{
	if (__ssb_do_emulate)
		return;

	for (int i = 0; i < ____NR_CPU; i++)
		emulated_inst_count[i] = 0;
}

void __record_emulated_inst(struct kssb_access *acc)
{
	int idx;
	int cpu = __smp_processor_id();
	if (cpu > ____NR_CPU)
		return;

	if (emulated_inst_count[cpu] >= MAX_EMULATED_INST)
		return;

	idx = emulated_inst_count[cpu];
	emulated_inst[cpu][idx] = *acc;
	emulated_inst_count[cpu]++;
}
