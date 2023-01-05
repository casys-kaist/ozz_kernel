#define NO_INSTRUMENT_ATOMIC

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/init.h>
#include <linux/vmalloc.h>
#include <linux/atomic.h>
#include <linux/percpu.h>
#include <linux/llist.h>
#include <linux/hash.h>

/* #define __DEBUG */

#include "kssb.h"

struct kssb_flush_vector *flush_vector;

bool kssb_initialized = false;
EXPORT_SYMBOL(kssb_initialized);

#define BUFFER_PAGES 4
// Non-contiguous per-cpu pages storing kssb_buffer_entry
static DEFINE_PER_CPU(void *, kssb_buffer_pages);
// Per-cpu cache for free kssb_buffer_entry. As new_entry() is the
// only consumer of the pool, we can locklessly implement it by using
// llist, and making sure that there are no two cpus that access the
// same per-cpu pool. This can be simply enforced by making each cpu
// to access its own pool.
static DEFINE_PER_CPU(struct llist_head, kssb_buffer_pool);

struct kssb_buffer_entry *new_entry()
{
	struct llist_head *pcpu_pool;
	struct llist_node *llist;
	struct kssb_buffer_entry *entry = NULL;

	pcpu_pool = &get_cpu_var(kssb_buffer_pool);
	if ((llist = __llist_del_first(pcpu_pool)))
		entry = container_of(llist, struct kssb_buffer_entry, llist);
	put_cpu_var(kssb_buffer_pool);
	return entry;
}

void __reclaim_entry(struct kssb_buffer_entry *entry, struct llist_head *llist)
{
	___llist_add_batch(&entry->llist, &entry->llist, llist);
}

void reclaim_entry(struct kssb_buffer_entry *entry)
{
	struct llist_head *llist = per_cpu_ptr(&kssb_buffer_pool, entry->cpu);
	__reclaim_entry(entry, llist);
}

int flush_vector_next(unsigned long inst)
{
	struct kssb_flush_vector *vector;
	int index, ret = FLUSH_VECTOR_ALL;

	rcu_read_lock();
	// Paired with smp_store_release() in ssb_feedinput()
	vector = smp_load_acquire(&flush_vector);
	if (!vector || !vector->size || !vector->vector)
		goto unlock;

	// Let's make retriveing the flush vector more reliable. If
	// the return address of the kssb callbacks is given, index
	// the flush vector using the hash value of it. Note that this
	// does not always return the same index across kernel builds
	// since the return address possibly varies. Rather, this is
	// intended to be used to reproduce the crash using the same
	// binary.
	if (unlikely(!inst))
		index = ((unsigned int)atomic_fetch_inc(&vector->index)) %
			vector->size;
	else
		index = hash_64_generic(inst, 64) % vector->size;

	BUG_ON(index < 0 || index >= vector->size);
	ret = vector->vector[index];
unlock:
	rcu_read_unlock();
	return ret;
}

static void free_flush_vector(struct rcu_head *rcu)
{
	struct kssb_flush_vector *vector =
		container_of(rcu, struct kssb_flush_vector, rcu);
	printk_debug(KERN_INFO "Cleaning up the flush_vector\n");
	kfree(vector);
}

static void cleanup_flush_vector(void)
{
	struct kssb_flush_vector *vector = READ_ONCE(flush_vector);
	if (!vector)
		return;
	WRITE_ONCE(flush_vector, NULL);
	call_rcu(&vector->rcu, free_flush_vector);
}

SYSCALL_DEFINE2(ssb_feedinput, unsigned long, uvector, size_t, size)
{
	struct kssb_flush_vector *vector;
	void __user *vectorp = (void __user *)uvector;
	int total_bytes = sizeof(vector->vector[0]) * size;

	// TODO: prevent multiple user threads from calling
	// ssb_feedinput() at the same time

	// Destory the flush vector first if already exists
	cleanup_flush_vector();
	if (!total_bytes)
		return 0;

	vector = (struct kssb_flush_vector *)kmalloc(sizeof(*vector),
						     GFP_KERNEL);
	vector->vector = (int *)kmalloc(total_bytes, GFP_KERNEL);
	if (copy_from_user(vector->vector, vectorp, total_bytes)) {
		kfree(vector->vector);
		kfree(vector);
		return -EINVAL;
	}
	atomic_set(&vector->index, 0);
	vector->size = size;

	// Let's allow others to see the flush vector. Paired with
	// smp_load_acquire() in flush_vector_next().
	smp_store_release(&flush_vector, vector);

	printk_debug(KERN_INFO "Allocating flush_vector (size: %d)\n", size);

	return 0;
}

SYSCALL_DEFINE0(ssb_switch)
{
#ifdef CONFIG_KSSB_SWITCH
	current->kssb_enabled = !current->kssb_enabled;
	return 0;
#else
	return -EINVAL;
#endif /* CONFIG_KSSB_SWITCH */
}

static void kssb_populate_pcpu_pages(unsigned long *pcpu_pages,
				     unsigned long size)
{
	unsigned long total = size / sizeof(unsigned long);
	unsigned long stride = PAGE_SIZE / sizeof(unsigned long);
	unsigned long offset;
	for (offset = 0; offset < total; offset += stride)
		READ_ONCE(pcpu_pages[offset]);
}

static int __init kssb_init(void)
{
	int i, cpu, num_entries;
	size_t buffer_size;
	struct kssb_buffer_entry *ptr;
	struct llist_head *pcpu_pool;
	void *pcpu_pages;

	buffer_size = BUFFER_PAGES * PAGE_SIZE;
	num_entries = buffer_size / sizeof(struct kssb_buffer_entry);

	for_each_possible_cpu(cpu) {
		printk(KERN_INFO "Allocating pages (CPU #%d)\n", cpu);
		printk(KERN_INFO "  size       %d\n", buffer_size);
		printk(KERN_INFO "  entry size %d\n",
		       sizeof(struct kssb_buffer_entry));
		printk(KERN_INFO "  entries    %d\n", num_entries);

		pcpu_pages = vmalloc(buffer_size);

		kssb_populate_pcpu_pages(pcpu_pages, buffer_size);

		per_cpu(kssb_buffer_pages, cpu) = pcpu_pages;
		pcpu_pool = per_cpu_ptr(&kssb_buffer_pool, cpu);
		init_llist_head(pcpu_pool);
		for (i = 0; i < num_entries; i++) {
			ptr = &((struct kssb_buffer_entry *)pcpu_pages)[i];
			ptr->cpu = cpu;
			__reclaim_entry(ptr, pcpu_pool);
		}
	}

	profile_reset();

	WRITE_ONCE(kssb_initialized, true);

	return 0;
}

static void kssb_cleanup(void)
{
	int cpu;
	void *pcpu_page;
	for_each_possible_cpu(cpu) {
		pcpu_page = per_cpu(kssb_buffer_pages, cpu);
		vfree(pcpu_page);
	}
	cleanup_flush_vector();
}

// Hypervisor-controllable switch to turn on/off the store buffer
// emulation. This is different with KSSB_SWITCH that allows the
// per-task emulation. NOTE: Should be volatile since there is no
// statement that changes the value in source codes.
#ifdef __TEST_KSSB
#pragma message("enable kssb from the booting")
volatile char __ssb_do_emulate = true;
#else
volatile char __ssb_do_emulate = false;
#endif
EXPORT_SYMBOL(__ssb_do_emulate);

module_init(kssb_init);
module_exit(kssb_cleanup);
