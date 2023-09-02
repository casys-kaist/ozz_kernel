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
#include <linux/ptrace.h>

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

static int lookup_flush_table(struct kssb_flush_vector *vector,
			      unsigned long inst)
{
	struct kssb_flush_table_entry *entry;
	// XXX: The current implementation dose not check whether it
	// contains two different entries for the same instructions. We
	// need to be careful not to insert such two entries.
	hash_for_each_possible(vector->table, entry, hlist, inst) {
		if (entry->inst == inst)
			return entry->value;
	}
	return -1;
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

	index = lookup_flush_table(vector, inst);
	if (unlikely(index >= 0)) {
		ret = index;
		goto unlock;
	}

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
	kfree(vector->raw_table);
	kfree(vector->vector);
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

static struct kssb_flush_vector *alloc_flush_vector(void __user *vectorp,
						    size_t vector_size,
						    void __user *tablep,
						    size_t table_count)
{
	struct kssb_flush_vector *vector;
	int vector_bytes = sizeof(vector->vector[0]) * vector_size;
	int table_bytes = sizeof(struct kssb_flush_table_entry) * table_count;
	void *err = ERR_PTR(-ENOMEM);
	struct kssb_flush_table_entry *table_entry;
	int i;

	vector = (struct kssb_flush_vector *)kmalloc(sizeof(*vector),
						     GFP_KERNEL);
	if (!vector)
		goto err1;
	vector->vector = (int *)kmalloc(vector_bytes, GFP_KERNEL);
	if (!vector->vector)
		goto err2;
	vector->raw_table = (void *)kmalloc(table_bytes, GFP_KERNEL);
	if (!vector->raw_table)
		goto err3;

	if (copy_from_user(vector->vector, vectorp, vector_bytes))
		goto err4;
	if (copy_from_user(vector->raw_table, tablep, table_bytes))
		goto err4;

	atomic_set(&vector->index, 0);
	vector->size = vector_size;
	vector->count = table_count;
	hash_init(vector->table);
	for (i = 0; i < table_count; i++) {
		table_entry = &(
			(struct kssb_flush_table_entry *)vector->raw_table)[i];
		hash_add(vector->table, &(table_entry->hlist),
			 table_entry->inst);
	}

	return vector;

err4:
	err = ERR_PTR(-EINVAL);
	kfree(vector->raw_table);
err3:
	kfree(vector->vector);
err2:
	kfree(vector);
err1:
	return err;
}

SYSCALL_DEFINE4(ssb_feedinput, unsigned long, uvector, size_t, vector_size,
		unsigned long, utable, int, table_count)
{
	struct kssb_flush_vector *vector;
	void __user *vectorp = (void __user *)uvector;
	void __user *tablep = (void __user *)utable;

	// TODO: prevent multiple user threads from calling
	// ssb_feedinput() at the same time using a lock

	// Destory the flush vector first if already exists
	cleanup_flush_vector();
	if (!vector_size)
		// We only reset the flush vector if vector_bytes == 0
		return 0;

	vector = alloc_flush_vector(vectorp, vector_size, tablep, table_count);
	if (IS_ERR(vector))
		return PTR_ERR(vector);

	printk_debug(KERN_INFO
		     "Allocated flush_vector (vector: %d, table: %d)\n",
		     vector_size, table_count);
	// Let's allow others to see the flush vector. Paired with
	// smp_load_acquire() in flush_vector_next().
	smp_store_release(&flush_vector, vector);
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

	kssb_debugfs_init();

	WRITE_ONCE(kssb_initialized, true);

	return 0;
}

static void __exit kssb_cleanup(void)
{
	int cpu;
	void *pcpu_page;

	kssb_debugfs_cleanup();

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
