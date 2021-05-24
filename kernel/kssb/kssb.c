#define NO_INSTRUMENT_ATOMIC

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/init.h>
#include <linux/vmalloc.h>
#include <linux/atomic.h>

/* #define __DEBUG */

#include "kssb.h"

struct kssb_flush_vector *flush_vector;

bool kssb_initialized = false;
EXPORT_SYMBOL(kssb_initialized);

#define BUFFER_PAGES 4
// non-contiguous pages storing kssb_buffer_entry
void *buffer_entry_pages;
// cache for free kssb_buffer_entry
LIST_HEAD(free_entry_pool);

struct kssb_buffer_entry *new_entry()
{
	struct kssb_buffer_entry *entry = list_first_entry_or_null(
		&free_entry_pool, struct kssb_buffer_entry, list);
	if (entry)
		list_del_init(&entry->list);
	return entry;
}

void reclaim_entry(struct kssb_buffer_entry *entry)
{
	list_add(&entry->list, &free_entry_pool);
}

int flush_vector_next()
{
	struct kssb_flush_vector *vector;
	int index, ret = 0;

	rcu_read_lock();
	// Paired with smp_store_release() in ssb_feedinput()
	vector = smp_load_acquire(&flush_vector);
	if (!vector || !vector->size || !vector->vector)
		goto unlock;

	index = ((unsigned int)atomic_fetch_inc(&vector->index)) % vector->size;
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

static int __init kssb_init(void)
{
	int i, num_entries;
	struct kssb_buffer_entry *ptr;
	size_t buffer_size = BUFFER_PAGES * PAGE_SIZE;

	buffer_entry_pages = vmalloc(buffer_size);
	num_entries = buffer_size / sizeof(struct kssb_buffer_entry);
	printk_debug(KERN_INFO "Allocating pages\n");
	printk_debug(KERN_INFO "  size       %d\n", buffer_size);
	printk_debug(KERN_INFO "  entry size %d\n",
		     sizeof(struct kssb_buffer_entry));
	printk_debug(KERN_INFO "  entries    %d\n", num_entries);
	for (i = 0; i < num_entries; i++) {
		ptr = &((struct kssb_buffer_entry *)buffer_entry_pages)[i];
		reclaim_entry(ptr);
	}

	WRITE_ONCE(kssb_initialized, true);

	return 0;
}

static void kssb_cleanup(void)
{
	vfree(buffer_entry_pages);
	cleanup_flush_vector();
}

module_init(kssb_init);
module_exit(kssb_cleanup);
