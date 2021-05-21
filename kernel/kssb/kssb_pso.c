#define NO_INSTRUMENT_ATOMIC
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/percpu.h>

/* #define __DEBUG */

#include "kssb.h"

#define STOREBUFFER_BITS 10
struct storebuffer {
	DECLARE_HASHTABLE(table, STOREBUFFER_BITS);
};

static DEFINE_PER_CPU(struct storebuffer, buffer) = {
	.table = { [0 ...((1 << (STOREBUFFER_BITS)) - 1)] = HLIST_HEAD_INIT },
};

static void do_buffer_flush(uint64_t);

static struct kssb_buffer_entry *alloc_entry(struct kssb_access *acc)
{
	struct kssb_buffer_entry *entry = new_entry();
	if (!entry)
		return NULL;
	memcpy(&entry->access, acc, sizeof(*acc));
	return entry;
}

static struct kssb_buffer_entry *latest_entry(struct kssb_access *acc)
{
	struct kssb_buffer_entry *entry;
	struct storebuffer *pcpu_buffer = this_cpu_ptr(&buffer);
	BUG_ON(!acc->aligned);
	hash_for_each_possible (pcpu_buffer->table, entry, hlist,
				(uint64_t)acc->aligned_addr) {
		// Two different addrs are possibly mashed into a same
		// bucket so we need to check the address
		if (entry->access.aligned_addr == acc->aligned_addr)
			return entry;
	}
	return NULL;
}

static void store_entry(struct kssb_buffer_entry *entry,
			struct kssb_access *acc)
{
	struct storebuffer *pcpu_buffer = this_cpu_ptr(&buffer);
	BUG_ON(!acc->aligned);
	hash_add(pcpu_buffer->table, &(entry->hlist),
		 (uint64_t)acc->aligned_addr);
}

static void __flush_single_entry_po_preserve(struct kssb_access *acc)
{
	do_buffer_flush(acc->aligned_addr);
	__store_single(acc);
}

static void flush_single_entry(struct kssb_buffer_entry *entry)
{
	__store_single(&entry->access);
	hash_del(&entry->hlist);
	reclaim_entry(entry);
}

static void do_buffer_flush(uint64_t aligned_addr)
{
	int bkt;
	struct kssb_buffer_entry *entry;
	struct hlist_node *tmp;
	struct storebuffer *pcpu_buffer = this_cpu_ptr(&buffer);
	bool flush_all = !aligned_addr;

	hash_for_each_safe (pcpu_buffer->table, bkt, tmp, entry, hlist) {
		// We just need to keep the stores' order only for
		// those having the same destination
		if (flush_all || entry->access.aligned_addr == aligned_addr)
			flush_single_entry(entry);
	}
	BUG_ON(flush_all && !hash_empty(pcpu_buffer->table));
}

static void do_buffer_flush_n(uint64_t aligned_addr, int freeing)
{
	struct hlist_node *tmp;
	struct kssb_buffer_entry *entry;
	struct storebuffer *pcpu_buffer = this_cpu_ptr(&buffer);
	int bkt, freed = 0;

	if (!freeing)
		return;

	printk_debug(KERN_INFO "flushing %d entries for %lx\n", freeing,
		     aligned_addr);

	bkt = hash_min(aligned_addr, STOREBUFFER_BITS);
	hlist_for_each_entry_safe (entry, tmp, &pcpu_buffer->table[bkt],
				   hlist) {
		if (entry->access.aligned_addr != aligned_addr)
			continue;
		flush_single_entry(entry);
		if (++freed >= freeing)
			break;
	}
}

static void do_buffer_flush_after_insn(struct kssb_access *acc)
{
	int freeing = flush_vector_next();
	BUG_ON(!acc->aligned);
	do_buffer_flush_n(acc->aligned_addr, freeing);
}

static inline void align_access(struct kssb_access *acc)
{
	// Align kssb_access to the word. Maybe called later after it
	// is initialized.
	acc->aligned_addr = (uint64_t)(acc->addr) & ~(BYTES_PER_WORD - 1);
	acc->offset = (loff_t)((uint64_t)acc->addr & (BYTES_PER_WORD - 1));
	acc->aligned_val = acc->val << _BITS(acc->offset);
	acc->mask = _BIT_MASK(_BITS(acc->size + acc->offset)) &
		    ~_BIT_MASK(_BITS(acc->offset));
	acc->aligned = true;
}

static inline uint64_t __assemble_value(struct kssb_buffer_entry *entry,
					struct kssb_access *acc)
{
	uint64_t ret, val;
	val = __load_single(acc) << _BITS(acc->offset);
	ret = (entry->access.aligned_val & entry->access.mask) |
	      (val & ~entry->access.mask);
	ret >>= _BITS(acc->offset);
	return ret;
}

static uint64_t do_buffer_load_aligned(struct kssb_access *acc)
{
	struct kssb_buffer_entry *latest;
	uint64_t ret;

	printk_debug(KERN_INFO "do_buffer_load_aligned (%px, %lu, %d)\n",
		     acc->aligned_addr, acc->offset, acc->size);

	// We don't have to masking upper bits of ret. It will be done
	// when the value is returned.
	if ((latest = latest_entry(acc)))
		ret = __assemble_value(latest, acc);
	else
		ret = __load_single(acc);

	printk_debug(KERN_INFO "do_buffer_load_aligned => %lx\n", ret);

	do_buffer_flush_after_insn(acc);
	return ret;
}

static uint64_t do_buffer_load(struct kssb_access *acc)
{
	printk_debug(KERN_INFO "do_buffer_load (%px, %d)\n", acc->addr,
		     acc->size);

	// TODO: spanning loads?

	align_access(acc);

	return do_buffer_load_aligned(acc);
}

static void compose_access(struct kssb_access *acc)
{
	struct kssb_buffer_entry *latest;
	// We need to retrieve the latest value of each bytes when a
	// load instruction is executed later. I.e., multiple store
	// instructions can be executed, for example, for 8 bytes at
	// 0x1000, 2 bytes at 0x1002, and 4 bytes at 0x1004, and a
	// load instruction for 8 bytes at 0x1000 should aggregate all
	// of those values to guarantee the correctness. Thus, we keep
	// a word-size and word-aligned store buffer entry for a later
	// load instruction while also keeping the original arguments
	// for a later flush.
	if ((latest = latest_entry(acc))) {
		// We have an entry for addr in the store
		// buffer. aligned_val must be filled with 0 for newly
		// masked bits.
		acc->aligned_val =
			((latest->access.aligned_val & latest->access.mask) &
			 ~acc->mask) |
			(acc->aligned_val & acc->mask);
		acc->mask |= latest->access.mask;
	}

	printk_debug(KERN_INFO "new_val: %llx new_mask %llx\n",
		     acc->aligned_val, acc->mask);
}

static void do_buffer_store_aligned(struct kssb_access *acc)
{
	struct kssb_buffer_entry *entry;

	printk_debug(KERN_INFO "do_buffer_store_aligned (%px, %llx, %llx)\n",
		     aligned_addr, aligned_val, mask);

	compose_access(acc);

	if ((entry = alloc_entry(acc))) {
		store_entry(entry, acc);
	} else {
		WARN_ONCE(1, "Store buffer is exhausted");
		__flush_single_entry_po_preserve(acc);
	}
	do_buffer_flush_after_insn(acc);
}

static bool is_spanning_access(struct kssb_access *acc)
{
	// return true if the access spans over two words.
	return acc->size + (((uint64_t)acc->addr) % 8) > 8;
}

static void do_spanning_access(struct kssb_access *acc)
{
	// TEMP: I do know how the real machine works in this
	// case. To be safe, flush the two words and the store
	// without emulating the store buffer.
	do_buffer_flush(acc->aligned_addr);
	do_buffer_flush(acc->aligned_addr + 8);
	__store_single(acc);
}

static void do_buffer_store(struct kssb_access *acc)
{
	printk_debug(KERN_INFO "do_buffer_store (%px, %llx, %d)\n", acc->addr,
		     acc->val, acc->size);

	align_access(acc);

	if (is_spanning_access(acc)) {
		do_spanning_access(acc);
		return;
	}

	do_buffer_store_aligned(acc);
}

// NOTE: Load/store callback should not be preempted until they are
// finished (they use a percpu store buffer). Whenever an interrupt is
// delivered, the percpu store buffer should be flushed to make sure
// that the percpu store buffer is not polluted.
// NOTE: Partial initialization of struct will fill 0 to the remainings
// TODO: support contexts other than task
static uint64_t __load_callback_pso(uint64_t *addr, size_t size)
{
	uint64_t ret;
	unsigned long flags;
	struct kssb_access acc = {
		.addr = addr, .val = 0, .size = size, .type = kssb_load
	};

	local_irq_save(flags);
	if (in_task())
		ret = do_buffer_load(&acc);
	else
		ret = __load_single(&acc);
	local_irq_restore(flags);
	return ret;
}

static void __store_callback_pso(uint64_t *addr, uint64_t val, size_t size)
{
	unsigned long flags;
	struct kssb_access acc = {
		.addr = addr, .val = val, .size = size, .type = kssb_store
	};

	local_irq_save(flags);
	if (in_task())
		do_buffer_store(&acc);
	else
		__flush_single_entry_po_preserve(&acc);
	local_irq_restore(flags);
}

static void __flush_callback_pso(void)
{
	unsigned long flags;
	local_irq_save(flags);
	// The flush callback should be called regardless of the
	// context.
	do_buffer_flush(0);
	local_irq_restore(flags);
}

#define MEMORYMODEL pso
#define STORE_CALLBACK_IMPL __store_callback_pso
#define LOAD_CALLBACK_IMPL __load_callback_pso
#define FLUSH_CALLBACK_IMPL __flush_callback_pso
#include "callback.h"
