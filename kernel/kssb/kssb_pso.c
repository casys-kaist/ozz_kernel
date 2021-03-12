#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/percpu.h>

#define __DEBUG

#include "kssb.h"

#define STOREBUFFER_BITS 10
struct storebuffer {
	DECLARE_HASHTABLE(table, STOREBUFFER_BITS);
};

static DEFINE_PER_CPU(struct storebuffer, buffer) = {
	.table = { [0 ...((1 << (STOREBUFFER_BITS)) - 1)] = HLIST_HEAD_INIT },
};

static struct buffer_entry *alloc_entry(uint64_t *addr, uint64_t val,
					size_t size, uint64_t *aligned_addr,
					uint64_t aligned_val, uint64_t mask)
{
	struct buffer_entry *entry = new_entry();
	if (!entry)
		return NULL;
	entry->addr = addr;
	entry->val = val;
	entry->size = size;
	entry->aligned_addr = aligned_addr;
	entry->aligned_val = aligned_val;
	entry->mask = mask;
	return entry;
}

static struct buffer_entry *latest_entry(uint64_t *addr)
{
	struct buffer_entry *entry;
	struct storebuffer *pcpu_buffer = this_cpu_ptr(&buffer);
	hash_for_each_possible (pcpu_buffer->table, entry, hlist,
				(uint64_t)addr) {
		// Two different addrs are possibly mashed into a same
		// bucket so we need to check the address
		if (entry->addr == addr)
			return entry;
	}
	return NULL;
}

static void __flush_single_entry(uint64_t *dst, uint64_t val, size_t size)
{
	switch (size) {
	case 1:
		*(uint8_t *)dst = val;
		break;
	case 2:
		*(uint16_t *)dst = val;
		break;
	case 4:
		*(uint32_t *)dst = val;
		break;
	case 8:
		*(uint64_t *)dst = val;
		break;
	default:
		BUG();
	}
}

static void flush_single_entry(struct buffer_entry *entry)
{
	__flush_single_entry(entry->addr, entry->val, entry->size);
	hash_del(&entry->hlist);
	reclaim_entry(entry);
}

static void store_entry(uint64_t *addr, struct buffer_entry *entry)
{
	struct storebuffer *pcpu_buffer = this_cpu_ptr(&buffer);
	hash_add(pcpu_buffer->table, &(entry->hlist), (uint64_t)addr);
}

static void do_buffer_flush_after_insn(uint64_t *addr)
{
	struct hlist_node *tmp;
	struct buffer_entry *entry;
	struct storebuffer *pcpu_buffer = this_cpu_ptr(&buffer);
	int bkt;
	int freeing = flush_vector_next();
	int freed = 0;

	if (!freeing)
		return;

	printk_debug(KERN_INFO "flushing %d entries for %px\n", freeing, addr);

	bkt = hash_min((uint64_t)addr, STOREBUFFER_BITS);
	hlist_for_each_entry_safe (entry, tmp, &pcpu_buffer->table[bkt],
				   hlist) {
		if (entry->addr != addr)
			continue;
		flush_single_entry(entry);
		if (++freed >= freeing)
			break;
	}
}

static uint64_t do_buffer_load_aligned(uint64_t *aligned_addr, loff_t offset,
				       size_t size)
{
	struct buffer_entry *latest;
	uint64_t ret;
	printk_debug(KERN_INFO "do_buffer_load_aligned (%px, %lu, %d)\n",
		     aligned_addr, offset, size);
	if ((latest = latest_entry(aligned_addr)))
		ret = latest->val | (READ_ONCE(*aligned_addr) & ~latest->mask);
	else
		// We don't have an entry for addr in the store
		// buffer. Just read the global memory content.
		ret = READ_ONCE(*aligned_addr);
	ret >>= (_BITS(offset)) & _BIT_MASK(_BITS(size));
	printk_debug(KERN_INFO "do_buffer_load_aligned => %lx\n", ret);
	do_buffer_flush_after_insn(aligned_addr);
	return ret;
}

static uint64_t do_buffer_load(uint64_t *_addr, size_t size)
{
	uint64_t *addr =
		(uint64_t *)((uint64_t)(_addr) & ~(BYTES_PER_WORD - 1));
	loff_t offset = (loff_t)((uint64_t)_addr % BYTES_PER_WORD);
	printk_debug(KERN_INFO "do_buffer_load (%px, %d)\n", addr, size);
	return do_buffer_load_aligned(addr, offset, size);
}

static void do_buffer_store_aligned(uint64_t *addr, uint64_t val, size_t size,
				    uint64_t *aligned_addr,
				    uint64_t aligned_val, uint64_t mask)
{
	struct buffer_entry *entry, *latest;

	printk_debug(KERN_INFO "do_buffer_store_aligned (%px, %llx, %llx)\n",
		     aligned_addr, aligned_val, mask);

	// We need to retrieve the latest value of each bytes when a
	// load instruction is executed later. I.e., multiple store
	// instructions can be executed, for example, for 8 bytes at
	// 0x1000, 2 bytes at 0x1002, and 4 bytes at 0x1004, and a
	// load instruction for 8 bytes at 0x1000 should aggregate all
	// of those values to guarantee the correctness. Thus, we keep
	// a word-size and word-aligned store buffer entry for a later
	// load instruction while also keeping the original arguments
	// for a later flush.
	if ((latest = latest_entry(aligned_addr))) {
		// We have an entry for addr in the store
		// buffer. aligned_val must be filled with 0 for
		// not-masked bits.
		aligned_val |= (latest->val & ~mask);
		mask |= latest->mask;
	}
	printk_debug(KERN_INFO "new_val: %llx new_mask %llx\n", aligned_val,
		     mask);

	entry = alloc_entry(addr, val, size, aligned_addr, aligned_val, mask);
	if (!entry) {
		WARN_ONCE(1, "Store buffer is exhausted");
		__flush_single_entry(addr, val, size);
	} else {
		store_entry(aligned_addr, entry);
	}
	do_buffer_flush_after_insn(aligned_addr);
}

static void do_buffer_store(uint64_t *addr, uint64_t val, size_t size)
{
	uint64_t aligned_addr, aligned_val, mask;
	loff_t offset;

	printk_debug(KERN_INFO "do_buffer_store (%px, %llx, %d)\n", addr, val,
		     size);

	offset = (loff_t)((uint64_t)addr % BYTES_PER_WORD);
	aligned_addr = (uint64_t)(addr) & ~(BYTES_PER_WORD - 1);
	aligned_val = val << _BITS(offset);
	mask = (~(uint64_t)0 << _BITS(offset)) &
	       _BIT_MASK(_BITS(size + offset));
	do_buffer_store_aligned(addr, val, size, (uint64_t *)aligned_addr,
				aligned_val, mask);
}

static void do_buffer_flush(uint64_t *addr)
{
	int bkt;
	struct buffer_entry *entry;
	struct hlist_node *tmp;
	struct storebuffer *pcpu_buffer = this_cpu_ptr(&buffer);
	hash_for_each_safe (pcpu_buffer->table, bkt, tmp, entry, hlist) {
		// We just need to keep the stores' order only for
		// those having a same destination
		flush_single_entry(entry);
	}
}

// NOTE: Load/store callback should not be preempted until they are
// finished (they use a percpu store buffer). Whenever an interrupt is
// delivered, the percpu store buffer should be flushed to make sure
// that the percpu store buffer is not polluted.
// TODO: support contexts other than task
static uint64_t __load_callback_pso(uint64_t *addr, size_t size)
{
	uint64_t ret;
	preempt_disable();
	if (!in_task())
		ret = (*addr) & _BIT_MASK(_BITS(size));
	else
		ret = do_buffer_load(addr, size);
	preempt_enable();
	return ret;
}

static void __store_callback_pso(uint64_t *addr, uint64_t val, size_t size)
{
	preempt_disable();
	if (!in_task())
		__flush_single_entry(addr, val, size);
	else
		do_buffer_store(addr, val, size);
	preempt_enable();
}

static void __flush_callback_pso(char *addr)
{
	preempt_disable();
	// The flush callback should be called regardless of the
	// context.
	do_buffer_flush((uint64_t *)addr);
	preempt_enable();
}

#define MEMORYMODEL pso
#define STORE_CALLBACK_IMPL __store_callback_pso
#define LOAD_CALLBACK_IMPL __load_callback_pso
#define FLUSH_CALLBACK_IMPL __flush_callback_pso
#include "callback.h"
