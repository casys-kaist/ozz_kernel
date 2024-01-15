#define NO_INSTRUMENT_ATOMIC
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/percpu.h>
#include <linux/sched/task_stack.h>
#include <linux/kssb.h>
#include <linux/kmemcov.h>
#include <linux/kasan.h>
#include <asm/unwind.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>

/* #define __DEBUG */

#include "kssb.h"

#define UNKNOWN_VALUE 0xdead

bool load_prefetch_enabled = false;

#define STOREBUFFER_BITS 10
struct store_buffer {
	DECLARE_HASHTABLE(table, STOREBUFFER_BITS);
	bool emulating;
};

#define STOREHISTORY_BITS 10
struct store_history {
	struct hlist_head table[1 << STOREHISTORY_BITS];
};

static DEFINE_PER_CPU(struct store_buffer, buffer) = {
	.table = { [0 ...((1 << (STOREBUFFER_BITS)) - 1)] = HLIST_HEAD_INIT },
};

static struct store_history global_history = {
	.table = { [0 ...((1 << (STOREHISTORY_BITS)) - 1)] = HLIST_HEAD_INIT },
};

// XXX: using lock surely slow down the kernel so I personally don't
// like it. Anyway in this project we have only two threads that one
// is mostly suspended, and it is very unlikely that there is a lock
// contention on this lock.
atomic_t __history_lock;
static void history_lock(void)
{
	if (!load_prefetch_enabled)
		return;
	int old = 0;
	do {
	} while (atomic_try_cmpxchg(&__history_lock, &old, 1));
}

static void history_unlock(void)
{
	if (!load_prefetch_enabled)
		return;
	// XXX: Missing write memory barrier. Whatever.
	atomic_set(&__history_lock, 0);
}

static uint64_t commit_count;
static DEFINE_PER_CPU(uint64_t, latest_access) = 0;
static DEFINE_PER_CPU(uint64_t, load_since) = 0;

static void do_buffer_flush(uint64_t);
static bool is_spanning_access(struct kssb_access *acc);
static void flush_spanning_access(struct kssb_access *acc);
static void clear_history(void);

// XXX: Should be defined in kssb.c
void kssb_print_store_buffer(void)
{
	struct kssb_buffer_entry *entry;
	struct store_buffer *pcpu_buffer = this_cpu_ptr(&buffer);
	int bkt, cnt = 0;

	pr_alert("Store buffer entries:\n");
	hash_for_each(pcpu_buffer->table, bkt, entry, hlist) {
		cnt++;
		pr_alert("  addr: %px\n", entry->access.addr);
		pr_alert("size: %ld\n", entry->access.size);
		pr_alert("  val : %lx\n", entry->access.val);
		pr_alert("  pid : %d\n", entry->pid);
	}
	pr_alert("%d entries", cnt);
}
EXPORT_SYMBOL(kssb_print_store_buffer);

static void set_emulating(bool emulating)
{
	struct store_buffer *pcpu_buffer = this_cpu_ptr(&buffer);
	pcpu_buffer->emulating = emulating;
}

#define declare_emulating() set_emulating(true)
#define revoke_emulating() set_emulating(false)

static struct kssb_buffer_entry *alloc_entry(struct kssb_access *acc)
{
	struct kssb_buffer_entry *entry = new_entry();
	if (entry)
		goto success;
	// The store buffer is exhausted. Let's flush the store buffer and
	// the history and give a second shot.
	do_buffer_flush(0);
	entry = new_entry();
	if (entry)
		goto success;
	return NULL;
success:
	entry->access = *acc;
	entry->pid = current->pid;
	return entry;
}

static struct kssb_buffer_entry *alloc_history_entry(struct kssb_access *acc)
{
	struct kssb_buffer_entry *entry = new_history_entry();
	if (entry)
		goto success;
	// The history buffer is exhausted. Let's flush the history buffer
	// and give a second shot.
	clear_history();
	entry = new_history_entry();
	if (entry)
		goto success;
	return NULL;
success:
	entry->access = *acc;
	entry->pid = current->pid;
	return entry;
}

static struct kssb_buffer_entry *latest_entry(struct kssb_access *acc)
{
	struct kssb_buffer_entry *entry;
	struct store_buffer *pcpu_buffer = this_cpu_ptr(&buffer);
	BUG_ON(!acc->aligned);
	hash_for_each_possible(pcpu_buffer->table, entry, hlist,
			       (uint64_t)acc->aligned_addr) {
		// Two different addrs are possibly mashed into a same
		// bucket so we need to check the address
		if (entry->access.aligned_addr == acc->aligned_addr)
			return entry;
	}
	return NULL;
}

static struct kssb_buffer_entry *get_history(struct kssb_access *acc)
{
	struct kssb_buffer_entry *entry;
	struct store_history *history = (struct store_history *)&global_history;
	BUG_ON(!acc->aligned);
	// This function should be called while lock is holded
	hash_for_each_possible(history->table, entry, hlist,
			       (uint64_t)acc->aligned_addr) {
		// Two different addrs are possibly mashed into a same
		// bucket so we need to check the address
		if ((entry->access.aligned_addr == acc->aligned_addr) &&
		    (entry->access.timestamp > __this_cpu_read(load_since))) {
			return entry;
		}
	}
	return NULL;
}

static inline bool in_stack_page(struct kssb_access *acc)
{
#ifdef CONFIG_X86_64
	// XXX: We support only the task contex only for now.
	unsigned long *begin = task_stack_page(current);
	unsigned long *end = task_stack_page(current) + THREAD_SIZE;
	unsigned long *addr = (unsigned long *)acc->addr;
	return begin <= addr && addr < end;
#else
	return false;
#endif
}

static void store_entry(struct kssb_buffer_entry *entry,
			struct kssb_access *acc)
{
	struct store_buffer *pcpu_buffer = this_cpu_ptr(&buffer);
	BUG_ON(!acc->aligned);
	hash_add(pcpu_buffer->table, &(entry->hlist),
		 (uint64_t)acc->aligned_addr);
}

static void __store_single_memcov_trace(struct kssb_access *acc)
{
	__sanitize_memcov_trace_store(acc->inst, acc->addr, acc->size);
	__store_single(acc);
}

static void __flush_single_entry_po_preserve(struct kssb_access *acc)
{
	do_buffer_flush(acc->aligned_addr);
	__store_single_memcov_trace(acc);
}

static void reclaim_entry_from_history(struct kssb_buffer_entry *entry)
{
	hash_del(&(entry->hlist));
	reclaim_history_entry(entry);
}

static void clear_history(void)
{
	int bkt;
	struct kssb_buffer_entry *entry;
	struct hlist_node *tmp;
	struct store_history *history = (struct store_history *)&global_history;
	history_lock();
	hash_for_each_safe(history->table, bkt, tmp, entry, hlist) {
		reclaim_entry_from_history(entry);
	}
	history_unlock();
}

static void charge_past_value(struct kssb_buffer_entry *entry)
{
	if (!load_prefetch_enabled)
		return;
	__this_cpu_write(latest_access, ++commit_count);
	entry->access.timestamp = commit_count;
	entry->access.aligned_old_val =
		READ_ONCE(*(uint64_t *)entry->access.aligned_addr);
}

static void record_history(struct kssb_buffer_entry *entry)
{
	struct hlist_node *tmp;
	struct kssb_buffer_entry *iter;
	struct store_history *history = (struct store_history *)&global_history;
	uint64_t aligned_addr = entry->access.aligned_addr;
	// Remove duplicated entry first
	hash_for_each_possible_safe(history->table, iter, tmp, hlist,
				    aligned_addr) {
		if (iter->access.aligned_addr == aligned_addr)
			reclaim_entry_from_history(iter);
	}
	// Then record the history
	hash_add(history->table, &(entry->hlist),
		 (uint64_t)entry->access.aligned_addr);
}

static void flush_single_entry(struct kssb_buffer_entry *entry)
{
	struct kssb_buffer_entry *new_entry = NULL;
	// We try our best to populate the page table entry before
	// storing the entry in the store callback. So here we expect
	// page table entries present for all entries. Although this
	// is not always true, we just BUG_ON() to panic the kernel so
	// the fuzzer can filter out the false alarm when our
	// expectation is not met.
	/* BUG_ON(in_page_fault_handler() && */
	/*        kssb_page_net_present(&entry->access)); */

	hash_del(&(entry->hlist));

	if (load_prefetch_enabled) {
		new_entry = alloc_history_entry(&(entry->access));
		if (!new_entry) 
			WARN_ONCE(1, "History buffer is exhausted");
	}
	history_lock();
	if (new_entry) {
		// Charge the past value in to the entry, and then update the
		// value in memory
		charge_past_value(new_entry);
		// Remove entry from the store buffer first, and then move the
		// entry to the history buffer.
		record_history(new_entry);
	}
	__store_single_memcov_trace(&(entry->access));
	history_unlock();
	reclaim_entry(entry);
}

static void do_buffer_flush(uint64_t aligned_addr)
{
	int bkt;
	struct kssb_buffer_entry *entry;
	struct hlist_node *tmp;
	struct store_buffer *pcpu_buffer = this_cpu_ptr(&buffer);
	bool flushed = false;
	bool flush_all = !aligned_addr;

	hash_for_each_safe(pcpu_buffer->table, bkt, tmp, entry, hlist) {
		// We just need to keep the stores' order only for
		// those having the same destination
		if (flush_all || entry->access.aligned_addr == aligned_addr) {
			flushed = true;
			flush_single_entry(entry);
		}
	}
	BUG_ON(flush_all && !hash_empty(pcpu_buffer->table));

	if (flushed)
		profile_flush(aligned_addr);

	if (flush_all)
		// Now the store buffer does not contain any entries.
		reset_context();
}

static void do_buffer_flush_n(uint64_t aligned_addr, int freeing)
{
	struct hlist_node *tmp;
	struct kssb_buffer_entry *entry;
	struct store_buffer *pcpu_buffer = this_cpu_ptr(&buffer);
	int bkt, freed = 0;

	if (!freeing)
		return;

	printk_debug(KERN_INFO "flushing %d entries for %lx\n", freeing,
		     aligned_addr);

	bkt = hash_min(aligned_addr, STOREBUFFER_BITS);
	hlist_for_each_entry_safe(entry, tmp, &pcpu_buffer->table[bkt], hlist) {
		if (entry->access.aligned_addr != aligned_addr)
			continue;
		flush_single_entry(entry);
		if (++freed >= freeing)
			break;
	}
}

static void do_buffer_flush_after_insn(struct kssb_access *acc)
{
	int freeing = flush_vector_next(acc->inst);
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

static inline void update_latest_access(uint64_t new)
{
	if (!load_prefetch_enabled)
		return;
	uint64_t old_access = __this_cpu_read(latest_access);
	__this_cpu_write(latest_access, (new > old_access) ? new : old_access);
}

static bool do_buffer_load_from_history(struct kssb_access *acc, uint64_t *ret)
{
	struct kssb_buffer_entry *old = get_history(acc);

	if (!old)
		return false;

	*ret = ((old->access.aligned_old_val) >> _BITS(acc->offset)) &
	       _BIT_MASK(_BITS(acc->size));
	update_latest_access(old->access.timestamp);
	reclaim_entry_from_history(old);

	return true;
}

static bool do_buffer_load_from_storebuffer(struct kssb_access *acc, uint64_t *ret)
{
	struct kssb_buffer_entry *latest;
	// We don't have to masking upper bits of ret. It will be done
	// when the value is returned.
	if ((latest = latest_entry(acc))) {
		*ret = __assemble_value(latest, acc);
		return true;
	}

	return false;
}

static uint64_t do_buffer_load_aligned(struct kssb_access *acc)
{
	bool ok = false;
	uint64_t ret = 0;
	bool load_old_value = load_prefetch_enabled &&
			      !flush_vector_next(acc->inst);

	printk_debug(KERN_INFO "do_buffer_load_aligned (%px, %lu, %d)\n",
		     acc->aligned_addr, acc->offset, acc->size);

	history_lock();
	ok = do_buffer_load_from_storebuffer(acc, &ret);
	
	if (!ok && load_old_value)
		ok = do_buffer_load_from_history(acc, &ret);

	if (!ok) {
		update_latest_access(commit_count);
		ret = __load_single(acc);
	}
	history_unlock();

	printk_debug(KERN_INFO "do_buffer_load_aligned => %lx\n", ret);

	do_buffer_flush_after_insn(acc);

	return ret;
}

static uint64_t do_buffer_load(struct kssb_access *acc)
{
	printk_debug(KERN_INFO "do_buffer_load (%px, %d)\n", acc->addr,
		     acc->size);

	assert_context(current);
	declare_emulating();

	align_access(acc);
	profile_load(acc);

	if (is_spanning_access(acc)) {
		flush_spanning_access(acc);
		return __load_single(acc);
	}

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
#ifdef CONFIG_KSSB_BINARY
		do_buffer_flush(acc->aligned_addr);
#else
		// We have an entry for addr in the store
		// buffer. aligned_val must be filled with 0 for newly
		// masked bits.
		acc->aligned_val =
			((latest->access.aligned_val & latest->access.mask) &
			 ~acc->mask) |
			(acc->aligned_val & acc->mask);
		acc->mask |= latest->access.mask;
#endif
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
	uint64_t offset = (uint64_t)acc->addr % 8;
	return acc->size + offset > 8;
}

static void flush_spanning_access(struct kssb_access *acc)
{
	// TEMP: I do know how the real machine works in this
	// case. To be safe, flush the two words and the store
	// without emulating the store buffer.
	do_buffer_flush(acc->aligned_addr);
	do_buffer_flush(acc->aligned_addr + 8);
}

static inline void populate_store_buffer(struct kssb_access *acc)
{
	// We do not support the store buffer emulation in contexts
	// other than task. So it is guaranteed that this function is
	// not called in the page fault, meaning loading a value does
	// not cause infinitely recursive page faults.
	(void)__load_single(acc);
}

static void do_buffer_store(struct kssb_access *acc)
{
	printk_debug(KERN_INFO "do_buffer_store (%px, %llx, %d)\n", acc->addr,
		     acc->val, acc->size);

	assert_context(current);
	declare_emulating();

	align_access(acc);
	profile_store(acc);

	// We need to populate the page table entry for acc before
	// storing the entry. Otherwise, the page fault may occurs
	// when flushing the entry later and the page fault handler
	// will try to flush it again at its entry point, causing
	// infinitely recursive page faults.
	populate_store_buffer(acc);

	if (is_spanning_access(acc)) {
		flush_spanning_access(acc);
		__store_single_memcov_trace(acc);
		return;
	}

	do_buffer_store_aligned(acc);
}

static bool __kssb_check_access(struct kssb_access *acc)
{
	if (acc->type == kssb_load)
		return kasan_check_read((void *)acc->inst, acc->size);
	else
		return kasan_check_write((void *)acc->inst, acc->size);
}

// NOTE: Load/store callback should not be preempted until they are
// finished (they use a percpu store buffer). Whenever an interrupt is
// delivered, the percpu store buffer should be flushed to make sure
// that the percpu store buffer is not polluted.
// NOTE: Partial initialization of struct will fill 0 to the remainings
static bool kssb_enabled(void)
{
	bool enabled =
#ifdef CONFIG_KSSB_SWITCH
		current->kssb_enabled;
#else
		true;
#endif
	return enabled && kssb_initialized;
}

// TODO: support contexts other than task
#define in_kssb_enabled_task() (in_task() && kssb_enabled())

#define CAN_EMULATE_KSSB(acc) (in_kssb_enabled_task() && !in_stack_page(acc))

#define INIT_KSSB_ACCESS(_addr, _val, _size, _type, inst)                \
	{                                                                \
		.inst = inst, .addr = _addr, .val = _val, .size = _size, \
		.type = _type,                                           \
	}
#define INIT_KSSB_LOAD(_addr, _size, inst) \
	INIT_KSSB_ACCESS(_addr, 0, _size, kssb_load, inst)
#define INIT_KSSB_STORE(_addr, _val, _size, inst) \
	INIT_KSSB_ACCESS(_addr, _val, _size, kssb_store, inst)

void kssb_record_history(const volatile void *v, size_t size)
{
	struct kssb_buffer_entry *entry;
	unsigned long flags;
	unsigned long inst = _RET_IP_;
	struct kssb_access *accp,
		acc = INIT_KSSB_STORE((uint64_t *)v, UNKNOWN_VALUE, size, inst);
	accp = &acc;

	raw_local_irq_save(flags);
	if (CAN_EMULATE_KSSB(accp) && load_prefetch_enabled) {
		align_access(accp);

		if ((entry = alloc_history_entry(accp))) {
			history_lock();
			charge_past_value(entry);
			record_history(entry);
			history_unlock();
		} else {
			WARN_ONCE(1, "Store buffer is exhausted");
		}
	}
	raw_local_irq_restore(flags);
}
EXPORT_SYMBOL(kssb_record_history);

static uint64_t __load_callback_pso(uint64_t *addr, size_t size,
				    unsigned long inst)
{
	uint64_t ret;
	unsigned long flags;
	struct kssb_access acc = INIT_KSSB_LOAD(addr, size, inst);

	__sanitize_memcov_trace_load(acc.inst, addr, size);
	__kssb_check_access(&acc);

	raw_local_irq_save(flags);
	if (CAN_EMULATE_KSSB(&acc))
		ret = do_buffer_load(&acc);
	else
		ret = __load_single(&acc);
	raw_local_irq_restore(flags);
	return ret;
}

static void __store_callback_pso(uint64_t *addr, uint64_t val, size_t size,
				 unsigned long inst)
{
	unsigned long flags;
	struct kssb_access acc = INIT_KSSB_STORE(addr, val, size, inst);

	__kssb_check_access(&acc);

	raw_local_irq_save(flags);
	if (CAN_EMULATE_KSSB(&acc))
		do_buffer_store(&acc);
	else
		__flush_single_entry_po_preserve(&acc);
	raw_local_irq_restore(flags);
}

static void __flush_callback_pso(void)
{
	unsigned long flags;
	raw_local_irq_save(flags);
	// The flush callback should be called regardless of the
	// context.
	do_buffer_flush(0);
	sanitize_memcov_trace_flush();
	revoke_emulating();
	raw_local_irq_restore(flags);
}

static void __lfence_callback_pso(void)
{
	uint64_t since;
	unsigned long flags;
	raw_local_irq_save(flags);
	sanitize_memcov_trace_lfence();
	if (in_kssb_enabled_task()) {
		profile_lfence();
		since = __this_cpu_read(latest_access);
		__this_cpu_write(load_since, since);
	}
	raw_local_irq_restore(flags);
}

static void __retchk_callback_pso(void *ret)
{
	unsigned long flags;

	if (!in_kssb_enabled_task())
		return;

	raw_local_irq_save(flags);
	if (!is_instrumented_address(ret)) {
		profile_retchk(ret);
		__flush_callback_pso();
	}
	raw_local_irq_restore(flags);
}

static void __funcentry_callback_pso(void *ret)
{
	unsigned long flags;
	struct store_buffer *pcpu_buffer;

	if (!in_kssb_enabled_task())
		return;

	// TODO: Not sure we need to disable IRQs. Do it to be safe.
	raw_local_irq_save(flags);
	pcpu_buffer = this_cpu_ptr(&buffer);
	if (pcpu_buffer->emulating) {
		profile_funcentry(ret);
		set_instrumented_address(ret);
	}
	raw_local_irq_restore(flags);
}

static bool is_kssb_callback(unsigned long ip)
{
	void *callbacks[] = { __store_callback_pso, __load_callback_pso };
	for (int i = 0; i < sizeof(callbacks) / sizeof(callbacks[0]); i++) {
		unsigned long callback_address = (unsigned long)callbacks[i];
		// XXX: Simple heuristic to determine that ip resides in our
		// callbacks.
		if (callback_address <= ip && ip < callback_address + PAGE_SIZE)
			return true;
	}
	return false;
}

static unsigned long callback_caller(struct pt_regs *regs)
{
	struct unwind_state state;
	unwind_start(&state, current, regs, (void *)regs->sp);
	return state.ip;
}

unsigned long skip_kssb_callbacks(struct pt_regs *regs)
{
	if (is_kssb_callback(regs->ip))
		return callback_caller(regs);
	return regs->ip;
}

#define MEMORYMODEL pso
#define STORE_CALLBACK_IMPL __store_callback_pso
#define LOAD_CALLBACK_IMPL __load_callback_pso
#define FLUSH_CALLBACK_IMPL __flush_callback_pso
#define LFENCE_CALLBACK_IMPL __lfence_callback_pso
#define RETCHK_CALLBACK_IMPL __retchk_callback_pso
#define FUNCENTRY_CALLBACK_IMPL __funcentry_callback_pso
#include "callback.h"
