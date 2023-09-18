#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/delay.h>

struct shared_t {
	int *ptr;
	bool ready;
};

struct shared_t shared;

int nothing;

noinline void pso_test_breakpoint(void)
{
	nothing = 0;
}

noinline void pso_do_nothing(void)
{
	nothing = 0;
}

__attribute__((softstorebuffer)) static void
do_writer(bool do_sleep, bool disable_irq, bool funccall)
{
	struct shared_t *ptr = (struct shared_t *)&shared;
	int *iptr = (int *)kmalloc(sizeof(*ptr->ptr), GFP_KERNEL);
	if (disable_irq)
		local_irq_disable();
	ptr->ptr = iptr;
	if (funccall)
		pso_do_nothing();
	smp_wmb();
	ptr->ready = true;
	if (!do_sleep)
		// NOTE: As of milestone-0.4, the return check
		// mechanism of our kssb pass always flushes the store
		// buffer, which is incomplete yet. This is safe
		// regarding the kernel booting process, it prevents
		// pso_test from triggering if we execute the
		// breakpoint function. So execute the function if
		// do_sleep is false for all tests work properly.
		pso_test_breakpoint();
	if (do_sleep)
		mdelay(3000);
	if (disable_irq)
		local_irq_enable();
}

__attribute__((softstorebuffer)) static void do_reader(bool do_sleep,
						       bool disable_irq)
{
	int a;
	struct shared_t *ptr;
	// printk(KERN_INFO "%s: do_sleep: %d disable_irq: %d\n", __func__,
	//        do_sleep, disable_irq);
	// if (do_sleep)
	// 	mdelay(1000);
	ptr = (struct shared_t *)&shared;
	if (disable_irq)
		local_irq_disable();
	if (ptr->ready) {
		// Uncomment to prevent reordering
		// kssb_rmb_real();
		a = *ptr->ptr;
		printk("%d\n", a);
	}
	if (disable_irq)
		local_irq_enable();
}

SYSCALL_DEFINE3(ssb_pso_writer, bool, do_sleep, bool, disable_irq, bool,
		funccall)
{
	do_writer(do_sleep, disable_irq, funccall);
	return 0;
}

SYSCALL_DEFINE2(ssb_pso_reader, bool, do_sleep, bool, disable_irq)
{
	do_reader(do_sleep, disable_irq);
	return 0;
}

SYSCALL_DEFINE0(pso_clear)
{
	shared.ready = false;
	if (shared.ptr != NULL) {
		kfree(shared.ptr);
		shared.ptr = NULL;
	}
	return 0;
}
