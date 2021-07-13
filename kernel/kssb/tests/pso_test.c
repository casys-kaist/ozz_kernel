#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/delay.h>

struct shared_t {
	int *ptr;
	bool ready;
};

struct shared_t shared;

static noinline void pso_test_breakpoint(void)
{
}

__attribute__((softstorebuffer)) static void do_writer(bool do_sleep)
{
	struct shared_t *ptr = (struct shared_t *)&shared;
	int *iptr = (int *)kmalloc(sizeof(*ptr->ptr), GFP_KERNEL);
	local_irq_disable();
	ptr->ptr = iptr;
	ptr->ready = true;
	pso_test_breakpoint();
	if (do_sleep)
		mdelay(3000);
	local_irq_enable();
}

__attribute__((softstorebuffer)) static void do_reader(bool do_sleep)
{
	int a;
	struct shared_t *ptr;
	if (do_sleep)
		mdelay(1000);
	ptr = (struct shared_t *)&shared;
	local_irq_disable();
	if (ptr->ready) {
		a = *ptr->ptr;
		printk("%d\n", a);
	}
	local_irq_enable();
}

SYSCALL_DEFINE1(ssb_pso_writer, bool, do_sleep)
{
	do_writer(do_sleep);
	return 0;
}

SYSCALL_DEFINE1(ssb_pso_reader, bool, do_sleep)
{
	do_reader(do_sleep);
	return 0;
}

SYSCALL_DEFINE0(pso_clear)
{
	shared.ready = false;
	kfree(shared.ptr);
	return 0;
}
