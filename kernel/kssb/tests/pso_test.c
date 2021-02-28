#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/delay.h>

struct shared_t {
	int *ptr;
	bool ready;
};

static struct shared_t shared;

#define _DO_SLEEP

__attribute__((softstorebuffer)) static void do_writer(void)
{
	struct shared_t *ptr = (struct shared_t *)&shared;
	int *iptr = (int *)kmalloc(sizeof(*ptr->ptr), GFP_KERNEL);
	local_irq_disable();
	ptr->ptr = iptr;
	ptr->ready = true;
#ifdef _DO_SLEEP
	mdelay(3000);
#endif
	local_irq_enable();
}

__attribute__((softstorebuffer)) static void do_reader(void)
{
	int a;
	struct shared_t *ptr = (struct shared_t *)&shared;
	local_irq_disable();
#ifdef _DO_SLEEP
	mdelay(1000);
#endif
	if (ptr->ready)
		a = *ptr->ptr;
	local_irq_enable();
}

SYSCALL_DEFINE0(ssb_pso_writer)
{
	do_writer();
	return 0;
}

SYSCALL_DEFINE0(ssb_pso_reader)
{
	do_reader();
	return 0;
}

SYSCALL_DEFINE0(pso_clear)
{
	kfree(shared.ptr);
	return 0;
}
