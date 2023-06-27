#include <linux/syscalls.h>
#include <linux/slab.h>

static int a = 0, b = 0;
static int r1 = 1, r2 = 1;

SYSCALL_DEFINE0(ssb_tso_thread1)
{
	a = 1;
	r1 = b;
	return 0;
}

SYSCALL_DEFINE0(ssb_tso_thread2)
{
	b = 1;
	r2 = a;
	return 0;
}

SYSCALL_DEFINE0(tso_check)
{
	printk(KERN_INFO "r1: %d r2: %d\n", r1, r2);
	BUG_ON(r1 == 0 && r2 == 0);
	a = 0;
	b = 0;
	r1 = 1;
	r2 = 1;
	return 0;
}
