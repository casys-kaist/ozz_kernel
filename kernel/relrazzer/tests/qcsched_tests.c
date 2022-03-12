#include <linux/syscalls.h>
#include <linux/printk.h>

volatile int var;

static noinline void __qcsched_simple_write()
{
	printk(KERN_INFO "qcsched simple write\n");
	WRITE_ONCE(var, 1);
	WRITE_ONCE(var, 2);
	WRITE_ONCE(var, 3);
	WRITE_ONCE(var, 4);
	WRITE_ONCE(var, 5);
	WRITE_ONCE(var, 6);
	WRITE_ONCE(var, 7);
	WRITE_ONCE(var, 8);
	WRITE_ONCE(var, 9);
	WRITE_ONCE(var, 10);
}

static noinline void __qcsched_simple_read()
{
	__attribute__((unused)) int local;
	printk(KERN_INFO "qcsched simple read\n");
	local = READ_ONCE(var);
	local = READ_ONCE(var);
	local = READ_ONCE(var);
	local = READ_ONCE(var);
	local = READ_ONCE(var);
	local = READ_ONCE(var);
	local = READ_ONCE(var);
	local = READ_ONCE(var);
	local = READ_ONCE(var);
	local = READ_ONCE(var);
}

SYSCALL_DEFINE0(qcsched_simple_write)
{
	__qcsched_simple_write();
	return 0;
}

SYSCALL_DEFINE0(qcsched_simple_read)
{
	__qcsched_simple_read();
	return 0;
}
