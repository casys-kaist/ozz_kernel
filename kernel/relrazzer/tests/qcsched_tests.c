#include <linux/syscalls.h>
#include <linux/printk.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/rwlock.h>
#include <linux/semaphore.h>

volatile int var;

static DEFINE_SPINLOCK(test_spinlock);
static DEFINE_MUTEX(test_mutex);
static rwlock_t test_rwlock;
static struct rw_semaphore test_rwsem;

enum lock_type {
	none = 1,
	spinlock,
	mutex,
	rwlock,
	rwsem,
};

static noinline void __lock(enum lock_type type, bool writer)
{
	switch (type) {
	case none:
		break;
	case spinlock:
		spin_lock(&test_spinlock);
		break;
	case mutex:
		mutex_lock(&test_mutex);
		break;
	case rwlock:
		if (writer)
			write_lock(&test_rwlock);
		else
			read_lock(&test_rwlock);
		break;
	case rwsem:
		if (writer)
			down_write(&test_rwsem);
		else
			down_read(&test_rwsem);
		break;
	}
}

static noinline void __unlock(enum lock_type type, bool writer)
{
	switch (type) {
	case none:
		break;
	case spinlock:
		spin_unlock(&test_spinlock);
		break;
	case mutex:
		mutex_unlock(&test_mutex);
		break;
	case rwlock:
		if (writer)
			write_unlock(&test_rwlock);
		else
			read_unlock(&test_rwlock);
	case rwsem:
		if (writer)
			up_write(&test_rwsem);
		else
			up_read(&test_rwsem);
		break;
	}
}

static noinline void __qcsched_simple_write(enum lock_type type)
{
	printk(KERN_INFO "qcsched simple write\n");
	__lock(type, true);
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
	__unlock(type, true);
}

static noinline void __qcsched_simple_read(enum lock_type type)
{
	__attribute__((unused)) int local;
	printk(KERN_INFO "qcsched simple read\n");
	__lock(type, false);
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
	__unlock(type, false);
}

SYSCALL_DEFINE1(qcsched_simple_write, int, lock)
{
	__qcsched_simple_write(lock);
	return 0;
}

SYSCALL_DEFINE1(qcsched_simple_read, int, lock)
{
	__qcsched_simple_read(lock);
	return 0;
}

static int __init qcsched_test_init(void)
{
	printk(KERN_INFO "%s", __func__);
	rwlock_init(&test_rwlock);
	init_rwsem(&test_rwsem);
	return 0;
}
late_initcall(qcsched_test_init);
