// Functions in this file are not intended to be a part of the
// kernel. Instead, they are used to test instrumentation is done
// correctly.

#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/atomic.h>
#include <linux/bitops.h>

#if defined(__clang__)
#pragma clang optimize off
#elif defined(__GNUC__) || defined(__GNUG__)
__attribute__((optimize("-O0")))
#endif
__attribute__((softstorebuffer)) void __list_atomics(void)
{
	unsigned long ul;
	atomic_t a;
	int i;
	/* bitops */
	/* Non-RMW ops: */
	/*   test_bit() */
bitops1:
	test_bit(0, &ul);

	/* RMW atomic operations without return value: */
	/*   {set,clear,change}_bit() */
	/*   clear_bit_unlock() */
bitops2:
	set_bit(0, &ul);
	clear_bit(0, &ul);
	change_bit(0, &ul);

	/* RMW atomic operations with return value: */
	/*   test_and_{set,clear,change}_bit() */
	/*   test_and_set_bit_lock() */
bitops3:
	test_and_set_bit(0, &ul);
	test_and_clear_bit(0, &ul);
	test_and_change_bit(0, &ul);
	test_and_set_bit_lock(0, &ul);

	/* atomic */
	/* Non-RMW ops: */
	/*   atomic_read(), atomic_set() */
	/*   atomic_read_acquire(), atomic_set_release() */
atomic1:
	atomic_read(&a);
	atomic_set(&a, 1);
	atomic_read_acquire(&a);
	atomic_set_release(&a, 1);

	/* RMW atomic operations: */
	/* Arithmetic: */
	/*   atomic_{add,sub,inc,dec}() */
atomic2:
	atomic_add(1, &a);
	atomic_sub(1, &a);
	atomic_inc(&a);
	atomic_dec(&a);
	/*   atomic_{add,sub,inc,dec}_return{,_relaxed,_acquire,_release}() */
atomic3:
	atomic_add_return(1, &a);
	atomic_sub_return(1, &a);
	atomic_inc_return(&a);
	atomic_dec_return(&a);
	atomic_add_return_relaxed(1, &a);
	atomic_sub_return_relaxed(1, &a);
	atomic_inc_return_relaxed(&a);
	atomic_dec_return_relaxed(&a);
	atomic_add_return_acquire(1, &a);
	atomic_sub_return_acquire(1, &a);
	atomic_inc_return_acquire(&a);
	atomic_dec_return_acquire(&a);
	atomic_add_return_release(1, &a);
	atomic_sub_return_release(1, &a);
	atomic_inc_return_release(&a);
	atomic_dec_return_release(&a);
	/*   atomic_fetch_{add,sub,inc,dec}{,_relaxed,_acquire,_release}() */
atomic4:
	atomic_fetch_add(1, &a);
	atomic_fetch_sub(1, &a);
	atomic_fetch_inc(&a);
	atomic_fetch_dec(&a);
	atomic_fetch_add_relaxed(1, &a);
	atomic_fetch_sub_relaxed(1, &a);
	atomic_fetch_inc_relaxed(&a);
	atomic_fetch_dec_relaxed(&a);
	atomic_fetch_add_acquire(1, &a);
	atomic_fetch_sub_acquire(1, &a);
	atomic_fetch_inc_acquire(&a);
	atomic_fetch_dec_acquire(&a);
	atomic_fetch_add_release(1, &a);
	atomic_fetch_sub_release(1, &a);
	atomic_fetch_inc_release(&a);
	atomic_fetch_dec_release(&a);
	/* Bitwise: */
	/*   atomic_{and,or,xor,andnot}() */
atomic5:
	atomic_and(0, &a);
	atomic_or(0, &a);
	atomic_xor(0, &a);
	atomic_andnot(0, &a);
	/*   atomic_fetch_{and,or,xor,andnot}{,_relaxed,_acquire,_release}() */
atomic6:
	atomic_fetch_and(0, &a);
	atomic_fetch_or(0, &a);
	atomic_fetch_xor(0, &a);
	atomic_fetch_andnot(0, &a);
	atomic_fetch_and_relaxed(0, &a);
	atomic_fetch_or_relaxed(0, &a);
	atomic_fetch_xor_relaxed(0, &a);
	atomic_fetch_andnot_relaxed(0, &a);
	atomic_fetch_and_acquire(0, &a);
	atomic_fetch_or_acquire(0, &a);
	atomic_fetch_xor_acquire(0, &a);
	atomic_fetch_andnot_acquire(0, &a);
	atomic_fetch_and_release(0, &a);
	atomic_fetch_or_release(0, &a);
	atomic_fetch_xor_release(0, &a);
	atomic_fetch_andnot_release(0, &a);
	/* Swap: */
	/*   atomic_xchg{,_relaxed,_acquire,_release}() */
atomic7:
	atomic_xchg(&a, 1);
	atomic_xchg_relaxed(&a, 1);
	atomic_xchg_acquire(&a, 1);
	atomic_xchg_release(&a, 1);
	/*   atomic_cmpxchg{,_relaxed,_acquire,_release}() */
atomic8:
	atomic_cmpxchg(&a, 0, 1);
	atomic_cmpxchg_relaxed(&a, 0, 1);
	atomic_cmpxchg_acquire(&a, 0, 1);
	atomic_cmpxchg_release(&a, 0, 1);
	/*   atomic_try_cmpxchg{,_relaxed,_acquire,_release}() */
atomic9:
	atomic_try_cmpxchg(&a, &i, 1);
	atomic_try_cmpxchg_relaxed(&a, &i, 1);
	atomic_try_cmpxchg_acquire(&a, &i, 1);
	atomic_try_cmpxchg_release(&a, &i, 1);

	/* Reference count (but please see refcount_t): */
	/*   atomic_add_unless(), atomic_inc_not_zero() */
atomic10:
	atomic_add_unless(&a, 0, 1);
	atomic_inc_not_zero(&a);
	/*   atomic_sub_and_test(), atomic_dec_and_test() */
atomic11:
	atomic_sub_and_test(0, &a);
	atomic_dec_and_test(&a);

	/* Misc: */
	/*   atomic_inc_and_test(), atomic_add_negative() */
	/*   atomic_dec_unless_positive(), atomic_inc_unless_negative() */
atomic12:
	atomic_inc_and_test(&a);
	atomic_add_negative(1, &a);
	atomic_dec_unless_positive(&a);
	atomic_inc_unless_negative(&a);

	/* Barriers: */
	/*   smp_mb__{before,after}_atomic() */
barriers:
	smp_mb__before_atomic();
	smp_mb__after_atomic();
}

#if !defined(__clang__) && (defined(__GNUC__) || defined(__GNUG__))
__attribute__((optimize("-O0")))
#endif
__attribute__((softstorebuffer)) void
__list_refcounts(void)
{
	refcount_t r;
	refcount_set(&r, 1);
	refcount_read(&r);
	(void)refcount_inc_not_zero(&r);
	refcount_inc(&r);
	(void)refcount_sub_and_test(0, &r);
	(void)refcount_dec_and_test(&r);
}

#if !defined(__clang__) && (defined(__GNUC__) || defined(__GNUG__))
__attribute__((optimize("-O0")))
#endif
__attribute__((softstorebuffer)) void
__list_rcus(void)
{
	synchronize_rcu();
	rcu_read_lock();
	rcu_read_unlock();
}

#if defined(__clang__)
#pragma clang optimize on
#endif
