#ifndef __ATOMIC_NO_KSSB_H
#define __ATOMIC_NO_KSSB_H

#define NO_FLUSH_SEMANTIC "/*no kssb*/"

#define arch_xchg_no_kssb_flush(ptr, v) \
	__xchg_op((ptr), (v), xchg, "", NO_FLUSH_SEMANTIC)

#define arch_cmpxchg_no_kssb_flush(ptr, old, new)					\
		__raw_cmpxchg((ptr), (old), (new), (sizeof(*(ptr))), LOCK_PREFIX, NO_FLUSH_SEMANTIC)
#define arch_cmpxchg64_no_kssb_flush arch_cmpxchg_no_kssb_flush

#define arch_try_cmpxchg_no_kssb_flush(ptr, pold, new) 				\
		__raw_try_cmpxchg((ptr), (pold), (new), (sizeof(*(ptr))), LOCK_PREFIX, NO_FLUSH_SEMANTIC)
#define arch_try_cmpxchg64_no_kssb_flush arch_try_cmpxchg_no_kssb_flush

#endif /* __ATOMIC_NO_KSSB_H */
