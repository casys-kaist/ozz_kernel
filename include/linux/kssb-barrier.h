#ifndef __KSSB_BARRIER_H
#define __KSSB_BARRIER_H

extern volatile char __ssb_do_emulate;
extern void __ssb_pso_flush(void);
extern void __ssb_pso_lfence(bool full);

#define ____flush() __ssb_pso_flush()
#define ____lfence(full) __ssb_pso_lfence(full)

#define kssb_mb() \
	do {       \
		____flush(); \
		____lfence(true); \
	} while (0)
// Adding callbacks in kssb_rmb raises build error in vdso.
// So, we temporariliy leave it empty.  
#define kssb_rmb() \
	do {       \
	} while (0)
#define kssb_rmb_real() ____lfence(false)
#define kssb_wmb() ____flush()
#define kssb_release() ____flush()

#endif
