#ifndef __KSSB_BARRIER_H
#define __KSSB_BARRIER_H

extern volatile char __ssb_do_emulate;
extern void __ssb_pso_flush(void);
extern void __ssb_pso_lfence(bool full);

#define ____flush() __ssb_pso_flush()
#define ____lfence(full) __ssb_pso_lfence(full)

#ifdef __KSSB_INSTRUMENT_BARRIERS__

#define kssb_mb()                 \
	do {                      \
		____flush();      \
		____lfence(true); \
	} while (0)
// Adding callbacks in kssb_rmb raises build error in vdso.
// So, we temporariliy leave it empty.
#define kssb_rmb()                \
	do {                      \
		____lfence(true); \
	} while (0)
#define kssb_wmb() ____flush()
#define kssb_release() ____flush()

#else

#define kssb_mb() \
	do {      \
	} while (0)
#define kssb_rmb() \
	do {       \
	} while (0)
#define kssb_wmb() \
	do {       \
	} while (0)
#define kssb_release() \
	do {           \
	} while (0)
#endif

#endif
