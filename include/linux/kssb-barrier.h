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
#define kssb_rmb() ____lfence(false)
#define kssb_wmb() ____flush()
#define kssb_release() ____flush()
#define kssb_acquire() ____lfence(false)

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
#define kssb_acquire() \
	do {           \
	} while (0)
#endif

#endif
