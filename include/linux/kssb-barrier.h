#ifndef __KSSB_BARRIER_H
#define __KSSB_BARRIER_H

extern volatile char __ssb_do_emulate;
extern void __ssb_pso_flush(void);
extern void __ssb_pso_lfence(void);

#define ____flush() __ssb_pso_flush()
#define ____lfence() __ssb_pso_lfence()

#ifdef __KSSB_INSTRUMENT_BARRIERS__

#define kssb_mb()             \
	do {                  \
		____flush();  \
		____lfence(); \
	} while (0)
#define kssb_rmb() ____lfence()
#define kssb_wmb() ____flush()
#define kssb_release() ____flush()
#define kssb_acquire() ____lfence()

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
