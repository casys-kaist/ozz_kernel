#ifndef __KSSB_BARRIER_H
#define __KSSB_BARRIER_H

extern volatile char __ssb_do_emulate;
extern void __ssb_pso_flush(void);

#define ____flush() __ssb_pso_flush()

#define kssb_mb() ____flush()
#define kssb_rmb() \
	do {       \
	} while (0)
#define kssb_wmb() ____flush()

#endif
