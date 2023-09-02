#ifndef __LINUX_KSSB_H
#define __LINUX_KSSB_H

#ifdef CONFIG_KSSB
#include <linux/ptrace.h>
void kssb_print_store_buffer(void);
unsigned long skip_kssb_callbacks(struct pt_regs *regs);
#else
#define kssb_print_store_buffer() \
	do {                      \
	} while (0);
#define skip_kssb_callbacks(regs) \
	do {                      \
	} while (0);
#endif

#endif /* __LINUX_KSSB_H */
