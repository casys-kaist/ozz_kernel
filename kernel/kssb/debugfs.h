#ifndef __KSSB_DEBUGFS_H
#define __KSSB_DEBUGFS_H

#ifdef CONFIG_KSSB_PROFILE
int kssb_debugfs_init(void);
void kssb_debugfs_cleanup(void);
#else
#define kssb_debugfs_init() \
	do {                \
	} while (0)
#define kssb_debugfs_cleanup() \
	do {                   \
	} while (0)
#endif

#endif
