#ifndef __KSSB_PROFILE_H
#define __KSSB_PROFILE_H

#ifdef CONFIG_KSSB_PROFILE
#include <linux/atomic.h>
#include <linux/module.h>

#include "kssb.h"

struct kssb_stat_t {
	atomic64_t load_count;
	atomic64_t store_count;
	atomic64_t flush_count;
	atomic64_t retchk_count;
	atomic64_t funcentry_count;
	atomic64_t lfence_count;
};

extern struct kssb_stat_t kssb_stat;
extern bool kssb_do_profile;

void profile_load(struct kssb_access *);
void profile_store(struct kssb_access *);
void profile_flush(uint64_t);
void profile_retchk(void *);
void profile_funcentry(void *);
void profile_reset(void);
void profile_lfence(void);
int profile_emulated_inst_show(struct seq_file *m, void *v);
void profile_reset_emulated_inst(void);
#else
#define profile_load(...) \
	do {              \
	} while (0)
#define profile_store(...) \
	do {               \
	} while (0)
#define profile_flush(...) \
	do {               \
	} while (0)
#define profile_reset(...) \
	do {               \
	} while (0)
#define profile_lfence(...) \
	do {                \
	} while (0)
#define profile_retchk(...) \
	do {                \
	} while (0)
#define profile_funcentry(...) \
	do {                   \
	} while (0)
#define profile_print_emulated_inst(...) \
	do {                             \
	} while (0)
#define profile_reset_emulated_inst(...) \
	do {                             \
	} while (0)
#endif

#endif /* __KSSB_PROFILE_H */
