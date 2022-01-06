#ifndef __LINUX_KMEMCOV_H
#define __LINUX_KMEMCOV_H

#include <uapi/linux/kmemcov.h>

struct task_struct;

#ifdef CONFIG_KMEMCOV

enum kmemcov_mode {
	KMEMCOV_MODE_DISABLED = 0,
	KMEMCOV_MODE_INIT = 1,
	KMEMCOV_MODE_TRACE_STLD = 2,
};

void kmemcov_task_init(struct task_struct *t);
void kmemcov_task_exit(struct task_struct *t);
void __sanitize_memcov_trace_store(unsigned long inst, void *addr, size_t size);
void __sanitize_memcov_trace_load(unsigned long inst, void *addr, size_t size);
void sanitize_memcov_trace_store(const volatile void *addr, size_t size);
void sanitize_memcov_trace_load(const volatile void *addr, size_t size);

#else

static inline void kmemcov_task_init(struct task_struct *t) {}
static inline void kmemcov_task_exit(struct task_struct *t) {}
static inline void __sanitize_memcov_trace_store(unsigned long inst, void *addr, size_t size) {}
static inline void __sanitize_memcov_trace_load(unsigned long inst, void *addr, size_t size) {}
static inline void sanitize_memcov_trace_store(const volatile void *addr, size_t size) {}
static inline void sanitize_memcov_trace_load(const volatile void *addr, size_t size) {}

#endif /* CONFIG_KMEMCOV */

#endif /* __LINUX_KMEMCOV_H */
