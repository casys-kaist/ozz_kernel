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
void sanitize_memcov_trace_flush(void);
void sanitize_memcov_trace_lfence(void);

#else

#define kmemcov_task_init(...) do { } while (0)
#define kmemcov_task_exit(...) do { } while (0)
#define __sanitize_memcov_trace_store(...) do { } while (0)
#define __sanitize_memcov_trace_load(...) do { } while (0)
#define sanitize_memcov_trace_store(...) do { } while (0)
#define sanitize_memcov_trace_load(...) do { } while (0)
#define sanitize_memcov_trace_flush(...) do { } while (0)
#define sanitize_memcov_trace_lfence(...) do { } while (0)

#endif /* CONFIG_KMEMCOV */

#endif /* __LINUX_KMEMCOV_H */
