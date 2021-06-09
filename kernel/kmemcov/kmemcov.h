#ifndef __KMEMCOV_H
#define __KMEMCOV_H

void notrace __sanitize_memcov_trace_store(void *addr, size_t size);
void notrace __sanitize_memcov_trace_load(void *addr, size_t size);

#endif /* __KMEMCOV_H */
