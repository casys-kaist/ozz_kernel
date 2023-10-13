#ifndef __LINUX_KCOV_IOCTLS_H
#define __LINUX_KCOV_IOCTLS_H

#define KMEMCOV_INIT_TRACE _IO('d', 100)
#define KMEMCOV_ENABLE _IO('d', 101)
#define KMEMCOV_DISABLE _IO('d', 102)

enum kmemcov_access_type {
	KMEMCOV_ACCESS_STORE,
	KMEMCOV_ACCESS_LOAD,
	KMEMCOV_ACCESS_FLUSH,
	KMEMCOV_ACCESS_LFENCE,
};

struct kmemcov_access {
	unsigned long inst;
	unsigned long addr;
	size_t size;
	enum kmemcov_access_type type;
	uint64_t timestamp;
};

#endif /* __LINUX_KCOV_IOCTLS_H */
