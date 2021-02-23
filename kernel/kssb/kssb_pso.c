#include <linux/kernel.h>

uint64_t __load_callback_pso(uint64_t *addr, const size_t size)
{
	return 0;
}

void __store_callback_pso(uint64_t *addr, const uint64_t val, const size_t size)
{
}

void __flush_callback_pso(const char *addr)
{
}

#define MEMORYMODEL pso
#define STORE_CALLBACK_IMPL __store_callback_pso
#define LOAD_CALLBACK_IMPL __load_callback_pso
#define FLUSH_CALLBACK_IMPL __flush_callback_pso
#include "callback.h"
