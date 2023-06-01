#define NO_INSTRUMENT_ATOMIC
#include <linux/kernel.h>
#include <linux/kssb.h>
#include <linux/hash.h>

#define INST_MAP_BIT 18
#define INST_MAP_SIZE 1 << INST_MAP_BIT
#define inst_addr_hash(addr) hash_long((uint64_t)addr, INST_MAP_BIT)

static bool inst_map[INST_MAP_SIZE];

void set_instrumented_address(void *addr)
{
	uint32_t idx = inst_addr_hash(addr);
	inst_map[idx] = true;
}

bool is_instrumented_address(void *addr)
{
	uint32_t idx = inst_addr_hash(addr);
	return inst_map[idx];
}
