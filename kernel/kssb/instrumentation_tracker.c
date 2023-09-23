#define NO_INSTRUMENT_ATOMIC
#include <linux/kernel.h>
#include <linux/kssb.h>
#include <linux/hash.h>

#define INST_MAP_BIT 18
#define INST_MAP_SIZE 1 << INST_MAP_BIT
#define inst_addr_hash(addr) hash_long((uint64_t)addr, INST_MAP_BIT)

#define BUCKET_SIZE 100

static unsigned int inst_map[INST_MAP_SIZE][BUCKET_SIZE];

#define truncate(addr) ((unsigned int)(intptr_t)addr)

void set_instrumented_address(void *addr)
{
	unsigned int truncated = truncate(addr);
	uint32_t idx = inst_addr_hash(addr);
	for (int i = 0; i < BUCKET_SIZE; i++) {
		if (inst_map[idx][i] == truncated)
			return;
		if (inst_map[idx][i] == 0) {
			inst_map[idx][i] = truncated;
			return;
		}
	}
	printk("inst_map exhausted!");
	for (int i = 0; i < BUCKET_SIZE; i++)
		printk("%x\n", inst_map[idx][i]);
	BUG();
}

bool is_instrumented_address(void *addr)
{
	uint32_t idx = inst_addr_hash(addr);
	for (int i = 0; i < BUCKET_SIZE; i++) {
		if (inst_map[idx][i] == 0)
			break;
		if (inst_map[idx][i] == truncate(addr))
			return true;
	}
	return false;
}
