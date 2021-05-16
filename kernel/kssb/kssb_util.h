#ifndef __KSSB_UTIL_H
#define __KSSB_UTIL_H

// TODO: Use Linux APIs

#define BYTES_PER_WORD (uint64_t)(sizeof(void *))

#define _BITS(val) ((val)*8)
#define _BIT_MASK(_BITS)                                                       \
	((_BITS) == 64 ? 0xffffffffffffffff : (1ULL << (_BITS)) - 1)

static inline uint64_t __load_single(struct kssb_access *acc)
{
	switch (acc->size) {
	case 1:
		return READ_ONCE(*(uint8_t *)acc->addr);
	case 2:
		return READ_ONCE(*(uint16_t *)acc->addr);
	case 4:
		return READ_ONCE(*(uint32_t *)acc->addr);
	case 8:
		return READ_ONCE(*(uint64_t *)acc->addr);
	default:
		BUG();
	}
}

static inline void __store_single(struct kssb_access *acc)
{
	switch (acc->size) {
	case 1:
		WRITE_ONCE(*(uint8_t *)acc->addr, acc->val);
		break;
	case 2:
		WRITE_ONCE(*(uint16_t *)acc->addr, acc->val);
		break;
	case 4:
		WRITE_ONCE(*(uint32_t *)acc->addr, acc->val);
		break;
	case 8:
		WRITE_ONCE(*(uint64_t *)acc->addr, acc->val);
		break;
	default:
		BUG();
	}
}

#endif /* __KSSB_UTIL_H */
