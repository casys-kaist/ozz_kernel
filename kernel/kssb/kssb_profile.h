#ifndef __KSSB_PROFILE_H
#define __KSSB_PROFILE_H

void profile_load(struct kssb_access *);
void profile_store(struct kssb_access *);
void profile_flush(uint64_t);
void profile_reset(void);

#endif /* __KSSB_PROFILE_H */
