#define NO_INSTRUMENT_ATOMIC

#include <linux/llist.h>
#include <linux/atomic.h>
#include <linux/kernel.h>

#include "kssb.h"

// XXX: These two functions are just copied from lib/llist.c. Since
// our pass instruments lib/llist.c, the original ones call the flush
// callback, which prevents the store buffer emulation. Thus, we need
// another version of them that is not instrumented.

struct llist_node *__llist_del_first(struct llist_head *head)
{
	struct llist_node *entry, *old_entry, *next;

	entry = smp_load_acquire(&head->first);
	for (;;) {
		if (entry == NULL)
			return NULL;
		old_entry = entry;
		next = READ_ONCE(entry->next);
		entry = cmpxchg(&head->first, old_entry, next);
		if (entry == old_entry)
			break;
	}

	return entry;
}

bool ___llist_add_batch(struct llist_node *new_first,
			struct llist_node *new_last, struct llist_head *head)
{
	struct llist_node *first;

	do {
		new_last->next = first = READ_ONCE(head->first);
	} while (cmpxchg(&head->first, first, new_first) != first);

	return !first;
}
