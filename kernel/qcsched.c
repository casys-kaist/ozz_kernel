#include <linux/kernel.h>
#include <linux/qcsched/qcsched.h>

noinline void __qcsched_hook(void)
{
}
EXPORT_SYMBOL(__qcsched_hook);

void qcsched_hook_entry(void)
{
	__qcsched_hook();
}
EXPORT_SYMBOL(qcsched_hook_entry);

void qcsched_hook_exit(void)
{
	__qcsched_hook();
}
EXPORT_SYMBOL(qcsched_hook_exit);
