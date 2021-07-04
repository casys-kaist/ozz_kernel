#include <linux/qcsched.h>

static noinline void __qcsched_hook(void)
{
}

void qcsched_hook_entry(void)
{
	__qcsched_hook();
}

void qcsched_hook_exit(void)
{
	__qcsched_hook();
}
