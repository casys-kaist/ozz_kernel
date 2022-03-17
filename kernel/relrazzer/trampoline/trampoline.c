#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/qcsched/hcall.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dae R. Jeong");
MODULE_DESCRIPTION("Trampoline module");
MODULE_VERSION("0.01");

/* #define _DEBUG */

static noinline void __trampoline(void)
{
	// Do here whatever if needed
#ifdef _DEBUG
	int cpu;
	cpu = get_cpu();
	printk("%d spinning\n", cpu);
	mdelay(2000);
	put_cpu();
#endif
}

void trampoline(void)
{
	// Do nothing here
loop:
	__trampoline();
	goto loop;
}
EXPORT_SYMBOL(trampoline);

static int __init trampoline_init(void)
{
	unsigned long trampoline_addr = (unsigned long)trampoline;
	unsigned long __trampoline_addr = (unsigned long)__trampoline;
	pr_info("Installing trampoline\n");
	pr_info("trampoline addr: %lx\n", trampoline_addr);
	hypercall(HCALL_VMI_HINT, VMI_TRAMPOLINE, trampoline_addr, 0);
	pr_info("__trampoline addr: %lx\n", __trampoline_addr);
	hypercall(HCALL_VMI_HINT, VMI_TRAMPOLINE + 1, __trampoline_addr, 0);
	return 0;
}

static void __exit trampoline_exit(void)
{
	pr_info("Uninstalling trampoline\n");
}

module_init(trampoline_init);
module_exit(trampoline_exit);
