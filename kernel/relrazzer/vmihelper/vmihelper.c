#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>

#include "../include/hcall.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dae R. Jeong");
MODULE_DESCRIPTION("VMI helper module");
MODULE_VERSION("0.01");

extern volatile char __ssb_do_emulate;

static int __init vmihelper_init(void)
{
	char *hook_name = "qcsched_hook_entry";
	unsigned long addr = kallsyms_lookup_name(hook_name);
	unsigned long ret;
	int i;

	pr_info("Installing vmihelper\n");
	pr_info("hook addr: %lx\n", addr);

	if (addr == 0) {
		pr_info("failed to get the hook address\n");
	} else {
		ret = hypercall(HCALL_VMI_HINT, VMI_HOOK, addr, 0);
		pr_info("return: %lx\n", ret);
	}

	pr_info("current_task: %lx\n", &current_task);
	hypercall(HCALL_VMI_HINT, VMI_CURRENT_TASK,
		  (unsigned long)&current_task, 0);

	for (i = 0; i < 64; i++) {
		pr_info("__per_cpu_offset[%d]: %lx\n", i, __per_cpu_offset[i]);
		hypercall(HCALL_VMI_HINT, VMI__PER_CPU_OFFSET0 + i,
			  __per_cpu_offset[i], 0);
	}

	pr_info("__ssb_do_emulate: %lx\n", &__ssb_do_emulate);
	hypercall(HCALL_VMI_HINT, VMI__SSB_DO_EMULATE,
		  (unsigned long)&__ssb_do_emulate, 0);

	return 0;
}

static void __exit vmihelper_exit(void)
{
	pr_info("Uninstalling vmihelper\n");
}

module_init(vmihelper_init);
module_exit(vmihelper_exit);
