#include <linux/syscalls.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/sbitmap.h>

struct sbitmap_queue sbq;

unsigned int val;
unsigned int *ptr;

// function 1 -> get sbitmap, change value of ptr, release sbitmap
__attribute__((softstorebuffer)) static void func1()
{
	int idx;
	unsigned int cpu;

	idx = sbitmap_queue_get(&sbq, &cpu);
	ptr = NULL;
	// below memory store can't be reorderded
	// store &val into ptr variable
	ptr = &val;
	// release bit in sbitmap_deferred_clear_bit
	sbitmap_queue_clear(&sbq, idx, cpu);

	return;
}

// function 2-> get sbitmap, write memory through ptr, release sbitmap
__attribute__((softstorebuffer)) static void func2()
{
	int idx;
	unsigned int cpu;

	idx = sbitmap_queue_get(&sbq, &cpu);
	*ptr = 0xdeadbeef;
	sbitmap_queue_clear(&sbq, idx, cpu);
}

SYSCALL_DEFINE0(ssb_sbitmap_func1)
{
	func1();
	return 0;
}

SYSCALL_DEFINE0(ssb_sbitmap_func2)
{
	func2();
	return 0;
}

SYSCALL_DEFINE0(ssb_sbitmap_init)
{
	int ret = 0;
	unsigned int cpu;

	// init sbitmap_queue
	cpu = get_cpu();
	put_cpu();

	// capacity 1
	ret = sbitmap_queue_init_node(&sbq, 1, -1, 0, GFP_KERNEL,
				      cpu_to_node(cpu));
	if (ret) {
		printk(KERN_ALERT "%s failed with %d\n",
		       "sbitmap_queue_init_node", ret);
		return ret;
	}

	// init ptr
	ptr = &val;

	printk("ssb sbitmap init complete!\n");
	return ret;
}

SYSCALL_DEFINE0(ssb_sbitmap_clear)
{
	sbitmap_queue_free(&sbq);

	printk("ssb sbitmap clear complete!\n");

	return 0;
}
