#include <linux/syscalls.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/sbitmap.h>
#include <linux/delay.h>

struct sbitmap_queue sbq;

unsigned int val;
volatile unsigned int *ptr;

// function 1 -> get sbitmap, change value of ptr, release sbitmap
__attribute__((softstorebuffer)) static void func1(bool delay)
{
	int idx;
	unsigned int cpu;

	//disable irq
	local_irq_disable();

	idx = sbitmap_queue_get(&sbq, &cpu);
	printk(KERN_INFO "%s idx: %d\n", __func__, idx);
	if (idx < 0) {
		local_irq_enable();
		return;
	}

	ptr = NULL;

	barrier();

	// below memory store can't be reorderded
	// store &val into ptr variable
	ptr = &val;
	// release bit in sbitmap_deferred_clear_bit
	sbitmap_queue_clear(&sbq, idx, cpu);
	if (delay)
		mdelay(2000);

	//reenable irq
	local_irq_enable();

	return;
}

// function 2-> get sbitmap, write memory through ptr, release sbitmap
__attribute__((softstorebuffer)) static void func2(bool delay)
{
	int idx;
	unsigned int cpu;

	//disable irq
	local_irq_disable();

	if (delay)
		mdelay(1000);

	idx = sbitmap_queue_get(&sbq, &cpu);
	printk(KERN_INFO "%s idx: %d\n", __func__, idx);
	if (idx < 0) {
		local_irq_enable();
		return;
	}

	*ptr = 0xdeadbeef;
	sbitmap_queue_clear(&sbq, idx, cpu);

	//reenable irq
	local_irq_enable();
}

SYSCALL_DEFINE1(ssb_sbitmap_func1, bool, delay)
{
	func1(delay);
	return 0;
}

SYSCALL_DEFINE1(ssb_sbitmap_func2, bool, delay)
{
	func2(delay);
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

	// init array
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
