#define NO_INSTRUMENT_ATOMIC

#include <linux/atomic.h>
#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/export.h>
#include <linux/types.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/preempt.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/sched/task_stack.h>
#include <linux/vmalloc.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/refcount.h>
#include <linux/kmemcov.h>
#include <asm/setup.h>

struct kmemcov {
	refcount_t refcount;
	spinlock_t lock;
	enum kmemcov_mode mode;
	unsigned size;
	void *area;
	struct task_struct *t;
};

static atomic_t kmemcov_clock;

bool kmemcov_trace_lock = false;

static bool notrace check_kmemcov_mode(enum kmemcov_mode needed_mode,
				       struct task_struct *t)
{
	unsigned int mode;
	if (!in_task())
		return false;
	mode = READ_ONCE(t->kmemcov_mode);
	barrier();
	return mode == needed_mode;
}

#define get_clock() atomic_fetch_inc(&kmemcov_clock)
// level 0 indicates the store/load callbacks, and level 1 indicates
// the caller of the kssb callbacks.
#define INIT_KMEMCOV_ACCESS(inst, addr, size, type)                 \
	{                                                           \
		.inst = inst, .type = type, .addr = (uint64_t)addr, \
		.size = size, .timestamp = get_clock(),             \
	}

static void __always_inline notrace
__sanitize_memcov_trace_access_safe(unsigned long inst, void *addr, size_t size,
				    enum kmemcov_access_type type)
{
	struct kmemcov_access acc = INIT_KMEMCOV_ACCESS(inst, addr, size, type);
	struct task_struct *t = current;
	struct kmemcov_access *area;
	unsigned long pos, *posp;

	if (object_is_on_stack(addr))
		return;

	area = t->kmemcov_area;
	// The first 64-bit word is the number of recorded events.
	posp = (unsigned long *)&area[0];
	pos = READ_ONCE(*posp);

	// We don't have to record subsequent barriers
	if (pos > 0 &&
	    (type == KMEMCOV_ACCESS_FLUSH || type == KMEMCOV_ACCESS_LFENCE) &&
	    area[pos].type == type)
		return;

	pos++;
	if (likely(pos < t->kmemcov_size)) {
		memcpy(&area[pos], &acc, sizeof(acc));
		WRITE_ONCE(*posp, pos);
	}
}

static void __always_inline notrace __sanitize_memcov_trace_access(
	unsigned long inst, void *addr, size_t size, bool write)
{
	struct task_struct *t = current;
	if (!check_kmemcov_mode(KMEMCOV_MODE_TRACE_STLD, t))
		return;
	__sanitize_memcov_trace_access_safe(inst, addr, size,
					    (write ? KMEMCOV_ACCESS_STORE :
						     KMEMCOV_ACCESS_LOAD));
}

static void __always_inline notrace __sanitize_memcov_trace_barrier(bool store)
{
	enum kmemcov_access_type typ;
	struct task_struct *t = current;
	if (!check_kmemcov_mode(KMEMCOV_MODE_TRACE_STLD, t))
		return;
	typ = (store ? KMEMCOV_ACCESS_FLUSH : KMEMCOV_ACCESS_LFENCE);
	__sanitize_memcov_trace_access_safe(0, 0, 0, typ);
}

void __always_inline notrace __sanitize_memcov_trace_lock(void *lockdep,
							  bool acquire)
{
	enum kmemcov_access_type typ;
	struct task_struct *t = current;
	if (!check_kmemcov_mode(KMEMCOV_MODE_TRACE_STLD, t))
		return;
	typ = (acquire ? KMEMCOV_ACCESS_LOCK_ACQUIRE :
			 KMEMCOV_ACCESS_LOCK_RELEASE);
	__sanitize_memcov_trace_access_safe(0, lockdep, 0, typ);
}
EXPORT_SYMBOL(__sanitize_memcov_trace_lock);

void __sanitize_memcov_trace_store(unsigned long inst, void *addr, size_t size)
{
	__sanitize_memcov_trace_access(inst, addr, size, true);
}
EXPORT_SYMBOL(__sanitize_memcov_trace_store);

void __sanitize_memcov_trace_load(unsigned long inst, void *addr, size_t size)
{
	__sanitize_memcov_trace_access(inst, addr, size, false);
}
EXPORT_SYMBOL(__sanitize_memcov_trace_load);

void sanitize_memcov_trace_store(const volatile void *addr, size_t size)
{
	__sanitize_memcov_trace_store(_RET_IP_, (void *)addr, size);
}
EXPORT_SYMBOL(sanitize_memcov_trace_store);

void sanitize_memcov_trace_load(const volatile void *addr, size_t size)
{
	__sanitize_memcov_trace_load(_RET_IP_, (void *)addr, size);
}
EXPORT_SYMBOL(sanitize_memcov_trace_load);

void sanitize_memcov_trace_flush(void)
{
	__sanitize_memcov_trace_barrier(true);
}
EXPORT_SYMBOL(sanitize_memcov_trace_flush);

void sanitize_memcov_trace_lfence(void)
{
	__sanitize_memcov_trace_barrier(false);
}
EXPORT_SYMBOL(sanitize_memcov_trace_lfence);

static void kmemcov_get(struct kmemcov *kmemcov)
{
	refcount_inc(&kmemcov->refcount);
}

static void kmemcov_put(struct kmemcov *kmemcov)
{
	if (refcount_dec_and_test(&kmemcov->refcount)) {
		vfree(kmemcov->area);
		kfree(kmemcov);
	}
}

void kmemcov_task_init(struct task_struct *t)
{
	WRITE_ONCE(t->kmemcov_mode, KMEMCOV_MODE_DISABLED);
	barrier();
	t->kmemcov_size = 0;
	t->kmemcov_area = NULL;
	t->kmemcov = NULL;
}

void kmemcov_task_exit(struct task_struct *t)
{
	struct kmemcov *kmemcov;

	kmemcov = t->kmemcov;
	if (kmemcov == NULL)
		return;
	spin_lock(&kmemcov->lock);
	if (WARN_ON(kmemcov->t != t)) {
		spin_unlock(&kmemcov->lock);
		return;
	}
	kmemcov_task_init(t);
	kmemcov->t = NULL;
	kmemcov->mode = KMEMCOV_MODE_INIT;
	spin_unlock(&kmemcov->lock);
	kmemcov_put(kmemcov);
}

static void kmemcov_fault_in_area(struct kmemcov *kmemcov)
{
	unsigned long total = kmemcov->size * sizeof(struct kmemcov_access) /
			      sizeof(unsigned long);
	unsigned long stride = PAGE_SIZE / sizeof(unsigned long);
	unsigned long *area = kmemcov->area;
	unsigned long offset;
	for (offset = 0; offset < total; offset += stride)
		READ_ONCE(area[offset]);
}

static long kmemcov_ioctl_locked(struct kmemcov *kmemcov, unsigned int cmd,
				 unsigned long arg)
{
	struct task_struct *t;
	unsigned long unused;

	switch (cmd) {
	case KMEMCOV_ENABLE:
		unused = arg;
		if (kmemcov->mode != KMEMCOV_MODE_INIT || !kmemcov->area ||
		    unused != 0)
			return -EINVAL;
		t = current;
		if (kmemcov->t != NULL || t->kmemcov != NULL)
			return -EBUSY;
		kmemcov->mode = KMEMCOV_MODE_TRACE_STLD;
		kmemcov_fault_in_area(kmemcov);
		t->kmemcov_size = kmemcov->size;
		t->kmemcov_area = kmemcov->area;
		barrier();
		WRITE_ONCE(t->kmemcov_mode, kmemcov->mode);
		t->kmemcov = kmemcov;
		kmemcov->t = t;
		kmemcov_get(kmemcov);
		return 0;
	case KMEMCOV_DISABLE:
		unused = arg;
		if (unused != 0 || current->kmemcov != kmemcov)
			return -EINVAL;
		t = current;
		if (WARN_ON(kmemcov->t != t))
			return -EINVAL;
		kmemcov_task_init(t);
		kmemcov->t = NULL;
		kmemcov->mode = KMEMCOV_MODE_INIT;
		kmemcov_put(kmemcov);
		return 0;
	default:
		return -EINVAL;
	}
}

static int kmemcov_mmap(struct file *filp, struct vm_area_struct *vma)
{
	int res = 0;
	struct kmemcov *kmemcov = vma->vm_file->private_data;
	unsigned long size, off;
	struct page *page;

	spin_lock(&kmemcov->lock);
	size = kmemcov->size * sizeof(struct kmemcov_access);
	if (kmemcov->area == NULL || vma->vm_pgoff != 0 ||
	    vma->vm_end - vma->vm_start != size) {
		res = -EINVAL;
		goto exit;
	}
	spin_unlock(&kmemcov->lock);
	vm_flags_set(vma, VM_DONTEXPAND);
	for (off = 0; off < size; off += PAGE_SIZE) {
		page = vmalloc_to_page(kmemcov->area + off);
		if (vm_insert_page(vma, vma->vm_start + off, page))
			WARN_ONCE(1, "vm_insert_page() failed");
	}
	return 0;
exit:
	spin_unlock(&kmemcov->lock);
	return res;
}

static long kmemcov_ioctl(struct file *filp, unsigned int cmd,
			  unsigned long arg)
{
	int res;
	unsigned long size;
	void *area;

	struct kmemcov *kmemcov = filp->private_data;
	switch (cmd) {
	case KMEMCOV_INIT_TRACE:
		size = arg;
		if (size < 2 || size > INT_MAX / sizeof(struct kmemcov_access))
			return -EINVAL;
		area = vmalloc_user(size * sizeof(struct kmemcov_access));
		if (area == NULL)
			return -ENOMEM;
		spin_lock(&kmemcov->lock);
		if (kmemcov->mode != KMEMCOV_MODE_DISABLED) {
			spin_unlock(&kmemcov->lock);
			vfree(area);
			return -EBUSY;
		}
		kmemcov->area = area;
		kmemcov->size = size;
		kmemcov->mode = KMEMCOV_MODE_INIT;
		spin_unlock(&kmemcov->lock);
		return 0;
	default:
		spin_lock(&kmemcov->lock);
		res = kmemcov_ioctl_locked(kmemcov, cmd, arg);
		spin_unlock(&kmemcov->lock);
	}
	return res;
}

static int kmemcov_open(struct inode *inode, struct file *filp)
{
	struct kmemcov *kmemcov;

	kmemcov = kzalloc(sizeof(*kmemcov), GFP_KERNEL);
	if (!kmemcov)
		return -ENOMEM;
	kmemcov->mode = KMEMCOV_MODE_DISABLED;
	refcount_set(&kmemcov->refcount, 1);
	spin_lock_init(&kmemcov->lock);
	filp->private_data = kmemcov;
	return nonseekable_open(inode, filp);
}

static int kmemcov_close(struct inode *node, struct file *filp)
{
	kmemcov_put(filp->private_data);
	return 0;
}

static const struct file_operations kmemcov_fops = {
	.open = kmemcov_open,
	.unlocked_ioctl = kmemcov_ioctl,
	.compat_ioctl = kmemcov_ioctl,
	.mmap = kmemcov_mmap,
	.release = kmemcov_close,
};

static ssize_t kmemcov_trace_lock_read(struct file *filp, char __user *ubuf,
				       size_t cnt, loff_t *ppos)
{
	char buf[8];
	int len;
	len = sprintf(buf, "%d\n", kmemcov_trace_lock);
	return simple_read_from_buffer(ubuf, cnt, ppos, buf, len);
}

static ssize_t kmemcov_trace_lock_write(struct file *filp,
					const char __user *ubuf, size_t cnt,
					loff_t *ppos)
{
	char buf[8];
	unsigned long val;
	int ret;
	if (cnt >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(&buf, ubuf, cnt))
		return -EFAULT;
	buf[cnt] = 0;
	ret = kstrtoul(buf, 10, &val);
	if (ret < 0)
		return ret;
	kmemcov_trace_lock = !!val;
	return cnt;
}

static struct file_operations kmemcov_trace_lock_fops = {
	.open = simple_open,
	.read = kmemcov_trace_lock_read,
	.write = kmemcov_trace_lock_write,
};

static int __init kmemcov_init(void)
{
	atomic_set(&kmemcov_clock, 0);
	debugfs_create_file_unsafe("kmemcov", 0600, NULL, NULL, &kmemcov_fops);
	debugfs_create_file_unsafe("kmemcov_trace_lock", 0666, NULL, NULL,
				   &kmemcov_trace_lock_fops);
	return 0;
}

device_initcall(kmemcov_init);
