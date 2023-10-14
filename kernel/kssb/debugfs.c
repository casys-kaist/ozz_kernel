#include <linux/module.h>
#include <linux/printk.h>
#include <linux/debugfs.h>

#include "kssb.h"

MODULE_LICENSE("GPL");

static struct dentry *kssb_debugfs_dir = 0;

static int kssb_profile_show(struct seq_file *m, void *v)
{
	struct kssb_stat_t *stat = &kssb_stat;
	seq_printf(m, "load  %5d\n", atomic64_read(&stat->load_count));
	seq_printf(m, "store %5d\n", atomic64_read(&stat->store_count));
	seq_printf(m, "flush %5d\n", atomic64_read(&stat->flush_count));
	seq_printf(m, "retchk %5d\n", atomic64_read(&stat->retchk_count));
	seq_printf(m, "funcentry %5d\n", atomic64_read(&stat->funcentry_count));
	return 0;
}

static int kssb_debug_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, kssb_profile_show, NULL);
}

static struct file_operations kssb_stats_fops = {
	.open = kssb_debug_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

static ssize_t do_profile_read(struct file *filp, char __user *ubuf, size_t cnt,
			       loff_t *ppos)
{
	char buf[8];
	int len;
	len = sprintf(buf, "%d\n", kssb_do_profile);
	return simple_read_from_buffer(ubuf, cnt, ppos, buf, len);
}

static ssize_t do_profile_write(struct file *filp, const char __user *ubuf,
				size_t cnt, loff_t *ppos)
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

	kssb_do_profile = !!val;

	return cnt;
}

static struct file_operations kssb_do_profile_fops = {
	.open = simple_open,
	.read = do_profile_read,
	.write = do_profile_write,
};

extern bool load_prefetch_enabled;
extern volatile char __ssb_do_emulate;

static ssize_t load_prefetch_enabled_read(struct file *filp, char __user *ubuf,
					  size_t cnt, loff_t *ppos)
{
	char buf[8];
	int len;
	BUG_ON(__ssb_do_emulate);
	len = sprintf(buf, "%d\n", load_prefetch_enabled);
	return simple_read_from_buffer(ubuf, cnt, ppos, buf, len);
}

static ssize_t load_prefetch_enabled_write(struct file *filp,
					   const char __user *ubuf, size_t cnt,
					   loff_t *ppos)
{
	char buf[8];
	unsigned long val;
	int ret;

	BUG_ON(__ssb_do_emulate);

	if (cnt >= sizeof(buf))
		return -EINVAL;

	if (copy_from_user(&buf, ubuf, cnt))
		return -EFAULT;

	buf[cnt] = 0;

	ret = kstrtoul(buf, 10, &val);
	if (ret < 0)
		return ret;

	load_prefetch_enabled = !!val;

	return cnt;
}

static struct file_operations load_prefetch_enabled_fops = {
	.open = simple_open,
	.read = load_prefetch_enabled_read,
	.write = load_prefetch_enabled_write,
};

static int kssb_emulated_inst_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, profile_emulated_inst_show, NULL);
}

static ssize_t emulated_inst_write(struct file *filp, const char __user *ubuf,
				   size_t cnt, loff_t *ppos)
{
	profile_reset_emulated_inst();
	return 0;
}

static struct file_operations kssb_emulated_inst_fops = {
	.open = kssb_emulated_inst_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
	.write = emulated_inst_write,
};

int __init kssb_debugfs_init(void)
{
	kssb_debugfs_dir = debugfs_create_dir("kssb", 0);
	debugfs_create_file("stats", 0666, kssb_debugfs_dir, NULL,
			    &kssb_stats_fops);
	debugfs_create_file("do_profile", 0666, kssb_debugfs_dir, NULL,
			    &kssb_do_profile_fops);
	debugfs_create_file("load_prefetch_enabled", 0666, kssb_debugfs_dir,
			    NULL, &load_prefetch_enabled_fops);
	debugfs_create_file("emulated_inst", 0666, kssb_debugfs_dir, NULL,
			    &kssb_emulated_inst_fops);
	return 0;
}

void __exit kssb_debugfs_cleanup(void)
{
	debugfs_remove_recursive(kssb_debugfs_dir);
}
