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
	return 0;
}

static int kssb_debug_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, kssb_profile_show, NULL);
}

static struct file_operations kssb_debugfs_fops = {
	.open = kssb_debug_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

int __init kssb_debugfs_init(void)
{
	kssb_debugfs_dir = debugfs_create_dir("kssb", 0);
	debugfs_create_file("profile", 0666, kssb_debugfs_dir, NULL,
			    &kssb_debugfs_fops);
	return 0;
}

void __exit kssb_debugfs_cleanup(void)
{
	debugfs_remove_recursive(kssb_debugfs_dir);
}
