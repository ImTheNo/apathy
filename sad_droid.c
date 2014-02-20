#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/selinux.h>
#include <linux/rwlock.h>
#include <linux/init.h>
#include <linux/uprobes.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/file.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <asm/uaccess.h>

#include "sad_droid.h"
#include "objsec.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Pavel Bushmakin <imtheno@lvk.cs.msu.su>");
MODULE_DESCRIPTION("Application safe execution control in Android");

struct rs_break {
	struct list_head list;

	struct uprobe_consumer uc;		// uprobe struct, describing this bpt
	char new_cont[CONT_MAXLEN]; 	// new SELinux context of the process

    struct inode *inode; //file inode on which to insert probes
    loff_t o; //vm address on which to probe
};

LIST_HEAD(break_list);

rwlock_t brk_lock = __RW_LOCK_UNLOCKED(brk_lock);
static struct class *sad_droid_class;
static struct device *sad_droid_dev;
static struct cdev   sad_droid_cdev;
static dev_t  sad_droid_devt;

int my_kern_setprocattr(void *value, size_t size)
{
	struct task_security_struct *tsec;
	struct cred *new;
	u32 sid = 0;
	int error;
	char *str = value;

	if (size && str[1] && str[1] != '\n') {
		if (str[size-1] == '\n') {
			str[size-1] = 0;
			size--;
		}
		error = selinux_string_to_sid(value, size, &sid);
		if (error)
		return error;
	}

	new = prepare_creds();
	if (!new)
		return -ENOMEM;

	tsec = new->security;

    error = -EINVAL;

    if (sid == 0)
    {
        goto abort_change;
    }

    tsec->sid = sid;

    commit_creds(new);
	return size;

abort_change:
	abort_creds(new);
	return error;
}

static int uprobe_handler(struct uprobe_consumer *self, struct pt_regs *regs)
{
	struct list_head *pos;
	struct rs_break *tmp;
	int ret = -EFAULT;
	u32 sid;
    unsigned long flags;

	printk(KERN_INFO "sad_droid: handler\n");
    read_lock_irqsave(&brk_lock, flags);
	list_for_each(pos, &break_list) {
		tmp = list_entry(pos, struct rs_break, list);
		if (&tmp->uc == self) {
			printk(KERN_INFO "Hit breakpoint at: %llu in thread %u\n", tmp->o, current->pid);
			printk(KERN_INFO "New context is %s\n", tmp->new_cont);

			ret = selinux_string_to_sid(tmp->new_cont,
					strlen(tmp->new_cont), &sid);

			if (ret == -EINVAL) {
				printk("Acedia: Failed to translate context to sid: %s\n",
						tmp->new_cont);
                read_unlock_irqrestore(&brk_lock, flags);
				return ret;
			} else {
				printk("Acedia: Sid for %s is %u\n", tmp->new_cont, sid);
			}

            ret = my_kern_setprocattr(tmp->new_cont, strlen(tmp->new_cont));
			break;
            }
    }
    read_unlock_irqrestore(&brk_lock, flags);
    return ret;
}

ssize_t sad_droid_dev_read(struct file* file, char *buffer,
		size_t length, loff_t* offset)
{
	printk(KERN_INFO "sad_droid: device read is not implemented\n");
	return -0;
}

int ioctl_set_break(void __user *p)
{
	struct rs_break *brk;
	struct list_head *pos;
	struct rs_break *tmp;
	struct sad_droid_trans trans;
    struct path binf_path;
    unsigned long flags;
	int ret;

	brk = kzalloc(sizeof(struct rs_break),GFP_KERNEL);
	if (!brk) {
		ret = -ENOMEM;
		goto out;
	}
    brk->uc.handler = uprobe_handler;

	if (copy_from_user(&trans, p, sizeof(struct sad_droid_trans))) {
		ret = -EFAULT;
		goto out_clean;
	}

	if (trans.new_cont[0] == '\0') {
		ret = -EINVAL;
		goto out_clean;
	}

	if (trans.bin_file[0] != '/') {
		ret = -EINVAL;
		goto out_clean;
	}

    //try to get inode
    if (kern_path(trans.bin_file, LOOKUP_FOLLOW, &binf_path)) 
    {
        printk(KERN_INFO "sad_droid: can't find file %s\n", 
                trans.bin_file);
		ret = -EINVAL;
		goto out_clean;
    }
    brk->inode = igrab(binf_path.dentry->d_inode);

    //copy offset and transition context
    brk->o = trans.addr;
	strncpy(brk->new_cont, trans.new_cont, CONT_MAXLEN-1);

    //check if we already have transition on this file:offset pair
    read_lock_irqsave(&brk_lock, flags);
	list_for_each(pos, &break_list) 
    {
		tmp = list_entry(pos, struct rs_break, list);
		if (tmp->inode == brk->inode && tmp->o == brk->o) 
        {
			printk(KERN_INFO "sad_droid: Breakpoint at %p for %s exists.\n",
					(void*)trans.addr,trans.bin_file);
			ret = -EBUSY;
            read_unlock_irqrestore(&brk_lock, flags);
			goto out_inode;
		}
	}
    read_unlock_irqrestore(&brk_lock, flags);

    //register uprobe
    if ((ret = uprobe_register(brk->inode, brk->o, &brk->uc))) 
    {
        goto out_inode;
    }

    write_lock_irqsave(&brk_lock, flags);
	list_add(&brk->list, &break_list);
    write_unlock_irqrestore(&brk_lock, flags);

	printk( KERN_INFO "sad_droid: Set bpt for %s\n", trans.bin_file);

	return 0;

out_inode:
    iput(brk->inode);

out_clean:
	kfree(brk);

out:
	return ret;

}

static void free_bpt_list(void)
{
	struct list_head *pos,*q;
	struct rs_break *tmp;

	list_for_each_safe(pos, q, &break_list) {
		tmp = list_entry(pos, struct rs_break,list);
		printk(KERN_INFO "sad_droid: deleting list: %s\n", tmp->new_cont);

        uprobe_unregister(tmp->inode, tmp->o, &tmp->uc); 
        iput(tmp->inode);

		list_del(pos);
		kfree(tmp);
	}
}

int ioctl_del_break(const struct sad_droid_trans* tr)
{
	return 0;
}

long sad_droid_dev_ioctl(struct file *f,
		unsigned int cmd, unsigned long __user arg)
{
	switch (cmd) {
		case SAD_DROID_IOCTL_SET_BREAK:
			printk(KERN_INFO "sad_droid: ioctl set_break\n");

			return ioctl_set_break((void __user *)arg);

		case SAD_DROID_IOCTL_DEL_BREAK:
			printk(KERN_INFO "sad_droid: ioctl del break\n");

			return ioctl_del_break((void __user *)arg);

		default: break;
	}
	return -0;
}

int sad_droid_dev_release(struct inode *i, struct file* f)
{
	printk(KERN_INFO "sad_droid: asdasd\n");
	return 0;
}

int sad_droid_dev_open(struct inode *i, struct file *f)
{
	printk(KERN_INFO "sad_droid: Open\n");

	if (!f)
		return -EIO;

	return 0;
}

struct file_operations sad_droid_file_ops = {
	.owner		= THIS_MODULE,
	// .read 		= sad_droid_dev_read,
	.open		= sad_droid_dev_open,
	.release 	= sad_droid_dev_release,
	.unlocked_ioctl = sad_droid_dev_ioctl,
};

static int __init sad_droid_init(void)
{
	int ret;

	sad_droid_class = class_create(THIS_MODULE, SAD_DROID_DEVICE_NAME);
	if (!sad_droid_class) {
		printk(KERN_INFO "sad_droid: Failed to create device class.\n");
		return -EFAULT;
	}

	ret = alloc_chrdev_region(&sad_droid_devt, 0, 11, SAD_DROID_DEVICE_NAME);
	if (ret) {
		printk(KERN_INFO "sad_droid: Failed to allocate chardev region.\n");
		return -EFAULT;
	}

    /* initialize and register char device for sad_droid's configuration */
	cdev_init(&sad_droid_cdev, &sad_droid_file_ops);
	sad_droid_cdev.ops = &sad_droid_file_ops;
	sad_droid_cdev.owner = THIS_MODULE;
	ret = cdev_add(&sad_droid_cdev, sad_droid_devt, 1);
	if (ret) {
		printk(KERN_INFO "sad_droid: failed to add cdev\n");
		return -EFAULT;
	}

    sad_droid_dev = device_create(sad_droid_class, NULL, sad_droid_devt, NULL,
            SAD_DROID_DEVICE_NAME); 
	if (ret) {
		printk(KERN_INFO "sad_droid: failed to create device\n");
		return -EFAULT;
	}
    
    printk(KERN_INFO "sad_droid: success boot\n");
	return 0;
}

static void __exit sad_droid_exit(void)
{
    device_destroy(sad_droid_class, sad_droid_devt); 
    cdev_del(&sad_droid_cdev);
	unregister_chrdev_region(sad_droid_devt, 11);
	class_destroy(sad_droid_class);
	free_bpt_list();
    printk(KERN_INFO "sad_droid: success unboot\n");
    return;
}

module_init(sad_droid_init);
module_exit(sad_droid_exit);
