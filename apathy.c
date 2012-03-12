#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/selinux.h>
#include <linux/init.h>
#include <linux/uprobes.h>
#include <linux/utrace.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/kprobes.h>
#include <linux/binfmts.h>
#include <asm/uaccess.h>

#include "apathy.h"
#include "objsec.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Fedor Sakharov <sakharov@lvk.cs.msu.su>");
MODULE_DESCRIPTION("Application safe execution control");

struct rs_break {
	struct list_head list;
	struct uprobe probe;		// uprobe struct, describing this bpt
	char new_cont[CONT_MAXLEN]; 	// new SELinux context of the process
};

struct rs_info {
	struct list_head list;
	struct apathy_trans trans;
};

struct traced_pid {
	struct list_head list;
    pid_t pid;
};				

LIST_HEAD(break_list);
LIST_HEAD(info_list);
LIST_HEAD(traced_list);

static struct class *apathy_class;
static struct device apathy_dev;
static struct cdev   apathy_cdev;
static dev_t  apathy_devt;


static void uprobe_handler(struct uprobe* u, struct pt_regs *regs);

static int unreg_bpts(struct task_struct *task)
{
	struct list_head *pos,*q;
	struct rs_break *tmp;

    if (task->tgid != task->pid) 
    {
        return 0;
    }

	list_for_each_safe(pos, q, &break_list) {
		tmp = list_entry(pos, struct rs_break,list);
		if (tmp->probe.pid == task->tgid) {
			unregister_uprobe(&tmp->probe);
			list_del(pos);
			kfree(tmp);
		}
	}

	return 0;
}

static int set_bpt(const struct rs_info* info)
{
	struct rs_break *brk;
	int ret = 0;

	brk = kzalloc(sizeof(struct rs_break), GFP_KERNEL);

	if (!brk) {
		ret = -ENOMEM;
		goto out;
	}

	printk("Apathy: Some info %u %p\n", current->pid, (void*)info->trans.addr);
	brk->probe.pid = current->pid;
	brk->probe.vaddr = info->trans.addr;
	brk->probe.handler = uprobe_handler;
	brk->probe.kdata = NULL;

	strncpy(brk->new_cont,info->trans.new_cont,CONT_MAXLEN-1);

	ret = register_uprobe(&brk->probe);

	if (ret) {
		printk(KERN_INFO "Apathy: register_uprobe returned %d\n", ret);
		goto out_clean;
	}

	list_add(&brk->list,&break_list);

	return 0;

out_clean:
	kfree(brk);

out:
	return ret;
}

static int detach_engine(struct utrace_engine *engine,
			    struct task_struct *task)
{
	struct list_head *t_pos, *q;
	struct traced_pid *t_tmp;
    int ret;

	printk(KERN_INFO "Apathy: detaching engine in %u\n", task->pid);
    list_for_each_safe(t_pos, q, &traced_list)
    {
        t_tmp = list_entry(t_pos, struct traced_pid, list);
        if (t_tmp->pid == task->pid) 
        {
            list_del(t_pos);
            kfree(t_tmp);
            break;
        }
    }

    if (engine->data) 
    {
        kfree(engine->data);
    }
	ret = utrace_control(task, engine, UTRACE_DETACH);

	unreg_bpts(task);

    module_put(THIS_MODULE);
    return 0;
}

static struct utrace_engine_ops my_utrace_ops;  

static u32 my_report_exec(u32 action, struct utrace_engine *engine,
		const struct linux_binfmt *fmt,
		const struct linux_binprm *bprm,
		struct pt_regs *regs)
{
	struct list_head *pos;
	struct rs_info *tmp;
    char not_detached = 0;
	printk(KERN_INFO "Apathy: my report exec\n");

    unreg_bpts(current); //FIXME: optimise this. when my_report_exec 
                              //is called its first time there are no breaks 
                              //on thread

	list_for_each(pos, &info_list) {
		tmp = list_entry(pos, struct rs_info, list);

		if (!strcmp(bprm->filename,tmp->trans.bin_file)) {
			printk(KERN_INFO "Apathy: About to set bpt on %s\n",
					tmp->trans.bin_file);


			if (set_bpt(tmp))
            {
                not_detached = 0; 
                break; //breakpoint setting was failed, so engine will
                       //be detached
            }
            else
            {
                not_detached = 1; 
            }
		}
	}

    //if thread doesn't use breakpoints, engine will be detached 
    if (not_detached) 
    {
        if (engine->data) 
        {
            kfree(engine->data);
        }
        engine->data = kzalloc(strlen(bprm->filename), GFP_KERNEL);
        strncpy(engine->data, bprm->filename, strlen(bprm->filename));
    }
    else
    {
        detach_engine(engine, current);
    }

	return 0;
}

static u32 my_report_exit(u32 action, struct utrace_engine *e,
		long orig_code, long *code)
{
	printk(KERN_INFO "Apathy: my_report_exit\n");

    detach_engine(e, current);

	return 0;
}

static u32 my_report_clone(u32 action, struct utrace_engine *engine,
			    unsigned long clone_flags,
			    struct task_struct *child)
{
    int ret = 0;
	struct utrace_engine *child_engine;			
	struct traced_pid *t_tmp;

	printk(KERN_INFO "Apathy: my_report_clone in %u\n", current->pid);

	if (!try_module_get(THIS_MODULE)) {
		ret = EBUSY;
		return ret;
	}
    child_engine = utrace_attach_task(child, UTRACE_ATTACH_CREATE, &my_utrace_ops, NULL);

    if (child_engine) 
    {
        child_engine->data = kzalloc(strlen(engine->data), GFP_KERNEL);
        strncpy(child_engine->data, engine->data, strlen(engine->data));

        t_tmp = kzalloc(sizeof(struct traced_pid), GFP_KERNEL);
        if (!t_tmp) 
        {
            goto detach_out;
        }
        t_tmp->pid = child->pid;
        list_add(&t_tmp->list, &traced_list);

        if (clone_flags & CLONE_THREAD) 
        {
            ret = utrace_set_events(child, child_engine, UTRACE_EVENT(EXEC) | 
                    UTRACE_EVENT(EXIT) | UTRACE_EVENT(CLONE));
        }
        else
        {
            ret = utrace_set_events(child, child_engine, UTRACE_EVENT(EXEC) | 
                    UTRACE_EVENT(EXIT) | UTRACE_EVENT(CLONE) | UTRACE_EVENT(QUIESCE));
            ret = utrace_control(child, child_engine, UTRACE_REPORT); 
        }
    }
    else 
    {
        module_put(THIS_MODULE);
        printk(KERN_INFO "Apathy: failed to attach utrace engine at thread %u\n", child->pid);
    }

    return 0;

detach_out:
    printk(KERN_INFO "Apathy: failed to trace %u\n", child->pid);
    detach_engine(child_engine, child);
    return 0;
}

static u32 my_report_quiesce(u32 action, struct utrace_engine *engine,
			      unsigned long event)
{
	struct list_head *pos;
	struct rs_info *tmp;
    char *binfile;
    int ret = 0;

	printk(KERN_INFO "Apathy: my_report_quiesce in %u\n", current->pid);
    if (!engine->data) 
    {
        goto detach_out;
    }
    binfile = (char *)engine->data;
	list_for_each(pos, &info_list) {
		tmp = list_entry(pos, struct rs_info, list);

		if (!strcmp(binfile,tmp->trans.bin_file)) {
			printk(KERN_INFO "Apathy: About to set bpt on %s\n",
					tmp->trans.bin_file);

			if (set_bpt(tmp))
            {
                goto detach_out;
            }
		}
	}

    ret = utrace_set_events(current, engine, UTRACE_EVENT(EXEC) | UTRACE_EVENT(EXIT)
            | UTRACE_EVENT(CLONE));
    if (ret) 
    {
        printk(KERN_INFO "Apathy: my_report_quiesce in %u\n, failed while changing \
set of events", current->pid);
    }
    else
    {
        return UTRACE_RESUME;
    }

detach_out:
    printk(KERN_INFO "Apathy: failed to trace %u\n", current->pid);
    detach_engine(engine, current);
    return 0;
}

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

static void uprobe_handler(struct uprobe* u, struct pt_regs *regs)
{
	struct list_head *pos;
	struct rs_break *tmp;
	int ret;
	u32 sid;

	printk(KERN_INFO "Apathy: handler\n");
	list_for_each(pos, &break_list) {
		tmp = list_entry(pos, struct rs_break, list);
		if (tmp->probe.vaddr == u->vaddr && tmp->probe.pid == u->pid) {
			printk(KERN_INFO "Hit breakpoint at: %p in thread %u\n", (void*)u->vaddr, u->pid);
			printk(KERN_INFO "New context is %s\n", tmp->new_cont);

			ret = selinux_string_to_sid(tmp->new_cont,
					strlen(tmp->new_cont), &sid);

			if (ret == -EINVAL) {
				printk("Acedia: Failed to translate context to sid: %s\n",
						tmp->new_cont);
				return;
			} else {
				printk("Acedia: Sid for %s is %u\n", tmp->new_cont, sid);
			}

            ret = my_kern_setprocattr(tmp->new_cont, strlen(tmp->new_cont));
			break;
            }

    }
}

static int handl_sbh(struct linux_binprm *bprm,struct pt_regs *regs)
{
	struct list_head *pos, *t_pos;
	struct rs_info *tmp;
	struct traced_pid *t_tmp;
    struct utrace_engine *engine = NULL;
	int ret;
    char attached = 0;

	list_for_each(pos, &info_list) {
		tmp = list_entry(pos, struct rs_info, list);

		if (!strcmp(bprm->filename,tmp->trans.bin_file)) {
            list_for_each(t_pos, &traced_list)
            {
                t_tmp = list_entry(t_pos, struct traced_pid, list);
                if (t_tmp->pid == current->pid) 
                {
                    attached = 1;
                    break;
                }
                
            }

            if (!attached) 
            {
                printk(KERN_INFO "Apathy: About to set bpt on %s\n",
                        tmp->trans.bin_file);

                if (!try_module_get(THIS_MODULE)) {
                    ret = EBUSY;
                    return ret;
                }
                engine = utrace_attach_task(current, UTRACE_ATTACH_CREATE, &my_utrace_ops, NULL);

                if ( engine ) {
                    ret = utrace_set_events(current, engine, UTRACE_EVENT(EXEC) | UTRACE_EVENT(EXIT)
                            | UTRACE_EVENT(CLONE));

                    t_tmp = kzalloc(sizeof(struct traced_pid), GFP_KERNEL);
                    if (!t_tmp) 
                    {
                        goto detach_out;
                    }
                    t_tmp->pid = current->pid;
                    list_add(&t_tmp->list, &traced_list);
                } else {
                    module_put(THIS_MODULE);
                    printk(KERN_INFO "Apathy: failed to attach utrace engine\n");
                }
            }

            break; //FIXME: not a good style to use break
			//set_bpt(tmp);
		}
	}

	jprobe_return();

detach_out:
    printk(KERN_INFO "Apathy: failed to trace %u\n", current->pid);
    detach_engine(engine, current);
	jprobe_return();
}

static struct jprobe do_execve_jprobe = {
	.kp.addr = (kprobe_opcode_t *)search_binary_handler,
	.entry   = (kprobe_opcode_t *)handl_sbh
};

static void apathy_destructor(struct device *d)
{
}

ssize_t apathy_dev_read(struct file* file, char *buffer,
		size_t length, loff_t* offset)
{
	printk(KERN_INFO "Apathy: device read is not implemented\n");
	return -0;
}

int ioctl_set_break(void __user *p)
{
	struct rs_info *brk;
	struct list_head *pos;
	struct rs_info *tmp;
	int ret;

	brk = kzalloc(sizeof(struct rs_info),GFP_KERNEL);

	if (!brk) {
		ret = -ENOMEM;
		goto out;
	}

	if (copy_from_user(&brk->trans, p, sizeof(struct apathy_trans))) {
		ret = -EFAULT;
		goto out_clean;
	}

	if (brk->trans.new_cont[0] == '\0') {
		ret = -EINVAL;
		goto out_clean;
	}

	if (brk->trans.bin_file[0] == '\0') {
		ret = -EINVAL;
		goto out_clean;
	}

	list_for_each(pos, &info_list) {
		tmp = list_entry(pos, struct rs_info, list);
		if (tmp->trans.addr == brk->trans.addr &&
			strcmp(tmp->trans.bin_file,brk->trans.bin_file) == 0 &&
			strcmp(tmp->trans.new_cont,brk->trans.new_cont) == 0) {
			printk(KERN_INFO "Apathy: Breakpoint at %p for %s exists.\n",
					(void*)tmp->trans.addr,tmp->trans.bin_file);
			ret = -EBUSY;
			goto out_clean;
		}
	}

	list_add(&brk->list, &info_list);
	printk( KERN_INFO "Apathy: Set bpt for %s\n", brk->trans.bin_file);

	return 0;

out_clean:

	kfree(brk);
out:
	return ret;

	/*
	brk->probe.pid = trans.pid;
	brk->probe.vaddr = trans.addr;
	brk->probe.handler = uprobe_handler;
	brk->probe.kdata = null;

	printk(kern_info "apathy: setting breakpoint pid %d vaddr %p\n",
			brk->probe.pid, (void*)brk->probe.vaddr);
	memset(brk->new_cont, 0, sizeof(brk->new_cont));
	strncpy(brk->new_cont, trans.new_cont, cont_maxlen);

	list_add(&brk->list, &break_list);

	ret = register_uprobe(&brk->probe);

	if (ret != 0) {
		unregister_uprobe(&brk->probe);
		printk(KERN_INFO "Apathy: failed to register uprobe\n");
		printk(KERN_INFO "Apathy: returned %d\n", ret);
	}
	*/

	return 0;
}

static void free_bpt_list(void)
{
	struct list_head *pos,*q;
	struct rs_break *tmp;

	list_for_each_safe(pos, q, &break_list) {
		tmp = list_entry(pos, struct rs_break,list);
		printk(KERN_INFO "Apathy: deleting list: %s\n", tmp->new_cont);
		unregister_uprobe(&tmp->probe);
		list_del(pos);

		kfree(tmp);
	}
}

static void free_inf_list(void)
{
	struct list_head *pos, *q;
	struct rs_info *tmp;

	list_for_each_safe(pos, q, &info_list) {
		tmp = list_entry(pos, struct rs_info, list);
		printk( KERN_INFO "Apathy: deleting info: %s\n", tmp->trans.bin_file);
		list_del(pos);
		kfree(tmp);
	}
}

static void free_traced_list(void)
{
	struct list_head *pos, *q;
	struct traced_pid *t_tmp;

	list_for_each_safe(pos, q, &traced_list) {
		t_tmp = list_entry(pos, struct traced_pid, list);
		printk( KERN_INFO "Apathy: deleting traced list from thread: %u\n", t_tmp->pid);
		list_del(pos);
		kfree(t_tmp);
	}
}

int ioctl_del_break(const struct apathy_trans* tr)
{
	return 0;
}

long apathy_dev_ioctl(struct file *f,
		unsigned int cmd, unsigned long __user arg)
{
	switch (cmd) {
		case APATHY_IOCTL_SET_BREAK:
			printk(KERN_INFO "Apathy: ioctl set_break\n");

			return ioctl_set_break((struct apathy_trans*)arg);

		case APATHY_IOCTL_DEL_BREAK:
			printk(KERN_INFO "Apathy: ioctl del break\n");

			return ioctl_del_break((struct apathy_trans*)arg);

		default: break;
	}
	return -0;
}

int apathy_dev_release(struct inode *i, struct file* f)
{
	printk(KERN_INFO "Apathy: asdasd\n");
	/*
	if (f->ops.close)
		f->ops.close(f);

	*/
	module_put(THIS_MODULE);
	return 0;
}

int apathy_dev_open(struct inode *i, struct file *f)
{
	int ret;
	printk(KERN_INFO "Apathy: Open\n");

	if (!f)
		return -EIO;

	if (!try_module_get(THIS_MODULE)) {
		ret = EBUSY;
		return ret;
	}

	return 0;
}

struct file_operations apathy_file_ops = {
	.owner		= THIS_MODULE,
	// .read 		= apathy_dev_read,
	.open		= apathy_dev_open,
	.release 	= apathy_dev_release,
	.unlocked_ioctl = apathy_dev_ioctl,
};

static int apathy_init(void)
{
	int ret;

	apathy_class = class_create(THIS_MODULE, "apathy");

	if (!apathy_class) {
		printk(KERN_INFO "Apathy: Failed to create device class.\n");
		return -EFAULT;
	}

	ret = alloc_chrdev_region(&apathy_devt, 0, 11, "apathy");

	if (ret < 0) {
		printk(KERN_INFO "Apathy: Failed to allocate chardev region.\n");
		return -EFAULT;
	}

	dev_set_name(&apathy_dev, "apathy");
	cdev_init(&apathy_cdev, &apathy_file_ops);
	apathy_cdev.ops = &apathy_file_ops;
	apathy_cdev.owner = THIS_MODULE;

	apathy_dev.devt = MKDEV(MAJOR(apathy_devt),MINOR(apathy_devt));
	apathy_dev.release = apathy_destructor;

	ret = cdev_add(&apathy_cdev, apathy_dev.devt, 1);

	if (ret < 0) {
		printk(KERN_INFO "Apathy: failed to add cdev\n");
		return -EFAULT;
	}

	ret = device_register(&apathy_dev);

	if (ret < 0) {
		printk(KERN_INFO "Apathy: failed to register device\n");
		return -EFAULT;
	}

	my_utrace_ops.report_exec = my_report_exec;
	my_utrace_ops.report_exit = my_report_exit;
    my_utrace_ops.report_clone = my_report_clone; 
    my_utrace_ops.report_quiesce = my_report_quiesce; 

	register_jprobe(&do_execve_jprobe);
	/*
	struct task_struct *tmp;
	u32 sid;
	char *p;
	printk("Listing processes and contexts\n");
	for_each_process(tmp) {
		selinux_kern_getprocattr(tmp, "current", &p);
		// printk("Task pid: %u procattr: %s\n", tmp->pid, p);
		if ( strcmp( p, "unconfined_u:unconfined_r:acedia_t:s0-s0:c0.c1023" ) == 0 ) {
			printk( "Setting context\n" );

			ret = selinux_string_to_sid( "system_u:system_r:sshd_t:s0-s0:c0.c1023",
						sizeof("system_u:system_r:sshd_t:s0-s0:c0.c1023"), &sid );

			if ( ret == -EINVAL ) {
				printk( "Shit\n" );
			} else {
				printk( "Sid: %u\n", sid );
			}

			ret = selinux_kern_setprocattr( tmp, "current", "system_u:system_r:sshd_t:s0-s0:c0.c1023",
								sizeof( "system_u:system_r:sshd_t:s0-s0:c0.c1023" ));

			printk( "Returned %d\n", ret );

		}
	}

	printk("Listing finished\n");
	*/
	return 0;
}

static void apathy_exit(void)
{
	printk(KERN_INFO "Exiting apathy\n");
	device_unregister(&apathy_dev);
	unregister_chrdev_region(apathy_devt, 11);
	class_destroy(apathy_class);
	free_bpt_list();
	free_inf_list();
	free_traced_list();
	unregister_jprobe(&do_execve_jprobe);
}

module_init(apathy_init);
module_exit(apathy_exit);
