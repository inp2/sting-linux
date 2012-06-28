#include <linux/sting.h>
#include <linux/user_unwind.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/hardirq.h>
#include <linux/sched.h>
#include <linux/relay.h>
#include <linux/debugfs.h>

#include <asm-generic/current.h>

#include "ept_dict.h"
#include "permission.h"
#include "syscalls.h"

/* sting_log file */

static struct dentry *create_sting_log_file_callback(const char *filename,
		struct dentry *parent, umode_t mode, struct rchan_buf *buf, int *is_global)
{
		return debugfs_create_file(filename, mode, parent, buf,
								   &relay_file_operations);
}

static int remove_sting_log_file_callback(struct dentry* dentry)
{
	debugfs_remove(dentry);
	return 0;
}

 /* callback when one subbuffer is full */
static int subbuf_sting_log_start_callback(struct rchan_buf *buf, void *subbuf,
		 void *prev_subbuf, size_t prev_padding)
{
	atomic_t* dropped;
	if (!relay_buf_full(buf))
		return 1;
	dropped = buf->chan->private_data;
	atomic_inc(dropped);
	if (atomic_read(dropped) % 5000 == 0)
		STING_ERR(1, "%s full, dropped: %d\n", STING_LOG_FILE, atomic_read(dropped));
	return 0;
}

atomic_t dropped = ATOMIC_INIT(0);
static struct rchan_callbacks sting_log_relay_callbacks =
{
	.subbuf_start		= subbuf_sting_log_start_callback,
	.create_buf_file	= create_sting_log_file_callback,
	.remove_buf_file	= remove_sting_log_file_callback,
};

struct rchan* sting_log_rchan;
EXPORT_SYMBOL(sting_log_rchan);

static int __init sting_log_init(void)
{
	sting_log_rchan = relay_open(STING_LOG_FILE, NULL, 1024 * 1024, 8,
			&sting_log_relay_callbacks, &dropped);
	if (!sting_log_rchan) {
		STING_ERR(1, "relay_open(%s) failed\n", STING_LOG_FILE);
		return 1;
	}
	return 0;
}
fs_initcall(sting_log_init);

/* file /sys/kernel/debug/sting_monitor_pid for selective pid tracing */

pid_t sting_monitor_pid = -1;

static ssize_t
sting_monitor_pid_read(struct file *file, char __user *ubuf,
					   size_t count, loff_t *ppos)
{
	/* TODO: 12??? */
	char tmpbuf[12];
	ssize_t length;

	length = scnprintf(tmpbuf, 12, "%d\n", sting_monitor_pid);
	return simple_read_from_buffer(ubuf, count, ppos, tmpbuf, length);
}

static ssize_t
sting_monitor_pid_write(struct file *filp, const char __user *buf,
				   size_t count, loff_t *ppos)
{
	char *page;
	ssize_t length;
	int new_value;

	if (count >= PAGE_SIZE)
		return -ENOMEM;
	if (*ppos != 0) {
		/* No partial writes. */
		return -EINVAL;
	}
	page = (char *)get_zeroed_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;
	length = -EFAULT;
	if (copy_from_user(page, buf, count))
		goto out;

	length = -EINVAL;
	if (sscanf(page, "%d", &new_value) != 1)
		goto out;

	sting_monitor_pid = new_value;
	length = count;
out:
	free_page((unsigned long) page);
	return length;
}

static const struct file_operations sting_monitor_pid_fops = {
	   .write  = sting_monitor_pid_write,
	   .read   = sting_monitor_pid_read,
};

static int __init sting_init(void)
{
	struct dentry *sting_monitor_pid;

	sting_monitor_pid = debugfs_create_file("sting_monitor_pid",
			0600, NULL, NULL, &sting_monitor_pid_fops);
	printk(KERN_INFO STING_MSG "creating sting_monitor_pid file\n");

	if(!sting_monitor_pid) {
		printk(KERN_INFO STING_MSG "unable to create sting_monitor_pid\n");
	}
	return 0;
}
fs_initcall(sting_init);

/* sting hooks and actions */
static int check_valid_user_context(struct task_struct *t)
{
	if (!t->mm)
		goto fail;
	if (sting_monitor_pid != -1 && t->pid != sting_monitor_pid)
		goto fail;
	/* request originating inside sting */
//	if (t->sting_request)
//		goto fail;
	if (in_atomic() || in_irq() || in_interrupt() || irqs_disabled())
		goto fail;

	return 1;

fail:
	return 0;
}

static inline int ept_inode_get(struct user_stack_info *us)
{
	return us->vma_inoden[us->ept_ind];
}

static inline int ept_offset_get(struct user_stack_info *us)
{
	return us->trace.entries[us->ept_ind] - us->vma_start[us->ept_ind];
}

void sting_syscall_begin(void)
{
	char *fname = NULL;
	int adv_uid_ind;
	struct ept_dict_entry e, *r;
	int ntest;

	if (!check_valid_user_context(current))
		goto end;
	/* check if nameres call */
	fname = get_syscall_fname();
	if (!fname)
		goto end;

	/* XXX: below flow logs every entrypoint, not just adversary-accessible
	   ones. rearrange if performance is needed */

	/* get entrypoint (if performance needed, do this after adversary check) */
	user_unwind(current);

	/* adversary check */
	adv_uid_ind = sting_get_adversary(fname, ATTACKER_BIND);

	/* check against ept dictionary */
	e.key.ino = ept_inode_get(&current->user_stack);
	e.key.offset = ept_offset_get(&current->user_stack);

	r = ept_dict_lookup(&e.key);
	if (r && !r->val.adversary_access &&
				sting_valid_adversary(adv_uid_ind)) {
		/* update ept dictionary */
		e.val.adversary_access = 1;
		e.val.attack_history = 0;
		r = ept_dict_entry_set(&e.key, &e.val);
	} else if (!r) {
		/* insert into ept dictionary */
		e.val.adversary_access = !!sting_valid_adversary(adv_uid_ind);
		e.val.attack_history = 0;
		r = ept_dict_entry_set(&e.key, &e.val);
	}

	if (!sting_valid_adversary(adv_uid_ind)) {
		/* exit - raise this check above if performance needed */
		goto end;
	}


#if 0
	if (sting_valid_adversary(adv_uid_ind))
		/* check retry */
		if (sting_pending_lookup_ept(current)) {
			/* retry => immune to pending attack (if any) */
			type = sting_pending_get_type(current, r->key.offset);
			sting_pending_remove_ept(current, r->key.offset);
			ept_dict_mark_immune(r, (r->value.attack_history) & type);
		}

		/* get next attack */
		ntest = get_next_attack(e.value.attack_history);
		if (!ntest)
			goto end;

		/* update pending */
		sting_pending_add_ept(current);

		/* attack! */
		fuzz_resource(fname, ntest, adv_uid, 0);
#endif
end:
	if (fname)
		putname(fname);
	return;
}
EXPORT_SYMBOL(sting_syscall_begin);
