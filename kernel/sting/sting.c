#include <linux/sting.h>
#include <linux/user_unwind.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/hardirq.h>
#include <linux/sched.h>
#include <linux/relay.h>
#include <linux/debugfs.h>
#include <linux/types.h>
#include <linux/mount.h>

#include <asm-generic/current.h>

#include "ept_dict.h"
#include "permission.h"
#include "syscalls.h"
#include "launch_attack.h"
#include "utility.h"
#include "shadow_resolution.h"

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

/* list of ongoing attacks (status and rollback information). 
 * Since the number of attacks is small, a list suffices. 
 * TODO: If we find scenarios where performance is hit because
 * of this list, change.  */

/* TODO: Below three functions should be in user_unwind.h */

static inline ino_t ept_inode_get(struct user_stack_info *us)
{
	return us->vma_inoden[us->ept_ind];
}

static unsigned long ept_offset_get(struct user_stack_info *us)
{
	return us->trace.entries[us->ept_ind] - us->vma_start[us->ept_ind];
}

static inline int valid_user_stack(struct user_stack_info *us)
{
	return (us->trace.entries[0] != ULONG_MAX);
}

static struct sting sting_list; 
static DEFINE_RWLOCK(stings_rwlock); 

void sting_list_add(struct sting *st) 
{
	unsigned long flags; 
	write_lock_irqsave(&stings_rwlock, flags); 
	list_add(&st->list, &sting_list.list); 
	write_unlock_irqrestore(&stings_rwlock, flags); 
}

void sting_list_del(struct sting *st)
{
	unsigned long flags; 
	write_lock_irqsave(&stings_rwlock, flags); 
	list_del(&sting_list.list); 
	write_unlock_irqrestore(&stings_rwlock, flags); 
}

struct sting *sting_list_get(struct sting *st, int st_flags)
{
	struct sting *t; 
	unsigned long flags; 
	read_lock_irqsave(&stings_rwlock, flags); 
	list_for_each_entry(t, &sting_list.list, list) {
		if ((st_flags & MATCH_PID) && (t->pid != st->pid))
			continue; 
		if ((st_flags & MATCH_EPT) && 
				((t->ino != st->ino) || (t->offset != st->offset))) 
			continue; 
		if ((st_flags & MATCH_DENTRY) && (t->path.dentry != st->path.dentry))
			continue; 

		/* match */
		read_unlock_irqrestore(&stings_rwlock, flags); 
		return t; 
	}

	/* no match */
	read_unlock_irqrestore(&stings_rwlock, flags); 
	return NULL;  
}

void task_fill_sting(struct sting *st, struct task_struct *t)
{
	st->pid = t->pid; 
	st->offset = ept_offset_get(&t->user_stack); 
	st->ino = ept_inode_get(&t->user_stack); 
}

static int __init sting_init(void)
{
	struct dentry *sting_monitor_pid;

	sting_monitor_pid = debugfs_create_file("sting_monitor_pid",
			0600, NULL, NULL, &sting_monitor_pid_fops);
	printk(KERN_INFO STING_MSG "creating sting_monitor_pid file\n");

	if(!sting_monitor_pid) {
		printk(KERN_INFO STING_MSG "unable to create sting_monitor_pid\n");
	}

	/* initialize linked list of ongoing stings */
	INIT_LIST_HEAD(&sting_list.list); 
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
	if (t->sting_request)
		goto fail;
	if (in_atomic() || in_irq() || in_interrupt() || irqs_disabled())
		goto fail;

	return 1;

fail:
	return 0;
}

void sting_mark_immune(struct ept_dict_val *v, int attack_type)
{
	v->attack_history |= attack_type << 8; 
	v->attack_history &= ~(attack_type); 
}

void sting_mark_vulnerable(struct ept_dict_val *v, int attack_type)
{
	v->attack_history |= attack_type << 8; 
	v->attack_history |= attack_type; 
}

/* TODO: mac adversary model
 * TODO: mark whether to redirect to lower or upper branch */

void sting_syscall_begin(void)
{
	char *fname = NULL;
	struct path fpath; 
	int adv_uid_ind = UID_NO_MATCH; 
	struct ept_dict_entry e, *r;
	int ntest;
	struct task_struct *t = current; 
	struct nameidata nd; 
	int lc = 0 /* last component? */, ctr = 0; 
	int err, sh_err = 0; 
	struct sting st, *m; 
	int added_current = 0; /* if added, cannot drop reference to path */
	struct path parent, child; 	

	if (!check_valid_user_context(t))
		goto end;
	/* check if nameres call */
	fname = get_syscall_fname();
	if (!fname)
		goto end;
	STING_ERR(1, "fname: [%s]\n", fname); 

	/* XXX: below flow logs every entrypoint, not just adversary-accessible
	   ones. rearrange if performance is needed */
	/* get entrypoint */
	user_unwind(t);
	if (!valid_user_stack(&t->user_stack))
		goto end;  /* change to put if moving below! */

	/* get adversary, scanning each binding */
	shadow_res_init(AT_FDCWD, fname, 0, &nd); 

	while (nd.last_type == LAST_BIND || !lc) {
		lc = shadow_res_advance_name(&fname, &ctr, &nd); 
		if (lc < 0) {
			/* can't recover from -ENOENT here, follow_link may
			   not have updated nd->path */
			sh_err = lc; 
			goto put; 
		}
		if (lc != 2) {
			/* not already resolved by follow_link */
			sh_err = shadow_res_resolve_name(&nd, &fname[ctr]); 
			if (sh_err < 0 && sh_err != -ENOENT) {
				err = sh_err; 
				goto put; 
			}
		}
		/* TODO: handle the case when the next component is a mountpoint  -- 
		 we have to traverse up the mount to check binding delete permission. */

		/* we check adversary permission only on last component */
		if (lc && (nd.last_type == LAST_NORM || nd.last_type == LAST_BIND)) {
			if (IS_ROOT(nd.path.dentry))
				continue;

			shadow_res_get_pc_paths(&parent, &child, &nd, sh_err); 

			adv_uid_ind = sting_get_adversary(parent.dentry, child.dentry, ATTACKER_BIND); 

			shadow_res_put_pc_paths(&parent, &child, sh_err); 

			if (sting_valid_adversary(adv_uid_ind)) {
				printk(KERN_INFO STING_MSG "adversary: %d for uid: %d and filename: %s\n", 
					uid_array[adv_uid_ind][0], current->cred->fsuid, fname); 
				break; 
			}
		}
		if (sh_err == -ENOENT) {
			/* component (non-last) doesn't exist -- if we have perm on parent, 
			   even if not last component, we can create directory 
			   hierarchy -- we don't do this yet */
			err = sh_err; 
			goto put; 
		}
	}
	
	shadow_res_get_pc_paths(&parent, &child, &nd, sh_err); 

	shadow_res_end(&nd); 

	/* get ept dictionary record, initializing a new one if needed */
	e.key.ino = ept_inode_get(&t->user_stack);
	e.key.offset = ept_offset_get(&t->user_stack);
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
		goto parent_put;
	}

	ntest = SYMLINK; 
	sting_launch_attack(shadow_res_get_last_name(&nd, &child), &parent, adv_uid_ind, ntest); 
#if 0
	/* check if dentry has been used for another test case */
	if (child.dentry != NULL) {
		err = sting_already_launched(child.dentry); 
		if (err < 0)
			goto put; 

		/* if so, add that test case to current ept. no need to 
		 * launch attack */
		if (err) {
			/* already in use for another attack. add current
			 * entrypoint to same attack if adversary. 
			 * TODO: if not, mark as redirect to lower branch.  */
			st.path.dentry = child.dentry; 
			st.path.mnt = child.mnt; 
			m = sting_list_get(&st, MATCH_DENTRY); 
			if (!m) {
				printk(KERN_INFO STING_MSG
						"no attack in list although marked: [%s]\n", fname); 
				goto put; 
			}
			/* if the attack were launched elsewhere, it means a new 
			 * cross-entrypoint path is exercised, so it does not matter if 
			 * we are immune to the same attack type _launched_ at our ept */
			if (r && sting_attack_checked(r->val.attack_history, m->attack_type)) {
				printk(KERN_INFO STING_MSG "new adversarial path\n"); 
			}
			if (!sting_adversary(uid_array[m->adv_uid_ind][0], t->cred->fsuid)) {
				printk(KERN_INFO STING_MSG
						"another non-adversarial attack ongoing: [%s]\n", fname); 
				goto put; 
			}

			memcpy(&st, m, sizeof(struct sting)); 
			task_fill_sting(&st, t); 
			sting_list_add(&st); 
			added_current = 1; 
			STING_LOG("added [%s:%lx] accessing [%s] to sting_list for " 
					"adversary [%d] and victim [%d]\n", 
					t->comm, st.offset, fname, 
					uid_array[adv_uid_ind][0], t->cred->fsuid); 
			goto put; 
		}
	}

	/* mark immune on retry; don't launch attack */
	task_fill_sting(&st, t); 
	m = sting_list_get(&st, MATCH_PID | MATCH_EPT); 
	if (m) {
		/* when rolling back, make sure that the file is still labeled by attacker.
		 * it might have been removed by the prog, we don't want to delete that.  */
		// sting_rollback(m->dentry); 
		sting_mark_immune(&r->val, m->attack_type); 
		sting_list_del(m); 
		goto put; 
	}

	/* get next attack */
	ntest = sting_get_next_attack(r->val.attack_history); 

	// added_current = 1; 
	// sting_list_add; 

	if (sting_valid_adversary(adv_uid_ind))
		/* check retry */
		if (sting_pending_lookup_ept(t)) {
			/* retry => immune to pending attack (if any) */
			type = sting_pending_get_type(t, r->key.offset);
			sting_pending_remove_ept(t, r->key.offset);
			ept_dict_mark_immune(r, (r->value.attack_history) & type);
		}

		/* get next attack */
		ntest = get_next_attack(e.value.attack_history);
		if (!ntest)
			goto put;

		/* update pending */
		sting_pending_add_ept(t);

		/* attack! */
		fuzz_resource(fname, ntest, adv_uid, 0);
#endif
parent_put:
	shadow_res_put_pc_paths(&parent, &child, sh_err); 
put:
	if (sh_err < 0)
		STING_DBG("sting: fname: %s [ %d ]\n", fname, sh_err); 
	shadow_res_put_lookup_path(&nd); 
//	path_put(&nd.path); 
end:
	/* we have to hold reference to nd until the end */
	if (fname)
		putname(fname);
	return;
}
EXPORT_SYMBOL(sting_syscall_begin);
