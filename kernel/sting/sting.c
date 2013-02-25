/*
 * Copyright (c) 2011-2012 Hayawardh Vijayakumar
 * Copyright (c) 2011-2012 Systems and Internet Infrastructure Security Lab
 * Copyright (c) 2011-2012 The Pennsylvania State University
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

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
#include <asm/syscall.h>

#include <linux/ept_dict.h>
#include <linux/interpreter_unwind.h>

#include "permission.h"
#include "syscalls.h"
#include "launch_attack.h"
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

	STING_LOG("message: reboot marker\n");
	return 0;
}
fs_initcall(sting_log_init);

/* file /sys/kernel/debug/sting_ignore_library_ept for ignoring repeat attacks
 * on already tested library entrypoints */

struct user_stack_frame {
	struct list_head list;
	ino_t f_ino;
	unsigned long offset;
};

static struct user_stack_frame frame_list;
static struct rw_semaphore frame_list_rwlock;

static unsigned int frame_list_load(void **data, size_t length)
{
    struct user_stack_frame *tmp, *n;
    char *inode_s, *offset_s, *e_s;
    int ret = 0;
	ino_t inode;
	unsigned long offset;

	down_write(&frame_list_rwlock);

	/* Empty the list */
	list_for_each_entry_safe(tmp, n, &frame_list.list, list) {
		list_del(&tmp->list);
		kfree(tmp);
	}

	printk(KERN_INFO STING_MSG "Initializing frame ignore list\n");

	INIT_LIST_HEAD(&frame_list.list);

	/* Parse and load input data:
	 * inode1 offset1
	 * inode2 offset2
	 * ...
	 */

	/* Null Terminate */
	*(*(char **)data + length - 1) = '\0';

	/* Parse the lines and insert into list */
	while (1) {
		inode_s = strsep((char **) data, " ");
		if (!inode_s)
			break;
		offset_s = strsep((char **) data, "\n");
		if (!offset_s)
			break;

		inode = simple_strtoul(inode_s, &e_s, 0);
		if (inode == 0 && inode_s == e_s) {
			ret = -EINVAL;
			break;
		}

		offset = simple_strtoul(offset_s, &e_s, 16);
		if (offset == 0 && offset_s == e_s) {
			ret = -EINVAL;
			break;
		}

		tmp = kmalloc(sizeof(struct user_stack_frame), GFP_ATOMIC);
		if (!tmp) {
			ret = -ENOMEM;
			break;
		}

		tmp->f_ino = inode;
		tmp->offset = offset;

		list_add_tail(&tmp->list, &frame_list.list);
		printk(KERN_INFO STING_MSG "added inode: [%lu] offset: [%lu]\n",
			tmp->f_ino, tmp->offset);
	}

	up_write(&frame_list_rwlock);

	return (ret < 0) ? ret : length;
}

static ssize_t
sting_frame_ignore_write(struct file *filp, const char __user *buf,
				   size_t count, loff_t *ppos)
{
	void *data = NULL;
	ssize_t length;

	if (count >= PAGE_SIZE)
		return -ENOMEM;

	if (*ppos != 0) {
		/* No partial writes. */
		return -EINVAL;
	}

	if ((count > 64 * 1024 * 1024)
		|| (data = vmalloc(count)) == NULL) {
		length = -ENOMEM;
		goto out;
	}

	length = -EFAULT;
	if (copy_from_user(data, buf, count) != 0)
		goto out;

	length = frame_list_load(&data, count);

	vfree(data);
out:
	return length;
}

static const struct file_operations sting_frame_ignore_fops = {
	   .write  = sting_frame_ignore_write,
};

/* return true if @us contains frame in frame_list */
int frame_ignore(struct user_stack_info *us)
{
	struct user_stack_frame *uf;
	int found = false, i;

	down_read(&frame_list_rwlock);

	for (i = 0; i < us->trace.nr_entries - 1; i++) {
		list_for_each_entry(uf, &frame_list.list, list) {
			if ((us->trace.vma_inoden[i] == uf->f_ino)) {
			   	if (uf->offset == 0 ||
						us_offset_get(us, i) == uf->offset) {
					found = true;
					goto out;
				}
			}
		}
	}

out:
	up_read(&frame_list_rwlock);

	return found;
}

/* file /sys/kernel/debug/sting_monitor_pid for selective pid tracing */

pid_t sting_monitor_pid = 0;

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

/* we have a simple list instead of a hash as the number of
 * current stings is small */

struct kmem_cache *sting_cachep;

static struct sting sting_list;
static struct rw_semaphore stings_rwlock;

void sting_list_add(struct sting *st)
{
	struct sting *news = kmem_cache_alloc(sting_cachep, GFP_KERNEL);
	if (!news) {
		STING_ERR(0, "failed to create sting");
		return;
	}

	st->path_ino = st->path.dentry->d_inode->i_ino; /* for ease of comparison */
	if (st->target_path.dentry && st->target_path.dentry->d_inode)
		st->target_path_ino = st->target_path.dentry->d_inode->i_ino;
	else
		st->target_path_ino = 0;

	memcpy(news, st, sizeof(struct sting));
	STING_LOG("message: added to sting_list, entrypoint: [%s:%lx:%s:%lu], "
				"resource: [%s], adversary sid: [%d], victim sid: [%d], "
				"adversary model: [%s]\n",
			current->comm, ept_offset_get(&news->user_stack),
			int_ept_filename_get(&news->user_stack),
			int_ept_lineno_get(&news->user_stack),
			news->path.dentry->d_name.name,
			news->adv_model->print_adv(news->adv_id),
			news->adv_model->print_victim(news->victim),
			news->adv_model->name
			);
	down_write(&stings_rwlock);
	path_get(&news->path);
	/* check if there is a target (may not be if it is a new file) */
	if (news->target_path.dentry);
		path_get(&news->target_path);
	list_add_tail(&news->list, &sting_list.list);
	up_write(&stings_rwlock);
}

void sting_list_del(struct sting *st)
{
	STING_LOG("message: deleted from sting_list, entrypoint: [%s:%lx:%s:%lu], "
				"resource: [%s], adversary sid: [%d], victim sid: [%d], "
				"adversary model: [%s]\n",
			current->comm, ept_offset_get(&st->user_stack),
			int_ept_filename_get(&st->user_stack),
			int_ept_lineno_get(&st->user_stack),
			st->path.dentry->d_name.name,
			st->adv_model->print_adv(st->adv_id),
			st->adv_model->print_victim(st->victim),
			st->adv_model->name
			);
	path_put(&st->path);
	if (st->target_path.dentry);
		path_put(&st->target_path);
	down_write(&stings_rwlock);
	list_del(&st->list);
	up_write(&stings_rwlock);
	kmem_cache_free(sting_cachep, st);
}

struct sting *sting_list_get(struct sting *st, int st_flags, struct sting *start)
{
	struct sting *t, *n;
	down_read(&stings_rwlock);
	list_for_each_entry_safe(t, n, &sting_list.list, list) {
		if ((st_flags & MATCH_PID) && (t->pid != st->pid))
			continue;
		if ((st_flags & MATCH_EPT) &&
				ept_match(&t->user_stack, &st->user_stack))
			continue;
		if ((st_flags & MATCH_INO) && (!
			((t->path_ino == st->path_ino) ||
			(t->target_path_ino &&
				(t->target_path_ino == st->path_ino)))
			))
			continue;
		if (start && !memcmp(start, t, sizeof(struct sting)))
			continue;
		/* match */
		up_read(&stings_rwlock);
		return t;
	}

	/* no match */
	up_read(&stings_rwlock);
	return NULL;
}

static int launch_from_script(struct task_struct *t)
{
	return (int_ept_exists(&t->user_stack) && !is_interpreter(t));
}

void task_fill_sting(struct sting *st, struct task_struct *t, int sting_parent)
{
	if (sting_parent == 1)
		st->pid = t->parent->pid;
	else
		st->pid = t->pid;

	memcpy(&st->user_stack, &t->user_stack, sizeof(struct user_stack_info));

	// st->offset = ept_offset_get(&t->user_stack);
	// st->ino = ept_inode_get(&t->user_stack);

	if (sting_parent)
		get_task_comm(st->comm, t->parent);
	else
		get_task_comm(st->comm, t);

	/* parent's interpreter context is stored in child during fork,
	 * if child itself is not an interpreter */
#if 0
	if (int_ept_exists(&t->user_stack))
		strcpy(st->int_filename, int_ept_filename_get(&t->user_stack));
	else
		st->int_filename[0] = 0;
	st->int_lineno = int_ept_lineno_get(&t->user_stack);
#endif
}

static void sting_ctor(void *data)
{
	/* zero everything */
	struct sting *st = data;

	memset(st, 0, sizeof(struct sting));
	st->attack_type = -1;
	st->adv_id = -1;
#if 0
	st->pid = 0;
	st->comm[0] = '\0';
	st->ino = 0;
	st->offset = 0;
	st->int_filename[0] = '\0';
	st->int_lineno = 0;
	st->path.dentry = NULL;
	st->path.mnt = NULL;
	st->path_ino = 0;
	st->target_path.dentry = NULL;
	st->target_path.ino = NULL;
	st->target_path_ino = 0;
#endif
}

static int __init sting_init(void)
{
	struct dentry *sting_monitor_pid, *sting_frame_ignore;

	sting_monitor_pid = debugfs_create_file("sting_monitor_pid",
			0600, NULL, NULL, &sting_monitor_pid_fops);
	printk(KERN_INFO STING_MSG "creating sting_monitor_pid file\n");

	if(!sting_monitor_pid) {
		printk(KERN_INFO STING_MSG "unable to create sting_monitor_pid\n");
	}

	sting_frame_ignore = debugfs_create_file("frame_ignore_list",
			0600, NULL, NULL, &sting_frame_ignore_fops);
	printk(KERN_INFO STING_MSG "creating sting_frame_ignore file\n");

	if(!sting_frame_ignore) {
		printk(KERN_INFO STING_MSG "unable to create sting_frame_ignore\n");
	}

	/* initialize linked list of ongoing stings */
	INIT_LIST_HEAD(&sting_list.list);
	init_rwsem(&stings_rwlock);

	/* initialize linked list of frames to skip testing */
	INIT_LIST_HEAD(&frame_list.list);
	init_rwsem(&frame_list_rwlock);

	/* initialize cache for ongoing stings */
	sting_cachep = kmem_cache_create("sting_cachep",
			sizeof(struct sting), 0,
			SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_NOTRACK, sting_ctor);

	return 0;
}
fs_initcall(sting_init);

static inline int ancestor_pid(struct task_struct *t, pid_t sting_monitor_pid)
{
	while (t->pid >= 1) {
		if (t->pid == sting_monitor_pid)
			return true;
		t = t->parent;
	}
	return false;
}

static inline int sting_should_monitor_pid(struct task_struct *t)
{
	if (sting_monitor_pid == 1) {
		return 1;
	} else if (sting_monitor_pid == -1 || sting_monitor_pid == 0) {
		return 0;
	} else if (sting_monitor_pid > 1) {
		if (!ancestor_pid(t, (pid_t) sting_monitor_pid))
			return 0;
		else
			return 1;
	} else if (sting_monitor_pid < -1) {

		if (ancestor_pid(t, (pid_t) -sting_monitor_pid))
			return 0;
		else
			return 1;
	}

	printk(KERN_INFO STING_MSG "logic error!\n");
	return 0;
}

/* sting hooks and actions */
static int check_valid_user_context(struct task_struct *t)
{
	if (!t->mm)
		goto fail;
	if (!sting_should_monitor_pid(t))
		goto fail;
	/* not dealing with init itself because it exits last and we cannot save
	   marked exit immunity. */
	if (t->pid == 1)
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

void sting_mark_immune(struct ept_dict_entry *e, int attack_type)
{
	e->val.attack_history |= (attack_type << ATTACK_CHECKED_SHIFT);
	/* nothing to do; by default, immune */
	// e->val.attack_history &= ~(attack_type);
}

void sting_mark_vulnerable(struct ept_dict_entry *e, int attack_type)
{
	e->val.attack_history |= (attack_type << ATTACK_CHECKED_SHIFT);
	e->val.attack_history |= (attack_type << ATTACK_VULNERABLE_SHIFT);
}

int is_attackable_syscall(struct task_struct *t)
{
	struct pt_regs *ptregs = task_pt_regs(t);
	int sn = ptregs->orig_ax;
	if (in_set(sn, create_set) || in_set(sn, use_set) ||
		bind_call(sn) || connect_call(sn))
		return 1;
	return 0;
}

/* TODO: mac adversary model
 * TODO: mark whether to redirect to lower or upper branch */

static inline void task_fill_ept_key(struct ept_dict_key *k, struct task_struct *t)
{
	// k->ino = ept_inode_get(&t->user_stack);
	// k->offset = ept_offset_get(&t->user_stack);
	memcpy(&k->user_stack, &t->user_stack, sizeof(struct user_stack_info));
	#if 0
	if (t->user_stack.int_trace.nr_entries > 0) {
		strcpy(k->int_filename, int_ept_filename_get(&t->user_stack));
		k->int_lineno = int_ept_lineno_get(&t->user_stack);
	} else {
		k->int_filename[0] = 0;
		k->int_lineno = 0;
	}
	#endif
}

static inline void sting_fill_ept_key(struct ept_dict_key *k, struct sting *st)
{
	memcpy(&k->user_stack, &st->user_stack, sizeof(struct user_stack_info));
	#if 0
	k->ino = st->ino;
	k->offset = st->offset;
	if (st->int_lineno > 0) {
		strcpy(k->int_filename, st->int_filename);
		k->int_lineno = st->int_lineno;
	} else {
		k->int_filename[0] = 0;
		k->int_lineno = 0;
	}
	#endif
}

char *get_last2(char *filename)
{
	char *ptr = (char *) filename + strlen(filename);
	while ((*ptr != '/') && (ptr != filename))
		ptr--;
	if (*ptr == '/')
		ptr++;
	return ptr;
}

char *get_dpath(struct path *path, char **pathname)
{
	char *p;

	p = d_path(path, *pathname, 256);
	if (IS_ERR(p)) {
		return NULL;
	}
	return p;
}

/* TODO: move rollback into its own file */
int sting_rollback(struct sting *st)
{
	int err = 0;
	const struct cred *old_cred;
	struct path path;
	struct sting *m;

	int sn = syscall_get_nr(current, task_pt_regs(current));
	int c_res_type;

	m = sting_list_get(st, MATCH_INO, NULL);
	if (m) {
		/* there exists a pending sting with the same inode number.
		   do not rollback. */
		return 0;
	}
	c_res_type = sting_set_res_type(current, ADV_RES);

	err = kern_path(st->pathname, 0, &path);
	if (err < 0) {
		STING_ERR(0, "Error getting dentry of launched attack: [%s]\n", st->pathname);
		goto out;
	}

	if (!in_set(sn, delete_set)) {
		/* remove adversary-controlled object */
		/* set credentials to root */
		old_cred = superuser_creds();
		/* TODO: locking? */
		current->sting_request++;
		/* TODO: graceful rollback without unionfs */
		/* currently, give up if some other operation has the lock */
		if (mutex_trylock(&path.dentry->d_inode->i_mutex)) {
			/* we can lock; delete the resource */
			mutex_unlock(&path.dentry->d_inode->i_mutex);
			if (!S_ISDIR(path.dentry->d_inode->i_mode))
				err = vfs_unlink(path.dentry->d_parent->d_inode, path.dentry);
			else
				err = vfs_rmdir(path.dentry->d_parent->d_inode, path.dentry);
		} else {
			/* at least remove xattr */
			path.dentry->d_inode->i_op->removexattr(path.dentry,
					ATTACKER_XATTR_STRING);
		}

		current->sting_request--;
		revert_creds(old_cred);
		BUG_ON(current->cred != current->real_cred);
	}

	/* delete will delete by itself */
out:
	sting_set_res_type(current, c_res_type);
	return err;
}


/*
 * this function:
 * 1. launches attacks
 * 2. checks and marks immune on retries
 * 3. decides whether VFS resolution should be "benign" or "malicious" (TODO)
 */
void sting_syscall_begin(void)
{
	char *fname = NULL;
	int adv_id = INV_ADV_ID; // UID_NO_MATCH;
	struct ept_dict_entry *e = NULL, *r;
	int ntest;
	struct task_struct *t = current;
	struct nameidata nd;
	int lc = 0 /* last component? */, ctr = 0;
	int err = 0, sh_err = 0;
	struct sting *st = NULL, *m;
	struct path parent, child;
	/* int is_ls = 0; */
	char *pfname = kzalloc(256, GFP_ATOMIC);
	int sn, sn_subtype;

	sn = syscall_get_nr(current, task_pt_regs(current));
	sn_subtype = task_pt_regs(current)->bx;

#if 0
	if (t->cred->fsuid == 0)
		t->sting_res_type = ADV_NORMAL_RES;
	else if (t->cred->fsuid == 1000)
		t->sting_res_type = NORMAL_RES;
	else if (t->cred->fsuid == 1001)
		t->sting_res_type = ADV_RES;
#endif

	if (!check_valid_user_context(t))
		goto end;

	/* calls going to avc_has_perm from here
	 * should not be checked for vulnerability */
	current->sting_request++;

	/* check if nameres call */
	fname = get_syscall_fname();
	if (!fname)
		goto request;

	#if 0
	if (t->cred->fsuid == 0)
		t->sting_res_type = ADV_RES;
	else
		t->sting_res_type = NORMAL_RES;

	t->sting_res_type = NA_RES;
	#endif

	/* get adversary, scanning each binding */
	shadow_res_init(AT_FDCWD, fname, 0, &nd);
	sting_set_res_type(current, ADV_NORMAL_RES);

	while (nd.last_type == LAST_BIND || !lc) {
		lc = shadow_res_advance_name(&fname, &ctr, &nd);
		if (lc < 0) {
			/* can't recover from -ENOENT here, follow_link may
			   not have updated nd->path */
			sh_err = lc;
			/* nothing to put */
			goto request;
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
			/* skip the case when last component is a mountpoint */
			if (sh_err != -ENOENT && IS_ROOT(nd.path.dentry))
				continue;

			shadow_res_get_pc_paths(&parent, &child, &nd, sh_err);

			sting_set_res_type(current, NORMAL_RES);
			adv_id = sting_adv_model->get_adversary(parent.dentry,
					child.dentry, PERM_BIND);
			sting_set_res_type(current, ADV_NORMAL_RES);

			shadow_res_put_pc_paths(&parent, &child, sh_err);

			if (sting_adv_model->valid_adversary(adv_id)) {
		//		STING_LOG("adversary: %d for uid: %d and filename: %s\n",
		//			uid_array[adv_id][0], current->cred->fsuid, fname);
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

	/*
	 * directories have ls operation. to decide
	 * whether to show adversarial branch, we have to
	 * scan each of the files under that directory
	 * to see if any has been created by an adversary.
	 * for simplicitly, we simply show all branches
	 * unconditionally.
	 * thus, this will lead to some files possibly
	 * being displayed that should not, or having
	 * different types, but an ls -l will access
	 * the actual dentry, and then it will
	 * be revalidated to the proper branch.
	 */

#if 0
	if (child.dentry && child.dentry->d_inode &&
			S_ISDIR(child.dentry->d_inode->i_mode)) {
		if (sn == __NR_openat || sn == __NR_open) {
			is_ls = 1;
			goto parent_put;
		}
	}
#endif
	if (!is_attackable_syscall(t))
		goto parent_put;

	if (!sting_adv_model->valid_adversary(adv_id))
		goto parent_put;

	/* get entrypoint */
	user_unwind(t);
	if (!valid_user_stack(&t->user_stack))
		goto parent_put;  /* change to put if moving below! */

	if (frame_ignore(&t->user_stack))
		goto parent_put;

	user_interpreter_unwind(&t->user_stack);

	/* TODO: ignore open[at]() on directories, because they involve
	 * deletion of directories that may upset the upper branch
	 * hierarchy in unionfs. Real way to deal with this: fix the unionfs
	 * bugs we have, or, mark all upper branch directories as attacker
	 * marked. ls causes open[at]() on directories. */
	/* get ept dictionary record, initializing a new one if needed */

	e = kzalloc(sizeof(struct ept_dict_entry), GFP_KERNEL);
	if (!e)
		goto parent_put;

	task_fill_ept_key(&e->key, t);
	r = ept_dict_lookup(&e->key);

	if (r) {
		/* update ept dictionary */
		/* TODO: protect modification (also see dict.c) */
		r->val.ctr++;
	} else if (!r) {
		/* insert into ept dictionary */
		rdtscl(e->val.time);
		e->val.ctr = 1;
		strncpy(e->val.comm, current->comm, MAX_PROC_NAME);
		e->val.dac.adversary_access = 0;
		e->val.dac.ctr_first_adv = 0;
		e->val.attack_history = 0;
		r = ept_dict_entry_set(&e->key, &e->val);
	}
	if ((!r->val.dac.adversary_access) &&
			sting_adv_model->valid_adversary(adv_id)) {
		r->val.dac.ctr_first_adv = r->val.ctr;
		r->val.dac.adversary_access = 1;
	}

	/*
	STING_LOG("[%s,%lx,%s,%lu,%s/%s,%d]\n", current->comm, r->key.offset,
			r->key.int_filename ? r->key.int_filename : "(null)", r->key.int_lineno,
			get_dpath(&parent, &pfname), get_last2(fname), r->val.dac.adversary_access);
	*/

	st = kmem_cache_alloc(sting_cachep, GFP_KERNEL);
	if (!st)
		goto e_free;

	/* check if inode has been used for another test case */
	if (child.dentry != NULL) {
		err = sting_already_launched(child.dentry);
		if (err < 0)
			goto st_free;

		/* if so, add that test case to current ept. no need to
		 * launch attack */
		if (err) {
			/* already in use for another attack. add current
			 * entrypoint to same attack if adversary.
			 * TODO: if not, mark as redirect to lower branch.  */
			st->path = child;
			m = sting_list_get(st, MATCH_INO, NULL);
			if (!m) {
				/* STING_ERR(1, "no attack in list although
				 * marked: [%s]\n", fname); */
				goto st_free;
			}
			/* if the attack was launched elsewhere, it means a new
			 * cross-entrypoint path is exercised, so it does not matter if
			 * we are immune to the same attack type _launched_ at our ept */
			if (r && sting_attack_checked(r->val.attack_history, m->attack_type)) {
				STING_DBG("new adversarial path\n");
			}
			if (!sting_adv_model->is_adversary(m->adv_id, current->cred)) {
				STING_DBG("another non-adversarial attack ongoing: [%s]\n", fname);
				goto st_free;
			}

			memcpy(st, m, sizeof(struct sting));
			st->syscall_nr = sn;
			st->syscall_nr_subtype = sn_subtype;
			task_fill_sting(st, t, launch_from_script(t));
			sting_list_add(st);
			goto st_free;
		}
	}

	/* mark immune on retry; don't launch attack */
	task_fill_sting(st, t, launch_from_script(t));
	m = sting_list_get(st, MATCH_PID | MATCH_EPT, NULL);
	if (m) {
		STING_LOG_STING_DETAILS(m, "retry immunity");
		sting_mark_immune(r, m->attack_type);
		memcpy(st, m, sizeof(struct sting));
		sting_list_del(m);
		/* after sting_list_del so we will not find ourselves on the list-> */
		sting_rollback(st);
		goto st_free;
	}

	/* get next attack */
	ntest = sting_get_next_attack(r->val.attack_history);
	if (ntest == -1) {
		/* all attacks tried */
		goto st_free;
	}

	/* check attack-specific conditions */
	err = sting_check_attack_specific(parent.dentry, ntest);
	if (err < 0) {
		err = 0;
		sting_mark_immune(r, ntest);
		goto st_free;
	}

	err = sting_launch_attack(shadow_res_get_last_name(&nd, &child),
			&parent, adv_id, ntest, st);

	if (err < 0)
		goto st_free;

	/* other fields already filled in */
	st->attack_type = ntest;
	st->syscall_nr = sn;
	st->syscall_nr_subtype = sn_subtype;

	st->adv_model = sting_adv_model;
	st->adv_id = adv_id;
	st->victim = sting_adv_model->get_sid(t->cred);

	strcpy(st->pathname, get_dpath(&parent, &pfname));
	strcat(st->pathname, "/");
	strcat(st->pathname, get_last2(fname));
	sting_list_add(st);

	/* sting_list_add got references, put ours */
	path_put(&st->path);
	if (st->target_path.dentry)
		path_put(&st->target_path);

st_free:
	kmem_cache_free(sting_cachep, st);
e_free:
	kfree(e);
parent_put:
	shadow_res_put_pc_paths(&parent, &child, sh_err);
put:
	if (sh_err < 0)
		STING_DBG("sting: resolution error: fname: %s [ %d ]\n", fname, sh_err);
	if (!nd.path.dentry->d_count)
		printk(KERN_INFO STING_MSG "d_count 0!\n");
	/* we have to hold reference to nd until the end */
	shadow_res_put_lookup_path(&nd);
request:
	current->sting_request--;
end:
	if (pfname)
		kfree(pfname);
	if (fname)
		putname(fname);
	/* determine unionfs branch visibility for real resolution */
	/* we should ideally fold this into the lookup itself */
	if (sting_adv_model->valid_adversary(adv_id)) {
		/* possible adversarial interference - show adversarial
		 * resource if one exists along path. */
		sting_set_res_type(current, ADV_NORMAL_RES);
	} else {
		/* no adversarial interference - do not show adversarial
		 * resource (and none should exist) */
		sting_set_res_type(current, NORMAL_RES);
	}

	if (t->cred->fsuid == 1001) {
		/* HACK */
		sting_set_res_type(current, ADV_RES);
	} else if (t->cred->fsuid == 1000) {
		/* HACK */
		sting_set_res_type(current, NORMAL_RES);
	}

//	if (is_ls)
//		sting_set_res_type(current, ADV_NORMAL_RES);

	return;
}
EXPORT_SYMBOL(sting_syscall_begin);

void sting_process_exit(void)
{
	struct sting *st = NULL, *m = NULL;
	struct ept_dict_entry *e, *r;
	struct sting *st_cp; /* copy of sting */

	if (!check_valid_user_context(current))
		return;

	st_cp = kmem_cache_alloc(sting_cachep, GFP_KERNEL);
	if (!st_cp)
		return;

	user_unwind(current);
	if (valid_user_stack(&current->user_stack))
		user_interpreter_unwind(&current->user_stack);

	st = kmem_cache_alloc(sting_cachep, GFP_KERNEL);
	if (!st)
		goto free_st_cp;

	/* st, e are dynamically allocated. make them and fix code */
	e = kzalloc(sizeof(struct ept_dict_entry), GFP_KERNEL);
	if (!e)
		goto free_st;

	task_fill_sting(st, current, 0);

	/* find and delete all corresponding stings and mark immune */
	while (1) {
		m = sting_list_get(st, MATCH_PID, m);
		if (!m)
			break;

		if (!m->adv_model->is_adversary(m->adv_id, current->cred)) {
			STING_DBG("another non-adversarial attack ongoing: [%s]\n", m->pathname);
			continue;
		}

		/* delete sting from list */
		STING_LOG_STING_DETAILS(m, "exit immunity");
		sting_fill_ept_key(&e->key, m);
		r = ept_dict_lookup(&e->key);
		sting_mark_immune(r, m->attack_type);
		memcpy(st_cp, m, sizeof(struct sting));
		sting_list_del(m);
		/* after sting_list_del so we will not find ourselves on the list. */
		sting_rollback(st_cp);
	}

	kfree(e);
free_st:
	kmem_cache_free(sting_cachep, st);
free_st_cp:
	kmem_cache_free(sting_cachep, st_cp);

	return;
}
EXPORT_SYMBOL(sting_process_exit);

struct dentry *dentry_from_auditdata(struct common_audit_data *a, char *path)
{
	struct dentry *dentry = NULL;
	struct inode *inode = NULL;

	strcpy(path, "N/A");
	//  path = kstrdup("N/A", GFP_ATOMIC);
	if (a) {
		switch (a->type) {
		case LSM_AUDIT_DATA_DENTRY: {
			dentry = a->u.dentry;
			inode = a->u.dentry->d_inode;
			break;
		}
		case LSM_AUDIT_DATA_INODE: {
			inode = a->u.inode;
			dentry = d_find_alias(inode);
			break;
		}
		case LSM_AUDIT_DATA_PATH: {
			inode = a->u.path.dentry->d_inode;
			dentry = d_find_alias(inode);
			break;
		}
		default:
		;
		}
	}
	if (dentry) {
		strcpy(path, dentry->d_name.name);
	}

	return dentry;
}

/* TODO: move detection to separate file */
static inline int is_accept_call(int sn, int attack_type)
{
	switch (attack_type) {
	case SYMLINK:
		if (in_set(sn, create_set) ||
				in_set(sn, symlink_accept_set))
			return true;
		break;
	case HARDLINK:
		if (in_set(sn, hardlink_accept_set))
			return true;
		break;
	case SQUAT:
		/* TODO: differentiate between creating in squatted
		 * directories and creating on the squatted file
		 * using LSM permissions */
		if (in_set(sn, squat_accept_set))
			return true;
		break;
	}

	return false;
}

static inline int is_reject_call(int sn, int attack_type)
{
	if (in_set(sn, delete_set))
		return true;
	if (attack_type == SQUAT) {
		/* TODO: check chown argument; if same as current uid,
		 * then reject */
		if (sn == __NR_chown ||
			sn == __NR_fchownat ||
			sn == __NR_lchown32)
			return true;
	}

	return false;
}

void sting_log_vulnerable_access(struct common_audit_data *a)
{
	int sn = syscall_get_nr(current, task_pt_regs(current));
	char *path = NULL;
	struct dentry *d = NULL;
	struct sting *m = NULL, *st_cp = NULL, *st = NULL;
	struct ept_dict_entry *e = NULL, *r;
	int i = 0;

	if (!check_valid_user_context(current))
		return;

	if (!a)
		return;

	path = __getname_gfp(GFP_ATOMIC);
	if (!path)
		goto end;

	d = dentry_from_auditdata(a, path);

	if (d && sting_already_launched(d)) {
		st = kmem_cache_alloc(sting_cachep, GFP_KERNEL);
		if (!st)
			goto put_path;

		st_cp = kmem_cache_alloc(sting_cachep, GFP_KERNEL);
		if (!st_cp)
			goto free_st;

		e = kzalloc(sizeof(struct ept_dict_entry), GFP_KERNEL);
		if (!e)
			goto free_st_cp;

		user_unwind(current);
		if (valid_user_stack(&current->user_stack))
			user_interpreter_unwind(&current->user_stack);

		st->path_ino = d->d_inode->i_ino;

		task_fill_sting(st, current, launch_from_script(current));
		/* find and delete all corresponding stings and mark vulnerable */
		while (1) {
			m = sting_list_get(st, MATCH_INO | MATCH_PID, m);
			if (!m) {
				if (!i)
					STING_LOG("message: no ongoing attack in sting_list "
						   	  "although resource already tainted, "
							  "resource: [%s]\n", d->d_name.name);
				break;
			}

			i++;
			if (!m->adv_model->is_adversary(m->adv_id, current->cred)) {
				STING_DBG("another non-adversarial attack ongoing: [%s]\n", d->d_name.name);
				goto done;
			}

			/* delete sting from list */
			if (is_reject_call(sn, m->attack_type)) {
				STING_LOG_STING_DETAILS(m, "reject immunity");
				sting_fill_ept_key(&e->key, m);
				r = ept_dict_lookup(&e->key);
				sting_mark_immune(r, m->attack_type);
			} else if (is_accept_call(sn, m->attack_type)) {
				STING_LOG_STING_DETAILS(m, "vulnerable name resolution");
				sting_fill_ept_key(&e->key, m);
				r = ept_dict_lookup(&e->key);
				sting_mark_vulnerable(r, m->attack_type);
			} else {
				/* neither immune nor vulnerable */
				continue;
			}

			memcpy(st_cp, m, sizeof(struct sting));
			sting_list_del(m);
			/* after sting_list_del so rollback will not find ourselves on the list. */
			sting_rollback(st_cp);
		}
	}
done:
	if (d) {
		if (a->type == LSM_AUDIT_DATA_PATH ||
		    a->type == LSM_AUDIT_DATA_INODE)
		    dput(d);
	}

	if (e)
		kfree(e);
free_st_cp:
	if (st_cp)
		kmem_cache_free(sting_cachep, st_cp);
free_st:
	if (st)
		kmem_cache_free(sting_cachep, st);
put_path:
	__putname(path);
end:
	return;
}
EXPORT_SYMBOL(sting_log_vulnerable_access);

/* called from execve */
void sting_lwd(void)
{
	struct task_struct *t = current;
	if (!check_valid_user_context(t))
		return;

	/* do not affect programs launched from scripts, which might
	 * have set their own working directory through cd.  */
	if (int_ept_exists(&t->user_stack) && !is_interpreter(t)) {
		return;
	}

	chdir_task(current, ATTACKER_HOMEDIR);
}
