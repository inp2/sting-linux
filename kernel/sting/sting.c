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
#include <linux/sort.h>

#include <asm-generic/current.h>
// #include <asm/msr.h>

#include "ept_dict.h"
#include "permission.h"
#include "syscalls.h"
#include "launch_attack.h"
#include "utility.h"
#include "shadow_resolution.h"
#include "interpreter_unwind.h"

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

/* file /sys/kernel/debug/utility_progs */

#define MAX_UTIL_PROGS 32
static int n_utility_progs = 0;
static ino_t utility_progs[MAX_UTIL_PROGS];

static int up_find(ino_t ino)
{
	int low = 0;
	int high = n_utility_progs;
	int mid;

	while (low < high) {
		mid = (low + high) / 2;
		if (utility_progs[mid] == ino)
			return 1;
		else if (utility_progs[mid] > ino)
			high = mid;
		else
			low = mid + 1;
	}
	return 0;
}

static int up_cmp(const void *ap, const void *bp)
{
	const ino_t a = *(const ino_t *) ap;
	const ino_t b = *(const ino_t *) bp;

	if (a > b)
		return 1;
	if (a < b)
		return -1;
	return 0;
}

/* example: 26484420 */
static int up_line_load(char *data)
{
	utility_progs[n_utility_progs] =
		simple_strtoul(data, NULL, 0);
	if (!utility_progs[n_utility_progs])
		return -EINVAL;
	n_utility_progs++;

	return 0;
}

static int up_load(char *data, size_t len)
{
	char **r = &data;
	char *l = NULL;
	int ret = 0;

	/* null terminate */
	*(data + len - 1) = 0;

	/* separate into tokens */
	while ((l = strsep(r, "\n"))) {
		/* parse each line */
		ret = up_line_load(l);
	}

	return (ret == 0) ? len : ret;
}

static ssize_t
utility_progs_write(struct file *filp, const char __user *buf,
				   size_t count, loff_t *ppos)
{
	char *page;
	ssize_t length;

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
	length = up_load(page, count);

	if (length >= 0)
		sort(utility_progs, n_utility_progs, sizeof(ino_t), up_cmp, NULL);

out:
	free_page((unsigned long) page);
	return length;
}

static const struct file_operations utility_progs_fops = {
	.write  = utility_progs_write,
};

static int __init utility_progs_init(void)
{
	struct dentry *utility_progs;

	utility_progs = debugfs_create_file("utility_progs",
			0600, NULL, NULL, &utility_progs_fops);
	printk(KERN_INFO STING_MSG "creating utility_progs file\n");

	if(!utility_progs) {
		printk(KERN_INFO STING_MSG "unable to create utility_progs\n");
	}
	return 0;
}
fs_initcall(utility_progs_init);

/* list of ongoing attacks (status and rollback information).
 * Since the number of attacks is small, a list suffices.
 * TODO: If we find scenarios where performance is hit because
 * of this list, change.  */

/* we have a simple list instead of a hash as the number of
 * current stings is small */

static struct sting sting_list;
static struct rw_semaphore stings_rwlock;

void sting_list_add(struct sting *st)
{
	struct sting *news = kmalloc(sizeof(struct sting), GFP_KERNEL);
	if (!news)
		return;
	memcpy(news, st, sizeof(struct sting));
	STING_LOG("added [%s:%lx:%s:%lu] accessing [%s] to sting_list for "
			"adversary [%d] and victim [%d]\n",
			current->comm, news->offset,
			news->int_filename, news->int_lineno,
			news->path.dentry->d_name.name,
			uid_array[news->adv_uid_ind][0], current->cred->fsuid
			);
	down_write(&stings_rwlock);
	path_get(&news->path);
	list_add_tail(&news->list, &sting_list.list);
	up_write(&stings_rwlock);
}

void sting_list_del(struct sting *st)
{
	STING_LOG("deleted [%s:%lx:%s:%lu] accessing [%s] to sting_list for "
			"adversary [%d] and victim [%d]\n",
			current->comm, st->offset,
			st->int_filename, st->int_lineno,
			st->path.dentry->d_name.name,
			uid_array[st->adv_uid_ind][0], current->cred->fsuid);
	path_put(&st->path);
	down_write(&stings_rwlock);
	list_del(&st->list);
	up_write(&stings_rwlock);
}

struct sting *sting_list_get(struct sting *st, int st_flags)
{
	struct sting *t, *n;
	down_read(&stings_rwlock);
	list_for_each_entry_safe(t, n, &sting_list.list, list) {
		if ((st_flags & MATCH_PID) && (t->pid != st->pid))
			continue;
		if ((st_flags & MATCH_EPT) &&
				(((t->ino != st->ino) || (t->offset != st->offset)) ||
				(strcmp(t->int_filename, st->int_filename)) ||
				(t->int_lineno != st->int_lineno)))
			continue;
		if ((st_flags & MATCH_DENTRY) && (t->path.dentry != st->path.dentry))
			continue;

		/* match */
		up_read(&stings_rwlock);
		return t;
	}

	/* no match */
	up_read(&stings_rwlock);
	return NULL;
}

void task_fill_sting(struct sting *st, struct task_struct *t, int sting_parent)
{
	if (sting_parent)
		st->pid = t->parent->pid;
	else
		st->pid = t->pid;
	st->offset = ept_offset_get(&t->user_stack);
	st->ino = ept_inode_get(&t->user_stack);

	/* parent's interpreter context is stored in child during fork,
	 * if child itself is not an interpreter */
	if (int_ept_exists(&t->user_stack))
		strcpy(st->int_filename, int_ept_filename_get(&t->user_stack));
	st->int_lineno = int_ept_lineno_get(&t->user_stack);
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
	init_rwsem(&stings_rwlock);
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
	/* not dealing with init because it exits last and we cannot save
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
	e->val.attack_history |= attack_type << 8;
	e->val.attack_history &= ~(attack_type);
	STING_LOG("marked immune [%s:%lx]\n",
			current->comm, e->key.offset);
}

void sting_mark_vulnerable(struct ept_dict_val *v, int attack_type)
{
	v->attack_history |= attack_type << 8;
	v->attack_history |= attack_type;
}

static int is_attackable_syscall(struct task_struct *t)
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
	k->ino = ept_inode_get(&t->user_stack);
	k->offset = ept_offset_get(&t->user_stack);
	if (t->user_stack.int_trace.nr_entries > 0) {
		strcpy(k->int_filename, int_ept_filename_get(&t->user_stack));
		k->int_lineno = int_ept_lineno_get(&t->user_stack);
	} else {
		k->int_filename[0] = 0;
		k->int_lineno = 0;
	}
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

/*
 * this function:
 * 1. launches attacks
 * 2. checks and marks immune on retries
 * 3. decides whether VFS resolution should be "benign" or "malicious" (TODO)
 */
void sting_syscall_begin(void)
{
	char *fname = NULL;
	int adv_uid_ind = UID_NO_MATCH;
	struct ept_dict_entry e, *r;
	int ntest;
	struct task_struct *t = current;
	struct nameidata nd;
	int lc = 0 /* last component? */, ctr = 0;
	int err = 0, sh_err = 0;
	struct sting st, *m;
	struct path parent, child, marked;

	char *pfname = kzalloc(256, GFP_ATOMIC);

	/* should sting be associated with this process (normal),
	 * or parent (utility programs)? */
	int sting_parent = 0;

	if (!check_valid_user_context(t))
		goto end;

	/* check if nameres call */
	fname = get_syscall_fname();
	if (!fname)
		goto end;

	if (!is_attackable_syscall(t))
		goto end;

	if (t->cred->fsuid == 0)
		t->sting_res_type = ADV_RES;
	else
		t->sting_res_type = NORMAL_RES;

	t->sting_res_type = NA_RES;
	goto end;

	/* XXX: below flow logs every entrypoint, not just adversary-accessible
	   ones. rearrange if performance is needed */
	/* get entrypoint */
	user_unwind(t);
	if (!valid_user_stack(&t->user_stack))
		goto end;  /* change to put if moving below! */
	user_interpreter_unwind(&t->user_stack);

	/*
	if (up_find(EPT_INO(t))) {
		sting_parent = 1;
		printk(KERN_INFO STING_MSG "[%s]: up found!\n", current->comm);
	}
	*/

	/* get adversary, scanning each binding */
	shadow_res_init(AT_FDCWD, fname, 0, &nd);

	while (nd.last_type == LAST_BIND || !lc) {
		lc = shadow_res_advance_name(&fname, &ctr, &nd);
		if (lc < 0) {
			/* can't recover from -ENOENT here, follow_link may
			   not have updated nd->path */
			sh_err = lc;
			/* nothing to put */
			goto end;
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
		//		STING_LOG("adversary: %d for uid: %d and filename: %s\n",
		//			uid_array[adv_uid_ind][0], current->cred->fsuid, fname);
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

	task_fill_ept_key(&e.key, t);
	r = ept_dict_lookup(&e.key);

	if (r) {
		/* update ept dictionary */
		/* TODO: protect modification (also see dict.c) */
		r->val.ctr++;
	} else if (!r) {
		/* insert into ept dictionary */
		rdtscl(e.val.time);
		e.val.ctr = 1;
		strncpy(e.val.comm, current->comm, MAX_PROC_NAME);
		e.val.dac.adversary_access = 0;
		e.val.dac.ctr_first_adv = 0;
		e.val.attack_history = 0;
		r = ept_dict_entry_set(&e.key, &e.val);
	}
	if ((!r->val.dac.adversary_access) &&
			sting_valid_adversary(adv_uid_ind)) {
		r->val.dac.ctr_first_adv = r->val.ctr;
		r->val.dac.adversary_access = 1;
	}

	// STING_LOG("[%s,%lx,%s/%s,%d]\n", current->comm, r->key.offset, get_dpath(&parent, &pfname), get_last2(fname), r->val.dac.adversary_access);

	/* there is no use marking utility program entrypoints as immune;
	 * they have to be tested anyway if the parent shell's entrypoint
	 * is not immune, as what matters is the context within the script */

	if (!sting_valid_adversary(adv_uid_ind)) {
		/* exit - raise this check above if performance needed */
		goto parent_put;
	}

	// goto parent_put;
	/* TODO: parent interpreter exits */
	if (is_interpreter(t->parent) && !is_interpreter(t))
		sting_parent = 1;

	/* check if dentry has been used for another test case */
	if (child.dentry != NULL) {
		err = sting_already_launched(child.dentry);
		if (err < 0)
			goto parent_put;

		/* if so, add that test case to current ept. no need to
		 * launch attack */
		if (err) {
			/* already in use for another attack. add current
			 * entrypoint to same attack if adversary.
			 * TODO: if not, mark as redirect to lower branch.  */
			st.path = child;
			m = sting_list_get(&st, MATCH_DENTRY);
			if (!m) {
				printk(KERN_INFO STING_MSG
						"no attack in list although marked: [%s]\n", fname);
				goto parent_put;
			}
			/* if the attack was launched elsewhere, it means a new
			 * cross-entrypoint path is exercised, so it does not matter if
			 * we are immune to the same attack type _launched_ at our ept */
			if (r && sting_attack_checked(r->val.attack_history, m->attack_type)) {
				printk(KERN_INFO STING_MSG "new adversarial path\n");
			}
			if (!sting_adversary(uid_array[m->adv_uid_ind][0], t->cred->fsuid)) {
				printk(KERN_INFO STING_MSG
						"another non-adversarial attack ongoing: [%s]\n", fname);
				goto parent_put;
			}

			memcpy(&st, m, sizeof(struct sting));
			task_fill_sting(&st, t, sting_parent);
			sting_list_add(&st);
			goto parent_put;
		}
	}

	/* mark immune on retry; don't launch attack */
	task_fill_sting(&st, t, sting_parent);
	m = sting_list_get(&st, MATCH_PID | MATCH_EPT);
	if (m) {
		/* when rolling back, make sure that the file is still labeled by attacker.
		 * it might have been removed by the prog, we don't want to delete that.  */
		/* delete only if the dentry refcount reaches 1 */
		// sting_rollback(m->dentry);
		STING_LOG("[%s:%lx] retry immunity\n", t->comm, m->offset);
		sting_mark_immune(r, m->attack_type);
		sting_list_del(m);
		goto parent_put;
	}

	/* get next attack */
	ntest = sting_get_next_attack(r->val.attack_history);
	if (ntest == -1) {
		/* all attacks tried */
		goto parent_put;
	}

	err = sting_launch_attack(shadow_res_get_last_name(&nd, &child),
			&parent, adv_uid_ind, ntest, &marked);
	if (err < 0)
		goto parent_put;

	st.pid = t->pid;
	st.ino = ept_inode_get(&t->user_stack);
	st.offset = ept_offset_get(&t->user_stack);
	st.path = marked;
	st.attack_type = ntest;
	st.adv_uid_ind = adv_uid_ind;

	sting_list_add(&st);
	path_put(&marked);

parent_put:
	shadow_res_put_pc_paths(&parent, &child, sh_err);
put:
	if (sh_err < 0)
		STING_DBG("sting: resolution error: fname: %s [ %d ]\n", fname, sh_err);
	if (!nd.path.dentry->d_count)
		printk(KERN_INFO STING_MSG "d_count 0!\n");
	shadow_res_put_lookup_path(&nd);
end:
	/* we have to hold reference to nd until the end */
	if (pfname)
		kfree(pfname);
	if (fname)
		putname(fname);
	return;
}
EXPORT_SYMBOL(sting_syscall_begin);

void sting_process_exit(void)
{
	/* mark pending sting entrypoints as immune */
	struct sting st, *m = NULL;
	struct ept_dict_entry e, *r;

	st.pid = current->pid;

	m = sting_list_get(&st, MATCH_PID);
	while (m) {
		e.key.ino = m->ino;
		e.key.offset = m->offset;

		r = ept_dict_lookup(&e.key);
		if (!r) {
			printk(KERN_INFO STING_MSG "pending sting [%lx:%lx] not in ept_dict!\n",
					e.key.ino, e.key.offset);
			goto out;
		}
		/* when rolling back, make sure that the file is still labeled by attacker.
		 * it might have been removed by the prog, we don't want to delete that.  */
		/* delete only if the dentry refcount reaches 1 */
		// sting_rollback(m->dentry);
		STING_LOG("[%s:%lx] exit immunity\n", r->val.comm, m->offset);
		sting_mark_immune(r, m->attack_type);
		sting_list_del(m);

		/* get next sting */
		m = sting_list_get(&st, MATCH_PID);
	}

out:
	return;
}
EXPORT_SYMBOL(sting_process_exit);
