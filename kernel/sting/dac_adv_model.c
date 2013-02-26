/*
 * Copyright (c) 2011-2012 Hayawardh Vijayakumar
 * Copyright (c) 2011-2012 Systems and Internet Infrastructure Security Lab
 * Copyright (c) 2011-2012 The Pennsylvania State University
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/stop_machine.h>
#include <linux/clocksource.h>
#include <linux/kallsyms.h>
#include <linux/seq_file.h>
#include <linux/debugfs.h>
#include <linux/sting.h>
#include <linux/hardirq.h>
#include <linux/module.h>
#include <linux/sysctl.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/rcupdate.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/cred.h>
#include <linux/namei.h>

#include <asm/syscall.h>

#include "syscalls.h"
#include "permission.h"

#define DAC_SUPERUSER_ID 0

uid_t sting_adversary_uid = -1;

/* TODO: Check below constants */
/* uid_array[x][0] is the UID, [x][1 .. ] are the GID of groups */
uid_t uid_array[MAX_USERS][GRP_MEMB_MAX];

EXPORT_SYMBOL(uid_array);
static DEFINE_MUTEX(node_lock);

/* file /sys/kernel/debug/uids to get uids from
 *	/etc/passwd and groups from /etc/group */

static ssize_t
uids_read(struct file *file, char __user *ubuf,
		size_t cnt, loff_t *ppos)
{
	char *buf = NULL; /* Allocate a single page for the buf */
	int i, ret;
	if (!(buf = (char*) get_zeroed_page(GFP_KERNEL))) {
		ret = -ENOMEM;
		goto out;
	}
	for (i = 0; uid_array[i]; i++)
		printk(KERN_INFO STING_MSG "uid: %d\n", uid_array[i][0]);
	strcpy(buf, "See printk buffer\n");
	ret = simple_read_from_buffer(ubuf, cnt, ppos, buf, strlen(buf) + 1);
out:
	if (buf)
		free_page((unsigned long) buf);
	return ret;
}

static ssize_t
uids_write(struct file *filp, const char __user *ubuf,
	size_t cnt, loff_t *ppos)
{
	ssize_t length;
	void *data = NULL;
	int i = 1, j = 0;
	char *runner = NULL;
	char *token = NULL;
	char *p = NULL;
	mutex_lock(&node_lock);

	if (*ppos != 0) {
		/* No partial writes. */
		length = -EINVAL;
		goto out;
	}

	if ((cnt > 64 * 1024 * 1024)
		|| (data = vmalloc(cnt)) == NULL) {
		length = -ENOMEM;
		goto out;
	}

	if ((length = copy_from_user(data, ubuf, cnt)) != 0)
		goto out;
	runner = data;

	uid_array[0][0] = uid_array[0][1] = DAC_SUPERUSER_ID;

	while ((token = strsep(&runner, "\n")) && (i < MAX_USERS)) {
		j = 0;
		if (!strcmp(token, ""))
			break;
		while ((p = strsep(&token, " ")) && (j < GRP_MEMB_MAX))
			uid_array[i][j++] = simple_strtoul(p, NULL, 10);
		i++;
	}

out:
	mutex_unlock(&node_lock);
	vfree(data);
	return cnt;
}

static const struct file_operations uids_fops = {
       .write  = uids_write,
       .read   = uids_read,
};

/*
 *	file /sys/kernel/debug/adversary_uid to get uid of
 *	adversary user
 */

static ssize_t
sting_adversary_uid_read(struct file *file, char __user *ubuf,
                       size_t count, loff_t *ppos)
{
    /* TODO: 12??? */
    char tmpbuf[12];
    ssize_t length;

    length = scnprintf(tmpbuf, 12, "%d\n", sting_adversary_uid);
    return simple_read_from_buffer(ubuf, count, ppos, tmpbuf, length);
}

static ssize_t
sting_adversary_uid_write(struct file *filp, const char __user *buf,
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

    sting_adversary_uid = new_value;
    length = count;
out:
    free_page((unsigned long) page);
    return length;
}

static const struct file_operations sting_adversary_uid_fops = {
       .write  = sting_adversary_uid_write,
       .read   = sting_adversary_uid_read,
};

int dac_print_adv(int adv_id)
{
	return uid_array[adv_id][0];
}

int dac_print_victim(int victim)
{
	return victim;
}

int dac_get_sid(const struct cred *c)
{
	return c->fsuid;
}

int dac_sid_to_id(int sid)
{
	int i = 0;
	for (i = 0; uid_array[i][0]; i++)
		if (uid_array[i][0] == sid)
			return i;
	return INV_ADV_ID;
}

/* fill a group_info from a user-space array - it must be allocated already
   - kernel version using memcpy instead of copy_from_user */
static int groups_from_list(struct group_info *group_info,
    gid_t __user *grouplist)
{
	int i;
	unsigned int count = group_info->ngroups;

	for (i = 0; i < group_info->nblocks; i++) {
		unsigned int cp_count = min(NGROUPS_PER_BLOCK, count);
		unsigned int len = cp_count * sizeof(*grouplist);

		memcpy(group_info->blocks[i], grouplist, len);

		grouplist += NGROUPS_PER_BLOCK;
		count -= cp_count;
	}
	return 0;
}

/* a simple Shell sort - have to duplicate here because kernel/groups.c is
   static */
static void groups_sort(struct group_info *group_info)
{
	int base, max, stride;
	int gidsetsize = group_info->ngroups;

	for (stride = 1; stride < gidsetsize; stride = 3 * stride + 1)
		; /* nothing */
	stride /= 3;

	while (stride) {
		max = gidsetsize - stride;
		for (base = 0; base < max; base++) {
			int left = base;
			int right = left + stride;
			gid_t tmp = GROUP_AT(group_info, right);

			while (left >= 0 && GROUP_AT(group_info, left) > tmp) {
				GROUP_AT(group_info, right) =
				    GROUP_AT(group_info, left);
				right = left;
				left -= stride;
			}
			GROUP_AT(group_info, right) = tmp;
		}
		stride /= 3;
	}
}

void dac_superuser_creds(struct cred *override_cred)
{
	override_cred->uid = override_cred->gid = DAC_SUPERUSER_ID;
	override_cred->euid = override_cred->egid = DAC_SUPERUSER_ID;
	override_cred->fsuid = override_cred->fsgid = DAC_SUPERUSER_ID;
	override_cred->suid = override_cred->sgid = DAC_SUPERUSER_ID;

	cap_raise(override_cred->cap_effective, CAP_SYS_ADMIN);
	cap_raise(override_cred->cap_effective, CAP_DAC_READ_SEARCH);
	cap_raise(override_cred->cap_effective, CAP_DAC_OVERRIDE);
	cap_raise(override_cred->cap_effective, CAP_FOWNER);

	return;
}

/**
 * dac_set_creds() - Change the credentials of current process temporarily
 * @adv_id:		ID of adversary to change credentials to
 * @ret:		Returns the old credentials
 *
 * Set process' credentials to attacker's
 * to see if she can do anything.
 * See nfsd_setuser() in fs/nfsd/auth.c for reference
 */

const struct cred *dac_set_creds(int adv_id)
{
	struct group_info *gi = NULL;
	struct cred *override_cred = NULL;
	const struct cred *old_cred;
	int ret = 0, size = 0, i;

	uid_t *ug_list;

	ug_list = uid_array[adv_id];

	override_cred = prepare_creds();
	if (!override_cred) {
		ret = -ENOMEM;
		goto out;
	}

	/* Calculate size of supplementary group list */
	for (i = 2; ug_list[i]; i++)
		size++;

	/* Set fsuid, fsgid */
	override_cred->fsuid = ug_list[0];
	override_cred->fsgid = (gid_t) ug_list[1];

	/* Set (clear) capabilities */
	cap_clear(override_cred->cap_effective);

	/* Set supplementary groups */
	gi = groups_alloc(size);
	if (!gi) {
		ret = -ENOMEM;
		goto out;
	}
	if (size > 0) {
		ret = groups_from_list(gi, (gid_t *) &ug_list[2]);
		if (ret < 0) {
			printk(KERN_INFO "attacker: groups failed!\n");
			if (gi)
				put_group_info(gi);
			goto out;
		}
		groups_sort(gi);
	}
	ret = set_groups(override_cred, gi);
	if (ret < 0)
		goto out;

	/* Alloc and set_group_info would have ++'ed group_info usage,
	   we don't need our reference (alloc) any more, so when next
	   put_group_info comes along, it will be kfree'd */
	put_group_info(gi);
//	(*override_cred)->group_info = *group_info;

	/* Finally, exchange creds */
	old_cred = override_creds(override_cred);
	put_cred(override_cred);

out:
	return (ret < 0) ? (const struct cred *) ERR_PTR(ret) : old_cred;
}

static inline int check_sticky(struct inode *dir, struct inode *inode)
{
	uid_t fsuid = current_fsuid();

	if (!(dir->i_mode & S_ISVTX))
		return 0;
	if (inode->i_uid == fsuid)
		return 0;
	if (dir->i_uid == fsuid)
		return 0;
	return !capable(CAP_FOWNER);
}

int may_create_noexist(struct inode *dir)
{
	if (IS_DEADDIR(dir))
		return -ENOENT;
	return inode_permission(dir, MAY_WRITE | MAY_EXEC);
}
EXPORT_SYMBOL(may_create_noexist);

static int may_delete(struct inode *dir,struct dentry *victim,int isdir)
{
	int error;

	if (!victim->d_inode)
		return -ENOENT;

	BUG_ON(victim->d_parent->d_inode != dir);

	error = inode_permission(dir, MAY_WRITE | MAY_EXEC);
	if (error)
		return error;
	if (IS_APPEND(dir))
		return -EPERM;
	if (check_sticky(dir, victim->d_inode)||IS_APPEND(victim->d_inode)||
	    IS_IMMUTABLE(victim->d_inode) || IS_SWAPFILE(victim->d_inode))
		return -EPERM;
	if (isdir) {
		if (!S_ISDIR(victim->d_inode->i_mode))
			return -ENOTDIR;
		if (IS_ROOT(victim))
			return -EBUSY;
	} else if (S_ISDIR(victim->d_inode->i_mode))
		return -EISDIR;
	if (IS_DEADDIR(dir))
		return -ENOENT;
	if (victim->d_flags & DCACHE_NFSFS_RENAMED)
		return -EBUSY;
	return 0;
}

int dac_valid_adversary(int adv_uid_ind)
{
	return (adv_uid_ind != INV_ADV_ID);
}

/* simple dac adversary */
int dac_adversary(int adv_id, const struct cred *vctm)
{
	/* adversary is not root and not victim */
	uid_t v = vctm->fsuid;
	uid_t a = uid_array[adv_id][0];

	return ((a != DAC_SUPERUSER_ID) && (a != v));
}

/* TODO: Can we aggregate all adversaries into one? e.g., the attacker
   user can be made member of all groups.  He can use all permissions
   except as the current UID and primary group (?) of the victim
   process. Is this true?

 * TODO: add unmount as a method to delete.
 */

#define ND_INODE(nd) nd.path.dentry->d_inode

int dac_uid_has_perm(int id, struct dentry *parent,
		struct dentry *child, int flags)
{
	int match = INV_ADV_ID, ret = 0;
	const struct cred *old_cred;
	uid_t *ug_list;

	ug_list = uid_array[id];
	/* Change creds to possible attacker's */
	old_cred = dac_set_creds(id); // ug_list);

	if ((flags & PERM_BIND) && child) {
		if (child->d_inode) {
			/* The file exists already, check delete permission */
			if (S_ISDIR(child->d_inode->i_mode))
				ret = may_delete(parent->d_inode, child, 1);
			else
				ret = may_delete(parent->d_inode, child, 0);
			if (ret)
				goto no_match;
		}
	}

	if ((flags & PERM_BIND) || (flags & PERM_PREBIND)) {
		/* Check creation, disregarding actual file existence */
		ret = may_create_noexist(parent->d_inode);
		if (ret)
			goto no_match;
	}

	/* If we come here, success */
	match = 1;

no_match:
	/* Revert original creds */
	revert_creds(old_cred);
	return (ret < 0) ? ret : match;
}
// EXPORT_SYMBOL(dac_uid_has_perm);

/**
 * dac_get_adversary() - Does there exist a uid with @flags permission on @filename?
 * @flags: %PERM_BIND, %PERM_PREBIND
 * @filename: name of file to check permissions on
 *
 * Returns index in uid_array of attacker if one exists, INV_ADV_ID if not, -errno if error.
 */

int dac_get_adversary(struct dentry *parent, struct dentry *child, int flags)
{
	int ret = 0, i = 0, j = 0, match = INV_ADV_ID;
	uid_t u;
	gid_t g;

	BUG_ON(parent == NULL);
	if (parent->d_inode == NULL) {
		/* someone changed our parent while we were inside
			(e.g., rm -r), simply ignore */
		return match;
	}
	/* Try parent directory owner if not current UID */
	u = parent->d_inode->i_uid;
	if (u != current->cred->fsuid)
		for (i = 1; uid_array[i][0]; i++)
			if (uid_array[i][0] == u) {
				ret = dac_uid_has_perm(i, parent, child, flags);
				if (ret == 1) {
					match = i;
					goto found;
				}
			}

	/* Try parent directory group users who are not current UID */
	g = parent->d_inode->i_gid;
	for (i = 1; uid_array[i][0]; i++) {
		if (uid_array[i][0] == current->cred->fsuid)
			continue;
		for (j = 1; uid_array[i][j]; j++) {
			if (g == uid_array[i][j]) {
				ret = dac_uid_has_perm(i, parent, child, flags);
				if (ret == 1) {
					match = i;
					goto found;
				}
			}
		}
	}

	/* Try world adversary */
	if (sting_adversary_uid != -1)
		for (i = 1; uid_array[i][0]; i++)
			if (uid_array[i][0] == sting_adversary_uid) {
				ret = dac_uid_has_perm(i, parent, child, flags);
				if (ret == 1) {
					match = i;
					goto found;
				}
			}

found:
	return (ret < 0) ? ret : match;
}

/* adversary models */
struct adversary_model dac_adv_model = {
	.name = "dac",

	.is_adversary = dac_adversary,
	.valid_adversary = dac_valid_adversary,

	.has_perm = dac_uid_has_perm,

	.get_adversary = dac_get_adversary,
	.set_creds = dac_set_creds,
	.fill_superuser_creds = dac_superuser_creds,

	.get_sid = dac_get_sid,

	.sid_to_id = dac_sid_to_id,

	.print_adv = dac_print_adv,
	.print_victim = dac_print_victim
};

static int __init dac_adv_model_init(void)
{
	struct dentry *uids, *sting_adversary_uid;

	uids = debugfs_create_file("uids", 0600, NULL, NULL, &uids_fops);
	printk(KERN_INFO STING_MSG "creating uids file\n");

	if(!uids)
		printk(KERN_INFO STING_MSG "unable to create uids\n");

	sting_adversary_uid = debugfs_create_file("adversary_uid",
			0600, NULL, NULL, &sting_adversary_uid_fops);
	printk(KERN_INFO STING_MSG "creating sting_adversary_uid file\n");

	if(!sting_adversary_uid) {
		printk(KERN_INFO STING_MSG "unable to create sting_adversary_uid\n");
	}

	register_adversary_model(&dac_adv_model);
	// register_adversary_model(&mac_adv_model);

	/* set default adversary model */
	// sting_adv_model = &dac_adv_model;

	return 0;
}
fs_initcall(dac_adv_model_init);
