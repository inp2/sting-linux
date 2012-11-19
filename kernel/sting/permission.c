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
	int i = 0, j = 0;
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

static int __init sting_permission_init(void)
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
	return 0;
}
fs_initcall(sting_permission_init);

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


struct cred *superuser_creds(void)
{
	struct cred *override_cred = NULL;
	const struct cred *old_cred;
	int ret = 0;

	override_cred = prepare_creds();
	if (!override_cred) {
		ret = -ENOMEM;
		goto out;
	}

	override_cred->uid = override_cred->gid = 0;
	override_cred->euid = override_cred->egid = 0;
	override_cred->fsuid = override_cred->fsgid = 0;
	override_cred->suid = override_cred->sgid = 0;

	cap_raise(override_cred->cap_effective, CAP_SYS_ADMIN);
	cap_raise(override_cred->cap_effective, CAP_DAC_READ_SEARCH);
	cap_raise(override_cred->cap_effective, CAP_DAC_OVERRIDE);
	cap_raise(override_cred->cap_effective, CAP_FOWNER);

	old_cred = override_creds(override_cred);

	/* don't need alloc reference anymore */
	put_cred(override_cred);

out:
	return (ret < 0) ? (struct cred *) ERR_PTR(ret) : old_cred;
}
EXPORT_SYMBOL(superuser_creds);

/**
 * set_creds() - Change the credentials of current process temporarily
 * @ug_list:		ug_list[0] is uid, ug_list[1] is gid,
 *			ug_list[2 .. ] are supplementary groups.
 * @ret:		Returns the old credentials
 *
 * Set process' credentials to attacker's
 * to see if she can do anything.
 * See nfsd_setuser() in fs/nfsd/auth.c for reference
 */

struct cred *set_creds(uid_t *ug_list)
{
	struct group_info *gi = NULL;
	struct cred *override_cred = NULL;
	const struct cred *old_cred;
	int ret = 0, size = 0, i;

	override_cred = prepare_creds();
	if (!override_cred) {
		ret = -ENOMEM;
		goto out;
	}

	/* Calculate size of supplementary group list */
	for (i = 2; ug_list[i]; i++)
		size++;

	/* Save old credential */
//	old_cred = override_creds(*override_cred);

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
	return (ret < 0) ? (struct cred *) ERR_PTR(ret) : old_cred;
}
EXPORT_SYMBOL(set_creds);

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

/* TODO: Can we aggregate all adversaries into one? e.g., the attacker
   user can be made member of all groups.  He can use all permissions
   except as the current UID and primary group (?) of the victim
   process. Is this true?

 * TODO: add unmount as a method to delete.
 */

#define ND_INODE(nd) nd.path.dentry->d_inode

static int adv_has_perm(int adv_ind, struct dentry *parent,
		struct dentry *child, int flags)
{
	int match = UID_NO_MATCH, ret = 0;
	struct cred *old_cred;

	/* Change creds to possible attacker's */
	old_cred = set_creds(uid_array[adv_ind]);

	if ((flags & ATTACKER_BIND) && child) {
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

	if ((flags & ATTACKER_BIND) || (flags & ATTACKER_PREBIND)) {
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

/**
 * sting_get_adversary() - Does there exist a uid with @flags permission on @filename?
 * @flags: %ATTACKER_BIND, %ATTACKER_PREBIND
 * @filename: name of file to check permissions on
 *
 * Returns index in uid_array of attacker if one exists, UID_NO_MATCH if not, -errno if error.
 */

int sting_get_adversary(struct dentry *parent, struct dentry *child, int flags)
{
	int ret = 0, i = 0, j = 0, match = UID_NO_MATCH;
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
		for (i = 0; uid_array[i][0]; i++)
			if (uid_array[i][0] == u) {
				ret = adv_has_perm(i, parent, child, flags);
				if (ret == 1) {
					match = i;
					goto found;
				}
			}

	/* Try parent directory group users who are not current UID */
	g = parent->d_inode->i_gid;
	for (i = 0; uid_array[i][0]; i++) {
		if (uid_array[i][0] == current->cred->fsuid)
			continue;
		for (j = 1; uid_array[i][j]; j++) {
			if (g == uid_array[i][j]) {
				ret = adv_has_perm(i, parent, child, flags);
				if (ret == 1) {
					match = i;
					goto found;
				}
			}
		}
	}

	/* Try world adversary */
	if (sting_adversary_uid != -1)
		for (i = 0; uid_array[i][0]; i++)
			if (uid_array[i][0] == sting_adversary_uid) {
				ret = adv_has_perm(i, parent, child, flags);
				if (ret == 1) {
					match = i;
					goto found;
				}
			}

found:
	return (ret < 0) ? ret : match;
}
EXPORT_SYMBOL(sting_get_adversary);
