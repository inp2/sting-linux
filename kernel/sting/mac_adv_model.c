/*
 * Copyright (c) 2011-2012 Hayawardh Vijayakumar
 * Copyright (c) 2011-2012 Xinyang Ge
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
#include <objsec.h>

#include <asm/syscall.h>

#include "syscalls.h"
#include "permission.h"
#include "utility.h"

#define MAC_SUPERUSER_ID 1

#define MAY_LINK	0
#define MAY_UNLINK	1
#define MAY_RMDIR	2

static int mac_get_sid(const struct cred *c)
{
	return ((struct task_security_struct *) c->security)->sid;
}

/* next three functions copied from selinux/hooks.c */
static inline u16 inode_mode_to_security_class(umode_t mode)
{
	switch (mode & S_IFMT) {
	case S_IFSOCK:
		return SECCLASS_SOCK_FILE;
	case S_IFLNK:
		return SECCLASS_LNK_FILE;
	case S_IFREG:
		return SECCLASS_FILE;
	case S_IFBLK:
		return SECCLASS_BLK_FILE;
	case S_IFDIR:
		return SECCLASS_DIR;
	case S_IFCHR:
		return SECCLASS_CHR_FILE;
	case S_IFIFO:
		return SECCLASS_FIFO_FILE;

	}

	return SECCLASS_FILE;
}

/* Check whether a task can link, unlink, or rmdir a file/directory. */
static int may_link(struct inode *dir,
		    struct dentry *dentry,
		    int kind)

{
	struct inode_security_struct *dsec, *isec;
	struct common_audit_data ad;
	struct selinux_audit_data sad = {0,};
	u32 sid = mac_get_sid(current->cred);
	u32 av;
	int rc;

	dsec = dir->i_security;
	isec = dentry->d_inode->i_security;

	COMMON_AUDIT_DATA_INIT(&ad, DENTRY);
	ad.u.dentry = dentry;
	ad.selinux_audit_data = &sad;

	av = DIR__SEARCH;
	av |= (kind ? DIR__REMOVE_NAME : DIR__ADD_NAME);
	rc = avc_has_perm(sid, dsec->sid, SECCLASS_DIR, av, &ad);
	if (rc)
		return rc;

	switch (kind) {
	case MAY_LINK:
		av = FILE__LINK;
		break;
	case MAY_UNLINK:
		av = FILE__UNLINK;
		break;
	case MAY_RMDIR:
		av = DIR__RMDIR;
		break;
	default:
		printk(KERN_WARNING "SELinux: %s:  unrecognized kind %d\n",
			__func__, kind);
		return 0;
	}

	rc = avc_has_perm(sid, isec->sid, isec->sclass, av, &ad);
	return rc;
}

/* Check whether a task can create a file. */
static int may_create(struct inode *dir, u16 tclass)
{
	const struct task_security_struct *tsec = current_security();
	struct inode_security_struct *dsec;
	struct superblock_security_struct *sbsec;
	u32 sid, newsid;
	int rc;
	struct av_decision avd;

	dsec = dir->i_security;
	sbsec = dir->i_sb->s_security;

	sid = tsec->sid;
	newsid = tsec->create_sid;

	rc = avc_has_perm_noaudit(sid, dsec->sid, SECCLASS_DIR,
			  DIR__ADD_NAME | DIR__SEARCH, 0, &avd);
	if (rc)
		return rc;

	rc = avc_has_perm_noaudit(sid, newsid, tclass, FILE__CREATE, 0, &avd);
	if (rc)
		return rc;

	return avc_has_perm_noaudit(newsid, sbsec->sid,
			    SECCLASS_FILESYSTEM,
			    FILESYSTEM__ASSOCIATE, 0, &avd);
}

static int mac_adversary(int adv_id, const struct cred *vctm)
{
	u32 sid = ((struct task_security_struct *) vctm->security)->sid;
	struct ts_node *node = NULL;
	while ((node = sting_seadversary_find_subject(sid, node))) {
		if (node->adversary_sid == adv_id)
			return 1;
	}
	return 0;
}

static int mac_valid_adversary(int adv_uid_ind)
{
	return (adv_uid_ind != INV_ADV_ID);
}

static const struct cred *mac_set_creds(int adv_id)
{
	struct cred *override_cred = NULL;
	const struct cred *old_cred;
    struct task_security_struct *tsec;
	int ret = 0;

	override_cred = prepare_creds();
	if (!override_cred) {
		ret = -ENOMEM;
		goto out;
	}

    tsec = (struct task_security_struct *) override_cred->security;
    tsec->osid = tsec->sid = adv_id;

	/* Set (clear) capabilities */
	cap_clear(override_cred->cap_effective);


	/* Finally, exchange creds */
	old_cred = override_creds(override_cred);
	printk(KERN_INFO STING_MSG "%s changes PID(%u) sid to %u\n",
            __FUNCTION__, current->pid, ((struct task_security_struct *) current_cred()->security)->sid);
	put_cred(override_cred);

out:
	return (ret < 0) ? (struct cred *) ERR_PTR(ret) : old_cred;
}

int mac_id_has_perm(int id, struct dentry *parent,
		struct dentry *child, int flags)
{
	int match = INV_ADV_ID, ret = 0;
	const struct cred *old_cred;
	int sn = syscall_get_nr(current, task_pt_regs(current));

	old_cred = mac_set_creds(id); // ug_list);

	if ((flags & PERM_BIND) && child) {
		if (child->d_inode) {
			/* The file exists already, check delete permission */
			if (S_ISDIR(child->d_inode->i_mode))
				ret = may_link(parent->d_inode, child, MAY_RMDIR);
			else
				ret = may_link(parent->d_inode, child, MAY_UNLINK);
			if (ret)
				goto no_match;
		}
	}

	if ((flags & PERM_BIND) || (flags & PERM_PREBIND)) {
		if (sn == __NR_mkdir || sn == __NR_mkdirat) {
			ret = may_create(parent->d_inode, SECCLASS_DIR);
		} else if (sn == __NR_mknod || sn == __NR_mknodat) {
			/* TODO: below, also other create_set syscalls */
#if 0
			/* get mode flags */
			ret = may_create(parent->d_inode, inode_mode_to_security_class(mode));
#endif
		} else if (sn == __NR_open || sn == __NR_openat || sn == __NR_creat) {
			ret = may_create(parent->d_inode, SECCLASS_FILE);
		} else if (sn == __NR_symlink || sn == __NR_symlinkat) {
			ret = may_create(parent->d_inode, SECCLASS_LNK_FILE);
		}

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

static int mac_get_adversary(struct dentry *parent, struct dentry *child, int flags)
{
	u32 sid = ((struct task_security_struct *) (current->cred->security))->sid;
	struct ts_node *node = NULL;
	while ((node = sting_seadversary_find_subject(sid, node))) {
		if (mac_id_has_perm(node->adversary_sid, parent, child, flags))
			return node->adversary_sid;
	}
	return INV_ADV_ID;
}

static void mac_superuser_creds(struct cred *override_cred)
{
	struct task_security_struct *tsec = (struct task_security_struct *) override_cred->security;
	tsec->osid = tsec->sid = MAC_SUPERUSER_ID;
}

static int mac_print_adv(int adv_id)
{
	return adv_id;
}

static int mac_print_victim(int victim)
{
	return victim;
}

/* adversary models */
struct adversary_model mac_adv_model = {
	.name = "mac",

	.is_adversary = mac_adversary,
	.valid_adversary = mac_valid_adversary,

	.has_perm = mac_id_has_perm,

	.get_adversary = mac_get_adversary,
	.set_creds = mac_set_creds,
	.fill_superuser_creds = mac_superuser_creds,

	.get_sid = mac_get_sid,

	.print_adv = mac_print_adv,
	.print_victim = mac_print_victim
};

static int __init mac_adv_model_init(void)
{
	struct dentry *sting_secontext_to_sid;
	struct dentry *sting_seadversary_feed;

	sting_secontext_to_sid = debugfs_create_file("sting_secontext_to_sid",
			0600, NULL, NULL, &sting_secontext_to_sid_fops);
	printk(KERN_INFO STING_MSG "creating sting_secontext_to_sid file\n");
	if(!sting_secontext_to_sid) {
		printk(KERN_INFO STING_MSG "unable to create sting_secontext_to_sid\n");
	}

	sting_seadversary_feed = debugfs_create_file("sting_seadversary_feed",
			0600, NULL, NULL, &sting_seadversary_feed_fops);
	printk(KERN_INFO STING_MSG "creating sting_seadversary_feed file\n");
	if(!sting_seadversary_feed) {
		printk(KERN_INFO STING_MSG "unable to create sting_seadversary_feed\n");
	}


	register_adversary_model(&mac_adv_model);
	// register_adversary_model(&mac_adv_model);

	/* set default adversary model */
	sting_adv_model = &mac_adv_model;

	return 0;
}
fs_initcall(mac_adv_model_init);
