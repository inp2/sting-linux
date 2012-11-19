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
#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/hardirq.h>
#include <linux/kthread.h>
#include <linux/uaccess.h>
#include <linux/ftrace.h>
#include <linux/sysctl.h>
#include <linux/slab.h>
#include <linux/ctype.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/rcupdate.h>
#include <linux/relay.h>
#include <linux/syscalls.h>
#include <linux/stat.h>
#include <linux/un.h>
#include <linux/net.h>
#include <linux/sting.h>
#include <linux/namei.h>
#include <linux/xattr.h>
#include <linux/fs_struct.h>
#include <linux/union_fs.h>
#include <linux/mount.h>
#include <linux/security.h>
#include <linux/fsnotify_backend.h>
#include <linux/audit.h>

#include <asm/syscall.h>

#include "launch_attack.h"
#include "syscalls.h"
#include "permission.h"
#include "interpreter_unwind.h"

/* Internal flags */
#define CREATE_FILE_NONEXISTENT 0x1
#define CREATE_FILE_EXISTENT 0x2
#define CREATE_DIR 0x4

#define SYMLINK_FILE_INFIX "symlink"
#define HARDLINK_FILE_INFIX "hardlink"

#define ATTACK_DIR_PREFIX "/attacker/"
#define ATTACK_EXISTING_FILE_PREFIX "/existing_file"
#define ATTACK_NEW_FILE_PREFIX "/new_file"
#define ATTACK_EXISTING_DIR_PREFIX "/existing_dir"

/*
 * STING: routines associated with attacks.
 * to launch actual attacks, we use *at() family of system calls,
 * passing the parent dentry we already resolved that is
 * adversary-accessible as a file.
 * we choose not to directly call VFS, as there will be
 * unnecessary duplication of complicated code for each system call.
 * The exception is listxattr, which does not have an *at(), so
 * we directly use VFS on the dentry.
 */

char *get_last(char *filename)
{
	char *ptr = (char *) filename + strlen(filename);
	while ((*ptr != '/') && (ptr != filename))
		ptr--;
	if (*ptr == '/')
		ptr++;
	return ptr;
}


/*
 * get_existing_target_file() - Return /attacker/uid/file_existing_#filename
 * @uid:
 * @filename:
 * @fname: allocated pointer
 * @type: %SYMLINK/HARDLINK
 */

char *get_existing_target_file(char *filename, char *fname, uid_t uid)// , int type)
{
	char uid_str[6];
	sprintf(uid_str, "%d", uid);
	strcpy(fname, ATTACK_DIR_PREFIX);
	strcat(fname, uid_str);
	strcat(fname, ATTACK_EXISTING_FILE_PREFIX);
	strcat(fname, "_");
	// strcat(fname, (type == SYMLINK) ? SYMLINK_FILE_INFIX : HARDLINK_FILE_INFIX);
	// strcat(fname, "_");
	strcat(fname, get_last(filename));

	return fname;
}
EXPORT_SYMBOL(get_existing_target_file);

/**
 * get_existing_target_dir() - /attacker/uid/existing_dir_#filename
 * @uid:
 * @filename:
 * @fname: allocated pointer
 */

char *get_existing_target_dir(char *filename, char *fname, uid_t uid)
{
	char uid_str[6];
	sprintf(uid_str, "%d", uid);
	strcpy(fname, ATTACK_DIR_PREFIX);
	strcat(fname, uid_str);
	strcat(fname, ATTACK_EXISTING_DIR_PREFIX);
	strcat(fname, "_");
	strcat(fname, get_last(filename));

	return fname;
}
EXPORT_SYMBOL(get_existing_target_dir);

/**
 * get_new_target_file() - /attacker/uid/new_file_#filename
 * @uid:
 * @filename:
 * Remember to free returned pointer!
 *
 */

char *get_new_target_file(char *filename, char *fname, uid_t uid)
{
	char uid_str[6];
	sprintf(uid_str, "%d", uid);
	strcpy(fname, ATTACK_DIR_PREFIX);
	strcat(fname, uid_str);
	strcat(fname, ATTACK_NEW_FILE_PREFIX);
	strcat(fname, "_");
	/* TODO: Possible bug page fault: use copy_from_user */
	strcat(fname, get_last(filename));

	return fname;
}
EXPORT_SYMBOL(get_new_target_file);

static ssize_t
listxattr(struct dentry *d, char **klist, size_t size)
{
	ssize_t error;

	if (size) {
		if (size > XATTR_LIST_MAX)
			size = XATTR_LIST_MAX;
		*klist = kmalloc(size, __GFP_NOWARN | GFP_KERNEL);
		if (!*klist) {
			*klist = vmalloc(size);
			if (!*klist)
				return -ENOMEM;
		}
	}

	error = vfs_listxattr(d, *klist, size);
	if (error == -ERANGE && size >= XATTR_LIST_MAX) {
		/* The file system tried to returned a list bigger
		   than XATTR_LIST_MAX bytes. Not possible. */
		error = -E2BIG;
	}

	return error;
}

/* Returns 1 if already checked */
int sting_already_launched(struct dentry *dentry)
{
	int tret = 0; /* Not marked */
	char *xattr_list = NULL;
	size_t size = 0;
	char *ptr = NULL;

	if (!dentry || !dentry->d_inode)
		return 0;

	STING_CALL(size = listxattr(dentry, &xattr_list, 0));
	if (((int) size) < 0) {
		tret = (int) size;
		goto out;
	}
	STING_CALL(tret = listxattr(dentry, &xattr_list, size));
	if (tret < 0) {
		printk(KERN_INFO STING_MSG "xattr error: [%d]\n", tret);
		goto out;
	}

	ptr = xattr_list;
	tret = 0; /* Not marked */
	while (ptr < xattr_list + size) {
		if (!ptr) /* In between keys - shouldn't happen! */
			continue;
		if (!strcmp(ptr, ATTACKER_XATTR_STRING)) {
			tret = 1;
			break;
		} else /* Jump to next key */
			ptr += strlen(ptr) + 1;
	}

out:
	if (xattr_list)
		kfree(xattr_list);
	return tret;
}
EXPORT_SYMBOL(sting_already_launched);

#if 0
int check_already_attacked(char __user *filename, int follow)
{
	int tret = 1; /* Not marked */
	char *xattr_list = NULL;
	size_t size = 0;
	char *ptr = NULL;
	mm_segment_t old_fs = get_fs();

	if (!follow) {
		STING_SYSCALL(size = sys_llistxattr(filename, xattr_list, 0));
		if (((int) size) < 0)
			goto out;
		xattr_list = kzalloc(size, GFP_ATOMIC);
		if (!xattr_list)
			goto out;
		STING_SYSCALL(tret = sys_llistxattr(filename, xattr_list, size));
	} else {
		STING_SYSCALL(size = sys_listxattr(filename, xattr_list, 0));
		if (((int) size) < 0) {
			/* Some error */
			goto out;
		}
		xattr_list = kzalloc(size, GFP_ATOMIC);
		if (!xattr_list) {
			goto out;
		}
		STING_SYSCALL(tret = sys_listxattr(filename, xattr_list, size));
	}
	if (tret == -ENOTSUPP) {
		printk(KERN_INFO STING_MSG "Xattrs not supported!\n");
		goto out;
	} else if (tret < 0)
		goto out;
	ptr = xattr_list;
	tret = 1; /* Not marked */
	while (ptr < xattr_list + size) {
		if (!ptr) /* In between keys - shouldn't happen! */
			continue;
		if (!strcmp(ptr, ATTACKER_XATTR_STRING)) {
			tret = 0;
			break;
		} else /* Jump to next key */
			ptr += strlen(ptr) + 1;
	}

out:
	if (xattr_list)
		kfree(xattr_list);
	return tret;
}
EXPORT_SYMBOL(check_already_attacked);
#endif

int set_attacked(char __user *filename, int follow)
{
	int tret = 0;
	mm_segment_t old_fs = get_fs();
	const struct cred *old_cred;

	/* Call as superuser, as permissions for labeling sticky dir etc.,
	   are not available to all. */
	old_cred = superuser_creds(); /* for labeling */

	/* TODO: The maximum length possible is XATTR_LIST_MAX */
	if (!follow) {
		STING_SYSCALL(tret = sys_lsetxattr(filename, ATTACKER_XATTR_STRING, ATTACKER_XATTR_VALUE, sizeof(ATTACKER_XATTR_VALUE), 0));
	} else {
		STING_SYSCALL(tret = sys_setxattr(filename, ATTACKER_XATTR_STRING, ATTACKER_XATTR_VALUE, sizeof(ATTACKER_XATTR_VALUE), 0));
	}
	if (tret == -ENOTSUPP) {
		printk(KERN_INFO STING_MSG "Xattrs not supported!\n");
	}

	/* Restore original creds */
	revert_creds(old_cred);

	BUG_ON(current->cred != current->real_cred);
	return tret;
}


int get_stat(char __user *filename, int follow, struct stat64 *buf)
{
	int ret;
	mm_segment_t old_fs = get_fs();

	if (!follow) {
		STING_SYSCALL(ret = sys_lstat64(filename, buf));
	} else {
		STING_SYSCALL(ret = sys_stat64(filename, buf));
	}

	return ret;
}

/**
 * already_exists() - Does an object at filename already exist?
 * @filename: Filename to resolve
 * @follow: Should a symbolic link be followed on the final object?
 * @buf: The stat buffer to be filled in with details of the
 *		object if it exists, otherwise NULL
 *
 * Returns 1 if already exists, otherwise 0
 */

int already_exists(char __user *filename, int follow, struct stat64 *buf)
{
	int ret;

	ret = get_stat(filename, follow, buf);

	if (ret == 0)
		return 1; /* stat succeeded - file exists */
	else
		return 0; /* Any other failure */
}

#define REASON_SQUAT 0x1
#define REASON_TARGET 0x2
#define REASON_TOCTTOU_RUNTIME 0x4
#define REASON_NORMAL_RUNTIME 0x8

#define T_REG 1
#define T_DIR 2
#define T_SOCK 3

/* special check for unionfs */
int sting_obj_exists(struct dentry *d, int bindex)
{
	if (!is_unionfs(d))
		return !!d->d_inode;
	else
		return !!unionfs_lower_dentry_idx_export(d, bindex);
}

static inline void fsnotify_create(struct inode *inode, struct dentry *dentry)
{
	audit_inode_child(dentry, inode);

	fsnotify(inode, FS_CREATE, dentry->d_inode, FSNOTIFY_EVENT_INODE, dentry->d_name.name, 0);
}

/*
 * special sting function to create in upper adversarial branch.
 * it calls vfs_symlink even if dentry->d_inode exists, so long as
 * the adversarial branch resource doesn't exist.
 *
 * this is symlinkat() from fs/namei.c without the initial name
 * resolution, which is already resolved for us.
 *
 * s_parent and s_child are dentries of source's parent and child
 * (these are resolved outside), and
 * path references to s_parent are held in sting_syscall_begin and
 * to s_child in the caller; so we do not need to worry about them.
 *
 * simply setting resolution type to ADV_RES on last component is
 * not enough, because the parent may not yet be copied up, and
 * we get a dentry whose start and end = -1 (because the parent's
 * lower dentry does not exist on adversarial branch 0).
 *
 * if we instead opt for resolution type to ADV_NORMAL_RES, the
 * dentry will become positive if the lower non-adversarial branch
 * contains it, and -EEXIST will be returned instead of calling
 * the vfs_symlink() function.
 */

int sting_symlink(char *target, struct path *s_parent,
					struct dentry *s_child)
{
	int error = 0;
	int r_int;

	struct inode *dir = s_parent->dentry->d_inode;

	/* for the security hooks we are calling, we do not
	 * want to re-invoke sting detection */
	r_int = sting_set_res_intent(current, LAUNCH_INT);

	mutex_lock(&s_parent->dentry->d_inode->i_mutex);
	error = mnt_want_write(s_parent->mnt);
	if (error)
		goto unlock;
	error = security_path_symlink(s_parent, s_child, target);
	if (error)
		goto unlock;

	/* copy of vfs_symlink, change may_create*/
	error = may_create_noexist(dir);

	if (error)
		goto unlock;

	if (!dir->i_op->symlink) {
		error = -EPERM;
		goto unlock;
	}

	error = security_inode_symlink(dir, s_child, target);
	if (error)
		goto unlock;

	error = dir->i_op->symlink(dir, s_child, target);
	if (!error)
		fsnotify_create(dir, s_child);

unlock:
	mutex_unlock(&s_parent->dentry->d_inode->i_mutex);
	sting_set_res_intent(current, r_int);
	return error;
}

/**
 * file_create() - Create a file/dir at location referenced by filename
 * @filename: name of file to create
 * @reason: What is the reason for file creation?
 * 	- %REASON_SQUAT:
 *		- Attempt at squat (Mark, as attacker)
 * 	- %REASON_TOCTTOU_RUNTIME:
 *		- Exercise stat()->use() instead of stat()->creat()
 *		- (Don't mark, as attacker)
 *		- Might be changed later (e.g., into symlink)
 * 	- %REASON_NORMAL_RUNTIME:
 *		- Exercise any path that goes down stat()
 *		- (Don't mark, as process)
 *	- %REASON_TARGET:
 *		- File is a target for a symlink created
 *		- (Mark, as process)
 * @type: Is a directory creation requested (instead of file)?
 *	T_REG	- regular file
 *	T_DIR	- directory
 *	T_SOCK	- unix-domain socket
 * @sn: System-call number for logging purposes
 *
 * If file already exists, attacker tries deleting first.
 * XATTRs set on file if created.
 * TODO: Extend to other types
 */

int file_create(char __user *fname, struct path* parent,
		int reason, int type, int sn, int att_uid_ind)
{
	const struct cred *old_cred;
	int ret = 0;
	mm_segment_t old_fs = get_fs();
	int exists = 0;
	struct dentry *child = NULL;
	int c_res_type;

	c_res_type = sting_get_res_type(current);

	/* If REASON_TOCTTOU_RUNTIME,  we still want to be able to delete afterwards, so
	   create with attacker permission, not process permission */
	/* With process permission may execute further paths */

	if ((reason == REASON_TARGET) || (reason == REASON_NORMAL_RUNTIME)) {
		/* Create the file with process permission */
		/* This is only done in /attacker/uid/ */
		sting_set_res_type(current, NORMAL_RES);
		if (type == T_REG) {
			STING_SYSCALL(ret = sys_open(fname, O_CREAT, 0755));
			if (ret > 0) {
				STING_SYSCALL(sys_close(ret));
			}
		} else if (type == T_DIR) {
			STING_SYSCALL(ret = sys_mkdir(fname, 0777));
		}
		if (ret == -EEXIST)
			ret = 0;
		if (ret < 0) {
			printk(KERN_INFO STING_MSG "Can't create file/dir %s: %d?\n", fname, ret);
		}
		/* goto mark; */
	} else if ((reason == REASON_SQUAT) || (reason == REASON_TOCTTOU_RUNTIME)) {
		/* Change creds to attacker's */
		old_cred = set_creds(uid_array[att_uid_ind]);
		sting_set_res_type(current, ADV_RES);

		mutex_lock(&parent->dentry->d_inode->i_mutex);
		child = lookup_one_len(fname, parent->dentry, strlen(fname));
		mutex_unlock(&parent->dentry->d_inode->i_mutex);
		if (IS_ERR(child)) {
			ret = PTR_ERR(child);
			goto fail;
		}

		/* does it exist on the non-adversarial branch? */
		exists = sting_obj_exists(child, STING_NON_ADV_BID);

		if (exists) {
			if (!is_unionfs(child)) {
				/* TODO: If REASON_SQUAT,
				   preserve contents */
				/* TODO: If TOCTTOU_RUNTIME,
				   no need to delete, as file
				   is already there */

				/* Try deleting first */
				STING_SYSCALL(ret = sys_unlink(fname));
				if (ret < 0) {
					if (ret == -ENOENT)
						printk(KERN_INFO STING_MSG "File found but not for delete?!\n");
					else if (ret == -EACCES)
						printk(KERN_INFO "attacker: att_uid_ind not working!\n");
					goto restore;
				} else {
				STING_LOG("Delete SUCCESS for squat: %s, proc "
							"euid: %d attacker uid: %d, process: %s system call:  %d\n",
							fname, current->real_cred->fsuid,
							uid_array[att_uid_ind][0], current->comm, sn);
				}
			} else {
				/* no actual deletion, but if done properly, the shadow resolution
				 * already evaluated delete permission on the lower branch */
				STING_LOG("Delete SUCCESS for squat: %s, proc "
							"euid: %d attacker uid: %d, process: %s system call:  %d\n",
							fname, current->real_cred->fsuid,
							uid_array[att_uid_ind][0], current->comm, sn);
			}
		}

		/* Create the file */
		if (type == T_REG) {
			STING_SYSCALL(ret = sys_open(fname, O_CREAT, 0777));
			if (ret == -ENOENT) ;
//					printk(KERN_INFO STING_MSG "Directory creation required: %s\n", fname);
			if (ret > 0)
				sys_close(ret);
		} else if (type == T_SOCK) {
			int s_fd;
			struct sockaddr_un sock;
			/* To squat a socket, socket(), bind(), close() */
			STING_SYSCALL(s_fd = sys_socket(AF_UNIX, SOCK_STREAM, 0));
			if (s_fd > 0) {
				sock.sun_family = AF_UNIX;
				strcpy(sock.sun_path, fname);
				STING_SYSCALL(ret = sys_bind(s_fd,
					(struct sockaddr *) &sock,
					sizeof(struct sockaddr_un)));
				STING_SYSCALL(sys_close(s_fd));
			}
		} else if (type == T_DIR) {
			STING_SYSCALL(ret = sys_mkdir(fname, 0777));
			if (ret == -ENOENT) ;
//					printk(KERN_INFO STING_MSG "Directory creation required: %s\n", fname);
		}
restore:
		/* Restore original creds */
		revert_creds(old_cred);

		if (ret >= 0) /* open, mkdir */ {
			/* Success! */
			goto mark;
		}
	}
mark:
	if (ret >= 0) {
		/* First, report success */
		if (reason == REASON_SQUAT || reason == REASON_TOCTTOU_RUNTIME) {
			STING_LOG(
			"%s SUCCESS!: %s, proc euid: %d attacker uid: %d, process: %s, system call: %d\n",
			((reason == REASON_SQUAT) ? "Squat" :
			 ((reason == REASON_TOCTTOU_RUNTIME) ? "Tocttou check" :
			 "Error")),
			fname, current->cred->fsuid,
			uid_array[att_uid_ind][0], current->comm, sn);
		} else if ((reason == REASON_TARGET) || (reason == REASON_NORMAL_RUNTIME)) {
			STING_LOG(
			"%s SUCCESS!: %s, proc euid: %d, process: %s, system call: %d\n",
			((reason == REASON_TARGET) ? "Target" :
			 ((reason == REASON_NORMAL_RUNTIME) ? "Normal Runtime" :
			 "Error")),
			fname, current->cred->fsuid,
			current->comm, sn);
		}

		/* Set xattr on created file if needed */
		if (reason == REASON_SQUAT || reason == REASON_TARGET) {
			if (reason == REASON_SQUAT)
				sting_set_res_type(current, ADV_RES);
			else if (reason == REASON_TARGET)
				sting_set_res_type(current, NORMAL_RES);
			ret = set_attacked(fname, DONT_FOLLOW);
			if (ret < 0)
				printk(KERN_INFO STING_MSG "Labeling %s failed: %d!\n", fname, ret);
		}
	}

	dput(child);
out:
	BUG_ON(current->cred != current->real_cred);
	BUG_ON(current->cred->group_info != current->real_cred->group_info);
	sting_set_res_type(current, c_res_type);
	return ret;

fail:
	revert_creds(old_cred);
	goto out;
}


/**
 * hardlink_create() - Create a hardlink
 * @filename: to create hard link
 * @flags:
 *	%T_REG: regular file
 *	%T_SOCK: socket file
 * @sn:	system call number for logging purposes.
 *
 * If file already exists, attacker tries deleting first.
 * Hard links need files to point to, that is also done here.
 * XATTRs set on links and actual files if created.
 * TODO: The target of hard link needs to be created
 * on the same filesystem as the link itself. For unionfs,
 * in addition, sys_link() should have two resolution modes -
 * the last component of source's resolution context is ADV_RES,
 * whereas the last component of target's resolution context is
 * ADV_NORMAL_RES.
 */

int hardlink_create(char *source, char *target, struct path *parent,
		int type, int sn, int att_uid_ind)
{
	const struct cred *old_cred;
	int ret = 0; /* index of attacker in uid_array */
	mm_segment_t old_fs = get_fs();
	int exists = 0;
	int orig_fsuid = 0; /* Original UID of process */
	struct dentry *child = NULL;
	int c_res_type;

	c_res_type = sting_get_res_type(current);

	orig_fsuid = current->cred->fsuid;
	mutex_lock(&parent->dentry->d_inode->i_mutex);
	child = lookup_one_len(source, parent->dentry, strlen(source));
	mutex_unlock(&parent->dentry->d_inode->i_mutex);
	if (IS_ERR(child)) {
		ret = PTR_ERR(child);
		goto out;
	}

	/* does it exist on the non-adversarial branch? */
	exists = sting_obj_exists(child, STING_NON_ADV_BID);

	/* Change creds to attacker's */
	old_cred = set_creds(uid_array[att_uid_ind]);

	/* Try deleting first if exists */
	if (exists) {
		if (!is_unionfs(child)) {
			STING_SYSCALL(ret = sys_unlink(source));
			if (ret < 0) {
				if (ret == -ENOENT) {
					printk(KERN_INFO STING_MSG "File found but not for delete?!\n");
				} else if (ret == -EACCES || ret == -EPERM) {
					STING_LOG("Cannot access! permission module error!: "
					"%s, proc euid: %d attacker uid: %d, process: %s system call: %d\n",
					source, current->real_cred->fsuid, uid_array[att_uid_ind][0],
					current->comm, sn);
				} else {
					STING_LOG("Delete SUCCESS for hardlink!: %s, proc euid: "
							"%d attacker uid: %d, process: %s system call: %d\n",
							source, current->real_cred->fsuid, uid_array[att_uid_ind][0]
							, current->comm, sn);
				}
				goto restore;
			}
		} else {
			/* no actual deletion, but if done properly, the shadow resolution
			 * already evaluated delete permission on the lower branch */
			STING_LOG("Delete SUCCESS for hardlink!: %s, proc euid: "
					"%d attacker uid: %d, process: %s system call: %d\n",
					source, current->real_cred->fsuid, uid_array[att_uid_ind][0]
					, current->comm, sn);
		}
	}

	/* Create the file as original user */
	/* TODO: Once everyone uses permission module, below revert_creds and set_creds
		will disappear */
	revert_creds(old_cred);
	ret = file_create(target, parent, REASON_TARGET, type, sn, att_uid_ind);
	old_cred = set_creds(uid_array[att_uid_ind]);
	/* Create the hardlink */
	sting_set_res_type(current, ADV_RES);
	STING_SYSCALL(ret = sys_link(target, source));
	if (ret == -ENOENT) ;
//			printk(KERN_INFO STING_MSG "Directory creation required: %s\n", source);
	if (ret < 0) {
		if (ret == -EACCES || ret == -EPERM) {
			STING_LOG("Cannot access! permission module error!: %s, proc "
					"euid: %d attacker uid: %d, process: %s system call: %d\n",
					source, current->real_cred->fsuid,
					uid_array[att_uid_ind][0], current->comm, sn);
		}
		goto restore;
	}
restore:
	/* Restore original creds */
	revert_creds(old_cred);

	if (ret == 0) {
		/* Success! */
		STING_LOG("Hardlink SUCCESS!: %s, proc euid: %d attacker uid: %d, "
				"process: %s, link to %s, system call: %d\n", source,
				current->cred->fsuid, uid_array[att_uid_ind][0],
				current->comm, target, sn);
		/* Set xattr on attacker hardlink */
		sting_set_res_type(current, ADV_RES);
		ret = set_attacked(source, DONT_FOLLOW);
		if (ret < 0) {
			printk(KERN_INFO STING_MSG "Labeling %s failed: %d!\n", source, ret);
		}
	}
	dput(child);
out:
	BUG_ON(current->cred != current->real_cred);
	BUG_ON(current->cred->group_info != current->real_cred->group_info);
	sting_set_res_type(current, c_res_type);

	return ret;
}

/**
 * symlink_create() - Create a symlink at filename
 * @filename: 		Where to create symlink
 * @flag:		Determines where symlink points to
 * 	%CREATE_FILE_NONEXISTENT:
 *		- filename -> /attacker/uid/new_file_#filename
 * 	%CREATE_FILE_EXISTENT:
 *		- filename -> /attacker/uid/existing_file_#filename
 * 		- Also creates the actual file
 *	%CREATE_DIR:
 *		- filename -> /attacker/uid/existing_dir_#filename
 * 		- Also creates the actual directory
 * @sn: System-call number for logging purposes
 *
 * If file already exists, attacker tries deleting first.
 * If a file needs to be created to point to, that is also done here.
 * XATTRs set on links and actual files if created.
 */

int symlink_create(char *source, char *target, struct path *parent,
		int flag, int sn, int att_uid_ind)
{
	const struct cred *old_cred;
	int ret = 0;
	mm_segment_t old_fs = get_fs();
	int exists = 0;
	int orig_fsuid = 0; /* Original UID of process */
	struct dentry *child = NULL;
	int c_res_type;

	c_res_type = sting_get_res_type(current);

	sting_set_res_type(current, ADV_NORMAL_RES);
	orig_fsuid = current->cred->fsuid;
	mutex_lock(&parent->dentry->d_inode->i_mutex);
	child = lookup_one_len(source, parent->dentry, strlen(source));
	mutex_unlock(&parent->dentry->d_inode->i_mutex);
	if (IS_ERR(child)) {
		ret = PTR_ERR(child);
		goto out;
	}

	/* does it exist on the non-adversarial branch? */
	exists = sting_obj_exists(child, STING_NON_ADV_BID);

	/* Change creds to attacker's */
	old_cred = set_creds(uid_array[att_uid_ind]);

	if (exists) {
		if (!is_unionfs(child)) {
			/* TODO: If CREATE_FILE_EXISTENT,
			   then preserve file contents using
			rename, and do not call REASON_TARGET */
			/* Try deleting first */
			if (!S_ISDIR(child->d_inode->i_mode)) {
				STING_SYSCALL(ret = sys_unlink(source));
			} else {
				STING_SYSCALL(ret = sys_rmdir(source));
			}

			if (ret < 0 && ret != -ENOENT) {
				// if (ret == -ENOENT)
				//	printk(KERN_INFO STING_MSG "File found but not for delete?!\n");
				goto restore;
			} else {
				STING_LOG("Delete SUCCESS for symlink!: %s, proc euid: %d "
						"attacker uid: %d, process: %s system call: %d\n",
						source, current->real_cred->fsuid,
						uid_array[att_uid_ind][0], current->comm, sn);
			}
		} else {
			/* no actual deletion, but if done properly, the shadow resolution
			 * already evaluated delete permission on the lower branch */
			STING_LOG("Delete SUCCESS for symlink!: %s, proc euid: %d "
					"attacker uid: %d, process: %s system call: %d\n",
					source, current->real_cred->fsuid,
					uid_array[att_uid_ind][0], current->comm, sn);
		}
	}

	/* Create the symlink */
	sting_set_res_type(current, ADV_NORMAL_RES);
	if (is_unionfs(child)) {
		sting_symlink(target, parent, child);
	} else {
		STING_SYSCALL(ret = sys_symlinkat(target, AT_FDCWD, source));
	}
	if (ret == -ENOENT)
		STING_ERR(0, "failed to create symlink: [%s -> %s]\n", source, target);

restore:
	/* Restore original creds */
	revert_creds(old_cred);

	if (ret == 0) {
		/* Success! */
		sting_set_res_type(current, ADV_RES);
		STING_LOG("Symlink attack launched: [%s,%lx], script entrypoint: [%s,%d], "
				"source: [%s], proc euid: [%d], attacker uid: [%d], "
				"process: [%s], link to [%s], system call: [%d]\n",
				current->comm, ept_offset_get(&current->user_stack),
				int_ept_exists(&current->user_stack) ? int_ept_filename_get(&current->user_stack) : "(null)",
				int_ept_exists(&current->user_stack) ? int_ept_lineno_get(&current->user_stack) : 0,
				source, current->cred->fsuid, uid_array[att_uid_ind][0],
				current->comm, target, sn);
		/* Set xattr on attacker symlink */
		ret = set_attacked(source, DONT_FOLLOW);
		if (ret < 0) {
			printk(KERN_INFO STING_MSG "Labeling %s failed: %d!\n", source, ret);
		}
		/* Create existing file if needed */
		if ((flag & CREATE_FILE_EXISTENT)
				|| (flag & CREATE_DIR)) {
			/* If existing file/dir requested, create it */
			if (flag & CREATE_FILE_EXISTENT) {
				ret = file_create(target, parent, REASON_TARGET, T_REG, sn, att_uid_ind);
			} else if (flag & CREATE_DIR) {
				ret = file_create(target, parent, REASON_TARGET, T_DIR, sn, att_uid_ind);
			}
			if (ret < 0) {
				printk(KERN_INFO STING_MSG "Actual create %s failed!\n", target);
			} else {
				sting_set_res_type(current, NORMAL_RES);
				ret = set_attacked(target, FOLLOW);
				if (ret < 0) {
					printk(KERN_INFO STING_MSG "Labeling target of %s failed: %d!\n", source, ret);
				}
			}
		}
	} else {
		STING_LOG("sting: [%d] couldn't create [%s] although has permission!\n",
			uid_array[att_uid_ind][0], source);
	}

	dput(child);
out:
	BUG_ON(current->cred != current->real_cred);
	BUG_ON(current->cred->group_info != current->real_cred->group_info);
	sting_set_res_type(current, c_res_type);

	return ret;
}

int should_skip(char __user *filename)
{
	if (!filename)
		return 0;
	if (!strncmp(filename, "/tmp/", 5))
		return 1;
//	if (!strcmp(current->comm, "tempfile") ||
//		(!strcmp(current->comm, "postdrop")) || (!strncmp(filename, "file", 4))) {
//	(!strncmp(filename, "/tmp/", 5) && !strncmp(filename, "file", 4))) { // && !(hack_ctr++ % 8)) {
//		printk(KERN_INFO STING_MSG "Allowing: %s: %s\n", filename, current->comm);
//		return 1;
//	}
	return 0;
}


static int get_attacked_path(char *fname, struct path *path)
{
	int err = 0;
	/* first, initial file */
	err = kern_path(fname, 0, path);

	return err;
}

/* don't drop reference to old path. don't get reference to
   new path */
void temp_set_fs_pwd(struct fs_struct *fs, struct path *path)
{
	struct path old_pwd;

	spin_lock(&fs->lock);
	write_seqcount_begin(&fs->seq);
	old_pwd = fs->pwd;
	fs->pwd = *path;
	write_seqcount_end(&fs->seq);
	spin_unlock(&fs->lock);
}

void temp_switch_cwd(struct path *new, struct path *old)
{
	get_fs_pwd(current->fs, old);
	temp_set_fs_pwd(current->fs, new);
}

void temp_restore_cwd(struct path *old)
{
	path_put(old); /* due to get_fs_pwd */
	temp_set_fs_pwd(current->fs, old);
}

/**
 * sting_launch_attack() - Launch attack
 * @fname:			Resource name (last component) relative to @parent
 * @parent:			Parent path
 * @a_ind:			Identity of attacker (index in uid_array)
 * @attack_type:	%SYMLINK, %HARDLINK, %SQUAT
 * @sting:			struct sting (whose path and target_path are filled in)
 */

int sting_launch_attack(char *source, struct path *parent,
		int a_ind, int attack_type, struct sting *sting)
{
	int tret = 0;
	struct pt_regs *ptregs = task_pt_regs(current);
	int sn = ptregs->orig_ax;

	struct path old_cwd;
	struct path child;
	struct nameidata *nd;

	char *target = NULL;
	uid_t uid = current->cred->fsuid;

	target = kzalloc(PATH_MAX, GFP_ATOMIC);
	if (!target)
		return -ENOMEM;


	/* chdir to parent */
	temp_switch_cwd(parent, &old_cwd);

	switch(attack_type) {
	case SYMLINK:
		if (in_set(sn, create_set) || bind_call(sn)) {
			if (((sn == __NR_open) && (ptregs->cx & O_CREAT)
			&& (!(ptregs->cx & O_NOFOLLOW))) ||
			(sn == __NR_creat) ||
			((sn == __NR_openat) && (ptregs->dx & O_CREAT)
			&& (!(ptregs->dx & O_NOFOLLOW)))
			) {
				/* Symlink to non-existent file */
				get_new_target_file(source, target, uid);
				tret = symlink_create(source, target, parent, CREATE_FILE_NONEXISTENT, sn,
						a_ind);
			} else {
				/* Symlink to existing file of right type -
				 these don't follow symlinks */
				/* These below create-like calls won't follow
				   symlinks, so no use creating symlinks to
				   new files */
				/* TODO: Other types */
				if (sn == __NR_mkdir || sn == __NR_mkdirat) {
					get_existing_target_dir(source, target, uid);
					tret = symlink_create(source, target, parent, CREATE_DIR, sn, a_ind);
				} else {
					get_existing_target_file(source, target, uid);
					tret = symlink_create(source, target, parent, CREATE_FILE_EXISTENT, sn,
							a_ind);
				}
			}
		} else if (in_set(sn, use_set)) {
			/* Symlink to existing file of right type */
			/* Doesn't make sense for sockets */
			if (sn == __NR_chdir) {
				get_existing_target_dir(source, target, uid);
				tret = symlink_create(source, target, parent, CREATE_DIR, sn, a_ind);
			} else {
				get_existing_target_file(source, target, uid);
				tret = symlink_create(source, target, parent, CREATE_FILE_EXISTENT, sn, a_ind);
			}
		}
		break;
	case SQUAT:
		/* Program may check for link, but may not check permissions or
		 return value EEXIST */
		if (in_set(sn, create_set) || bind_call(sn)) {
			if (sn == __NR_mkdir || sn == __NR_mkdirat)
				tret = file_create(source, parent, REASON_SQUAT, T_DIR, sn, a_ind);
			else if (sn == __NR_socketcall) /* bind */
				tret = file_create(source, parent, REASON_SQUAT, T_SOCK, sn, a_ind);
			else
				tret = file_create(source, parent, REASON_SQUAT, T_REG, sn, a_ind);
		} else if (in_set(sn, use_set) || connect_call(sn)) {
			if (sn == __NR_chdir); /* HACK */
				// tret = file_create(source, parent, REASON_SQUAT, T_DIR, sn, a_ind);
			else if (sn == __NR_socketcall) /* connect */
				tret = file_create(source, parent, REASON_SQUAT, T_SOCK, sn, a_ind);
			else
				tret = file_create(source, parent, REASON_SQUAT, T_REG, sn, a_ind);
		}
		break;
	case HARDLINK:
		/* Can't create hardlink to non-existent file */
		if (in_set(sn, create_set) || bind_call(sn) ||
		in_set(sn, use_set) || connect_call(sn)) {
			/* TODO: Other types */
			if (sn == __NR_chdir)  {
				/* OS limitation: Can't create hardlink to directory */
				;
			} else if (sn == __NR_socketcall && bind_call(sn)) {
				/* connect to a hardlink to a socket */
				/* connecting program may check for symlink but not owner */
				/* Does this add anything apart from IPC squat?
				   We could hardlink to a root-owned socket and get around
				   owner restriction during connect, but this requires knowledge
				   during stat() that file checked is supposed to be socket, so
				   we can create the hardlink then.
				   Currently no such knowledge is tracked. */

				/* High -> low redirection */
				get_existing_target_file(source, target, uid);
				tret = hardlink_create(source, target, parent, T_SOCK, sn, a_ind);
			} else {
				get_existing_target_file(source, target, uid);
				tret = hardlink_create(source, target, parent, T_REG, sn, a_ind);
			}
		}
		break;
	default:
		STING_ERR(0, "invalid attack type");
		tret = -EINVAL;
	}

	#if 0
	if (rt->check_find) {
		if (in_set(sn, check_set)) {
			/* TODO: Run with both is_dir = 1 and 0 */
			file_create(source, REASON_TOCTTOU_RUNTIME, T_REG, sn, a_ind);
		}
	}
	#endif
// out_eexist:

	/* get changed path (we do it in caller itself) */
	if (tret == 0) {
		int r;
		sting_set_res_type(current, ADV_NORMAL_RES);
		/* get reference to launched attack's dentry */
		/* TODO: reduce the number of name resolutions by using vfs directly
		 * and filling in the following inside symlink/hardlink/file create */
		/* path_put for these paths are done by caller */
		r = kern_path(source, 0, &sting->path);
		if (r < 0) {
			STING_ERR(0, "Error getting dentry of launched attack: [%s]\n", source);
			tret = r;
		}

		if (attack_type & (SYMLINK | HARDLINK)) {
			sting->target_path.dentry = sting->target_path.mnt = NULL;
			r = kern_path(target, 0, &sting->target_path);
			if (r < 0 && r != -ENOENT) {
				STING_ERR(0, "Error getting dentry of launched attack's target: [%s]\n", source);
				tret = r;
			}
		}
	}

	/* restore cwd */
	temp_restore_cwd(&old_cwd);
	if (target)
		kfree(target);
	return tret;
}
EXPORT_SYMBOL(sting_launch_attack);
