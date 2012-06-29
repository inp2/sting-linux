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

#include <asm/syscall.h>

#include "launch_attack.h"
#include "syscalls.h"
#include "permission.h"

/* Internal flags */
#define CREATE_FILE_NONEXISTENT 0x1
#define CREATE_FILE_EXISTENT 0x2
#define CREATE_DIR 0x4

#define DONT_FOLLOW 0
#define FOLLOW 1

#define SYMLINK_FILE_INFIX "symlink"
#define HARDLINK_FILE_INFIX "hardlink"

#define ATTACK_DIR_PREFIX "/attacker/"
#define ATTACK_EXISTING_FILE_PREFIX "/existing_file"
#define ATTACK_NEW_FILE_PREFIX "/new_file"
#define ATTACK_EXISTING_DIR_PREFIX "/existing_dir"

#define TYPE_HARDLINK 0x1
#define TYPE_SYMLINK 0x2


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
 * @type: %TYPE_SYMLINK/HARDLINK
 */

char *get_existing_target_file(uid_t uid, char *filename, char *fname, int type)
{
	char uid_str[6];

	sprintf(uid_str, "%d", uid);
	strcpy(fname, ATTACK_DIR_PREFIX);
	strcat(fname, uid_str);
	strcat(fname, ATTACK_EXISTING_FILE_PREFIX);
	strcat(fname, "_");
	strcat(fname, (type == TYPE_SYMLINK) ? SYMLINK_FILE_INFIX : HARDLINK_FILE_INFIX);
	strcat(fname, "_");
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

char *get_existing_target_dir(uid_t uid, char *filename, char *fname)
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

char *get_new_target_file(uid_t uid, char *filename, char *fname)
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


/* Returns 0 if already checked */
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

/* Call as superuser, as permissions for sticky dir etc.,
   are not available to all */
int set_attacked(char __user *filename, int follow)
{
	int tret = 0;
	mm_segment_t old_fs = get_fs();

	/* TODO: The maximum length possible is XATTR_LIST_MAX */
	if (!follow) {
		STING_SYSCALL(tret = sys_lsetxattr(filename, ATTACKER_XATTR_STRING, ATTACKER_XATTR_VALUE, sizeof(ATTACKER_XATTR_VALUE), 0));
	} else {
		STING_SYSCALL(tret = sys_setxattr(filename, ATTACKER_XATTR_STRING, ATTACKER_XATTR_VALUE, sizeof(ATTACKER_XATTR_VALUE), 0));
	}
	if (tret == -ENOTSUPP) {
		printk(KERN_INFO STING_MSG "Xattrs not supported!\n");
	}
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

int file_create(char __user *filename, int reason, int type, int sn, int att_uid_ind)
{
	const struct cred *old_cred;
	int ret = 0;
	mm_segment_t old_fs = get_fs();
	int exists = 0;
	struct stat64 buf;

	exists = already_exists(filename, DONT_FOLLOW, &buf);

	/* If REASON_TOCTTOU_RUNTIME,  we still want to be able to delete afterwards, so
	   create with attacker permission, not process permission */
	/* With process permission may execute further paths */
	if ((reason == REASON_TARGET) || (reason == REASON_NORMAL_RUNTIME)) {
		/* Create the file with process permission */
		/* This is only done in /attacker/uid/ */
		if (type == T_REG) {
			STING_SYSCALL(ret = sys_open(filename, O_CREAT, 0755));
			if (ret > 0) {
				STING_SYSCALL(sys_close(ret));
			}
		} else if (type == T_DIR) {
			STING_SYSCALL(ret = sys_mkdir(filename, 0777));
		}
		if ((ret < 0) && (ret != -EEXIST)) {
			printk(KERN_INFO STING_MSG "Can't create file/dir %s: %d?\n", filename, ret);
		}
		/* goto mark; */
	} else if ((reason == REASON_SQUAT) || (reason == REASON_TOCTTOU_RUNTIME)) {
		/* Change creds to attacker's */
		old_cred = set_creds(uid_array[att_uid_ind]);

		if (exists) {
			/* TODO: If REASON_SQUAT,
			   preserve contents */
			/* TODO: If TOCTTOU_RUNTIME,
			   no need to delete, as file
			   is already there */

			/* Try deleting first */
			STING_SYSCALL(ret = sys_unlink(filename));
			if (ret < 0) {
				if (ret == -ENOENT)
					printk(KERN_INFO STING_MSG "File found but not for delete?!\n");
				else if (ret == -EACCES)
					printk(KERN_INFO "attacker: att_uid_ind not working!\n");
				goto restore;
			} else {
				STING_LOG("Delete SUCCESS for Tocttou runtime!: %s, proc "
						"euid: %d attacker uid: %d, process: %s system call:  %d\n",
						filename, current->real_cred->fsuid,
						uid_array[att_uid_ind][0], current->comm, sn);
				# if 0
				printk(KERN_INFO STING_MSG "Delete SUCCESS for Tocttou runtime!: %s, proc euid: %d attacker uid: %d, process: %s system call: %d\n", filename, current->real_cred->fsuid, uid_array[att_uid_ind][0], current->comm, sn);
				log_str = kasprintf(GFP_ATOMIC, STING_MSG "Delete SUCCESS for Tocttou runtime!: %s, proc euid: %d attacker uid: %d, process: %s system call: %d\n", filename, current->real_cred->fsuid, uid_array[att_uid_ind][0], current->comm, sn);
				relay_write(wall_rchan, log_str, strlen(log_str) + 1);
				kfree(log_str);
				#endif
			}
		}

		/* Create the file */
		if (type == T_REG) {
			STING_SYSCALL(ret = sys_open(filename, O_CREAT, 0777));
			if (ret == -ENOENT) ;
//					printk(KERN_INFO STING_MSG "Directory creation required: %s\n", filename);
			if (ret > 0)
				sys_close(ret);
		} else if (type == T_SOCK) {
			int s_fd;
			struct sockaddr_un sock;
			/* To squat a socket, socket(), bind(), close() */
			STING_SYSCALL(s_fd = sys_socket(AF_UNIX, SOCK_STREAM, 0));
			if (s_fd > 0) {
				sock.sun_family = AF_UNIX;
				strcpy(sock.sun_path, filename);
				STING_SYSCALL(ret = sys_bind(s_fd,
					(struct sockaddr *) &sock,
					sizeof(struct sockaddr_un)));
				STING_SYSCALL(sys_close(s_fd));
			}
		} else if (type == T_DIR) {
			STING_SYSCALL(ret = sys_mkdir(filename, 0777));
			if (ret == -ENOENT) ;
//					printk(KERN_INFO STING_MSG "Directory creation required: %s\n", filename);
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
			filename, current->cred->fsuid,
			uid_array[att_uid_ind][0], current->comm, sn);
		} else if ((reason == REASON_TARGET) || (reason == REASON_NORMAL_RUNTIME)) {
			STING_LOG(
			"%s SUCCESS!: %s, proc euid: %d, process: %s, system call: %d\n",
			((reason == REASON_TARGET) ? "Target" :
			 ((reason == REASON_NORMAL_RUNTIME) ? "Normal Runtime" :
			 "Error")),
			filename, current->cred->fsuid,
			current->comm, sn);
		}

		/* Set xattr on created file if needed */
		if (reason == REASON_SQUAT || reason == REASON_TARGET) {
			ret = set_attacked(filename, DONT_FOLLOW);
			if (ret < 0)
				printk(KERN_INFO STING_MSG "Labeling %s failed: %d!\n", filename, ret);
		}
	}

	BUG_ON(current->cred != current->real_cred);
	BUG_ON(current->cred->group_info != current->real_cred->group_info);
	return ret;
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
 */

int hardlink_create(char __user *filename, int type, int sn, int att_uid_ind)
{
	const struct cred *old_cred;
	int ret = 0; /* index of attacker in uid_array */
	mm_segment_t old_fs = get_fs();
	char *tmp_f = kzalloc(PATH_MAX, GFP_ATOMIC);
	int exists = 0;
	int orig_fsuid = 0; /* Original UID of process */
	struct stat64 buf;

	if (!tmp_f)
		return -ENOMEM;

	exists = already_exists(filename, DONT_FOLLOW, &buf);
	orig_fsuid = current->cred->fsuid;

	/* Change creds to attacker's */
	old_cred = set_creds(uid_array[att_uid_ind]);
	get_existing_target_file(orig_fsuid, filename, tmp_f, TYPE_HARDLINK);
	/* TODO: Preserve file contents somehow */
	/* Try deleting first if exists */
	if (exists) {
		STING_SYSCALL(ret = sys_unlink(filename));
		if (ret < 0) {
			if (ret == -ENOENT) {
				printk(KERN_INFO STING_MSG "File found but not for delete?!\n");
			} else if (ret == -EACCES || ret == -EPERM) {
				STING_LOG("Cannot access! permission module error!: "
				"%s, proc euid: %d attacker uid: %d, process: %s system call: %d\n",
				filename, current->real_cred->fsuid, uid_array[att_uid_ind][0],
				current->comm, sn);
			} else {
				STING_LOG("Delete SUCCESS for hardlink!: %s, proc euid: "
						"%d attacker uid: %d, process: %s system call: %d\n",
						filename, current->real_cred->fsuid, uid_array[att_uid_ind][0]
						, current->comm, sn);
			}
			goto restore;
		}
	}

	/* Create the file as original user */
	/* TODO: Once everyone uses permission module, below revert_creds and set_creds
		will disappear */
	revert_creds(old_cred);
	ret = file_create(tmp_f, REASON_TARGET, type, sn, att_uid_ind);
	old_cred = set_creds(uid_array[att_uid_ind]);
	/* Create the hardlink */
	STING_SYSCALL(ret = sys_link(tmp_f, filename));
	if (ret == -ENOENT) ;
//			printk(KERN_INFO STING_MSG "Directory creation required: %s\n", filename);
	if (ret < 0) {
		if (ret == -EACCES || ret == -EPERM) {
			STING_LOG("Cannot access! permission module error!: %s, proc "
					"euid: %d attacker uid: %d, process: %s system call: %d\n",
					filename, current->real_cred->fsuid,
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
				"process: %s, link to %s, system call: %d\n", filename,
				current->cred->fsuid, uid_array[att_uid_ind][0],
				current->comm, tmp_f, sn);
		/* Set xattr on attacker hardlink */
		ret = set_attacked(filename, DONT_FOLLOW);
		if (ret < 0) {
			printk(KERN_INFO STING_MSG "Labeling %s failed: %d!\n", filename, ret);
		}
	}

	BUG_ON(current->cred != current->real_cred);
	BUG_ON(current->cred->group_info != current->real_cred->group_info);
	if (tmp_f)
		kfree(tmp_f);
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

int symlink_create(char __user *filename, int flag, int sn, int att_uid_ind)
{
	const struct cred *old_cred;
	int ret = 0;
	mm_segment_t old_fs = get_fs();
	char *tmp_f = kzalloc(PATH_MAX, GFP_ATOMIC);
	int exists = 0;
	int orig_fsuid = 0; /* Original UID of process */
	struct stat64 buf;

	if (!tmp_f)
		return -ENOMEM;

	exists = already_exists(filename, DONT_FOLLOW, &buf);

	orig_fsuid = current->cred->fsuid;

	/* Change creds to attacker's */
	old_cred = set_creds(uid_array[att_uid_ind]);

	if (flag == CREATE_FILE_NONEXISTENT) {
		/* Point to non-existent file */
		get_new_target_file(orig_fsuid, filename, tmp_f);
	} else if (flag == CREATE_FILE_EXISTENT) {
		/* Point to existing file */
		get_existing_target_file(orig_fsuid, filename, tmp_f, TYPE_SYMLINK);
	} else if (flag == CREATE_DIR) {
		/* Point to existing directory */
		get_existing_target_dir(orig_fsuid, filename, tmp_f);
	}

	if (exists) {
		/* TODO: If CREATE_FILE_EXISTENT,
		   then preserve file contents using
		rename, and do not call REASON_TARGET */
		/* Try deleting first */
		STING_SYSCALL(ret = sys_unlink(filename));
		if (ret < 0) {
			if (ret == -ENOENT)
				printk(KERN_INFO STING_MSG "File found but not for delete?!\n");
			goto restore;
		} else {
			STING_LOG("Delete SUCCESS for symlink!: %s, proc euid: %d "
					"attacker uid: %d, process: %s system call: %d\n",
					filename, current->real_cred->fsuid,
					uid_array[att_uid_ind][0], current->comm, sn);
		}
	}

	/* Create the symlink */
	STING_SYSCALL(ret = sys_symlink(tmp_f, filename));
	if (ret == -ENOENT) ;
//			printk(KERN_INFO STING_MSG "Directory creation required: %s\n", filename);

restore:
	/* Restore original creds */
	revert_creds(old_cred);

	if (ret == 0) {
		/* Success! */
		STING_LOG("Symlink SUCCESS!: %s, proc euid: %d attacker uid: %d, "
				"process: %s, link to %s, system call: %d\n", filename,
				current->cred->fsuid, uid_array[att_uid_ind][0],
				current->comm, tmp_f, sn);
		/* Set xattr on attacker symlink */
		ret = set_attacked(filename, DONT_FOLLOW);
		if (ret < 0) {
			printk(KERN_INFO STING_MSG "Labeling %s failed: %d!\n", filename, ret);
		}
		/* Create existing file if needed */
		if ((flag & CREATE_FILE_EXISTENT)
				|| (flag & CREATE_DIR)) {
			/* If existing file/dir requested, create it */
			if (flag & CREATE_FILE_EXISTENT) {
				ret = file_create(tmp_f, REASON_TARGET, T_REG, sn, att_uid_ind);
			} else if (flag & CREATE_DIR) {
				ret = file_create(tmp_f, REASON_TARGET, T_DIR, sn, att_uid_ind);
			}
			if (ret < 0) {
				printk(KERN_INFO STING_MSG "Actual create %s failed!\n", tmp_f);
			}
		}
	} else {
		printk(KERN_INFO "sting: [%d] couldn't create [%s] although has permission!\n",
			uid_array[att_uid_ind][0], filename);
	}

	BUG_ON(current->cred != current->real_cred);
	BUG_ON(current->cred->group_info != current->real_cred->group_info);
	if (tmp_f)
		kfree(tmp_f);
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

int sting_launch_attack(char *fname, int a_ind, int attack_type)
{
	int tret = 0;
	struct pt_regs *ptregs = task_pt_regs(current);
	int sn = ptregs->orig_ax;

	/* Not a syscall involving name resolution? */
	if (!fname)
		goto out;

	#if 0
	/* Cases of random filenames etc., allow through */
	if (should_skip(fname)) {
		goto out;
	}
	#endif

	/* If file exists and already marked,
	   attacker already played her card, move on */

	tret = check_already_attacked(fname, DONT_FOLLOW);
	if (tret == 0)
		goto out;

	/* TODO: Can we model this in terms of in_set() alone? */
	if (attack_type & SYMLINK) {
		if (in_set(sn, create_set) || bind_call(sn)) {
			if (((sn == __NR_open) && (ptregs->cx & O_CREAT)
			&& (!(ptregs->cx & O_NOFOLLOW))) ||
			(sn == __NR_creat) ||
			((sn == __NR_openat) && (ptregs->dx & O_CREAT)
			&& (!(ptregs->dx & O_NOFOLLOW)))
			) {
				/* Symlink to non-existent file */
				tret = symlink_create(fname, CREATE_FILE_NONEXISTENT, sn, a_ind);
			} else {
				/* Symlink to existing file of right type -
				 these don't follow symlinks */
				/* These below create-like calls won't follow
				   symlinks, so no use creating symlinks to
				   new files */
				/* TODO: Other types */
				if (sn == __NR_mkdir || sn == __NR_mkdirat)
					tret = symlink_create(fname, CREATE_DIR, sn, a_ind);
				else
					tret = symlink_create(fname, CREATE_FILE_EXISTENT, sn, a_ind);
			}
		} else if (in_set(sn, use_set)) {
			/* Symlink to existing file of right type */
			/* Doesn't make sense for sockets */
			if (sn == __NR_chdir)
				tret = symlink_create(fname, CREATE_DIR, sn, a_ind);
			else
				tret = symlink_create(fname, CREATE_FILE_EXISTENT, sn, a_ind);
		}
	} else if (attack_type & SQUAT) {
		/* Program may check for link, but may not check permissions or
		 return value EEXIST */
		if (in_set(sn, create_set) || bind_call(sn)) {
			if (sn == __NR_mkdir || sn == __NR_mkdirat)
				tret = file_create(fname, REASON_SQUAT, T_DIR, sn, a_ind);
			else if (sn == __NR_socketcall) /* bind */
				tret = file_create(fname, REASON_SQUAT, T_SOCK, sn, a_ind);
			else
				tret = file_create(fname, REASON_SQUAT, T_REG, sn, a_ind);
		} else if (in_set(sn, use_set) || connect_call(sn)) {
			if (sn == __NR_chdir)
				tret = file_create(fname, REASON_SQUAT, T_DIR, sn, a_ind);
			else if (sn == __NR_socketcall) /* connect */
				tret = file_create(fname, REASON_SQUAT, T_SOCK, sn, a_ind);
			else
				tret = file_create(fname, REASON_SQUAT, T_REG, sn, a_ind);
		}
	} else if (attack_type & HARDLINK) {

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
				tret = hardlink_create(fname, T_SOCK, sn, a_ind);
			} else {
				tret = hardlink_create(fname, T_REG, sn, a_ind);
			}
		}
	}

	#if 0
	if (rt->check_find) {
		if (in_set(sn, check_set)) {
			/* TODO: Run with both is_dir = 1 and 0 */
			file_create(fname, REASON_TOCTTOU_RUNTIME, T_REG, sn, a_ind);
		}
	}
	#endif
out:
	return tret;
}
EXPORT_SYMBOL(sting_launch_attack);
