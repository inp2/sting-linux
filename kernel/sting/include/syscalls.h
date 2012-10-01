#ifndef _STING_SYSCALLS_H
#define _STING_SYSCALLS_H
#include <asm/unistd.h>
#include <linux/ptrace.h>
#include <linux/fcntl.h>
#include <linux/net.h>

/* system call sets */
static int check_set[] = {
	__NR_access,
	__NR_stat,
	__NR_lstat,
	__NR_stat64,
	__NR_lstat64,
	__NR_fstatat64,
	__NR_faccessat,
	__NR_statfs,
	__NR_statfs64,
	__NR_lgetxattr,
	__NR_llistxattr,
	__NR_listxattr,
	__NR_getxattr,
	-1
};

/* System calls creating resources (and thus namespace bindings) */
static int create_set[] = {
	/* __NR_open, 2nd - O_CREAT */
	__NR_creat,
	__NR_link, /* second argument */
	__NR_mknod,
	__NR_rename, /* second argument */
	__NR_mkdir,
	__NR_symlink, /* second argument */
	/* __NR_socketcall (bind) */
	/* __NR_openat, 3rd - O_CREAT */
	__NR_mkdirat,
	__NR_mknodat,
	__NR_linkat,
	__NR_symlinkat,
	-1
};

/* System calls using resources (and thus traversing namespace bindings) */
static int use_set[] = {
	/* __NR_open, 2nd - ~O_CREAT */
	/* __NR_unlink, */
	/* __NR_execve, */
	// __NR_chdir,
	__NR_chmod,
	__NR_mount,
	__NR_utime,
	__NR_rename,
	__NR_rmdir,
	__NR_readlink,
	__NR_truncate,
	__NR_chown,
	__NR_truncate64,
	__NR_lchown32,
	__NR_mount,
	__NR_setxattr,
	__NR_lsetxattr,
	// __NR_getxattr,
	// __NR_lgetxattr,
	// __NR_listxattr,
	// __NR_llistxattr,
	__NR_removexattr,
	__NR_lremovexattr,
	__NR_utimes,
	/* __NR_openat, 3rd - ~O_CREAT */
	__NR_fchownat,
	__NR_futimesat,
	/* __NR_unlinkat, */
	__NR_renameat,
	__NR_readlinkat,
	__NR_fchmodat,
	/* __NR_socketcall (connect) */
	-1
};

/* These system calls won't follow the last component if it is a symlink, or will act on the link itself.
   If in this set, LOOKUP_FOLLOW should not be set for the name resolution */
static int nosym_set[] = {
	/* __NR_open 2nd - O_NOFOLLOW */
	/* __NR_openat 3rd - O_NOFOLLOW */
	/* __NR_utimensat 4th - AT_SYMLINK_NOFOLLOW */
	/* __NR_linkat 5th - ~AT_SYMLINK_FOLLOW (for first argument) */
	/* __NR_name_to_handle_at 5th - ~AT_SYMLINK_FOLLOW */
	/* __NR_socketcall bind */
	__NR_link, /* second argument */
	__NR_unlink,
	__NR_mknod,
	__NR_rename,
	__NR_mkdir,
	__NR_rmdir,
	__NR_symlink, /* second argument */
	__NR_readlink,
	__NR_lstat,
	__NR_lstat64,
	__NR_lchown32,
	__NR_lsetxattr,
	__NR_lgetxattr,
	__NR_llistxattr,
	__NR_lremovexattr,
	__NR_mkdirat,
	__NR_mknodat,
	__NR_unlinkat,
	__NR_renameat,
	__NR_symlinkat,
	__NR_readlinkat,
	-1
};

static int delete_set[] = {
	__NR_unlink,
	__NR_unlinkat,
	__NR_rmdir,
	__NR_rename,
	__NR_renameat,
	-1
};

static int first_arg_set[] = {
	__NR_open,
	__NR_creat,
	__NR_link,
	/* __NR_unlink, */
	/* __NR_execve, */
	// __NR_chdir,
	__NR_mknod,
	__NR_chmod,
	__NR_mount,
	__NR_utime,
	__NR_access,
	/* __NR_rename, */
	__NR_mkdir,
	/* __NR_rmdir, */
	__NR_chroot,
	__NR_symlink,
	__NR_readlink,
	__NR_uselib,
	__NR_swapon,
	__NR_truncate,
	__NR_statfs,
	__NR_swapoff,
	__NR_chown,
	__NR_truncate64,
	__NR_lchown32,
	__NR_mount,
	__NR_pivot_root,
	__NR_utimes,
	__NR_stat,
	__NR_lstat,
	__NR_stat64,
	__NR_lstat64,
	__NR_setxattr,
	__NR_lsetxattr,
	__NR_getxattr,
	__NR_lgetxattr,
	__NR_listxattr,
	__NR_llistxattr,
	__NR_removexattr,
	__NR_lremovexattr,
	__NR_statfs64,
	__NR_symlinkat,
	-1
};

/* System calls for which the second argument is a filename to resolve */
static int second_arg_set[] = {
	__NR_quotactl,
	__NR_inotify_add_watch,
	__NR_openat,
	__NR_mkdirat,
	__NR_mknodat,
	__NR_fchownat,
	__NR_futimesat,
	__NR_fstatat64,
	__NR_unlinkat,
	__NR_renameat,
	__NR_linkat,
	__NR_readlinkat,
	__NR_fchmodat,
	__NR_faccessat,
	__NR_utimensat,
	__NR_name_to_handle_at,
	-1
};

/* Special cases */
static inline int bind_call(int sn)
{
	struct pt_regs *ptregs = (struct pt_regs *)
			(current->thread.sp0 - sizeof (struct pt_regs));
	int call = (int) ptregs->bx;
	if (sn == __NR_socketcall && call == SYS_BIND)
		return 1;
	else
		return 0;

}

static inline int connect_call(int sn)
{
	struct pt_regs *ptregs = (struct pt_regs *)
			(current->thread.sp0 - sizeof (struct pt_regs));
	int call = (int) ptregs->bx;
	if (sn == __NR_socketcall && call == SYS_CONNECT)
		return 1;
	else
		return 0;

}

static inline int in_spcs_create_set(struct pt_regs *ptregs)
{
	int sn = ptregs->orig_ax;

	if ((((sn == __NR_open) && (((int) (ptregs->cx)) & O_CREAT))) ||
		(((sn == __NR_openat) && (((int) (ptregs->dx)) & O_CREAT))) ||
		bind_call(sn))
		return 1;

	return 0;
}

static inline int in_spcs_use_set(struct pt_regs *ptregs)
{
	int sn = ptregs->orig_ax;

	if (sn == __NR_open) {
		if (((int) ptregs->cx) & (O_CREAT)) // | O_DIRECTORY))
			return 0;
	} else if (sn == __NR_openat) {
		if (((int) ptregs->dx) & (O_CREAT)) // | O_DIRECTORY))
			return 0;
	} else if (!connect_call(sn)) {
		return 0;
	}

	return 1;
}

static inline int in_spcs_nosym_set(struct pt_regs *ptregs)
{
	int sn = ptregs->orig_ax;

	if (((sn == __NR_open) && (!(((int) ptregs->cx) & O_NOFOLLOW))) ||
		((sn == __NR_openat) && (((int) ptregs->dx) & O_NOFOLLOW)) ||
		((sn == __NR_utimensat) && (((int) ptregs->si) & AT_SYMLINK_NOFOLLOW)) ||
		((sn == __NR_linkat) && (((int) ptregs->di) & AT_SYMLINK_NOFOLLOW)) ||
		((sn == __NR_name_to_handle_at) && (!(((int) ptregs->di) & AT_SYMLINK_FOLLOW))) ||
		bind_call(sn))
		return 1;

	return 0;
}


static inline int in_set(int sn, int *array)
{
	int i;
	struct pt_regs *ptregs = task_pt_regs(current);

	if ((array == create_set) &&
			(in_spcs_create_set(ptregs)))
		return 1;
	else if ((array == use_set) &&
			(in_spcs_use_set(ptregs)))
		return 1;
	else if ((array == nosym_set) &&
			(in_spcs_nosym_set(ptregs)))
		return 1;

	for (i = 0; array[i] != -1; i++)
		if (sn == array[i])
			return 1;
	return 0;
}

extern char *get_syscall_fname(void);

#endif /* _STING_SYSCALLS_H */
