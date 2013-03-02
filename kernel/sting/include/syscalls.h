/*
 * Copyright (c) 2011-2012 Hayawardh Vijayakumar
 * Copyright (c) 2011-2012 Systems and Internet Infrastructure Security Lab
 * Copyright (c) 2011-2012 The Pennsylvania State University
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _STING_SYSCALLS_H
#define _STING_SYSCALLS_H
#include <linux/unistd.h>
#include <linux/ptrace.h>
#include <linux/fcntl.h>
#include <linux/net.h>

extern int *check_set;
extern int *create_set;
extern int *use_set;
extern int *symlink_accept_set;
extern int *hardlink_accept_set;
extern int *squat_accept_set;
extern int *nosym_set;
extern int *delete_set;
extern int *first_arg_set;
extern int *second_arg_set;

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
		if (((int) ptregs->cx) & !(O_CREAT))
			return 1;
	} else if (sn == __NR_openat) {
		if (((int) ptregs->dx) & !(O_CREAT))
			return 1;
	} else if (connect_call(sn)) {
		return 1;
	}

	return 0;
}

static inline int in_spcs_nosym_set(struct pt_regs *ptregs)
{
	int sn = ptregs->orig_ax;

	if (((sn == __NR_open) && (!(((int) ptregs->cx) & O_NOFOLLOW))) ||
	    ((sn == __NR_openat) && (((int) ptregs->dx) & O_NOFOLLOW)) ||
	    ((sn == __NR_utimensat) && (((int) ptregs->si) & AT_SYMLINK_NOFOLLOW)) ||
	    ((sn == __NR_linkat) && (((int) ptregs->di) & AT_SYMLINK_NOFOLLOW)) ||
		((sn == __NR_name_to_handle_at) && (!(((int) ptregs->di) &
				AT_SYMLINK_FOLLOW))) ||
	    bind_call(sn))
		return 1;

	return 0;
}

static inline int in_spcs_squat_accept_set(struct pt_regs *ptregs)
{
	int sn = ptregs->orig_ax;

	if (connect_call(sn))
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
	else if ((array == squat_accept_set) &&
			(in_spcs_squat_accept_set(ptregs)))
		return 1;

	for (i = 0; array[i] != -1; i++)
		if (sn == array[i])
			return 1;
	return 0;
}

extern char *get_syscall_fname(void);
#endif /* _STING_SYSCALLS_H */
