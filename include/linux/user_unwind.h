/*
 * Copyright (c) 2011-2012 Hayawardh Vijayakumar
 * Copyright (c) 2011-2012 Systems and Internet Infrastructure Security Lab
 * Copyright (c) 2011-2012 The Pennsylvania State University
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef UNWIND_H
#define UNWIND_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/stacktrace.h>
#else
#include <sys/types.h>
#endif

#define USER_STACK_MAX 16
#define INT_FNAME_MAX 32

/* Same as stack_trace except static size */
struct static_stack_trace {
	unsigned int nr_entries, max_entries;
	unsigned long entries[USER_STACK_MAX]; /* ip */
	unsigned long stack_bases[USER_STACK_MAX]; /* sp - for local vars */

	int bin_ip_exists; /* Does entrypoint exist in program? */
	int ept_ind; /* Entrypoint index */
	/* inode and start address for each VMA in program trace */
	ino_t vma_inoden[USER_STACK_MAX];
	unsigned long vma_start[USER_STACK_MAX];
};

/* interpreter stack trace */
struct interpreter_stack_trace {
	unsigned int nr_entries, max_entries;
	/* line numbers */
	unsigned long entries[USER_STACK_MAX];
	/* filename for each script file in the stack trace */
	char int_filename[USER_STACK_MAX][INT_FNAME_MAX];
};

struct user_stack_info {
	struct static_stack_trace trace;
	struct interpreter_stack_trace int_trace;
};

#ifdef __KERNEL__
extern void user_unwind(struct task_struct *);
#endif

#endif /* UNWIND_H */
