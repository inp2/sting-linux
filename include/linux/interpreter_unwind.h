/*
 * Copyright (c) 2011-2012 Hayawardh Vijayakumar
 * Copyright (c) 2011-2012 Systems and Internet Infrastructure Security Lab
 * Copyright (c) 2011-2012 The Pennsylvania State University
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _INTERPRETER_UNWIND_H
#define _INTERPRETER_UNWIND_H

#include <linux/user_unwind.h>
#include <linux/sched.h>

static inline char *int_ept_filename_get(struct user_stack_info *us)
{
	return (us->int_trace.nr_entries > 0) ?
		(us->int_trace.int_filename[0]) : "(null)";
}

static inline unsigned long int_ept_lineno_get(struct user_stack_info *us)
{
	return (us->int_trace.nr_entries > 0) ? (us->int_trace.entries[0]) : 0;
}

static inline int int_ept_exists(struct user_stack_info *us)
{
	return (us->int_trace.nr_entries > 0);
}

extern int is_interpreter(struct task_struct *t);
extern void copy_interpreter_info(struct task_struct *c, struct task_struct *p);
extern struct int_bt_info *on_script_behalf(struct user_stack_info *us);
extern int user_interpreter_unwind(struct user_stack_info *us);

#endif
