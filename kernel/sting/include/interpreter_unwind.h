/*
 * Copyright (c) 2011-2012 Hayawardh Vijayakumar
 * Copyright (c) 2011-2012 Systems and Internet Infrastructure Security Lab
 * Copyright (c) 2011-2012 The Pennsylvania State University
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

static inline char *int_ept_filename_get(struct user_stack_info *us)
{
	return (us->int_trace.nr_entries > 0) ?
		(us->int_trace.int_filename[0]) : NULL;
}

static inline int int_ept_lineno_get(struct user_stack_info *us)
{
	return (us->int_trace.nr_entries > 0) ? (us->int_trace.entries[0]) : 0;
}

static inline int int_ept_exists(struct user_stack_info *us)
{
	return (us->int_trace.nr_entries > 0);
}

extern int is_interpreter(struct task_struct *t);
