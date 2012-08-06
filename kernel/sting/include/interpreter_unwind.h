static inline char *int_ept_filename_get(struct user_stack_info *us)
{
	return (us->int_trace.nr_entries > 0) ? (us->int_filename[0]) : NULL; 
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
