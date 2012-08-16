#ifndef UNWIND_H
#define UNWIND_H

#include <linux/types.h>
#include <linux/stacktrace.h>

// extern int unw_user_dict_set_value(ino_t, char *); 
// extern int unw_user_dict_get_value(ino_t, char *); 

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

extern void user_unwind(struct task_struct *); 
#endif /* UNWIND_H */
