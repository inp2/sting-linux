#ifndef UNWIND_H
#define UNWIND_H

#include <linux/types.h>
#include <linux/stacktrace.h>

// extern int unw_user_dict_set_value(ino_t, char *); 
// extern int unw_user_dict_get_value(ino_t, char *); 

#define USER_STACK_MAX 16

/* Same as stack_trace except static size */
struct static_stack_trace {
	unsigned int nr_entries, max_entries;
	int skip;	/* input argument: How many entries to skip */
	unsigned long entries[USER_STACK_MAX];
}; 

struct user_stack_info {
	struct static_stack_trace trace;
	int bin_ip_exists; /* Does entrypoint exist in program? */
	int ept_ind; /* Entrypoint index */
	ino_t vma_inoden[USER_STACK_MAX]; /* inodes for each VMA in trace */
	unsigned long vma_start[USER_STACK_MAX]; /* Start address for each VMA in trace */
}; 

extern void user_unwind(struct task_struct *); 
#endif /* UNWIND_H */
