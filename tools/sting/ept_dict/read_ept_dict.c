/* reads a dump from /sys/kernel/debug/ept_dict_dump* */

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include "ept_dict.h"

#define SYMLINK 0x1
#define HARDLINK 0x2
#define SQUAT 0x4

#define ATTACK_CHECKED_SHIFT 8
#define ATTACK_VULNERABLE_SHIFT 0

#define ATTACK_CHECKED(h, a) (bool_to_str((h >> ATTACK_CHECKED_SHIFT) & a))
#define ATTACK_VULNERABLE(h, a) (bool_to_str((h >> ATTACK_VULNERABLE_SHIFT) & a))

static inline ino_t ept_inode_get(struct user_stack_info *us)
{
    return us->trace.vma_inoden[us->trace.ept_ind];
}

static inline unsigned long ept_offset_get(struct user_stack_info *us)
{
    return us->trace.entries[us->trace.ept_ind] - us->trace.vma_start[us->trace.ept_ind];
}

static inline unsigned long us_offset_get(struct user_stack_info *us, int i)
{
    return us->trace.entries[i] - us->trace.vma_start[i];
}

static inline char *int_ept_filename_get(struct user_stack_info *us)
{
    return (us->int_trace.nr_entries > 0) ?
        (us->int_trace.int_filename[0]) : "(null)";
}

static inline unsigned long int_ept_lineno_get(struct user_stack_info *us)
{   
    return (us->int_trace.nr_entries > 0) ? (us->int_trace.entries[0]) : 0;
}

static inline void sting_log_full_stack(struct user_stack_info *us)
{   
    int i = 0;
    printf(" full_stack (frame making syscall is first): [");
    for (i = 0; i < us->trace.nr_entries - 1; i++) 
        printf("(vma_inode: [%lu], offset: [%lx]), ",
                us->trace.vma_inoden[i], us_offset_get(us, i));
    printf("]\n");
}

char *bool_to_str(int val)
{
	if (val)
		return "yes"; 
	else
		return "no"; 
}

int main(int argc, char **argv)
{
	int fd, n, i = 0; 
	struct ept_dict_entry et; 	
	int a_h; /* attack_history */
	
	if (argc < 2) {
		printf("%s [ept_dict_dump file name]\n", argv[0]); 
		exit(0);
	}
	
	fd = open(argv[1], O_RDONLY); 

	while ((n = read(fd, &et, sizeof(et)))) {
		printf("-------------------\n"); 
		printf("entrypoint: [%s:%lx:%s,%lu]\n", 
			et.val.comm, ept_offset_get(&et.key.user_stack), 
			int_ept_filename_get(&et.key.user_stack), 
			int_ept_lineno_get(&et.key.user_stack)); 
		a_h = et.val.attack_history; 

		printf("attack history: \n\t"
			"checked: squat: %s symlink: %s hardlink: %s\n\t"
			"vulnerable: squat: %s symlink: %s hardlink: %s\n", 
			ATTACK_CHECKED(a_h, SQUAT), ATTACK_CHECKED(a_h, SYMLINK), 
			ATTACK_CHECKED(a_h, HARDLINK), 
			ATTACK_VULNERABLE(a_h, SQUAT), ATTACK_VULNERABLE(a_h, SYMLINK), 
			ATTACK_VULNERABLE(a_h, HARDLINK)
			); 
		sting_log_full_stack(&et.key.user_stack); 
		printf("-------------------\n"); 
	}
}
