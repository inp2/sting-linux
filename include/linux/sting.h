#include <linux/types.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/path.h>
#include <linux/user_unwind.h>

#define STING_MSG "sting: "

#define STING_MAX_PENDING 16

#define STING_DBG_ON 0
#define STING_ERR_LVL 0

#define STING_DBG(s, ...) \
	do { \
		if (STING_DBG_ON == 1) { \
			printk(KERN_INFO STING_MSG "debug: [%s:%05d]: " s, \
					__FUNCTION__, __LINE__, ## __VA_ARGS__); \
		} \
	} while (0)

#define STING_ERR(l, s, ...) \
	do { \
			if (l <= STING_ERR_LVL) { \
				printk(KERN_INFO STING_MSG "error: [%s:%05d]: " s, \
						__FUNCTION__, __LINE__, ## __VA_ARGS__); \
			} \
	} while (0)

#define STING_SYSCALL(call) { \
	set_fs(KERNEL_DS); \
	current->sting_request++; \
	call; \
	current->sting_request--; \
	set_fs(old_fs); \
}

#define STING_CALL(call) { \
	current->sting_request++; \
	call; \
	current->sting_request--; \
}

extern void sting_syscall_begin(void);
void sting_process_exit(void);

/* logging */

#define STING_LOG_FILE "sting_log"
extern struct rchan *sting_log_rchan;
#define STING_LOG(str, ...) { \
	char *log_str = NULL; \
	log_str = kasprintf(GFP_ATOMIC, "[%s:%d]: " str, __FILE__, __LINE__, __VA_ARGS__); \
	if (log_str) { \
		current->sting_request++; \
		relay_write(sting_log_rchan, log_str, strlen(log_str) + 1); \
		current->sting_request--; \
		kfree(log_str); \
	} \
}


#define STING_LOG_ALLOCED(s) { \
	if (s) { \
		current->sting_request++; \
		relay_write(sting_log_rchan, s, strlen(s) + 1); \
		current->sting_request--; \
		kfree(log_str); \
	} \
}

/* current attacks (stings) */

#define INT_FNAME_MAX 32

struct sting {
	struct list_head list;
	pid_t pid;
	ino_t ino;
	unsigned long offset;
	char int_filename[INT_FNAME_MAX];
	unsigned long int_lineno;
	struct path path;
	int attack_type;
	int adv_uid_ind; /* TODO: mac */
};

#define MATCH_PID 		0x1
#define MATCH_EPT 		0x2
#define MATCH_DENTRY 	0x4

// extern void sting_list_add(struct sting *st);
// extern void sting_list_del(struct sting *st);
// extern struct sting *sting_list_get(struct sting *st, int flags);

/* goes into interpreter_unwind.h, here because copy_process() needs it */
int user_interpreter_unwind(struct user_stack_info *us);
void copy_interpreter_info(struct task_struct *c, struct task_struct *p);
struct int_bt_info *on_script_behalf(struct user_stack_info *us);

/* goes into user_unwind.h */
#define VMA_INO(vma) (vma->vm_file->f_dentry->d_inode->i_ino)
#define EXE_INO(t) (t->mm->exe_file->f_dentry->d_inode->i_ino)

#define EPT_VMA_OFFSET(addr, us) ((addr) + (us->trace.vma_start[us->trace.ept_ind]))
#define EPT_INO(t) (t->user_stack.trace.vma_inoden[t->user_stack.trace.ept_ind])

/* TODO: Below three functions should be in user_unwind.h */

static inline ino_t ept_inode_get(struct user_stack_info *us)
{
	return us->trace.vma_inoden[us->trace.ept_ind];
}

static inline unsigned long ept_offset_get(struct user_stack_info *us)
{
	return us->trace.entries[us->trace.ept_ind] - us->trace.vma_start[us->trace.ept_ind];
}

static inline int valid_user_stack(struct user_stack_info *us)
{
	return (us->trace.entries[0] > 0);
}


/* from permission.h, used by unionfs */
/* simple dac adversary */
static inline int sting_adversary(uid_t a, uid_t v)
{
	/* adversary is not root and not victim */
	return ((a != 0) && (a != v));
}

extern int sting_already_launched(struct dentry *dentry);
