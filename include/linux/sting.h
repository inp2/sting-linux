#include <linux/types.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/path.h>

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

struct sting {
	struct list_head list; 
	pid_t pid; 
	ino_t ino; 
	unsigned long offset; 
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
