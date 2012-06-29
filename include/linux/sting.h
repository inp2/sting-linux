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

extern void sting_syscall_begin(void);

/* Logging */

#define STING_LOG_FILE "sting_log"
extern struct rchan *sting_log_rchan;
#define STING_LOG(...) { \
	char *log_str = NULL; \
	log_str = kasprintf(GFP_ATOMIC, __VA_ARGS__); \
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
