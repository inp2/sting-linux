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

extern void sting_syscall_begin(void); 
