/*
 * Copyright (c) 2011-2012 Hayawardh Vijayakumar
 * Copyright (c) 2011-2012 Systems and Internet Infrastructure Security Lab
 * Copyright (c) 2011-2012 The Pennsylvania State University
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/* TODO: this file should only include the bare necessary exported functions
 * and declarations */

#ifndef _STING_H_
#define _STING_H_
#ifdef CONFIG_STING

#include <linux/types.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/path.h>
#include <linux/interpreter_unwind.h>
#include <linux/user_unwind.h>
#include <linux/lsm_audit.h>
#include <linux/relay.h>

#define STING_VULNERABLE 1
#define STING_IMMUNE -1

#define STING_MSG "sting: "

#define STING_MAX_PENDING 16

#define STING_DBG_ON 0
#define STING_ERR_LVL 0

/* TODO: get this from userspace */
#define ATTACKER_HOMEDIR "/home/attacker"

#define STING_DBG(s, ...) \
	do { \
		if (STING_DBG_ON == 1) { \
			printk(KERN_INFO STING_MSG "debug: [%s:%05d]: " s, \
					__func__, __LINE__, ## __VA_ARGS__); \
		} \
	} while (0)

#define STING_ERR(l, s, ...) \
	do { \
			if (l <= STING_ERR_LVL) { \
				printk(KERN_INFO STING_MSG "error: [%s:%05d]: " s, \
						__func__, __LINE__, ## __VA_ARGS__); \
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

/* hooks exported by sting */
extern void sting_syscall_begin(void);
void sting_process_exit(void);
extern void sting_log_vulnerable_access(struct common_audit_data *a);
void sting_lwd(void);

/* TODO: Below five functions should be in user_unwind.h */

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

static inline int valid_user_stack(struct user_stack_info *us)
{
	return (us->trace.entries[0] > 0);
}

static inline int ept_match(struct user_stack_info *us1, struct user_stack_info *us2)
{
	if ((ept_inode_get(us1) != ept_inode_get(us2)) ||
			(ept_offset_get(us1) != ept_offset_get(us2)) ||
			(strcmp(int_ept_filename_get(us1), int_ept_filename_get(us2))) ||
			(int_ept_lineno_get(us1) != int_ept_lineno_get(us2)))
		return 1; /* no match */

	return 0; /* match */
}


/* logging */

#define STING_LOG_FILE "sting_log"
extern struct rchan *sting_log_rchan;
#define STING_LOG(str, ...) { \
	char *log_str = NULL; \
	log_str = kasprintf(GFP_ATOMIC, "[%s:%d]: " str, \
			__FILE__, __LINE__, ##__VA_ARGS__); \
	if (log_str) { \
		current->sting_request++; \
		relay_write(sting_log_rchan, log_str, strlen(log_str)); \
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


static inline void sting_log_full_stack(struct user_stack_info *us)
{
	int i = 0;
	STING_LOG(" full_stack: [");
	for (i = 0; i < us->trace.nr_entries - 1; i++)
		STING_LOG("(vma_inode: [%lu], offset: [%lx]), ",
				us->trace.vma_inoden[i], us_offset_get(us, i));
	STING_LOG("]\n");
}

#define STING_LOG_STING_DETAILS(m, str) { \
	STING_LOG("message: " str ": sting_entrypoint: [%s:%lx:%s,%lu], " \
		"resource: [%s], " \
		"system call: [%d], attack_type: [%s], " \
		"adversary uid: [%d], victim uid: [%d]\n", \
		m->comm, ept_offset_get(&m->user_stack), \
		int_ept_filename_get(&m->user_stack), \
		int_ept_lineno_get(&m->user_stack), \
		m->pathname, \
		syscall_get_nr(current, task_pt_regs(current)), \
		sting_attack_to_str(m->attack_type), \
		uid_array[m->adv_uid_ind][0], \
		m->victim_uid); \
}


/* current attacks (stings) */

#define INT_FNAME_MAX 32

/* temporary in-memory structure describing stings taking place.
 * created when launching an attack, destroyed when we know
 * the result of an attack. */
struct sting {
	/* process info */
	struct list_head list;
	pid_t pid;
	char comm[TASK_COMM_LEN];
	struct user_stack_info user_stack;

	/* rollback info */
	char pathname[512];
	struct path path;
	ino_t path_ino; /* path->d_inode.i_ino */
	struct path target_path;
	ino_t target_path_ino; /* target_path->d_inode.i_ino */

	/* sting info */
	int attack_type;
	int syscall_nr;
	int syscall_nr_subtype; /* for socketcall */
	uid_t victim_uid;
	int adv_uid_ind; /* TODO: mac */
};

#define MATCH_PID	0x1
#define MATCH_EPT	0x2
#define MATCH_INO	0x8

/* goes into user_unwind.h */
#define VMA_INO(vma) (vma->vm_file->f_dentry->d_inode->i_ino)
#define EXE_INO(t) (t->mm->exe_file->f_dentry->d_inode->i_ino)

#define EPT_VMA_OFFSET(addr, us) \
			((addr) + (us->trace.vma_start[us->trace.ept_ind]))
#define EPT_INO(t) \
			(t->user_stack.trace.vma_inoden[t->user_stack.trace.ept_ind])

/* from permission.h, used by unionfs */
/* simple dac adversary */
static inline int sting_adversary(uid_t a, uid_t v)
{
	/* adversary is not root and not victim */
	return ((a != 0) && (a != v));
}

extern int sting_already_launched(struct dentry *dentry);
#else
void sting_syscall_begin(void)
{

}

void sting_process_exit(void)
{

}

void sting_log_vulnerable_access(struct common_audit_data *a)
{

}
#endif /* CONFIG_STING */

#ifdef CONFIG_STING
/* unionfs-related */
#define STING_ADV_BID 0
#define STING_NON_ADV_BID 1

/* status of current resolution - marked during shadow resolution */

#define RES_BRANCH_MASK 0xF
/* default resolution */
#define NA_RES 0x0
/* only adversarial resource shown. for launch.
 * bstart = bend = 0. Error if adversarial resource is not
 * available. Used by launch attack and rollback
 */
#define ADV_RES 0x1
/* adversarial resource if available, else normal.
 * for shadow resolution. bstart = 0 (traditional unionfs) */
#define ADV_NORMAL_RES 0x2
/* only normal resource shown.
 * non-adversarial last resource. */
#define NORMAL_RES 0x4

/* resolution intents, in addition to branch */
/* in avc_has_perm, do not mark taint if called from sting. */
#define RES_INTENT_MASK 0xF0
#define LAUNCH_INT 0x10
#define SHADOW_RES_INT 0x20
#define ROLLBACK_INT   0x40
#define NORMAL_RES_INT 0x80

#ifdef CONFIG_STING_UNION_FS
static inline int sting_set_res_type(struct task_struct *t, int type)
{
	int c_res_type = (t->sting_res_type & RES_BRANCH_MASK);
	t->sting_res_type = type;
	return c_res_type;
}

static inline int sting_set_res_intent(struct task_struct *t, int flag)
{
	int c_res_intent = (t->sting_res_type & RES_INTENT_MASK);
	t->sting_res_type |= flag;
	return c_res_intent;
}

static inline int sting_get_res_type(struct task_struct *t)
{
	return (t->sting_res_type & RES_BRANCH_MASK);
}

static inline int sting_get_res_intent(struct task_struct *t)
{
	return (t->sting_res_type & RES_INTENT_MASK);
}

/* we limit ourselves to only two branches --
 * STING_ADV_BID, STING_NON_ADV_BID */

/* given lowest possible start */
static inline int sting_res_branch_start(int cstart)
{
	switch (sting_get_res_type(current)) {
	case ADV_RES:
		return STING_ADV_BID;
	case ADV_NORMAL_RES:
		return (STING_ADV_BID < cstart) ? cstart : STING_ADV_BID;
	case NA_RES:
	case NORMAL_RES:
		return STING_NON_ADV_BID;
	default:
		BUG_ON(1);
	}
}

/* given highest possible end */
static inline int sting_res_branch_end(int cend)
{
	switch (sting_get_res_type(current)) {
	case ADV_RES:
		return STING_ADV_BID;
	case ADV_NORMAL_RES:
		return (STING_NON_ADV_BID > cend) ? cend : STING_NON_ADV_BID;
	case NA_RES:
	case NORMAL_RES:
		return STING_NON_ADV_BID;
	default:
		BUG_ON(1);
	}
}

static inline int sdbstart(void)
{
	switch (sting_get_res_type(current)) {
	case ADV_RES:
	case ADV_NORMAL_RES:
		return STING_ADV_BID;
	case NORMAL_RES:
		return STING_NON_ADV_BID;
	default:
		BUG_ON(1);
	}
}

static inline int sdbend(void)
{
	switch (sting_get_res_type(current)) {
	case ADV_RES:
		return STING_ADV_BID;
	case ADV_NORMAL_RES:
	case NORMAL_RES:
		return STING_NON_ADV_BID;
	default:
		BUG_ON(1);
	}
}
#else
static inline int sting_set_res_type(struct task_struct *t, int type)
{
	return 0;
}

static inline int sting_set_res_intent(struct task_struct *t, int flag)
{
	return 0;
}

static inline int sting_get_res_type(struct task_struct *t)
{
	return 0;
}

static inline int sting_get_res_intent(struct task_struct *t)
{
	return 0;
}

#endif /* CONFIG_STING_UNION_FS */

extern int is_interpreter(struct task_struct *t);

#endif /* CONFIG_STING */

#endif /* _STING_H_ */
