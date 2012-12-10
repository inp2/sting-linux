/*
 * Copyright (c) 2011-2012 Hayawardh Vijayakumar
 * Copyright (c) 2011-2012 Systems and Internet Infrastructure Security Lab
 * Copyright (c) 2011-2012 The Pennsylvania State University
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#define INT_FNAME_MAX 32

struct ept_dict_key {
	/* normal user ept */
	ino_t ino;
	unsigned long offset;
	/* interpreter ept (assume first in stack) */
	char int_filename[INT_FNAME_MAX];
	unsigned long int_lineno;
};

struct adv_model {
	 /* below information is only useful if we insert
	  * entrypoints into dictionary independent of
	  * adversary access.  otherwise, all inserted
	  * entrypoints are adversary accessible under
	  * some adversary model. */

	/* how many times to get first adversary accessibility
	 * under this model? */
	int ctr_first_adv;
	/* is it accessible to adversary under this model? */
	int adversary_access;
};

#define MAX_PROC_NAME 32
struct ept_dict_val {
	/* TSC time when ept was first recorded */
	unsigned long time;
	/* how many times has this ept been accessed? */
	int ctr;
	/* name of process */
	char comm[MAX_PROC_NAME];

	struct adv_model dac;
	struct adv_model mac;

	/* format: 16 empty bits || checked (8 bits) || immune (8 bits) */
	/* immunity means only to attack type launched at this entrypoint,
	 * not immunity to attack types launched from other entrypoints */
	int attack_history;
};

#ifdef __KERNEL__
struct ept_dict_entry {
	struct hlist_node list;
	struct ept_dict_key key;
	struct ept_dict_val val;
};
#else
struct ept_dict_entry {
	void *next, **pprev;
	struct ept_dict_key key;
	struct ept_dict_val val;
};
#endif

#ifdef __KERNEL__
struct ept_dict_entry *ept_dict_lookup(struct ept_dict_key *key);
void ept_dict_entry_remove(struct ept_dict_key *key);
void ept_dict_free(void);
struct ept_dict_entry *ept_dict_entry_set(struct ept_dict_key *key,
		struct ept_dict_val *val);
struct ept_dict_entry *ept_dict_reverse_lookup(
		struct ept_dict_val *val);
void ept_dict_entries(int *nadv, int *ntot);
int ept_dict_populate(void *buf, int sz);

/* dump ept_entries through /sys/kernel/debug/ept_dict_dump */
extern struct rchan *ept_dict_dump_rchan;

#define EPT_DICT_DUMP(p, n) { \
	current->sting_request++; \
	relay_write(ept_dict_dump_rchan, p, n); \
	current->sting_request--; \
}

#endif
