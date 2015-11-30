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
#include "user_unwind.h"

/* the entrypoint dictionary (struct ept_dict) maintains a permanent
 * history of past attacks and their results. userspace tools save
 * and restore it on every boot. */
struct ept_dict_key {
	/* the actual key used in the hash table is the entrypoint. we
	 * store the full stack so we can compare library entrypoints
	 * also, as needed */
	struct user_stack_info user_stack;
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

struct ept_dict_entry {
	void *next, **pprev;
	struct ept_dict_key key;
	struct ept_dict_val val;
};

