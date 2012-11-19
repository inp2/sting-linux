/*
 * Copyright (c) 2011-2012 Hayawardh Vijayakumar
 * Copyright (c) 2011-2012 Systems and Internet Infrastructure Security Lab
 * Copyright (c) 2011-2012 The Pennsylvania State University
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "dict.h"
#include <linux/module.h>

struct dict_entry *dict_lookup(struct hlist_head *dict,
		struct dict_key *key, struct dict_fns *df)
{
	struct dict_entry *tmp;
	unsigned long i;
	struct hlist_node *node;
	i = df->dict_hash(key);

	df->dict_get_read_lock();

    hlist_for_each_entry(tmp, node, &dict[i], list) {
		if (!df->dict_key_cmp(df->dict_key_get(tmp), key)) {
			df->dict_release_read_lock();
			return tmp;
		}
    }
	df->dict_release_read_lock();
    return NULL;
}
EXPORT_SYMBOL(dict_lookup);

void dict_free(struct hlist_head *dict, unsigned long dict_sz,
		struct dict_fns *df)
{
	struct dict_entry *tmp;
	struct hlist_node *node, *n;
	int i;

	df->dict_get_write_lock();

	for (i = 0; i < dict_sz; i++) {
		hlist_for_each_entry_safe(tmp, node, n, &dict[i], list) {
			hlist_del(&(tmp->list));
			df->dict_entry_free(tmp);
		}
	}

	df->dict_release_write_lock();
}
EXPORT_SYMBOL(dict_free);

void dict_entry_remove(struct hlist_head *dict,
		struct dict_key *key, struct dict_fns *df)
{
	struct dict_entry *tmp;
	struct hlist_node *node, *n;
	int i;

	/* Get the hash index for this subject */
	i = df->dict_hash(key);

	df->dict_get_write_lock();
    hlist_for_each_entry_safe(tmp, node, n, &dict[i], list) {
		if (!df->dict_key_cmp(df->dict_key_get(tmp), key)) {
			hlist_del(&(tmp->list));
			df->dict_entry_free(tmp);
			break;
		}
	}

	df->dict_release_write_lock();
    return;
}
EXPORT_SYMBOL(dict_entry_remove);

struct dict_entry *dict_entry_set(struct hlist_head *dict,
		struct dict_key *key, struct dict_val *val, struct dict_fns *df)
{
    struct dict_entry *tmp;
	int i;


	if ((tmp = dict_lookup(dict, key, df)) != NULL) {
		/* Update existing entry */
		/* TODO: For in-place mods, we don't lock, even
		   in sting.c */
		// df->dict_get_write_lock();
		df->dict_val_cpy(df->dict_val_get(tmp), val);
		// df->dict_release_write_lock();
	} else {
		/* Create new entry */
		tmp = df->dict_entry_alloc();
		if (!tmp) {
			return ERR_PTR(-ENOMEM);
		}

		df->dict_val_cpy(df->dict_val_get(tmp), val);
		df->dict_key_cpy(df->dict_key_get(tmp), key);

		i = df->dict_hash(df->dict_key_get(tmp));

		df->dict_get_write_lock();
		hlist_add_head(&(tmp->list), &(dict[i]));
		df->dict_release_write_lock();
	}
    return tmp;
}
EXPORT_SYMBOL(dict_entry_set);

/* reverse lookup: get first entry that has matching value */
struct dict_entry *dict_reverse_lookup(struct hlist_head *dict,
		struct dict_val *val, unsigned long dict_sz, struct dict_fns *df)
{
	struct dict_entry *tmp;
	unsigned long i;
	struct hlist_node *node;

	df->dict_get_read_lock();

	for (i = 0; i < dict_sz; i++) {
		hlist_for_each_entry(tmp, node, &dict[i], list) {
			if (!df->dict_val_cmp(df->dict_val_get(tmp), val)) {
				df->dict_release_read_lock();
				return tmp;
			}
		}
	}
	df->dict_release_read_lock();
	return NULL;
}
EXPORT_SYMBOL(dict_reverse_lookup);

/* generic callback function on each dict entry */
void dict_entry_generic(struct hlist_head *dict, unsigned long dict_sz,
		struct dict_fns *df, void *private_data,
		void (*dict_gen_func) (struct dict_entry *e, void *private_data))
{
	struct dict_entry *tmp;
	unsigned long i;
	struct hlist_node *node, *n;

	df->dict_get_write_lock();

	for (i = 0; i < dict_sz; i++)
		hlist_for_each_entry_safe(tmp, node, n, &dict[i], list)
			dict_gen_func(tmp, private_data);

	df->dict_release_write_lock();

	return;
}
EXPORT_SYMBOL(dict_entry_generic);
