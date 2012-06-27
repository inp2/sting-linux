#include "dict.h"
#include <linux/module.h>

struct dict_entry *dict_lookup(struct hlist_head *dict, 
		struct dict_key *key, struct dict_fns *df)
{
	struct dict_entry *tmp; 
	unsigned long i; 
	struct hlist_node *node;
	i = df->dict_hash(key); 

    hlist_for_each_entry(tmp, node, &dict[i], list) {
		if (!df->dict_key_cmp(df->dict_key_get(tmp), key)) 
			return tmp;
    }
    return NULL;
}
EXPORT_SYMBOL(dict_lookup); 

void dict_entry_remove(struct hlist_head *dict, 
		struct dict_key *key, struct dict_fns *df) 
{
	struct dict_entry *tmp;
	int i; 

	/* Get the hash index for this subject */
	i = df->dict_hash(key);

	if ((tmp = dict_lookup(dict, key, df))) {
		hlist_del(&(tmp->list)); 
		df->dict_entry_free(tmp); 
	}
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
		df->dict_val_cpy(df->dict_val_get(tmp), val); 
	} else {
		/* Create new entry */
		tmp = df->dict_entry_alloc(); 
		if (!tmp)
			return tmp;

		df->dict_val_cpy(df->dict_val_get(tmp), val); 
		df->dict_key_cpy(df->dict_key_get(tmp), key); 

		i = df->dict_hash(df->dict_key_get(tmp)); 
		hlist_add_head(&(tmp->list), &(dict[i]));
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

	for (i = 0; i < dict_sz; i++) {
		hlist_for_each_entry(tmp, node, &dict[i], list) {
			if (!df->dict_val_cmp(df->dict_val_get(tmp), val)) 
				return tmp;
		}
	}
	return NULL; 
}
EXPORT_SYMBOL(dict_reverse_lookup); 
