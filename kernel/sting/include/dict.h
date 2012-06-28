#include <linux/list.h>

/* partly-generic hash table. clients of this must have entries as follows:
   	struct my_entry {
   		struct hlist_head list;
		[key, value] stuff;
	};
*/

struct dict_key {

};

struct dict_val {

};

struct dict_entry {
	struct hlist_node list;
};

struct dict_fns {
	/* hash function */
	unsigned long (*dict_hash) (struct dict_key *k);
	/* get key, val (offsets) from entry */
	struct dict_key * (*dict_key_get) (struct dict_entry *e);
	struct dict_val * (*dict_val_get) (struct dict_entry *e);
	/* return 0 if equal */
	int (*dict_key_cmp) (struct dict_key *k1, struct dict_key *k2);
	int (*dict_val_cmp) (struct dict_val *v1, struct dict_val *v2);
	/* copy values */
	void (*dict_key_cpy) (struct dict_key *kd, struct dict_key *ks);
	void (*dict_val_cpy) (struct dict_val *vd, struct dict_val *vs);
	/* allocation and de-allocation*/
	struct dict_entry * (*dict_entry_alloc) (void);
	void (*dict_entry_free) (struct dict_entry *e);
};

struct dict_entry *dict_lookup(struct hlist_head *dict,
		struct dict_key *key, struct dict_fns *df);
void dict_entry_remove(struct hlist_head *dict,
		struct dict_key *key, struct dict_fns *df);
struct dict_entry *dict_entry_set(struct hlist_head *dict,
		struct dict_key *key, struct dict_val *val, struct dict_fns *df);
struct dict_entry *dict_reverse_lookup(struct hlist_head *dict,
		struct dict_val *val, unsigned long dict_sz, struct dict_fns *df);
void dict_entry_generic(struct hlist_head *dict, unsigned long dict_sz,
		void *private_data, void (*dict_generic) (struct dict_entry *e,
		void *private_data));
