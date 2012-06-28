struct ept_dict_key {
	ino_t ino;
	int offset;
};

struct ept_dict_val {
	int adversary_access;
	/* format: 16 empty bits || immune (8 bits) || attack_type (8 bits) */
	int attack_history;
};

struct ept_dict_entry {
	struct hlist_node list;
	struct ept_dict_key key;
	struct ept_dict_val val;
};

struct ept_dict_entry *ept_dict_lookup(struct ept_dict_key *key);
void ept_dict_entry_remove(struct ept_dict_key *key);
struct ept_dict_entry *ept_dict_entry_set(struct ept_dict_key *key, struct ept_dict_val *val);
struct ept_dict_entry *ept_dict_reverse_lookup(struct ept_dict_val *val);
void ept_dict_entries(int *nadv, int *ntot);
