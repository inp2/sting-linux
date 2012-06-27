#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/sting.h>
#include <linux/relay.h>
#include <asm/syscall.h>
#include <linux/module.h>
#include "dict.h"
#include "ept_dict.h"

extern struct rchan* wall_rchan;
#define RELAY_LOG(...) { \
	char *log_str = NULL; \
	log_str = kasprintf(GFP_ATOMIC, __VA_ARGS__); \
	if (log_str) { \
		current->kernel_request++; \
		relay_write(wall_rchan, log_str, strlen(log_str) + 1); \
		current->kernel_request--; \
		kfree(log_str); \
	} \
}

/* Entrypoint dictionary */

#define DICT_HASH_BITS            8
#define DICT_HTABLE_SIZE (1 << DICT_HASH_BITS)

struct hlist_head ept_dict_htable[DICT_HTABLE_SIZE];

static unsigned long ept_dict_hash(struct dict_key *key)
{
	struct ept_dict_key *k = (struct ept_dict_key *) key; 
	/* Simple hash */
	return (unsigned long) hash_long(
			(unsigned long) (k->ino + k->offset), DICT_HTABLE_SIZE); 
}

static struct dict_key *ept_dict_key_get(struct dict_entry *e) 
{
	return (struct dict_key *) &(((struct ept_dict_entry *) e)->key); 
}

static struct dict_val *ept_dict_val_get(struct dict_entry *e) 
{
	return (struct dict_val *) &(((struct ept_dict_entry *) e)->val); 
}

static int ept_dict_key_cmp(struct dict_key *k1, struct dict_key *k2)
{
	return memcmp(k1, k2, sizeof(struct ept_dict_key)); 
}

static int ept_dict_val_cmp(struct dict_val *v1, struct dict_val *v2)
{
	return memcmp(v1, v2, sizeof(struct ept_dict_val)); 
}

static void ept_dict_key_cpy(struct dict_key *kdest, struct dict_key *ksrc)
{
	memcpy(kdest, ksrc, sizeof(struct ept_dict_key)); 
}

static void ept_dict_val_cpy(struct dict_val *vdest, struct dict_val *vsrc)
{
	memcpy(vdest, vsrc, sizeof(struct ept_dict_val)); 
}

static struct dict_entry *ept_dict_entry_alloc(void)
{
	return kmalloc(sizeof(struct ept_dict_entry), GFP_KERNEL); 
}

static void ept_dict_entry_free(struct dict_entry *e) 
{
	kfree(e); 
}

static struct dict_fns ept_dict_fns = {
	.dict_hash = ept_dict_hash, 
	.dict_key_get = ept_dict_key_get, 
	.dict_val_get = ept_dict_val_get, 
	.dict_key_cmp = ept_dict_key_cmp,
	.dict_val_cmp = ept_dict_val_cmp,
	.dict_key_cpy = ept_dict_key_cpy, 
	.dict_val_cpy = ept_dict_val_cpy, 
	.dict_entry_alloc = ept_dict_entry_alloc, 
	.dict_entry_free = ept_dict_entry_free, 
}; 

struct ept_dict_entry *ept_dict_lookup(struct ept_dict_key *key)
{
	return (struct ept_dict_entry *) dict_lookup(ept_dict_htable, 
			(struct dict_key *) key, &ept_dict_fns); 
}
EXPORT_SYMBOL(ept_dict_lookup);

void ept_dict_entry_remove(struct ept_dict_key *key)
{
	dict_entry_remove(ept_dict_htable, (struct dict_key *) key, &ept_dict_fns); 
	return; 
}
EXPORT_SYMBOL(ept_dict_entry_remove); 

struct ept_dict_entry *ept_dict_entry_set(struct ept_dict_key *key, struct ept_dict_val *val)
{
	return (struct ept_dict_entry *) dict_entry_set(ept_dict_htable, 
			(struct dict_key *) key, (struct dict_val *) val, &ept_dict_fns); 
}
EXPORT_SYMBOL(ept_dict_entry_set); 

struct ept_dict_entry *ept_dict_reverse_lookup(struct ept_dict_val *val)
{
	return (struct ept_dict_entry *) dict_reverse_lookup(ept_dict_htable, 
			(struct dict_val *) val, DICT_HTABLE_SIZE, &ept_dict_fns); 
}
EXPORT_SYMBOL(ept_dict_reverse_lookup);

#if 0
struct ept_dict_entry *ept_dict_entry_get(struct ept_dict_key *key)
{
	struct ept_dict_entry *tmp;
	int index;
	struct hlist_node *node;

	/* Get the hash index for this subject */
	index = ept_dict_hash(key); 

    hlist_for_each_entry(tmp, node, &ept_dict_htable[index], list) {
		if (!ept_dict_cmp(tmp->key, key)) 
			return tmp;
    }
    return NULL;
}
EXPORT_SYMBOL(ept_dict_entry_get);

/* Remove key and its corresponding val from dictionary */
void ept_dict_remove_entry(struct ept_dict_key *key)
{
	struct ept_dict_entry *tmp;
	int index;
	struct hlist_node *node;

	/* Get the hash index for this subject */
	index = ept_dict_hash(key);

	if ((tmp = ept_dict_entry_get(key)) != NULL) {
		hlist_del(&(tmp->list)); 
		kfree(tmp); 
	}

out:
    return;
}
EXPORT_SYMBOL(ept_dict_remove_entry);

/* Insert (key, val) pair. Overwrite val if already exists */
struct ept_dict_key *ept_dict_set_entry(struct ept_dict_key *key, struct ept_dict_val *val)
{
    struct ept_dict_entry *tmp;
	int index;

	if ((tmp = ept_dict_entry_get(key)) != NULL) {
		/* Update existing entry */
		ept_copy_val(tmp->val, val); 
	} else {
		/* Create new entry */
		tmp = kmalloc(sizeof(struct ept_dict_entry), GFP_ATOMIC);
		if (!tmp)
			return ERR_PTR(-ENOMEM);
		ept_copy_key(tmp->key, key); 
		ept_copy_val(tmp->val, val); 

		index = ept_dict_hash(&(tmp->key));
//		STING_DBG( "%s(): ept_dict_hash[%d] = [%s]\n", __FUNCTION__, index, key);
		hlist_add_head(&(tmp->list), &(ept_dict_htable[index]));
	}
    return tmp; 
}
EXPORT_SYMBOL(ept_dict_set_entry); 

/* Set a (k, v) pair, delete a (k, v) pair, return a verdict */
int ept_dict_target(struct pf_packet_context *p, void *target_specific_data)
{
	struct ept_dict_target *st = (struct ept_dict_target *)
				target_specific_data;
	int rc = 0;
	struct ept_dict_key k; 
	struct ept_dict_val v; 
	struct ept_dict_entry *n; 
	int adv; 

	if (!p->syscall_filename)
		return rc; 
	adv = get_uid_with_permission(ATTACKER_BIND, p->syscall_filename); 
	if (adv < 0 || adv == PFW_UID_NO_MATCH)
		adv = -1; 
	else
		adv = 1; 
	/* TODO: Very specific action hardcoded */
	k.ino = p->vm_area_inoden[p->trace_first_program_ip]; 
	k.offset = p->trace.entries[p->trace_first_program_ip] - p->vma_start[p->trace_first_program_ip]; 

	n = ept_dict_entry_get(&k); 

	/* Logging */
	if (adv == 1) {
		int i, j = 0; 
		int len = current->mm->arg_end - current->mm->arg_start; 
		char *str = kzalloc(len, GFP_ATOMIC); 
		// kzalloc(12 * 33, GFP_ATOMIC); 
		const char __user *pt;
		/* for (i = p->trace_first_program_ip; p->trace.entries[i] != ULONG_MAX && p->trace.entries[i] && i < 32; i++)
			j += sprintf(str + j, "0x%x ", p->trace.entries[i]);  
		str[j] = 0; */
		pt = (const char __user *) current->mm->arg_start;
		copy_from_user(str, pt, len); 
	
		/* Convert \0 to spaces */
		for (i = 0; i < len; i++) {
			if (!str[i]) {
			   	if (!str[i + 1])
					break; 
				else 
					str[i] = ' '; 
			}
		}

		if (n && n->val.adversary_access == 1) {
			STING_DBG("adversary access: %s accesses %s old: %s\n", 
				current->comm, p->syscall_filename, str);
		} else {
			STING_DBG("adversary access: %s accesses %s new: %s\n", 
				current->comm, p->syscall_filename, str); 
		}

		if (str)
			kfree(str); 
	}

	if (n && n->val.adversary_access == 1) 
		return 1; 
	else if (adv == -1) {
		v.adversary_access = 0; 
		v.attacked = 0; 
		rc = ept_dict_set_val(&k, &v); 
	} else {
		v.adversary_access = 1; 
		v.attacked = 0; 
		rc = ept_dict_set_val(&k, &v); 
	}

	if (st->flags & PF_SET)
		rc = ept_dict_set_val(&(st->key), &(st->val)); 
	else if (st->flags & PF_DELETE)
		ept_dict_remove_key(&(st->key));

	return rc;
}
EXPORT_SYMBOL(ept_dict_target); 
#endif 

static int __init ept_dict_target_init(void)
{
	int rc = 0;
	int i;

	STING_DBG("ept_dict target module initializing\n");
	for (i = 0; i < DICT_HTABLE_SIZE; i++)
		INIT_HLIST_HEAD(&ept_dict_htable[i]);

	return rc;
}
module_init(ept_dict_target_init);

