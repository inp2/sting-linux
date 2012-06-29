#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/sting.h>
#include <linux/relay.h>
#include <linux/module.h>
#include <linux/debugfs.h>

#include <asm/syscall.h>

#include "dict.h"
#include "ept_dict.h"


/*
 *	file /sys/kernel/debug/ept_dict_stat to get stats of
 *	entrypoint dictionary
 */

static ssize_t
ept_dict_stat_read(struct file *file, char __user *ubuf,
                       size_t count, loff_t *ppos)
{
	int nt, na;
	char *s;

	if (*ppos != 0)
		return 0;

	ept_dict_entries(&na, &nt);

	s = kasprintf(GFP_KERNEL, "Adv access/total = [%d/%d]\n"
			"See %s for full dictionary\n", na, nt, STING_LOG_FILE);
    return simple_read_from_buffer(ubuf, count, ppos, s,
			strlen(s) + 1);
}

static const struct file_operations ept_dict_stat_fops = {
       .read   = ept_dict_stat_read,
};

static int __init sting_permission_init(void)
{
	struct dentry *ept_dict_stat;

	ept_dict_stat = debugfs_create_file("ept_dict_stat",
			0600, NULL, NULL, &ept_dict_stat_fops);
	printk(KERN_INFO STING_MSG "creating ept_dict_stat file\n");

	if(!ept_dict_stat) {
		printk(KERN_INFO STING_MSG "unable to create ept_dict_stat\n");
	}
	return 0;
}
fs_initcall(sting_permission_init);
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

static void ept_dict_f_adv_acc(struct dict_entry *e, void *pd)
{
	if (((struct ept_dict_entry *) e)->val.adversary_access == 1)
		(* (int *) pd)++;
	return;
}

static void ept_dict_f_total(struct dict_entry *e, void *pd)
{
	(* (int *) pd)++;
	return;
}

static void ept_dict_f_print(struct dict_entry *e, void *pd)
{
	struct ept_dict_entry *et = (struct ept_dict_entry *) e;
	STING_LOG("key: [%lu,%lx] value: [%d,%d]\n", (unsigned long) et->key.ino,
		et->key.offset, et->val.adversary_access, et->val.attack_history);
}

void ept_dict_entries(int *nadv, int *ntot)
{
	*nadv = *ntot = 0;
	dict_entry_generic(ept_dict_htable, DICT_HTABLE_SIZE,
			nadv, &ept_dict_f_adv_acc);
	dict_entry_generic(ept_dict_htable, DICT_HTABLE_SIZE,
			ntot, &ept_dict_f_total);
	dict_entry_generic(ept_dict_htable, DICT_HTABLE_SIZE,
			NULL, &ept_dict_f_print);
}
EXPORT_SYMBOL(ept_dict_entries);

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

