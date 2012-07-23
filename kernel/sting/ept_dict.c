#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/sting.h>
#include <linux/relay.h>
#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/rwsem.h>

#include <asm/syscall.h>

#include "dict.h"
#include "ept_dict.h"

/*
 *	file /sys/kernel/debug/ept_dict to get stats of
 *	entrypoint dictionary, and to load and read it. 
 */

static ssize_t
ept_dict_read(struct file *file, char __user *ubuf,
                       size_t count, loff_t *ppos)
{
	int nt, na, n = 0;
	char *s;

	if (*ppos != 0)
		return 0;

	ept_dict_entries(&na, &nt);

	s = kasprintf(GFP_KERNEL, "Adv access/total = [%d/%d]\n"
			"See %s for full dictionary\n", na, nt, STING_LOG_FILE);
	if (s) {
	    n = simple_read_from_buffer(ubuf, count, ppos, s, 
				strlen(s) + 1);
		kfree(s); 
	} else {
		n = -ENOMEM; 
	}
	
	return n; 
}

static ssize_t ept_dict_write(struct file *file, const char __user *ubuf,
			size_t count, loff_t *ppos)
{
	/* ppos - actual number of bytes read */
	/* done - position in buf to store */
	/* rcount - number of bytes to store in buf */
	/* total - total number of bytes to store in buf 
	 * -- not the total number of bytes read */
	static char *buf; 
	static int total = 0; 
	static int done; 
	int res = 0; 
	int rcount = count; /* real count */
	
	if (!(*ppos)) {
		/* first input */
		if (copy_from_user(&total, ubuf, sizeof(int)))
			return -EFAULT; 
		done = 0; 
		buf = kzalloc(total, GFP_ATOMIC); 
		if (!buf)
			return -ENOMEM; 
		rcount = count - sizeof(int); 
	}

	if (!buf)
		return -EINVAL; 

	if (((rcount + done) > total) || 
		(copy_from_user(buf + done, ubuf, rcount))) {
		kfree(buf); 
		buf = NULL; 
		return -EFAULT; 
	}

	*ppos += count; 
	done += rcount; 

	if (done == total) {
		ept_dict_free(); 
		res = ept_dict_populate(buf, total); 
		kfree(buf); 
	}

	return (res < 0) ? res : count; 
}

static const struct file_operations ept_dict_fops = {
	.read   = ept_dict_read,
	.write	= ept_dict_write
};

static int __init sting_ept_dict_init(void)
{
	struct dentry *ept_dict;

	ept_dict = debugfs_create_file("ept_dict",
			0600, NULL, NULL, &ept_dict_fops);
	printk(KERN_INFO STING_MSG "creating ept_dict file\n");

	if(!ept_dict) {
		printk(KERN_INFO STING_MSG "unable to create ept_dict\n");
	}
	return 0;
}
fs_initcall(sting_ept_dict_init);

/* Entrypoint dictionary */

static struct rw_semaphore ept_dict_lock; 
// DEFINE_RWLOCK(ept_dict_lock);

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

static void ept_dict_get_read_lock(void)
{
	down_read(&ept_dict_lock); 
	// read_lock(&ept_dict_lock); 
}

static void ept_dict_release_read_lock(void)
{
	up_read(&ept_dict_lock); 
	// read_unlock(&ept_dict_lock);
}

static void ept_dict_get_write_lock(void)
{
	down_write(&ept_dict_lock); 
	// write_lock(&ept_dict_lock); 
}

static void ept_dict_release_write_lock(void)
{
	up_write(&ept_dict_lock); 
	// write_unlock(&ept_dict_lock); 
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
	.dict_get_read_lock = ept_dict_get_read_lock,
	.dict_release_read_lock = ept_dict_release_read_lock,
	.dict_get_write_lock = ept_dict_get_write_lock,
	.dict_release_write_lock = ept_dict_release_write_lock,
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

void ept_dict_free(void)
{
	dict_free(ept_dict_htable, DICT_HTABLE_SIZE, &ept_dict_fns); 
}
EXPORT_SYMBOL(ept_dict_free); 

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
	if (((struct ept_dict_entry *) e)->val.dac.adversary_access == 1)
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

	#if 0
	STING_LOG("key: [%lu,%lx] value: [%lu,%d,%s,%d,%d,%d,%d,%d]\n", 
			(unsigned long) et->key.ino, et->key.offset, 
			et->val.time, et->val.ctr, et->val.comm, 
			et->val.dac.ctr_first_adv, et->val.dac.adversary_access, 
			et->val.mac.ctr_first_adv, et->val.mac.adversary_access, 
			et->val.attack_history);
	#endif

	EPT_DICT_DUMP(et, sizeof(*et)); 
}

void ept_dict_entries(int *nadv, int *ntot)
{
	*nadv = *ntot = 0;
	dict_entry_generic(ept_dict_htable, DICT_HTABLE_SIZE, &ept_dict_fns,
			nadv, &ept_dict_f_adv_acc);
	dict_entry_generic(ept_dict_htable, DICT_HTABLE_SIZE, &ept_dict_fns,
			ntot, &ept_dict_f_total);
	dict_entry_generic(ept_dict_htable, DICT_HTABLE_SIZE, &ept_dict_fns,
			NULL, &ept_dict_f_print);
}
EXPORT_SYMBOL(ept_dict_entries);

int ept_dict_populate(void *buf, int sz)
{
	struct ept_dict_entry *r; 
	struct ept_dict_entry *e; 
	for (e = (struct ept_dict_entry *) buf; 
			(char *) e < ((char *) buf + sz); e++) {
		r = ept_dict_entry_set(&e->key, &e->val); 
		if (IS_ERR(r))
			return PTR_ERR(r); 
	}
	return 0; 
}
EXPORT_SYMBOL(ept_dict_populate); 

static int __init ept_dict_target_init(void)
{
	int rc = 0;
	int i;

	STING_DBG("ept_dict target module initializing\n");
	for (i = 0; i < DICT_HTABLE_SIZE; i++)
		INIT_HLIST_HEAD(&ept_dict_htable[i]);

	init_rwsem(&ept_dict_lock); 

	return rc;
}
module_init(ept_dict_target_init);


/* Dumping and restoring the ept dictionary */

/*
 *	file /sys/kernel/debug/ept_dict_dump to get stats of
 *	entrypoint dictionary
 */

/* ept_dict_dump file */

static struct dentry *create_ept_dict_dump_file_callback(const char *filename,
		struct dentry *parent, umode_t mode, struct rchan_buf *buf, int *is_global)
{
	return debugfs_create_file(filename, mode, parent, buf,
								   &relay_file_operations);
}

static int remove_ept_dict_dump_file_callback(struct dentry* dentry)
{
	debugfs_remove(dentry);
	return 0;
}

#define EPT_DICT_DUMP_FILE "ept_dict_dump"
 /* callback when one subbuffer is full */
static int subbuf_ept_dict_dump_start_callback(struct rchan_buf *buf, void *subbuf,
		 void *prev_subbuf, size_t prev_padding)
{
	atomic_t* dropped;
	if (!relay_buf_full(buf))
		return 1;
	dropped = buf->chan->private_data;
	atomic_inc(dropped);
	if (atomic_read(dropped) % 5000 == 0)
		STING_ERR(1, "%s full, dropped: %d\n", EPT_DICT_DUMP_FILE, atomic_read(dropped));
	return 0;
}

static atomic_t dropped = ATOMIC_INIT(0);
static struct rchan_callbacks ept_dict_dump_relay_callbacks =
{
	.subbuf_start		= subbuf_ept_dict_dump_start_callback,
	.create_buf_file	= create_ept_dict_dump_file_callback,
	.remove_buf_file	= remove_ept_dict_dump_file_callback,
};

struct rchan* ept_dict_dump_rchan;

static int __init ept_dict_dump_init(void)
{
	ept_dict_dump_rchan = relay_open(EPT_DICT_DUMP_FILE, NULL, 1024 * 1024, 8,
			&ept_dict_dump_relay_callbacks, &dropped);
	if (!ept_dict_dump_rchan) {
		STING_ERR(1, "relay_open(%s) failed\n", EPT_DICT_DUMP_FILE);
		return 1;
	}
	return 0;
}
fs_initcall(ept_dict_dump_init);
