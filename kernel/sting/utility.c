/*
 * Copyright (c) 2011-2012 Hayawardh Vijayakumar
 * Copyright (c) 2011-2012 Xinyang Ge
 * Copyright (c) 2011-2012 Systems and Internet Infrastructure Security Lab
 * Copyright (c) 2011-2012 The Pennsylvania State University
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/namei.h>
#include <linux/fcntl.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/module.h>
#include <asm/syscall.h>
#include <linux/sting.h>
#include <linux/debugfs.h>
#include <security.h>

#include "syscalls.h"
#include "permission.h"
#include "utility.h"

int last_query_sid = 0;

ssize_t sting_secontext_to_sid_read(struct file *file, char __user *ubuf, size_t count, loff_t *ppos)
{
	char tmpbuf[12];
	ssize_t length;

	length = scnprintf(tmpbuf, 12, "%d\n", last_query_sid);
	return simple_read_from_buffer(ubuf, count, ppos, tmpbuf, length);
}

static ssize_t sting_secontext_to_sid_write(struct file *filp, const char __user *buf, size_t count, loff_t *ppos)
{
	char *page;
	ssize_t length;
	int new_value;

	if (count >= PAGE_SIZE)
		return -ENOMEM;
	if (*ppos != 0) {
		/* No partial writes. */
		return -EINVAL;
	}
	page = (char *)get_zeroed_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	printk(KERN_INFO STING_MSG "secontext page allocated OK\n");
	length = -EFAULT;
	if (copy_from_user(page, buf, count))
		goto out;

	printk(KERN_INFO STING_MSG "secontext copy_from_user (%lu bytes) OK\n", count);
	if ((length = security_context_to_sid(page, count, &new_value)))
		goto out;

	printk(KERN_INFO STING_MSG "secontext security_context_to_sid OK\n");
    last_query_sid = new_value;
	length = count;

out:
	free_page((unsigned long) page);
	return length;
}

const struct file_operations sting_secontext_to_sid_fops = {
	   .write  = sting_secontext_to_sid_write,
	   .read   = sting_secontext_to_sid_read,
};

/* ---------------------------------------------------------------------------- */

#define TS_HASH_BITS 8
#define TS_HTABLE_SIZE (1 << TS_HASH_BITS)
#define ts_hash(num) ((num) % TS_HTABLE_SIZE)

struct hlist_head ts_htable[TS_HTABLE_SIZE];

struct ts_node *sting_seadversary_find_subject(unsigned int victim_sid, struct ts_node *cookie)
{
	struct ts_node *tmp;
	int index, hit = 0;
	struct hlist_node *node;

    if (cookie == NULL)
        hit = 1;
	/* Get the hash index for this subject */
	index = ts_hash(victim_sid);

    hlist_for_each_entry(tmp, node, &ts_htable[index], list) {
	    if (tmp->victim_sid == victim_sid) {
            if (hit)
                return tmp;
            if (cookie == tmp)
                hit = 1;
        }
    }
    return NULL;
}
EXPORT_SYMBOL(sting_seadversary_find_subject);

#define next(ptr) while(*(ptr)++ >= 48)
#define is_new_victim(ptr) (*((ptr) - 1) == '\n')
#define is_end(ptr) (*((ptr) - 1) == '\0')

ssize_t sting_seadversary_load(char *data, size_t count)
{
    struct ts_node *tmp;
    struct hlist_node *node;
    char *ptr = data;
    int i;
    /* make some clean work */
	for (i = 0; i < TS_HTABLE_SIZE; i++) {
        node = ts_htable[i].first;
        while (node != NULL)
        {
            tmp = hlist_entry(node, struct ts_node, list);
            node = node->next;
            kfree(tmp);
        }
	}
	for (i = 0; i < TS_HTABLE_SIZE; i++)
	    INIT_HLIST_HEAD(&ts_htable[i]);

    do {
        int victim;
        sscanf(ptr, "%d", &victim);
        next(ptr);
        while (!is_new_victim(ptr) && !is_end(ptr))
        {
            int adversary;
            sscanf(ptr, "%d", &adversary);
            /* add element */
            tmp = (struct ts_node *)kmalloc(sizeof(struct ts_node), GFP_ATOMIC);
            tmp->victim_sid = victim;
            tmp->adversary_sid = adversary;
		    printk(KERN_ALERT STING_MSG "ts_htable[%d] += [%d, %d]\n", ts_hash(victim), victim, adversary);
		    hlist_add_head(&(tmp->list), &(ts_htable[ts_hash(victim)]));
            next(ptr);
        }
    } while (!is_end(ptr));
    return count;
}

ssize_t sting_seadversary_feed_write(struct file *filp, const char __user *ubuf, size_t count, loff_t *ppos)
{
    ssize_t length;
    void *data = NULL;

    if (*ppos != 0) {
    /* No partial writes. */
        length = -EINVAL;
        goto out;
    }

    if ((count > 64 * 1024 * 1024) || (data = vmalloc(count)) == NULL) {
        length = -ENOMEM;
        goto out;
    }

    length = -EFAULT;
    if (copy_from_user(data, ubuf, count) != 0)
        goto out;
    length = sting_seadversary_load((char *)data, count);
out:
    vfree(data);
    return length;
}

ssize_t sting_seadversary_feed_read(struct file *file, char __user *ubuf, size_t count, loff_t *ppos)
{
	char tmpbuf[12] = "abc";
    struct ts_node * node = sting_seadversary_find_subject(643, NULL);
    while (node != NULL)
    {
        printk(KERN_ALERT STING_MSG "[%d, %d]\n", node->victim_sid, node->adversary_sid);
        node = sting_seadversary_find_subject(643, node);
    }

	return simple_read_from_buffer(ubuf, count, ppos, tmpbuf, 3);
}

const struct file_operations sting_seadversary_feed_fops = {
	.read = sting_seadversary_feed_read,
	.write  = sting_seadversary_feed_write,
};

/**
 * fname_to_dentry() - 	get dentry from filename, creating the dentry if
 * 						it does not already exist
 * @fname:		filename to get dentry of
 */
struct dentry *fname_to_dentry(const char *fname, int flag_follow)
{
	struct path p_nd, f_nd;
	struct dentry *fdentry = NULL;
	int dfd = AT_FDCWD, ret = 0;
	struct nameidata par_nd;

	/* If parent directory doesn't exist, exit immediately */
	ret = kern_path_parent(fname, &par_nd);
	if (ret) {
		if (ret == -ENOENT)
			STING_DBG("Directory creation: %s required for process: %s\n",
					fname, current->comm);
		fdentry = ERR_PTR(-ENOENT);
		goto out;
	}
	path_put(&par_nd.path);

	/* check if file already exists */
	flag_follow = (in_set(syscall_get_nr(current, task_pt_regs(current)),
				nosym_set)) ? 0 : LOOKUP_FOLLOW;
	ret = kern_path(fname, flag_follow, &f_nd);
	if (ret < 0 && ret != -ENOENT) {
		fdentry = ERR_PTR(ret);
		goto out;
	} else if (ret == -ENOENT) {
		/* create a (negative) dentry for the new file */
		fdentry = kern_path_create(dfd, fname, &p_nd, 0);
		if (IS_ERR(fdentry)) {
			ret = PTR_ERR(fdentry);
			goto out;
		}
		/* unlock i_mutex as we are not going to actually
		 * associate an inode with the just-created dentry */
		mutex_unlock(&p_nd.dentry->d_inode->i_mutex);

		/* drop reference to parent path that
		 * kern_path_create gets */
		path_put(&p_nd);
	} else {
		fdentry = f_nd.dentry;

		/* release reference to vfsmount, we only need
		 * reference to dentry itself */
		mntput(f_nd.mnt);
	}

out:
	return fdentry;
}
EXPORT_SYMBOL(fname_to_dentry);
