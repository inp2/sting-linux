/*
 * Copyright (c) 2011-2012 Hayawardh Vijayakumar
 * Copyright (c) 2011-2012 Systems and Internet Infrastructure Security Lab
 * Copyright (c) 2011-2012 The Pennsylvania State University
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/stop_machine.h>
#include <linux/clocksource.h>
#include <linux/kallsyms.h>
#include <linux/seq_file.h>
#include <linux/debugfs.h>
#include <linux/sting.h>
#include <linux/hardirq.h>
#include <linux/module.h>
#include <linux/sysctl.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/rcupdate.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/cred.h>
#include <linux/namei.h>

#include <asm/syscall.h>

/* adversary model list */
struct adversary_model *sting_adv_model;
EXPORT_SYMBOL(sting_adv_model);

static struct adversary_model adv_model_list;
static DEFINE_RWLOCK(adv_model_list_lock);

int register_adversary_model(struct adversary_model *am)
{
	int ret = 0;
	struct adversary_model *tmp, *m = NULL;
	struct list_head *lht;

	write_lock_irq(&adv_model_list_lock);

	/* Check if list is initialized */
	if (adv_model_list.list.next == NULL) {
		printk(KERN_INFO STING_MSG "Initializing adv_model_list\n");
		INIT_LIST_HEAD(&adv_model_list.list);
	}

	list_for_each(lht, &adv_model_list.list) {
		tmp = list_entry(lht, struct adversary_model, list);
		if (!strcmp(tmp->name, am->name)) {
			ret = -EEXIST;
			goto unlock;
		}
	}

	/* Insert into list */
	m = kmemdup(am, sizeof(struct adversary_model), GFP_ATOMIC);
	if (!m) {
		ret = -ENOMEM;
		goto unlock;
	}

	list_add(&(m->list), &(adv_model_list.list));
	write_unlock_irq(&adv_model_list_lock);
	return ret;
unlock:
	write_unlock_irq(&adv_model_list_lock);
	if (m)
		kfree(m);
	return ret;
}
EXPORT_SYMBOL(register_adversary_model);

const struct cred *superuser_creds(void)
{
	struct cred *override_cred = NULL;
	const struct cred *old_cred;
	int ret = 0;
	struct adversary_model *m;
	struct list_head *lht;

	override_cred = prepare_creds();
	if (!override_cred) {
		ret = -ENOMEM;
		goto out;
	}

	/* TODO: maintain a list of adversary models and call
	 * superuser for each of them */

	list_for_each(lht, &adv_model_list.list) {
		m = list_entry(lht, struct adversary_model, list);
		m->fill_superuser_creds(override_cred);
	}

	old_cred = override_creds(override_cred);

	/* don't need alloc reference anymore */
	put_cred(override_cred);

out:
	return (ret < 0) ? (const struct cred *) ERR_PTR(ret) : old_cred;
}
EXPORT_SYMBOL(superuser_creds);
