/*
 * Copyright (c) 2011-2012 Xinyang Ge
 * Copyright (c) 2011-2012 Systems and Internet Infrastructure Security Lab
 * Copyright (c) 2011-2012 The Pennsylvania State University
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

struct ts_node {
	struct hlist_node list;
    unsigned int victim_sid;
    unsigned int adversary_sid;
};

extern const struct file_operations sting_secontext_to_sid_fops;
extern const struct file_operations sting_seadversary_feed_fops;
extern struct ts_node *sting_seadversary_find_subject(unsigned int victim_sid, struct ts_node *cookie);
