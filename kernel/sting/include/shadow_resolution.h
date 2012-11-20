/*
 * Copyright (c) 2011-2012 Hayawardh Vijayakumar
 * Copyright (c) 2011-2012 Systems and Internet Infrastructure Security Lab
 * Copyright (c) 2011-2012 The Pennsylvania State University
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/namei.h>

extern int shadow_res_init(int dfd, const char *name,
		unsigned int flags, struct nameidata *nd);
extern int shadow_res_advance_name(char **n, int *nptr, struct nameidata *nd);
extern int shadow_res_resolve_name(struct nameidata *nd, char *name);
extern int shadow_res_end(struct nameidata *nd);

void shadow_res_get_pc_paths(struct path *parent, struct path *child,
		struct nameidata *nd, int err);
void shadow_res_put_pc_paths(struct path *parent, struct path *child, int err);
char *shadow_res_get_last_name(struct nameidata *nd, struct path *child);
void shadow_res_put_lookup_path(struct nameidata *nd);
