/*
 * Copyright (c) 2011-2012 Hayawardh Vijayakumar
 * Copyright (c) 2011-2012 Systems and Internet Infrastructure Security Lab
 * Copyright (c) 2011-2012 The Pennsylvania State University
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/init.h>
#include <linux/export.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/pagemap.h>
#include <linux/fsnotify.h>
#include <linux/personality.h>
#include <linux/security.h>
#include <linux/ima.h>
#include <linux/syscalls.h>
#include <linux/mount.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/file.h>
#include <linux/fcntl.h>
#include <linux/device_cgroup.h>
#include <linux/fs_struct.h>
#include <linux/posix_acl.h>
#include <asm/uaccess.h>

#include <linux/sting.h>

/* given a pointer to the end of the component, get its
   beginning */
static inline int get_curr_start(char *s, int curr)
{
	/* if current component is the last one, curr points to
	   the NULL after its last character, else curr points to
	   one char after that component */
	int prev = curr - 1;
	while (s[prev] == '/' && prev > 0)
		prev--;
	while (s[prev] != '/' && prev > 0)
		prev--;
	if (s[prev] == '/')
		prev++;
	/* point to first character of current component */
	return prev;
}

/* modify component of path given symlink target.
   return new position to resolve from */
int modify_lnk_name(char **orig, int pos, char *lnk)
{
	char *tmp;
	int prev = 0;
	/* for relative paths, does there exist path components
	   before the current symbolic link? */
	int is_prefix = 0;
	/* for both relative and absolute paths, does there exist
	   path components after the current symbolic link? */
	int	is_suffix = 0;

	prev = get_curr_start(*orig, pos);

	is_prefix = (prev > 0);
	is_suffix = (*orig)[pos];

	if (lnk[0] == '/') {
		/* absolute */
		if (is_suffix)
			tmp = kasprintf(GFP_KERNEL, "%s/%s", lnk, &(*orig)[pos]);
		else
			tmp = kasprintf(GFP_KERNEL, "%s", lnk);
		strcpy(*orig, tmp);
		kfree(tmp);
		return 0;
	} else {
		/* relative */
		if (!is_prefix && !is_suffix)
			tmp = kasprintf(GFP_KERNEL, "%s", lnk);
		else if (!is_prefix && is_suffix)
			tmp = kasprintf(GFP_KERNEL, "%s/%s", lnk, &((*orig)[pos]));
		else if (is_prefix && !is_suffix) {
			(*orig)[prev - 1] = 0;
			tmp = kasprintf(GFP_KERNEL, "%s/%s", (*orig), lnk);
		} else if (is_prefix && is_suffix) {
			(*orig)[prev - 1] = 0;
			tmp = kasprintf(GFP_KERNEL, "%s/%s/%s", (*orig), lnk, &(*orig)[pos]);
		} else
			BUG_ON(1);
		strncpy(*orig, tmp, PATH_MAX);
		kfree(tmp);
		return prev;
	}
}

int get_d_path(struct path *path, char **n)
{
	char *p, *pathname;
	int pos;
	/* We will allow 11 spaces for ' (deleted)' to be appended */
	pathname = kmalloc(PATH_MAX + 11, GFP_KERNEL);
	if (!pathname)
		return -ENOMEM;

	p = d_path(path, pathname, PATH_MAX + 11);
	if (IS_ERR(p)) {
		kfree(pathname);
		return PTR_ERR(p);
	}

	strcpy(*n, p);
	pos = strlen(p) - 1;
	while (p[pos] != '/')
		pos--;
	kfree(pathname);

	return pos;
}


/* an iterative version of path lookup based on path_lookupat(),
 * treating all bindings equally, whether they be final or path.
 *
 * this is so we can perform actions such as adversary permission
 * check on each component.
 *
 * LOOKUP_RCU flag is ignored -- only traditional ref-walk
 * is supported.
 *
 * depth is irrelevant because we make it iterative.
 */

int shadow_res_advance_name(char **n, int *nptr,
		struct nameidata *nd)
{
	long len = 0;
	int last_component = 0;
	char *name;
	/* we want to maintain exact name being analyzed,
	 * nd->saved_names will lose it when we need to print it
	 * (it is lost as soon as resolution is done). */
	if (nd->last_type == LAST_BIND) {
		void *res;

		// if (link->mnt == nd->path.mnt)
		//	mntget(link->mnt);

		nd_set_link(nd, NULL);
		BUG_ON(!nd->inode->i_op->follow_link);

		/* follow_link, if directly resolving, drops reference to parent if -ENOENT, but
		 * it changes nd.path to (negative dentry) child. change it back to
		 * the previous (parent) */
		res = nd->inode->i_op->follow_link(nd->path.dentry, nd);

		if (IS_ERR(res))
			return PTR_ERR(res);

		if (nd_get_link(nd))
			*nptr = modify_lnk_name(n, *nptr, nd_get_link(nd));
		else {
			/* resolution already done in follow_link */
			int ret;

			nd->flags |= LOOKUP_JUMPED;
			nd->inode = nd->path.dentry->d_inode;
			ret = get_d_path(&nd->path, n);
			if (ret < 0)
				return ret;
			if (nd->inode->i_op->follow_link) {
				/* stepped on a _really_ weird one */
				path_put(&nd->path);
				return -ELOOP;
			}
			/* we have to set other fields that would
			   normally be done by shadow_res_resolve_name */
			*nptr = ret;
			nd->last_type = LAST_NORM;
			nd->flags &= ~LOOKUP_JUMPED;
			return 2;
		}

		if (nd->inode->i_op->put_link)
			nd->inode->i_op->put_link(nd->path.dentry, nd, res);
		goto out;
	}

	name = (*n) + (*nptr);
	while (*name=='/') {
		name++;
		(*nptr)++;
	}

	if (!*name)
		last_component = 1;

	len = hash_name(name, &nd->last.hash);
	nd->last.name = name;
	nd->last.len = len;

	nd->last_type = LAST_NORM;
	if (name[0] == '.') switch (len) {
		case 2:
			if (name[1] == '.') {
				nd->last_type = LAST_DOTDOT;
			}
			break;
		case 1:
			nd->last_type = LAST_DOT;
	}

	if (!name[len]) {
		last_component = 1;
		goto out;
	}
	/*
	 * If it wasn't NUL, we know it was '/'. Skip that
	 * slash, and continue until no more slashes.
	 */
	do {
		len++;
	} while (unlikely(name[len] == '/'));
	if (!name[len])
		last_component = 1;

out:
	*nptr += len;

	return last_component;
}
EXPORT_SYMBOL(shadow_res_advance_name);

static inline int can_lookup(struct inode *inode)
{
	if (likely(inode->i_opflags & IOP_LOOKUP))
		return 1;
	if (likely(!inode->i_op->lookup))
		return 0;

	/* We do this once for the lifetime of the inode */
	spin_lock(&inode->i_lock);
	inode->i_opflags |= IOP_LOOKUP;
	spin_unlock(&inode->i_lock);
	return 1;
}

static __always_inline void set_root(struct nameidata *nd)
{
	if (!nd->root.mnt)
		get_fs_root(current->fs, &nd->root);
}

/*
   from Documentation/filesystems/path-lookup.txt:
   Making the child a parent for the next lookup requires more checks and
   procedures. Symlinks essentially substitute the symlink name for the target
   name in the name string, and require some recursive path walking.  Mount
   points must be followed into, switching from the mount point path to the root of
   the particular mounted vfsmount.
 */

/* resolve name in nd->last_type to a path in nd->path */
int shadow_res_resolve_name(struct nameidata *nd, char *name)
{
	struct path next;
	int err = 0;
	struct path prev = nd->path; /* restore in case of -ENOENT */

	if (unlikely(current->total_link_count >= 40)) {
		return -ELOOP;
	}

	/* if the previous component was a symlink, re-initialize nd.
	 * slightly different from path_init because there is no dfd. */
	if (nd->last_type == LAST_BIND) {
		if (name[0] == '/') {
			/* absolute */
			set_root(nd);
			path_put(&nd->path);
			nd->path = nd->root;
			path_get(&nd->root);
			nd->flags |= LOOKUP_JUMPED;
		} else {
			/* relative, restore the parent to continue walk */
			nd->path.dentry = nd->path.dentry->d_parent;
		}
		nd->last_type = LAST_NORM;
		current->total_link_count++;
		goto out;
	}

	/* continue with resolution */
	if (!can_lookup(nd->inode))
		return -ENOTDIR;

	err = may_lookup(nd);
	if (err)
		return err;

	if (nd->last_type == LAST_DOTDOT)
		nd->flags |= LOOKUP_JUMPED;

	if (likely(nd->last_type == LAST_NORM)) {
		struct dentry *parent = nd->path.dentry;
		nd->flags &= ~LOOKUP_JUMPED;
		if (unlikely(parent->d_flags & DCACHE_OP_HASH)) {
			err = parent->d_op->d_hash(parent, nd->inode,
						   &nd->last);
			if (err < 0)
				return err;
		}
	}

	path_get(&prev);
	err = walk_component(nd, &next, &nd->last, nd->last_type, LOOKUP_FOLLOW);
	/* walk_component drops reference to parent if -ENOENT, but
	 * it changes nd.path to (negative dentry) child. change it back to
	 * the previous (parent) */
	if (err == -ENOENT)
		nd->path = prev;
	else if (nd->last_type == LAST_DOT)
		/* no additional reference obtained in walk_component if LAST_DOT */;
	else
		path_put(&prev);

	if (err < 0) {
		goto out;
	}
	if (err) {
		/* walk_component does not set nd->path to next if next is a symlink,
		 * as it will lose the parent, which we may need for further resolution.
		 * we manually restore the parent (see above).
		 * this means if someone makes our parent dentry negative (e.g, rm -r),
		 * we have a negative dentry parent on which we can't check permission.
		 * correspondingly, adversary permission module has been modified to
		 * simply ignore this case. */
		nd->last_type = LAST_BIND;
		nd->path.mnt = next.mnt;
		nd->path.dentry = next.dentry;
	}

out:
	/* consistency */
	nd->inode = nd->path.dentry->d_inode;
	return err;
}
EXPORT_SYMBOL(shadow_res_resolve_name);


int shadow_res_init(int dfd, const char *name,
		unsigned int flags, struct nameidata *nd)
{
	int retval = 0;
	int fput_needed;
	struct file *file;

	current->total_link_count = 0;

	nd->last_type = LAST_ROOT; /* if there are only slashes... */
	nd->flags = flags | LOOKUP_JUMPED;
	nd->depth = 0;

	nd->root.mnt = NULL;

	if (*name=='/') {
		set_root(nd);
		path_get(&nd->root);
		nd->path = nd->root;
	} else if (dfd == AT_FDCWD) {
			get_fs_pwd(current->fs, &nd->path);
	} else {
		struct dentry *dentry;

		file = fget_raw_light(dfd, &fput_needed);
		retval = -EBADF;
		if (!file)
			goto out_fail;

		dentry = file->f_path.dentry;

		if (*name) {
			retval = -ENOTDIR;
			if (!S_ISDIR(dentry->d_inode->i_mode))
				goto fput_fail;

			retval = inode_permission(dentry->d_inode, MAY_EXEC);
			if (retval)
				goto fput_fail;
		}

		nd->path = file->f_path;
		path_get(&file->f_path);
		fput_light(file, fput_needed);
	}

	nd->inode = nd->path.dentry->d_inode;
	current->sting_res_type = ADV_NORMAL_RES;
	return 0;

fput_fail:
	fput_light(file, fput_needed);
out_fail:
	return retval;
}

int shadow_res_end(struct nameidata *nd)
{
	int err;
	err = complete_walk(nd);

	/*
	if (!err && nd->flags & LOOKUP_DIRECTORY) {
		if (!nd->inode->i_op->lookup) {
			path_put(&nd->path);
			err = -ENOTDIR;
		}
	}

	if (nd->root.mnt && !(nd->flags & LOOKUP_ROOT)) {
		path_put(&nd->root);
		nd->root.mnt = NULL;
	} */
	return err;
}
EXPORT_SYMBOL(shadow_res_end);

void shadow_res_get_pc_paths(struct path *parent, struct path *child,
		struct nameidata *nd, int err)
{
	if (err != -ENOENT) {
		*child = nd->path;
		*parent = *child;
		// parent->dentry = child->dentry->d_parent;
		// if (child->dentry != parent->dentry)
			// path_get(parent);
		path_get_parent(child, parent);
	} else {
		*parent = nd->path;
		child->dentry = NULL;
		child->mnt = NULL;
	}
}
EXPORT_SYMBOL(shadow_res_get_pc_paths);

void shadow_res_put_pc_paths(struct path *parent, struct path *child, int err)
{
	if (err != -ENOENT && child->dentry != parent->dentry)
		path_put(parent);
}
EXPORT_SYMBOL(shadow_res_put_pc_paths);

void shadow_res_put_lookup_path(struct nameidata *nd)
{
	path_put(&nd->path);
}
EXPORT_SYMBOL(shadow_res_put_lookup_path);

char *shadow_res_get_last_name(struct nameidata *nd, struct path *child)
{
	/* if child exists, child dentry holds right name from the parent */
	if (child->dentry)
		return child->dentry->d_name.name;

	/* otherwise, nd->last.name holds name where -ENOENT occurred */
	return nd->last.name;
}
EXPORT_SYMBOL(shadow_res_get_last_name);
