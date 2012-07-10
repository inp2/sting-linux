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

/* an iterative version of path lookup, treating all 
 * bindings equally, whether they be final or path. 
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

	if (nd->last_type == LAST_BIND) {
		void *res; 
		if (!nd->inode->i_op->follow_link) {
			printk(KERN_INFO "no follow_link! [%s]\n", *n); 
			return -EINVAL; 
		}
		res = nd->inode->i_op->follow_link(nd->path.dentry, nd); 
		if (IS_ERR(res))
			return PTR_ERR(res); 
		strcpy(*n, nd->saved_names[0]); 
		if (nd->inode->i_op->put_link)
			nd->inode->i_op->put_link(nd->path.dentry, nd, res); 
		*nptr = 0; 
		goto out; 
	}

	name = (*n) + (*nptr); 
	while (*name=='/')
		name++;
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

/* resolve name in nd->last_type to a path in nd->path */
int shadow_res_resolve_name(struct nameidata *nd, char *name)
{
	struct path next;
	int err = 0;

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
			nd->inode = nd->path.dentry->d_inode;
		} else {
			/* relative, restore the parent to continue walk */
			nd->path.dentry = nd->path.dentry->d_parent; 
			nd->inode = nd->path.dentry->d_inode; 
		}
		nd->last_type = LAST_NORM; 
		current->total_link_count++; 
		return err; 
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

	err = walk_component(nd, &next, &nd->last, nd->last_type, LOOKUP_FOLLOW);
	if (err < 0)
		return err;
	if (err) {
		/* walk_component does not set nd->path to next if next is a symlink,
		 * as it will lose the parent, which we may need for further resolution. 
		 * we manually restore the parent (see above) (is this ok?). */
		nd->last_type = LAST_BIND; 
		nd->path.mnt = next.mnt; 
		nd->path.dentry = next.dentry; 
		nd->inode = nd->path.dentry->d_inode; 
	}

	// terminate_walk(nd);
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

	if (!err && nd->flags & LOOKUP_DIRECTORY) {
		if (!nd->inode->i_op->lookup) {
			path_put(&nd->path);
			err = -ENOTDIR;
		}
	}

	if (nd->root.mnt && !(nd->flags & LOOKUP_ROOT)) {
		path_put(&nd->root);
		nd->root.mnt = NULL;
	}
	return err;
}
EXPORT_SYMBOL(shadow_res_end); 
