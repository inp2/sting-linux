#include <linux/namei.h>
#include <linux/fcntl.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/module.h>
#include <asm/syscall.h>
#include <linux/sting.h>

#include "syscalls.h"
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
