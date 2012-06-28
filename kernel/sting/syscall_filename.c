/* sting: if syscall performs name resolution, get filename */

#include <linux/stop_machine.h>
#include <linux/clocksource.h>
#include <linux/kallsyms.h>
#include <linux/seq_file.h>
#include <linux/suspend.h>
#include <linux/debugfs.h>
#include <linux/hardirq.h>
#include <linux/kthread.h>
#include <linux/uaccess.h>
#include <linux/ftrace.h>
#include <linux/sysctl.h>
#include <linux/slab.h>
#include <linux/ctype.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/rcupdate.h>
#include <linux/relay.h>
#include <linux/un.h>
#include <linux/net.h>
#include <linux/module.h>

#include "syscalls.h"

/* For socketcalls */
#define AL(x) ((x) * sizeof(unsigned long))
static const unsigned char nargs[20] = {
	AL(0),AL(3),AL(3),AL(3),AL(2),AL(3),
	AL(3),AL(3),AL(4),AL(4),AL(4),AL(6),
	AL(6),AL(2),AL(5),AL(5),AL(3),AL(3),
	AL(4),AL(5)
};

char *get_syscall_fname(void)
{
	int ret = 0, nr_arg = 0;
	struct pt_regs *ptregs = task_pt_regs(current);
	int sn = ptregs->orig_ax; /* Syscall number */
	struct sockaddr_un *sock = NULL;
	char __user *u_fname = NULL;

	if (in_set(sn, first_arg_set))
		nr_arg = 1;
	else if (in_set(sn, second_arg_set))
		nr_arg = 2;

	switch(nr_arg) {
		case 1:
			u_fname = (char __user *) ptregs->bx;
			break;
		case 2:
			u_fname = (char __user *) ptregs->cx;
			break;
		default:
			/* Not in list of syscalls performing nameres */
			u_fname = NULL;
	}

	/* Handle socketcall specially, and only for AF_UNIX */
	/* Currently, we handle only bind and connect */
	if (sn == __NR_socketcall) {
		unsigned long a[6];
		unsigned int len;
		int call = ptregs->bx;
		unsigned long __user *args = (unsigned long __user *) ptregs->cx;

		if (call < 1 || call > SYS_RECVMMSG) {
			ret = -EINVAL;
			goto out;
		}

		len = nargs[call];
		if (len > sizeof(a)) {
			ret = -EFAULT;
			goto out;
		}

		/* copy_from_user should be SMP safe. */
		if (copy_from_user(a, args, len)) {
			ret = -EFAULT;
			goto out;
		}

		switch(ptregs->bx) {
			case SYS_BIND:
			case SYS_CONNECT:
				sock = kmalloc(sizeof(struct sockaddr_un), GFP_ATOMIC);
				if (!sock)
					goto out;
				if (copy_from_user(sock, (const void __user *) a[1],
					sizeof(struct sockaddr))) {
					ret = -EFAULT;
					goto out_free;
				}
				if (((struct sockaddr *) sock)->sa_family == AF_UNIX) {
					u_fname = (char __user *)
						((struct sockaddr_un __user *) a[1])->sun_path;
					/* TODO: Why does this happen? */
					/* TODO: Handle pagefaults - use copy_from_user */
					if (!strcmp(u_fname, ""))
						u_fname = NULL;
					#if 0
					if (copy_from_user(sock, (const void __user *) a[1],
						sizeof(struct sockaddr_un))) {
						ret = -EFAULT;
						goto out_free;
					}
					u_fname = (char __user *) (sock->sun_path);
					#endif
				}
				break;
			default:
				;
		}
	}

out_free:
	if (sock)
		kfree(sock);
out:
	/* TODO: Why empty fname "" even in e.g., stat64 (cat "")? */
	/* TODO: Handle pagefaults - use copy_from_user */
	if (u_fname && strcmp(u_fname, ""))
		return getname(u_fname);
	return NULL;
}
EXPORT_SYMBOL(get_syscall_fname);
