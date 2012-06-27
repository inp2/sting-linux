#include <linux/sting.h>
#include <linux/user_unwind.h>
#include <asm-generic/current.h>
#include <linux/module.h>
#include <linux/fs.h>
#include "ept_dict.h"

extern int sting_get_adversary(const char *fname, int flags);
extern char *get_syscall_fname(void); 

void sting_syscall_begin(void) 
{
	char *fname; 
	uid_t adv_uid; 
	struct ept_dict_entry *e, *r; 
	int ntest; 
	struct ept_dict_key k; 
	struct ept_dict_val v; 
	k.ino = 12; 
	k.offset = 13; 
	v.adversary_access = 2; 
	v.attack_history = 1; 

#if 0
	/* check if nameres call */
	fname = get_syscall_fname(); 
	if (!fname) 
		goto end; 
#endif
	
	/* get entrypoint (if performance needed, do this after adversary check) */
	user_unwind(current); 

	e = ept_dict_lookup(&k); 
	if (!e)
		ept_dict_entry_set(&k, &v); 

#if 0
	/* adversary check */
	adv_uid = sting_get_adversary(fname, ATTACKER_BIND); 

	/* check against attack history */
	e = kmalloc(sizeof(struct ept_dict_entry), GFP_KERNEL); 
	if (!e)
		goto end; 
	e->key.ino = get_ept_inode(current->user_stack); 
	e->key.offset = get_ept_offset(current->user_stack); 

	r = ept_dict_get_entry(e->key); 
	if (!r) {
		/* insert into history */
		e->value.adversary_access |= (adv_uid != -1); 
		e->value.attack_history = 0; 
		r = ept_dict_set_entry(e->key, e->value); 
	} 
	kfree(e); 

	if (adv_uid != -1) {
		/* check retry */
		if (sting_pending_lookup_ept(current)) {
			/* retry => immune to pending attack (if any) */
			type = sting_pending_get_type(current, r->key.offset); 
			sting_pending_remove_ept(current, r->key.offset); 
			ept_dict_mark_immune(r, (r->value.attack_history) & type); 
		}

		/* get next attack */
		ntest = get_next_attack(e->value.attack_history); 
		if (!ntest) 
			goto end; 

		/* update pending */
		sting_pending_add_ept(current); 

		/* attack! */
		fuzz_resource(fname, ntest, adv_uid, 0); 
#endif 
end:
	if (fname)
		putname(fname); 
	return; 
}
EXPORT_SYMBOL(sting_syscall_begin); 
