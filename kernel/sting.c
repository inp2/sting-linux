#include <linux/sting.h>
#include <linux/user_unwind.h>
#include <asm-generic/current.h>

void sting_syscall_begin(void) 
{
	user_unwind(current); 
}
EXPORT_SYMBOL(sting_syscall_begin); 
