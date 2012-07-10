#include <linux/namei.h>

int shadow_res_init(int dfd, const char *name, 
		unsigned int flags, struct nameidata *nd); 
int shadow_res_advance_name(char **n, int *nptr, struct nameidata *nd); 
int shadow_res_resolve_name(struct nameidata *nd, char *name); 
int shadow_res_end(struct nameidata *nd); 
