/* permissions module */
#define PERM_BIND 0x1
#define PERM_PREBIND 0x2

/* Maximum number of users in the system */
#define MAX_USERS 256
/* Maximum number of groups a user can be a member of */
#define GRP_MEMB_MAX 32

/* Return value space augment */
#define UID_NO_MATCH MAX_USERS

static inline int sting_valid_adversary(int adv_uid_ind)
{
	return ((adv_uid_ind >= 0) && (adv_uid_ind != UID_NO_MATCH));
}

int sting_get_adversary(struct dentry *parent, struct dentry *child, int flags);
struct cred *set_creds(uid_t *ug_list);
struct cred *superuser_creds(void);
int may_create_noexist(struct inode *dir);
uid_t *get_ug_list(uid_t u);
int uid_has_perm(uid_t *ug_list, struct dentry *parent,
	struct dentry *child, int flags);

extern uid_t uid_array[MAX_USERS][GRP_MEMB_MAX];
