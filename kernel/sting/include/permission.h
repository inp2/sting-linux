/* permissions module */
#define ATTACKER_BIND 0x1
#define ATTACKER_PREBIND 0x2

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

extern int sting_get_adversary(const char *fname, int flags);
