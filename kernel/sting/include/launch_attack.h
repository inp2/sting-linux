/* Type of attack to launch */
#define SYMLINK 0x1
#define HARDLINK 0x2
#define SQUAT 0x4

/* Extended attributes */
#define ATTACKER_XATTR_PREFIX "security."
#define ATTACKER_XATTR_SUFFIX "attacker"
#define ATTACKER_XATTR_STRING ATTACKER_XATTR_PREFIX ATTACKER_XATTR_SUFFIX
#define ATTACKER_XATTR_VALUE "1"

int sting_launch_attack(char *fname, int a_ind, int attack_type); 
