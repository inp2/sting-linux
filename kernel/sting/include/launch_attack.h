/*
 * Copyright (c) 2011-2012 Hayawardh Vijayakumar
 * Copyright (c) 2011-2012 Systems and Internet Infrastructure Security Lab
 * Copyright (c) 2011-2012 The Pennsylvania State University
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/* Type of attack to launch */
#define SYMLINK 0x1
#define HARDLINK 0x2
#define SQUAT 0x4
#define USP 0x4 /* untrusted search path */

/* attacks already launched */
#define CHECK_SYMLINK (SYMLINK << 8)
#define CHECK_HARDLINK (HARDLINK << 8)
#define CHECK_SQUAT (SQUAT << 8)
#define CHECK_USP (USP << 8)

/* Extended attributes */
#define ATTACKER_XATTR_PREFIX "security."
#define ATTACKER_XATTR_SUFFIX "attacker"
#define ATTACKER_XATTR_STRING ATTACKER_XATTR_PREFIX ATTACKER_XATTR_SUFFIX
#define ATTACKER_XATTR_VALUE "1"

static inline char *sting_attack_to_str(int attack_type)
{
	if (attack_type == SYMLINK)
		return "symlink";
	else if (attack_type == HARDLINK)
		return "hardlink";
	else if (attack_type == SQUAT)
		return "squat";
	else
		return "invalid";
}

int sting_launch_attack(char *fname, struct path *parent,
		int a_ind, int attack_type, struct sting *st);

static inline int sting_attack_checked(int attack_history, int attack_type)
{
	return (attack_history & (attack_type << 8));
}

static inline int sting_get_next_attack(int attack_history)
{
	if (!sting_attack_checked(attack_history, SYMLINK))
		return SYMLINK;
	return -1;
	if (!sting_attack_checked(attack_history, HARDLINK))
		return HARDLINK;
	if (!sting_attack_checked(attack_history, SQUAT))
		return SQUAT;
}

#define DONT_FOLLOW 0
#define FOLLOW 1
