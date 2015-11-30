/* reads a dump from /sys/kernel/debug/ept_dict_dump* */

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>

#include "sting.h"

#define TEST_FILE "/tmp/my_file"

int main(int argc, char **argv)
{
	int fd, i; 
	char template[64]; 

	set_sting_pid(getpid()); 

	for (i = 0; i < 2; i++)	{
		sprintf(template, "%sXXXXXX", TEST_FILE); 
		fd = mkstemp(template); 
		printf("Attempting to create file: %s\n", template); 
		if (fd < 0)
			printf("mkstemp failed: %s\n", strerror(errno)); 
	}
}
