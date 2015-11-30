/* writes a dump from /sys/kernel/debug/ept_dict_dump* 
 * to /sys/kernel/debug/ept_dict */

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#define EPT_DICT_FILE "ept_dict"
#define BUF_SIZE 32768

int main(int argc, char **argv)
{
	int wfd, n, rfd, sz, rc = 0; 
	struct stat sbuf; 
	char buf[BUF_SIZE];
	char *fnm; 

	if (argc < 3) {
		printf("%s [debugfs mount path] [ept_dict saved file]\n", argv[0]); 
		exit(0);
	}

	rfd = open(argv[2], O_RDONLY); 
	if (rfd < 0) {
		printf("Error opening rfd: %d\n", errno); 
		exit(0);
	}

	rc = asprintf(&fnm, "%s/%s", argv[1], EPT_DICT_FILE); 
	if (rc < 0) {
		printf("Error allocating string: %d\n", errno); 
		exit(0); 
	}


	wfd = open(fnm, O_RDWR); 
	if (wfd < 0) {
		printf("Error opening wfd: %d\n", errno); 
		exit(0);
	}

	rc = fstat(rfd, &sbuf); 
	if (rc < 0) {
		printf("Error fstat: %d\n", rc); 
		exit(0);
	}

	sz = (int) sbuf.st_size; 
	write(wfd, &sz, sizeof(int)); 

	while ((n = read(rfd, &buf, sizeof(buf)))) {
		write(wfd, buf, n); 
	}
}
