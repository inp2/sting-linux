#define STING_PID_FILE "/sys/kernel/debug/sting_monitor_pid"

static int set_sting_pid(pid_t pid)
{
	int fd; 
	char pid_buf[6];

	fd = open(STING_PID_FILE, O_RDWR); 
	if (fd < 0) {
		printf("Error opening %s\n", STING_PID_FILE); 
		exit(0);
	}
	sprintf(pid_buf, "%d", pid); 
	write(fd, pid_buf, 6); 
}
