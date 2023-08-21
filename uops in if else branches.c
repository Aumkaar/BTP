// code for a LInux + 11th gen Intel machine which observes the difference in number of microoperations executed for different branches in an if-else statement

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <asm/unistd.h>

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu, int group_fd, unsigned long flags)	{
	int ret;
	ret = syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
	return ret;
}

int main()
{
	struct perf_event_attr pe;

	// count1 measures the number of microoperations executed for the if branch
	// count2 measures the number of microoperations executed for the else branch
	long long count1 = 0;
	long long count2 = 0;

	long long count1sum = 0;
	double count1avg = 0;

	long long count2sum = 0;
	double count2avg = 0;

	int fd1, fd2;
	char event[] = "UOPS_EXECUTED.CORE";

	memset(&pe, 0, sizeof(struct perf_event_attr));
    pe.type = PERF_TYPE_RAW;
    pe.size = sizeof(struct perf_event_attr);
    pe.config = 0x02b1;
    pe.disabled = 1;
    pe.exclude_kernel = 1;
	pe.exclude_hv = 1;

	fd1 = perf_event_open(&pe, 0, -1, -1, 0);
	if (fd1 == -1)	{
		fprintf(stderr, "Error opening leader %llx\n", pe.config);
		exit(EXIT_FAILURE);
	}

	fd2 = perf_event_open(&pe, 0, -1, -1, 0);
	if (fd2 == -1)	{
		fprintf(stderr, "Error opening leader %llx\n", pe.config);
		exit(EXIT_FAILURE);
	}

	for (int i = 0; i < 1000000; i++); // warmup

	// multiply and square algorithm

	uint64_t x = 2;
	uint64_t y = 0b10110100;
	uint64_t result = 1;
	long long noOfCycles1 = 0;
	long long noOfCycles2 = 0;

	while (y > 0) {
		if (y & 1) {
			ioctl(fd1, PERF_EVENT_IOC_RESET, 0);
			ioctl(fd1, PERF_EVENT_IOC_ENABLE, 0);
			
			result *= x;
			
			ioctl(fd1, PERF_EVENT_IOC_DISABLE, 0);
			read(fd1, &count1, sizeof(long long));
		}
		ioctl(fd2, PERF_EVENT_IOC_RESET, 0);
		ioctl(fd2, PERF_EVENT_IOC_ENABLE, 0);
		y >>= 1;
		x *= x;
		ioctl(fd2, PERF_EVENT_IOC_DISABLE, 0);
		read(fd2, &count2, sizeof(long long));

		count1 += count2;

		if(count1 != count2)				// if branch was taken if count1 != count2
		{
			noOfCycles1++;
			count1sum += count1;
			count1 = 0;
		}
		else								// else branch was taken if count1 == count2, or count1 == 0
		{
			noOfCycles2++;
			count2sum += count2;
			count2 = 0;
		}
	}

	count1avg = (double) count1sum / noOfCycles1;
	count2avg = (double) count2sum / noOfCycles2;

	printf("Average number of microoperations executed for the if branch: %f\n", count1avg);
	printf("Average number of microoperations executed for the else branch: %f\n", count2avg);

	close(fd1);
	close(fd2);

	return 0;
}


