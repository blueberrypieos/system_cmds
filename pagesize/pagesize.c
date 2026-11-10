/* SPDX-License-Identifier: BSD-2-Clause */

#include <stdio.h>
#include <sys/sysctl.h>

int
main(void)
{
	int pagesize;
	size_t size = sizeof(pagesize);

	if (sysctlbyname("hw.pagesize", &pagesize, &size, NULL, 0) == -1) {
		perror("pagesize");
		return 1;
	}

	printf("%d\n", pagesize);
	return 0;
}
