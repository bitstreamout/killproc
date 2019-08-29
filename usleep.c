/*
 * usleep.c     Sleep for the specified number of microseconds
 *
 * Usage:       usleep [ microseconds ]
 *
 * Copyright 2001 Werner Fink, 2001 SuSE GmbH Nuernberg, Germany.
 * Copyright 2005 Werner Fink, 2005 SUSE LINUX Products GmbH, Germany.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Author:      Werner Fink <werner@suse.de>
 */

#ifndef  __USE_STRING_INLINES
# define __USE_STRING_INLINES
#endif
#ifdef   __NO_STRING_INLINES
# undef  __NO_STRING_INLINES
#endif
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#define USAGE		"Usage:\t%s [ microseconds ]\n", we_are

static char *we_are;
int main(int argc, char **argv)
{
    unsigned long int usec = 1;
    int fd;

    if (argc > 2)
	goto err;

    if (argc > 1) {
	char *endptr;
	usec = strtoul(argv[1], &endptr, 10);
	if (*endptr != '\0')
	    goto err;
    }

    if ((fd = open("/dev/null", O_RDWR|O_NOCTTY|O_CLOEXEC)) >= 0) {
	dup2(fd, 0);
	dup2(fd, 1);
	dup2(fd, 2);
	if (fd > 2) close(fd);
    }

    if (usec) {
#if defined(_POSIX_C_SOURCE) && (_POSIX_C_SOURCE >= 199309L)
	struct timespec req = {0, 0}, rem = {0, 0};
	int ret;

	while (usec >= 1000000UL) {
	    req.tv_sec++;
	    usec -= 1000000UL;
	}
	req.tv_nsec = usec * 1000;

	do {
	    ret = nanosleep(&req, &rem);
	    if (ret == 0 || errno != EINTR)
		break;
	    req = rem;
	} while (req.tv_nsec > 0 || req.tv_sec > 0);
#else
	usleep(usec);
#endif
    } else
	(void)sched_yield();
    _exit(0);

    /* Do this at the end for speed */
err:
    we_are = basename(argv[0]);
    fprintf(stderr, USAGE);

    if (argc > 1 && *(argv[1]) == '-') {
	argv[1]++;
	if (!strcmp(argv[1], "-help") || *(argv[1]) == 'h' || *(argv[1]) == '?') {
	    fprintf(stderr, "Sleep for the specified number of microseconds.\n\n");
	    fprintf(stderr, "Help options:\n");
	    fprintf(stderr, "  -h, -?, --help    display this help and exit.\n");
	    exit (0);
	}
    }
    exit (1);
}
