/*
 * fsync.c      File data sync for the specified file
 *
 * Usage:       fsync file
 *
 * Copyright 2007 Werner Fink, 2007 SUSE LINUX Products GmbH, Germany.
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
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <string.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#define USAGE		"Usage:\t%s file\n", we_are

static char *we_are;
int main(int argc, char **argv)
{
    int ret, fd, flags;
    char *path, *dir = NULL;

    if (argc != 2)
	goto err;

    if ((path = strdup(argv[1])) == (char*)0)
	goto err;

    dir  = dirname(path);
    flags =  O_RDONLY|O_NOCTTY|O_NONBLOCK;

    if (getuid() == 0)
	flags |= O_NOATIME;

    if ((fd = open(argv[1], flags)) < 0) {
	if (errno != ENOENT)
	    goto err;
	if ((fd = open(dir, flags|O_DIRECTORY)) < 0)
	    goto err;
	ret = fsync(fd);
	close(fd);
	if (ret < 0)
	    goto err;
	if ((fd = open(argv[1], flags)) < 0)
	    goto err;
    }
    ret = fsync(fd);
    close(fd);
    if (ret < 0)
	goto err;

    return 0;
    /* Do this at the end for speed */
err:
    we_are = basename(argv[0]);
    fprintf(stderr, USAGE);

    if (argc > 1 && *(argv[1]) == '-') {
	argv[1]++;
	if (!strcmp(argv[1], "-help") || *(argv[1]) == 'h' || *(argv[1]) == '?') {
	    fprintf(stderr, "Do a fsync(2) on the specified file.\n\n");
	    fprintf(stderr, "Help options:\n");
	    fprintf(stderr, "  -h, -?, --help    display this help and exit.\n");
	    exit (0);
	}
    } else if (errno != 0)
	fprintf(stderr, "%s: %s\n", argv[1], strerror(errno));
    exit (1);
}
