/*
 * vhangup.c    Cause a hangup on the specified terminals
 *
 * Usage:       vhangup /dev/tty1 ...
 *
 * Copyright 2008 Werner Fink, 2008 SUSE LINUX Products GmbH, Germany.
 * Copyright 2012 Werner Fink, 2012 SUSE LINUX Products GmbH, Germany.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Author:      Werner Fink <werner@suse.de>
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#include "lists.h"

/*
 * Kernel above 3.0 may cause D state if a process has open the system
 * console /dev/console if vhangup(2) is perfomed. This is a well known
 * bug in the kernel and we may see this also with other bug reports.
 */
#define USE_VHANGUP	0

#if USE_VHANGUP == 0
typedef struct _s_proc_
{
    list_t this;
    pid_t   pid;
} proc_t;

static list_t procs  = {&procs, &procs};

static void add_proc(pid_t pid)
{
    proc_t *restrict ptr;

    if (posix_memalign((void*)&ptr, sizeof(void*), alignof(proc_t)) != 0) {
	perror("vhangup: malloc()");
	exit(1);
    }
    append(ptr, procs);
    ptr->pid = pid;
}

extern inline DIR * opendirat(int dirfd, const char *path)
{
    int fd = openat(dirfd, path, O_RDONLY|O_NONBLOCK|O_LARGEFILE|O_DIRECTORY);
    if (fd < 0)
	return (DIR*)0;
    return fdopendir(fd);
}

static void ttyprocs(const char *device)
{
    int fd;
    DIR * proc;
    struct dirent * dent;
    const pid_t pid = getpid();
    const pid_t sid = getsid(0);
    const pid_t ppid = getppid();

    if ((proc = opendir("/proc")) == (DIR*)0)
	return;
    fd = dirfd(proc);

    while ((dent = readdir(proc)) != (struct dirent*)0) {
	int fds;
	pid_t curr;
	ssize_t len;
	DIR * fdir;
	char * slash;
	char path[256];
	struct dirent * fddir;

	if (*dent->d_name == '.')
	    continue;
	if (*dent->d_name < '0' || *dent->d_name > '9')
	    continue;
	curr = (pid_t)atol(dent->d_name);

	if (1 == curr)
	    continue;
	if (pid == curr)
	    continue;
	if (sid == curr)
	    continue;
	if (ppid == curr)
	    continue;

	strcpy(path, dent->d_name);
	len = strlen(dent->d_name);
	slash = &path[len];

	*slash = '\0';
	strcat(slash, "/fd");

	if ((fdir = opendirat(fd, path)) == (DIR*)0)
	    continue;
	fds = dirfd(fdir);
	while ((fddir = readdir(fdir)) != (struct dirent*)0) {
	    char name[PATH_MAX+1];
	    if (*fddir->d_name == '.')
		continue;
	    if ((len = readlinkat(fds, fddir->d_name, name, PATH_MAX)) < 0)
		continue;
	    name[len] = '\0';
	    if (strcmp(device, name) == 0) {
		add_proc(curr);
		break;
	    }
	}
	(void)closedir(fdir);
    }
    (void)closedir(proc);
}
#endif

int main(int argc, char* argv[])
{
    int ret;
#if USE_VHANGUP == 0
    int num;
    list_t *ptr;
    struct sigaction sa, sa_old;

    sa.sa_flags = 0;
    sa.sa_handler = SIG_IGN;
    sigemptyset (&sa.sa_mask);
    sigaction (SIGHUP, &sa, &sa_old);

    for (ret = num = 1; num < argc; num++) {
	ttyprocs(argv[num]);
	ret++;
    }
    list_for_each(ptr, &procs) {
	    proc_t *p = list_entry(ptr, proc_t);
	    (void)kill(p->pid, SIGHUP);
    }

    sigaction (SIGHUP, &sa_old, NULL);
    return (ret != num);
#else
    switch (fork()) {
    case -1:
	fprintf(stderr, "vhangup: %s\n", strerror(errno));
	return 1;
    case 0: {
	struct sigaction sa, sa_old;
	int num, sid = 0;

	sa.sa_flags = 0;
	sa.sa_handler = SIG_IGN;
	sigemptyset (&sa.sa_mask);
	sigaction (SIGHUP, &sa, &sa_old);

	for (ret = num = 1; num < argc; num++) {
	    int fd = open(argv[num], O_RDWR|O_NONBLOCK|O_NOCTTY, 0);
	    if (fd < 0) {
		switch (errno) {
		case ENOENT:
		case ENODEV:
		case ENXIO:
		   ret++;
		default:
		   break;
		}
		continue;
	    }
	    if (!sid) {
#ifdef TIOCVHANGUP
		if (ioctl(fd, TIOCVHANGUP, 1) == 0)
		    ret++;
		if (errno != EINVAL)
		    goto next;
		ret = num;
#endif
		setsid();
		sid++;
	    }
	    if ((ioctl (fd, TIOCSCTTY, 1) == 0) && (vhangup() == 0))
		ret++;
#ifdef TIOCVHANGUP
	next:
#endif
	    close(fd);
	}

	sigaction (SIGHUP, &sa_old, NULL);
	exit(ret != num);
    }
    default:
	waitpid(-1, &ret, 0);
	break;
    }

    return (WIFEXITED(ret)) ? WEXITSTATUS(ret) : 1;
#endif
}
