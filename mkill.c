/*
 * mkill.c	Send a signal to all processes accessing a mount point
 *
 * Usage:	mkill [-SIG] /mnt ...
 *
 * Copyright 2008 Werner Fink, 2008 SUSE LINUX Products GmbH, Germany.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Author:      Werner Fink <werner@suse.de>
 */

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <mntent.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "libinit.h"
#include "lists.h"
#include "statx.h"

#ifndef  MNT_FORCE
# define MNT_FORCE	0x00000001
#endif
#ifndef  MNT_DETACH
# define MNT_DETACH	0x00000002
#endif
#ifndef  MNT_EXPIRE
# define MNT_EXPIRE	0x00000004
#endif

extern inline FILE * fopenat(int dirfd, const char *path)
{
    int fd = openat(dirfd, path, O_RDONLY|O_NONBLOCK|O_LARGEFILE);
    if (fd < 0)
	return (FILE*)0;
    return fdopen(fd , "r");
}

extern inline DIR * opendirat(int dirfd, const char *path)
{
    int fd = openat(dirfd, path, O_RDONLY|O_NONBLOCK|O_LARGEFILE|O_DIRECTORY);
    if (fd < 0)
	return (DIR*)0;
    return fdopendir(fd);
}

#define USAGE		"Usage:\n"\
			"    %s [-SIG] [-u] /mnt1 [/mnt2...]\n"\
			"    %s -l\n", we_are, we_are

typedef struct _s_shadow
{
    list_t this;
    size_t nlen;
    char * name;
} shadow_t;

typedef struct _s_mnt
{
    list_t     this;
    int       order;		/* Order of the mount point*/
    int      parent;		/* Order of the parent mount point*/
    shadow_t shadow;		/* Pointer to shadows	   */
    boolean     use;
    size_t     nlen;
    char *     name;
} mntent_t;

typedef struct _s_proc_
{
    list_t this;
    pid_t   pid;		/* Process ID.             */
    int   order;		/* Order of the mount point*/
} proc_t;

static int maxorder = 1;	/* This has to be initial 1 */

static list_t mntent = {&mntent, &mntent};
static list_t procs  = {&procs, &procs};
static list_t sort   = {&sort, &sort};

static void init_mnt(int argc, char* argv[]);
static void clear_mnt(const boolean lazy);
static void add_proc(pid_t pid, int order);
static void sort_proc(void);
static int check(const char *restrict name);

int main(int argc, char* argv[])
{
    const pid_t pid = getpid();
    const pid_t sid = getsid(0);
    const pid_t ppid = getppid();
    list_t * this, *ptr;
    struct dirent * dent;
    int dfd, num, nsig = SIGTERM;
    boolean lazy = false;
    boolean stop = false;
    struct stat st;
    boolean found;
    DIR * proc;

    we_are = base_name(argv[0]);

    num = argc;
    while (--num) {
	if (*(argv[num]) == '-') {
	    char *sig = argv[num];
	    int tmp, len = strlen(sig);
	    sig++;
	    if ((tmp = atoi(sig)) > 0 && tmp < NSIG) {
		memset(sig, '\0', len);
		nsig = tmp;
		break;
	    } else if ((tmp = signame_to_signum(sig)) > 0) {
		memset(sig, '\0', len);
		nsig = tmp;
		break;
	    }
	}
    }

    opterr = 0;
    while ((num = getopt(argc, argv, "0lhu")) != -1) {
	switch (num) {
	case '0':
	    nsig = 0;
	    break;
	case 'l':
	    list_signames();
	    exit(0);
	    break;
	case 'u':
	    lazy = true;
	    break;
	case '?':
	    error(LSB_WRGSYN, USAGE);
	    break;
	case 'h':
	    error(0, USAGE);
	    break;
	default:
	    break;
	}
    }
    argv += optind;
    argc -= optind;

    if (nsig == SIGTERM || nsig == SIGKILL) {
	stop = true;
	signal(SIGTERM, SIG_IGN);
	signal(SIGTSTP, SIG_IGN);
	signal(SIGINT,  SIG_IGN);
    } else
	lazy = false;

    if (nsig == SIGHUP)
	signal(SIGHUP, SIG_IGN);

    for (num = 0; num < argc; num++) {
	const size_t alen = strlen(argv[num]);
	char * astr = argv[num];

	if (alen <= 1)
	    continue;

	if (*(astr+(alen-1)) == '/')
	    *(astr+(alen-1)) = '\0';
    }

    init_mnt(argc, argv);

    if ((proc = opendir("/proc")) == (DIR*)0)
	error(100, "cannot open /proc: %s\n", strerror(errno));

    dfd = dirfd(proc);
    while ((dent = readdir(proc)) != (struct dirent*)0) {
	const pid_t curr = (pid_t)atol(dent->d_name);
	struct dirent * fddir;
	char name[PATH_MAX+1];
	char line[BUFSIZ+1];
	char path[256];
	char * slash;
	char * pline;
	ssize_t len;
	FILE * file;
	DIR * fdir;
	int order;
	int dffd;

	if (*dent->d_name == '.')
	    continue;
	if (*dent->d_name < '0' || *dent->d_name > '9')
	    continue;

	if (1 == curr)
	    continue;

	if (pid == curr)
	    continue;

	if (sid == curr)
	    continue;

	if (ppid == curr)
	    continue;

	found = false;

	strcpy(path, dent->d_name);
	len = strlen(dent->d_name);
	slash = &path[len];

	*slash = '\0';
	strcat(slash, "/statm");

	if ((file = fopenat(dfd, path)) == (FILE*)0)
	    continue;
	pline = fgets(line, BUFSIZ, file);
	fclose(file);
	if (!pline || line[0] == '0')
	    continue;

	*slash = '\0';
	strcat(slash, "/root");

	errno = 0;
	if ((len = readlinkat(dfd, path, name, PATH_MAX)) < 0)
	    continue;
	name[len] = '\0';
	if ((order = check(name))) {
	    add_proc(curr, order);
	    goto fuse;
	}

	*slash = '\0';
	strcat(slash, "/cwd");

	errno = 0;
	if ((len = readlinkat(dfd, path, name, PATH_MAX)) < 0)
	    continue;
	name[len] = '\0';
	if ((order = check(name))) {
	    add_proc(curr, order);
	    goto fuse;
	}

	*slash = '\0';
	strcat(slash, "/exe");

	errno = 0;
	if ((len = readlinkat(dfd, path, name, PATH_MAX)) < 0)
	    continue;
	name[len] = '\0';
	if (strncmp(name, "/sbin/udevd", 11) == 0)
	    continue;
	if (strncmp(name, "/usr/sbin/udevd", 15) == 0)
	    continue;
	if ((order = check(name))) {
	    add_proc(curr, order);
	    goto fuse;
	}

	*slash = '\0';
	strcat(slash, "/maps");

	if ((file = fopenat(dfd, path)) == (FILE*)0)
	    continue;
	while (fgets(line, BUFSIZ, file)) {
	    if (sscanf(line, "%*s %*s %*s %*x:%*x %*d %s", name) == 1) {

		if (name[0] == '\0' || name[0] == '[')
		    continue;

		if ((order = check(name))) {
		    found = true;
		    break;
		}
	    }
	    if (found) break;
	}
	(void)fclose(file);

	if (found) {
	    add_proc(curr, order);
	    goto fuse;
	}

    fuse:
	*slash = '\0';
	strcat(slash, "/fd");

	if ((fdir = opendirat(dfd, path)) == (DIR*)0)
	    continue;
	dffd = dirfd(fdir);
	while ((fddir = readdir(fdir)) != (struct dirent*)0) {
	    boolean isfuse = false;

	    if (*fddir->d_name == '.')
		continue;

	    errno = 0;
	    if ((len = readlinkat(dffd, fddir->d_name, name, PATH_MAX)) < 0)
		continue;
	    name[len] = '\0';

	    if (strcmp("/dev/fuse", name) == 0)
		isfuse = true;

	    if (found) {
		if (isfuse) {
		    list_for_each_safe(this, ptr, &procs) {
			proc_t *p = list_entry(this, proc_t);
			if (p->pid != curr)
			    continue;
			delete(this);
			free(p);
		    }
		    break;
		}
		continue;
	    }

	    if ((*name == '/') && (order = check(name))) {
		if (isfuse)
		    break;
		found = true;
		add_proc(curr, order);
	    }
	}
	(void)closedir(fdir);
    }
    (void)closedir(proc);
    clear_mnt(lazy);
    sort_proc();

    num = 0;
    found = false;
    list_for_each(ptr, &procs) {
	proc_t *p = list_entry(ptr, proc_t);
	if (nsig) {
	    if (stop)
		kill(p->pid, SIGSTOP);
	    kill(p->pid, nsig);
	    found = true;
	} else {
	    if (num++ > 0)
		putc(' ', stdout);
	    printf("%d", p->pid);
	}
    }
    if (stop)
	kill(-1, SIGCONT);

    if (num > 0)
	putc('\n', stdout);

    if (nsig != SIGTERM || !found)
	goto out;

    if (statn("/fastboot", STATX_INO, &st) < 0)
	num = 2000000;
    else
	num = 6000000;

    while (found) {

	if ((num <= 0) || !found)
	    break;
	usleep(10000);
	num -= 10000;

	found = false;
	list_for_each_safe(this, ptr, &procs) {
	    proc_t *p = list_entry(this, proc_t);
	    if (kill (p->pid, 0) < 0) {
		delete(this);
		free(p);
		continue;
	    }
	    found = true;
	}
    }

    if (!found)
	goto out;

    list_for_each(ptr, &procs) {
	proc_t *p = list_entry(ptr, proc_t);
	kill(p->pid, SIGSTOP);
	kill(p->pid, SIGKILL);
    }
    kill(-1, SIGCONT);

out:
    return 0;
}

static void init_mnt(int argc, char* argv[])
{
    char mpoint[PATH_MAX*4 + 1];	    /* octal escaping takes 4 chars per 1 char */
    struct stat st;
    struct mntent ent;
    FILE * mnt;
    int order = maxorder;

    /* Stat /proc/version to see if /proc is mounted. */
    if (statn("/proc/version", STATX_INO, &st) < 0)
	getproc();

    /* Use /proc/self/mountinfo if available */
    if ((mnt = fopen("/proc/self/mountinfo", "r"))) {
	int mid, parid;

	while (fscanf(mnt, "%i %i %*u:%*u %*s %s %*[^-] - %*s %*s %*[^\n]", &mid, &parid, &mpoint[0]) == 3) {
	    mntent_t *restrict ptr = (mntent_t*)0;
	    boolean found = false;
	    size_t nlen;
	    int num;

	    for (num = 0; num < argc; num++) {
		if (*(argv[num]) == '\0')
		    continue;
		if ((found = (strcmp(argv[num], mpoint) == 0)))
		    break;
	    }

	    nlen = strlen(mpoint);

	    if (posix_memalign((void*)&ptr, sizeof(void*), alignof(mntent_t)+(nlen+1)) != 0)
		error(100, "malloc(): %s\n", strerror(errno));
	    append(ptr, mntent);
	    ptr->order = mid;
	    ptr->parent = parid;
	    ptr->use = found;
	    ptr->name = ((char*)ptr)+alignof(mntent_t);
	    strcpy(ptr->name, mpoint);
	    ptr->nlen = nlen;
	    initial(&ptr->shadow.this);	    /* not required as we sort below */
	    if (mid > order)
		order = mid;
	}
	fclose(mnt);
	maxorder = order;

	/*
	 * Now sort into reverse mount order, with this we do not
	 * need any shadow mounts anymore.
	 */
	initial(&sort);
	for (mid = 1; mid <= maxorder; mid++) {
	    list_t *this, *cpy;
	    list_for_each_safe(this, cpy, &mntent) {
		mntent_t * m = list_entry(this, mntent_t);
		if (mid != m->order)
		    continue;
		move_head(this, &sort);
		break;
	    }
	    list_for_each_safe(this, cpy, &mntent) {
		mntent_t * m = list_entry(this, mntent_t);
		if (mid != m->parent)
		    continue;
		move_head(this, &sort);
	    }
	}
	if (!list_empty(&mntent))
	    error(100, "init_mnt(): %s\n", strerror(EBADE));
	join(&sort, &mntent);
	return;
    }

    if ((mnt = setmntent("/proc/mounts", "r")) == (FILE*)0)
	error(100, "cannot open /proc/mounts: %s\n", strerror(errno));

    while (getmntent_r(mnt, &ent, mpoint, sizeof(mpoint))) {
	mntent_t *restrict ptr = (mntent_t*)0;
	boolean found = false;
	size_t nlen;
	int num;

	for (num = 0; num < argc; num++) {
	    if (*(argv[num]) == '\0')
		continue;
	    if ((found = (strcmp(argv[num], ent.mnt_dir) == 0)))
		break;
	}

	if (!found)
	    continue;
	nlen = strlen(ent.mnt_dir);

	if (posix_memalign((void*)&ptr, sizeof(void*), alignof(mntent_t)+(nlen+1)) != 0)
	    error(100, "malloc(): %s\n", strerror(errno));
	append(ptr, mntent);
	ptr->order = order++;
	ptr->parent = -1;
	ptr->use = true;
	ptr->name = ((char*)ptr)+alignof(mntent_t);
	strcpy(ptr->name, ent.mnt_dir);
	ptr->nlen = nlen;
	initial(&ptr->shadow.this);
    }
    endmntent(mnt);
    maxorder = order;

    if ((mnt = setmntent("/proc/mounts", "r")) == (FILE*)0)
	error(100, "cannot open /proc/mounts: %s\n", strerror(errno));

    while (getmntent_r(mnt, &ent, mpoint, sizeof(mpoint))) {
	list_t *ptr;

	list_for_each(ptr, &mntent) {
	    mntent_t *p = list_entry(ptr, mntent_t);
	    shadow_t *restrict s = (shadow_t*)0;
	    size_t nlen;

	    if (strcmp(ent.mnt_dir, p->name) == 0)
		continue;
	    if (strncmp(ent.mnt_dir, p->name, p->nlen) != 0)
		continue;

	    nlen = strlen(ent.mnt_dir);
	    if (posix_memalign((void*)&s, sizeof(void*), alignof(shadow_t)+(nlen+1)) != 0)
		error(100, "malloc(): %s\n", strerror(errno));
	    append(s, p->shadow.this);
	    s->name = ((char*)s)+alignof(shadow_t);
	    strcpy(s->name, ent.mnt_dir);
	    s->nlen = nlen;
	}
    }
    endmntent(mnt);
}

static void clear_shadow(list_t *restrict shadow, const boolean lazy)
{
    list_t *this, *ptr;
    list_for_each_safe(this, ptr, shadow) {
	shadow_t *s = list_entry(this, shadow_t);
	delete(this);
	if (lazy)
	    umount2(s->name, MNT_DETACH);
	free(s);
    }
}

static void clear_mnt(const boolean lazy)
{
    list_t *this, *ptr;

    list_for_each_safe(this, ptr, &mntent) {
	mntent_t *p = list_entry(this, mntent_t);
	delete(this);
	if (!list_empty(&p->shadow.this)) {
	    clear_shadow(&p->shadow.this, lazy);
	}
	if (lazy)
	    umount2(p->name, MNT_DETACH);
	free(p);
    }
}

static void add_proc(pid_t pid, int order)
{
    proc_t *restrict ptr = (proc_t*)0;

    if (posix_memalign((void*)&ptr, sizeof(void*), alignof(proc_t)) != 0)
	error(100, "malloc(): %s\n", strerror(errno));
    append(ptr, procs);
    ptr->pid = pid;
    ptr->order = order;
}

static void sort_proc(void)
{
    int order;

    initial(&sort);
    for (order = maxorder; order > 0; order--) {
	list_t *this, *ptr;

	list_for_each_safe(this, ptr, &procs) {
	    proc_t *p = list_entry(this, proc_t);

	    if (p->order != order)
		continue;

	    move_tail(this, &sort);
	}
    }
    join(&sort, &procs);
}

static boolean shadow(list_t *restrict shadow, const char *restrict name, const size_t nlen)
{
    list_t *ptr;

    if (!shadow || list_empty(shadow))
	goto out;

    list_for_each(ptr, shadow) {
	shadow_t *s = list_entry(ptr, shadow_t);
	if (nlen < s->nlen)
	    continue;
	if (name[s->nlen] != '\0' && name[s->nlen] != '/')
	    continue;
	if (strncmp(name, s->name, s->nlen) == 0)
	    return true;
    }
out:
    return false;
}

static int check(const char *restrict name)
{
    const size_t nlen = strlen(name);
    list_t *ptr;

    list_for_each(ptr, &mntent) {
	mntent_t *p = list_entry(ptr, mntent_t);
	if (nlen < p->nlen)
	    continue;
	if (name[p->nlen] != '\0' && name[p->nlen] != '/')
	    continue;
	if (strncmp(name, p->name, p->nlen) == 0) {
	    if (!p->use)
		break;
	    if (shadow(&p->shadow.this, name, nlen))
		continue;
	    return p->order;
	}
    }
    return 0;
}
