/*
 * Routines for daemon, killproc, killall5, pidof, and runlevel.
 *
 * Version:     2.0 10-Nov-2000 Fink
 *
 * Copyright 1994-2000 Werner Fink, 1996-2000 SuSE GmbH Nuernberg, Germany.
 * Copyright 2005 Werner Fink, 2005 SUSE LINUX Products GmbH, Germany.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Author:    Werner Fink <werner@suse.de>, 1994-2000
 *
 * 1998/09/29 Werner Fink: Add kernel thread handling.
 * 1999/02/24 Werner Fink: Add xread to avoid EINTR
 * 1999/08/05 Werner Fink: environment, move some inlined into libint.c
 * 2000/11/10 Werner Fink: LSB specs, logging
 */

#ifndef _LIBINIT_H
#define _LIBINIT_H
#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <utmp.h>
#include <pwd.h>
#include <mntent.h>
#include <libgen.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <syslog.h>
#include <errno.h>
#include <stdarg.h>
#include <ctype.h>
#ifdef USE_BLOGD
# include <libblogger.h>
#endif
#include "lists.h"
#ifndef O_CLOEXEC
# define O_CLOEXEC 0	
#endif

/*
 * LSB specs:
 *
 * For start/stop and others but status
 *   0 - success
 *   1 - generic or unspecified error
 *   2 - invalid or excess argument(s)
 *   3 - unimplemented feature (e.g. "reload")
 *   4 - insufficient privilege
 *   5 - program is not installed
 *   6 - program is not configured
 *   7 - program is not running
 */
#define LSB_OK			0
#define LSB_FAILED		1
#define LSB_WRGSYN		2
#define LSB_MISSED		3	/* not used */
#define LSB_NOPERM		4
#define LSB_NOENTR		5
#define LSB_NOCONF		6	/* not used */
#define LSB_NOPROC		((flags & KSTOP) ? LSB_OK : 7 )

#define LSB_PROOF 		((errno == EPERM || errno == EACCES) ? LSB_NOPERM : LSB_FAILED )
#define LSB_PROOFX 		((errno == ENOENT) ? LSB_NOENTR : LSB_PROOF )
#define LSB_PROOFE 		((errno == EPERM || errno == EACCES) ? LSB_NOPERM : LSB_NOPROC )
/*
 * For status
 *   0 - service running
 *   1 - service dead, but /var/run/  pid  file exists
 *   2 - service dead, but /var/lock/ lock file exists
 *   3 - service not running
 */
#define LSB_STATUS_OK		((flags & KILL) ? LSB_OK     : 0 )
#define LSB_STATUS_ISDEAD	((flags & KILL) ? LSB_NOPROC : 1 )
#define LSB_STATUS_NOLOCK	2	/* not used */
#define LSB_STATUS_NOPROC	((flags & KILL) ? LSB_NOPROC : 3 )

#define WRGSYNTAX		102	/* usage etc. */
#define NOPIDREAD		101	/* trouble */

#define LSB_STATUS_PROOF	((errno == EPERM || errno == EACCES) ? LSB_NOPERM : LSB_STATUS_ISDEAD )
#define LSB_STATUS_PROOFX	((errno == ENOENT) ? (flags & KILL) ? LSB_NOENTR : 4 : LSB_STATUS_PROOF )

#define LOG_OPTIONS	(LOG_ODELAY|LOG_CONS)
#define LOG_FACILITY	LOG_LOCAL7

#define PIDOF   0x0001
#define DAEMON  0x0002
#define KILL    0x0004
#define KTHREAD 0x0008
#define NZOMBIE 0x0010
#define KSHORT  0x0020
#define FLWLINK 0x0040
#define KSTOP   0x0080
#define KBASE   0x0100
#define STSCRPT 0x0200

#define  MAXENV  20
#define  CMDLLEN MAXNAMLEN	/* The string length of /proc/12345/cmdline\0\0 + 1 */
#ifdef _PATH_VARRUN
# define DEFPIDDIR _PATH_VARRUN
#else
# define DEFPIDDIR "/var/run/"
#endif
#define  DEFPIDEXT ".pid"
#define  DEFPIDLEN 14		/* The string length of /var/run/.pid + 1 */
#define  COMM_LEN 15		/* The lenght of the task command name in /proc/<pid>/stat */

extern char **environ;
extern char     * newenvp[];
extern unsigned   newenvc;

extern char * we_are;
extern unsigned short stopped;
extern pid_t p_pid, p_sid, p_ppid;

/* Declare */
extern int  pidof  (const char * inname, const char * root, const unsigned short flag);
extern int  remember_pids (const char * pids, const char * inname, const char * root,
			   unsigned short flags);
extern int  verify_pidfile (const char * pid_file, const char * inname, const char * root,
			    const unsigned short flag, const boolean ignore);
extern int  check_pids (const char * inname, const char * root, const unsigned short flag);
extern void clear_pids (void);
extern void error(int stat, const char *fmt, ...);
extern void warn(const char *fmt, ...);
extern int rlstat(char ** file, struct stat *st, const unsigned short flag);
extern char* expandpath(const char * path);
extern void init_nfs(void);
extern void clear_nfs(void);
extern void getproc(void);
extern boolean check4nfs(const char * path);
extern size_t dirdepth(const char *const path);

/* Feature */
extern int signame_to_signum (const char *sig);
extern const char * signum_to_signame (const int sig);
extern void list_signames(void);

#if 0
/* Used in killproc.c only once to list the signal names */
static inline void list_signames(void)
{
    int n, l;

    for (n = 1, l = 0; n < NSIG+1; n++) {
	const char * signame = signum_to_signame(n);
	if (signame) {
	    printf("%2d) SIG%-9s", n, signame);
	    l++;
	}
	if (!(l % 4))
	    putc('\n', stdout);
    }
    if (l % 4)
	putc('\n', stdout);
}
#endif

typedef struct _proc_
{
    list_t this;
    pid_t   pid;			/* Process ID. */
    pid_t   sid;			/* Session ID. */
} PROC;

extern list_t remember;
extern list_t doignore;

/* Inlined functions: just like macros */

static inline void *xmalloc(const size_t bytes)
{
    void *p = malloc(bytes);

    if (p == (void*)0) {
	if (stopped) kill(-1, SIGCONT);
	error(100, "malloc(): %s\n", strerror(errno));
    }
    return p;
}

static inline char *xstrdup(const char * string)
{
    char *p = strdup(string);

    if (p == (char*)0) {
	if (stopped) kill(-1, SIGCONT);
	error(100, "strdup(): %s\n", strerror(errno));
    }
    return p;
}

static inline char * base_name ( const char * full )
{
    char *basename = strrchr(full, '/');

    if (basename == (char *)0)
	basename = (char *)full;
    else
	basename++;

    return basename;
}

static inline char * swap_name ( const char * base )
{
    size_t len = strlen(base);
    char *swap;
    if (len > COMM_LEN)
	len = COMM_LEN;
    swap = (char*)xmalloc(len + 2 + 1);
    return strcat(strncat(strcpy(swap,"("),base, COMM_LEN),")");
}

extern void addnewenv ( const char * name, const char * entry );
extern char ** runlevel(const char *file);

/* Used in startproc only once to overwrite the environment */
static inline void set_newenv(const char * fullname)
{
    char *tmp;
    char buf[_POSIX_PATH_MAX + 1];

/*
 *  Default environment for a daemon:
 *  PATH=..., HOME=..., SHELL=...
 *  We need control environment:
 *  DAEMON=fullname, PREVLEVEL=..., RUNLEVEL=...
 */
    if ( (tmp = getenv("HOME")) != (char*)0 )
	addnewenv("HOME",tmp);
    else
	addnewenv("HOME","/");

    if ( (tmp = getenv("PATH")) != (char*)0 )
	addnewenv("PATH",tmp);
    else
	addnewenv("PATH","/usr/bin:/usr/sbin:/bin:/sbin");

    if ( (tmp = getenv("SHELL")) != (char*)0 )
	addnewenv("SHELL",tmp);
    else
	addnewenv("SHELL","/bin/sh");

    if ( (tmp = getenv("LISTEN_PID")) != (char*)0 )
	addnewenv("LISTEN_PID",tmp);

    if ( (tmp = getenv("LISTEN_FDS")) != (char*)0 )
	addnewenv("LISTEN_FDS",tmp);

    if ( (tmp = getenv("RUNLEVEL")) != (char*)0 )
	addnewenv("RUNLEVEL",tmp);

    if ( (tmp = getenv("PREVLEVEL")) != (char*)0 )
	addnewenv("PREVLEVEL",tmp);
    else {
	char ** tmp = runlevel((char*)0);
	addnewenv("PREVLEVEL",tmp[0]);
	addnewenv("RUNLEVEL", tmp[1]);
    }

    environ = (char**)newenvp; /* Make new environment active */

    (void)snprintf(buf, _POSIX_PATH_MAX, "%s",fullname);
    addnewenv("DAEMON",buf);

    return;
}

/* Used in startproc only once to extend the environment */
static inline void set_environ(const char * fullname)
{
    char *tmp;
    char buf[_POSIX_PATH_MAX + 1];

    if ( (tmp = getenv("RUNLEVEL")) != (char*)0 )
	setenv("RUNLEVEL",tmp,1);
    if ( (tmp = getenv("PREVLEVEL")) != (char*)0 )
	setenv("PREVLEVEL",tmp,1);
    else {
	char ** tmp = runlevel((char*)0);
	setenv("PREVLEVEL",tmp[0],1);
	setenv("RUNLEVEL", tmp[1],1);
    }

    (void)snprintf(buf, _POSIX_PATH_MAX, "%s",fullname);
    setenv("DAEMON",buf,1);
    return;
}

/* Add a task to our remember list */
static inline void do_list(const pid_t pid, const pid_t sid, const boolean ignore)
{
    PROC * p = (PROC*)xmalloc(sizeof(PROC));
    p->pid = pid;
    p->sid = sid;
    if (ignore) {
	append(p, doignore);
    } else {
	append(p, remember);
    }
}

static inline boolean check_ignore(const pid_t pid)
{
    list_t *m;

    if (pid <= 1)
	goto out;

    list_for_each(m, &doignore) {
	PROC *q = list_entry(m, PROC);
        if (pid == q->pid)
	    return true;
    }
out:
    return false;
}

static inline void clear_ignore(void)
{
    list_t *n, *l;

    if (list_empty(&doignore))
	return;

    list_for_each_safe(n, l, &remember) {
	PROC *p = list_entry(n, PROC);

	if (!check_ignore(p->pid))
	    continue;

	/* Remove this entry in remember because we ignore it */
	delete(n);
	free(p);
    }
}
#endif /* _LIBINIT_H */
