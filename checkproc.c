/*
 * checkproc.c  Checks process(es) of the named program.
 *
 * Usage:       checkproc [-v] [-k] [-p pid_file] /full/path/to/program
 *
 * Copyright 1994-2000 Werner Fink, 1996-2000 SuSE GmbH Nuernberg, Germany.
 * Copyright 2005 Werner Fink, 2005 SUSE LINUX Products GmbH, Germany.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Author:      Werner Fink <werner@suse.de>
 * 1998/05/06 Werner Fink: rework, added "-p" for pid files
 * 2000/11/10 Werner Fink: LSB specs, logging
 * 2007/11/29 Werner Fink: ignore more than one pid
 */

#include "libinit.h"
#include "statx.h"

#define USAGE		"Usage:\n"\
			"\t%s [-v] [-k] [-p pid_file] /full/path/to/program\n" \
			, we_are

int main(int argc, char **argv)
{
    extern char * we_are;
    int c, num;
#ifdef USE_BLOGD
    int blog = 0;
#endif
    struct stat st;
    list_t *list;
    char *fullname = NULL, * basename = NULL;
    char *pid_file = NULL, *ignore_file = NULL;
    char *root = NULL;
    extension char *iargv[argc];
    char *posixa, *posixb;	/* Don't fool me with posix correct */
    int quiet = 1, iargc = 0;
    unsigned short flags = (DAEMON|PIDOF|NZOMBIE);
    boolean pid_forced = false;

    we_are = base_name(argv[0]);
    for (c = 0; c < argc; c++)
	iargv[c] = (char*)0;
    if (!strcmp(we_are, "pidofproc"))
	quiet = 0;
    openlog (we_are, LOG_OPTIONS, LOG_FACILITY);

    /*
     *  We should stat() fullname, because only the path identifies the executable.
     *  If there is one hardlink we have only to stat() the orignal executable.
     *  If there is more than one hardlink and we have to distinguish the
     *  executables by their swapname.  Note if the cmdline of some executables
     *  will changed by the running process its self the name is not clearly
     *  defined ... see libinit.c for more information.
     */

    posixa = getenv("_POSIX_OPTION_ORDER"); unsetenv("_POSIX_OPTION_ORDER");
    posixb = getenv("POSIXLY_CORRECT");     unsetenv("POSIXLY_CORRECT");
    opterr = 0;
    while ((c = getopt(argc, argv, "c:kp:nNhqvzLi:x")) != -1) {
	switch (c) {
	    case 'c':
		if (optarg && optarg[0] != '-' && !root) {
		    root = optarg;
		} else
		    error(LSB_WRGSYN,"Option -c requires special root directory\n");
		break;
	    case 'L':
		flags |= FLWLINK;
		break;
	    case 'k':
		flags &= ~DAEMON;
		flags |= KILL;
		break;
	    case 'q':
		break;
	    case 'v':
		quiet = 0;
		break;
	    case 'n':
		flags |= KTHREAD;
		break;
	    case 'N':
		init_nfs();
		break;
	    case 'x':
		flags |= STSCRPT;
		break;
	    case 'z':
		flags &= ~NZOMBIE;
		break;
	    case 'p':		/* Changed from -f to -p to fit startproc and LSB */
		/* Allocate here: address optarg (current *argv) isn't freeable */
		if (optarg && !pid_file) {
		    pid_file = xstrdup(optarg);
		} else
		    error(WRGSYNTAX, "Option -p requires pid file to read pid from\n");
		break;
	    case 'i':
		/* Remember: address optarg (current *argv) */
		if (optarg && optarg[0] != '-') {
		    iargv[iargc++] = optarg;
		} else
		    error(LSB_WRGSYN,"Option -i requires pid file to read pid from\n");
		break;
	    case 'h':
		error(0, USAGE);
		break;
	    case '?':
		error(WRGSYNTAX, USAGE);
		break;
	    default:
		break;
	}
    }
    if (posixa) setenv("_POSIX_OPTION_ORDER", posixa, 0);
    if (posixb) setenv("POSIXLY_CORRECT",     posixb, 0);

    argv += optind;
    argc -= optind;

    if (!*argv)
	error(WRGSYNTAX, USAGE);
    if (root) {
	fullname = (char*) xmalloc(strlen(*argv)+strlen(root)+1);
	fullname = strcat(strcpy(fullname,root),*argv);
    } else
	fullname = *argv;

    if (flags & FLWLINK) {
	/* rlstat replaces the current fullname with that of the real file */
	if (rlstat(&fullname, &st, flags) < 0)
	    warn("cannot stat %s: %s\n", fullname, strerror(errno));
    }
    basename = base_name(fullname);

    if (*fullname != '/')
	flags |= KSHORT;
    else if (check4nfs(fullname))
	flags |= (KSHORT|KBASE);
    clear_nfs(); 

    if (!pid_file) {		/* the default pid file */
	if (root) {
	    pid_file = (char*) xmalloc(DEFPIDLEN+strlen(basename)+strlen(root)+1);
	    pid_file = strcpy(pid_file,root);
	    pid_file = strcat(strcat(strcat(pid_file,DEFPIDDIR),basename),DEFPIDEXT);
	} else {
	    pid_file = (char*) xmalloc(DEFPIDLEN+strlen(basename)+1);
	    pid_file = strcat(strcat(strcpy(pid_file,DEFPIDDIR),basename),DEFPIDEXT);
	}
    } else
	pid_forced = true;

    /* Check and verify the pid file */
    errno = 0;
    if (statn(pid_file, STATX_SIZE, &st) < 0) {
	if (errno != ENOENT) {
	    /* An other error like permission or HW problem */
	    warn("Can not stat %s: %s\n", pid_file, strerror(errno));

	} else if (pid_forced) {
	    /*
	     * Pid file was provided by the user therefore we assume that
	     * the proc is dead if the specified pid can not be veryfied.
	     */
	    if (remember_pids(pid_file,fullname,root,flags) < 0)
		exit(LSB_STATUS_PROOFX);

	    if (list_empty(&remember))
		exit(LSB_STATUS_NOPROC);	/* New LSB: no pid file is no job */
	}
	free(pid_file);
	pid_file = NULL;

	/* No pid file means that we have to search in /proc/ */
    }

    if (pid_file && !st.st_size) {
	warn("Empty pid file %s for %s\n", pid_file, fullname);

	free(pid_file);
	pid_file = NULL;

	if (pid_forced)
	    exit(LSB_STATUS_NOPROC);

	/* No pid file means that we have to search in /proc/ */
    }

    /* Check and verify the ignore file */
    for (c = 0; (c < iargc) && (ignore_file = iargv[c]); c++) {
	errno = 0;
	if (statn(ignore_file, STATX_SIZE, &st) < 0) {
	    if (errno != ENOENT)
		warn("Can not stat %s: %s\n", ignore_file, strerror(errno));
	    continue;
	}
	if (!st.st_size) {
	    warn("Empty ignore file %s for %s\n", ignore_file, fullname);
	    continue;
	}
				/* The case of having a ignore file */
	if (verify_pidfile(ignore_file,fullname,root,flags,true) < 0)
	    exit(LSB_PROOFX);
    }

    /* Do main work */
    if (flags & DAEMON) {	/* Do the verification just like checkproc */
	if (pid_file) {		  /* The case of having a pid file */
	    if (verify_pidfile(pid_file,fullname,root,flags,false) < 0)
		exit(LSB_STATUS_PROOFX);
	    if (iargc)
		clear_pids();
	}
	if (list_empty(&remember)) {	  /* No process found with pid file */
	    if (pid_forced)
		exit(LSB_STATUS_PROOFX);
	    if (pidof(fullname,root,flags) < 0)
		exit(LSB_STATUS_PROOFX);
	}
    } else {		/* Now we're act like killproc: restrictive */
	if (pid_file) {		  /* The case of having a pid file */
	    if (verify_pidfile(pid_file,fullname,root,flags,false) < 0)
		exit(LSB_PROOFX);
	} else {		  /* No pid file found or given */
	    if (pidof(fullname,root,flags) < 0)
		exit(LSB_PROOFX);
	}
    }
    clear_pids();		/* Remove all pids which should be ignored */

    num = 0;	/* If quiet we could test 'remember' and exit appropiate */
    list_for_each(list, &remember) {
	PROC *proc = list_entry(list, PROC);
	if (!quiet) {
	    if (num) putchar(' ');
	    printf("%ld", (long int)proc->pid);
	}
#ifdef USE_BLOGD
	if (bootlog(B_NOTICE, "%s: %s ", we_are, fullname) == 0) {
	    blog++;
	    if (num) bootlog(-1, " ");
	    bootlog(-1, "%ld", (long int)proc->pid);
	}
#endif
	num++;
    }

    if (!num) {
	if (pid_file)
	    exit(LSB_STATUS_ISDEAD);
	exit(LSB_STATUS_NOPROC);
    }
    if (!quiet)
	putchar('\n');
#ifdef USE_BLOGD
    if (blog) {
	bootlog(-1, "\n");
	closeblog();
    }
#endif
    closelog();
    exit(LSB_STATUS_OK);
}
