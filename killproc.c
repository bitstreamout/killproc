/*
 * killproc.c   Kill all running processes of a named program.
 *
 * Usage:       killproc [-v] [-t<sec>] [-g|-G] [-SIG] /full/path/to/program
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
 *
 * 1998/05/06 Florian La Roche: added "-g" option to kill process groups
 * 1998/05/06 Werner Fink: rework, added "-p" for pid files
 * 1998/15/09 Werner Fink: exit status for killing not running processes is 0
 * 1998/29/09 Werner Fink: Add kernel thread handling.
 * 2000/11/10 Werner Fink: LSB specs, logging
 * 2007/11/29 Werner Fink: ignore more than one pid
 */

#include "libinit.h"
#include "statx.h"

#define DEFSIG		"TERM"
#define OTHERSIG	"HUP"

#define USAGE		"Usage:\n"\
			"    %s [-v] [-q] [-L] [-g|-G] [-N] [-p pid_file] [-i ingnore_file] \\\n"\
			"        [-c root] [-t<sec>] [-SIG] /full/path/to/executable\n"\
		 	"    %s -l\n", we_are, we_are

static int do_kill(const char *name, const pid_t proc, const int sig,
		   const int group_leader, const int process_group);

static int quiet = 1, num;

int main(int argc, char **argv)
{
    int c, snum;
    struct stat st;
    list_t *list;
    char *fullname = NULL, *basename = NULL;
    char *pid_file = NULL, *ignore_file = NULL;
    char *root = NULL;
    extension char *iargv[argc];
    char *posixa, *posixb;	/* Don't fool me with posix correct */
    int process_group = 0, group_leader = 0, wait = 5, iargc = 0;
    unsigned short flags = (KILL|PIDOF|KSTOP);
    boolean pid_forced = false;
    boolean sig_forced = true;

    we_are = base_name(argv[0]);
    openlog (we_are, LOG_OPTIONS, LOG_FACILITY);
    for (c = 0; c < argc; c++)
	iargv[c] = (char*)0;

    /* If we are not called as killproc use HUP (e.g. for sigproc) */
    if (strcmp(we_are,"killproc") != 0)
	snum = signame_to_signum(OTHERSIG);
    else
	snum = signame_to_signum(DEFSIG);

    /*
     *  We should stat() fullname, because only the path identifies the executable.
     *  If there is one hardlink we have only to stat() the orignal executable.
     *  If there is more than one hardlink and we have to distinguish the
     *  executables by their swapname.  Note if the cmdline of some executables
     *  will changed by the running process its self the name is not clearly
     *  defined ... see libinit.c for more information.
     */

    c = argc;
    while (--c) {
	if (*(argv[c]) == '-') {
	    char *sig = argv[c];
	    int tmp, len = strlen(sig);
	    sig++;
	    if ( (tmp = atoi(sig)) > 0 && tmp < NSIG ) {
		memset(sig, 0, len);
		*sig = 'q';		/* set dummy option -q */
		snum = tmp;
		sig_forced = false;
		break;
	    } else if ( (tmp = signame_to_signum(sig)) > 0 ) {
		memset(sig, 0, len);
		*sig = 'q';		/* set dummy option -q */
		snum = tmp;
		sig_forced = false;
		break;
	    }
	}
    }

    posixa = getenv("_POSIX_OPTION_ORDER"); unsetenv("_POSIX_OPTION_ORDER");
    posixb = getenv("POSIXLY_CORRECT");     unsetenv("POSIXLY_CORRECT");
    opterr = 0;
    while ((c = getopt(argc, argv, "c:p:gGnNhlvqt:Li:x")) != -1) {
	switch (c) {
	    case 'c':
		if (optarg && optarg[0] != '-' && !root) {
		    root = optarg;
		} else
		    error(LSB_WRGSYN,"Option -c requires special root directory\n");
		break;
	    case 't':
		wait = atoi(optarg);
		if (wait < 1)
		    error(LSB_WRGSYN, USAGE);
		break;
	    case 'q':
		flags &= ~KSTOP;
		/* A signal which has been handled or the old but unused -q option */
		break;
	    case 'v':
		quiet = 0;
		break;
	    case 'L':
		flags |= FLWLINK;
		break;
	    case 'g':
		if (process_group)
		    error(LSB_WRGSYN, USAGE);
		group_leader++;
		break;
	    case 'G':
		if (group_leader)
		    error(LSB_WRGSYN, USAGE);
		process_group++;
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
	    case 'p':		/* Changed from -f to -p to fit startproc and LSB */
		/* Allocate here: address optarg (current *argv) isn't freeable */
		if (optarg && !pid_file) {
		    pid_file = xstrdup(optarg);
		} else
		    error(LSB_WRGSYN,"Option -p requires pid file to read pid from\n");
		break;
	    case 'l':
		list_signames();
		exit(0);
	    case 'i':
		/* Remember: address optarg (current *argv) */
		if (optarg && optarg[0] != '-') {
		    iargv[iargc++] = optarg;
		} else
		    error(LSB_WRGSYN,"Option -i requires pid file to read pid from\n");
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
    if (posixa) setenv("_POSIX_OPTION_ORDER", posixa, 0);
    if (posixb) setenv("POSIXLY_CORRECT",     posixb, 0);

    argv += optind;
    argc -= optind;

    if (!*argv)
	error(LSB_WRGSYN, USAGE);

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

    if (!pid_file) {            /* the default pid file */
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
		exit(LSB_PROOFX);

	    if (list_empty(&remember))
	        exit(LSB_NOPROC);	/* New LSB: no pid file is no job */
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

    if (pid_file) {		/* The case of having a pid file */
	if (verify_pidfile(pid_file,fullname,root,flags,false) < 0)
	    exit(LSB_PROOFX);
    } else {			/* No pid file found or given */
	if (pidof(fullname,root,flags) < 0)
	    exit(LSB_PROOFX);
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

    if (iargc)
	clear_pids();		/* Remove all pids which should be ignored */

    /* Do main work */
    if (list_empty(&remember)) {
	/* killing a none existing process is already success.
	 * Nevertheless LSB says that we should note that if
	 * a signal is explicit given.
	 */
	exit(LSB_NOPROC);
    }

    num = 0;
    list_for_each(list, &remember) {
	PROC *proc = list_entry(list, PROC);
	do_kill(basename, proc->pid, snum, group_leader, process_group);
    }

    if (snum == SIGTERM || snum == SIGKILL) {
	int partsec = 5*wait;	/* We look 5 times within a second */
	/*
	 * Does anybody have a better idea ... something with sigaction()/signal()
	 * and alarm(). Who wakes us if the terminated process is finished?
	 * The process(es) is/are not a child of us.
	 */
	usleep(60*1000);	/* 60 ms time for the process and its childs */
again:
	if (check_pids(fullname,root,flags) < 0)
	    exit(LSB_PROOFX);

	if (list_empty(&remember))		/* success */
	    goto success;

	fflush(stdout);
	fflush(stderr);
	if (partsec-- > 0) {	/* sleep 0.2 seconds and try again */
	    usleep(2*100*1000);
	    goto again;
	}

	if (snum == SIGKILL)	/* SIGKILL was specified on the command line */
	    goto badterm;

	if (!sig_forced)	/* SIGTERM was specified on the command line */
	    goto badterm;

	if (check_pids(fullname,root,flags) < 0)
	    exit(LSB_PROOFX);

	list_for_each(list, &remember) {
	    PROC *proc = list_entry(list, PROC);
	    do_kill(basename, proc->pid, SIGKILL, group_leader, process_group);
	}

	/* Do we have killed them? */

	usleep(60*1000);	/* 60 ms time for the process and its childs */
	if (check_pids(fullname,root,flags) < 0)
	    exit(LSB_PROOFX);

	if (!list_empty(&remember))
	    goto badterm;

success:
	if (num) putchar('\n');
	errno = 0;
	if (pid_file && (unlink(pid_file) < 0)) {
	    if (errno != ENOENT)
		warn("Can not remove %s: %s\n", pid_file, strerror(errno));
	}
	exit(LSB_OK);

badterm:
	if (num) putchar('\n');
	exit(LSB_FAILED);
    }

    if (num)
	putchar('\n');
    exit(LSB_OK);

} /* end of main */

/* The core function */
static int do_kill(const char *inname, const pid_t proc, const int sig,
		   const int group_leader, const int process_group)
{
    pid_t target = proc;
    int stop = (sig == SIGTERM || sig == SIGKILL);

    errno = 0;
    if (group_leader) {
	if ((target = -getpgid(proc)) >= 0) {
	    if (errno != ESRCH)
		warn("Can not signal %s to process with pid %d: %s\n",
			signum_to_signame(sig), (int)proc, strerror(errno));
	    exit(LSB_PROOFX);
	}
    } else if (process_group)
	target = -proc;
#if DEBUG
    printf("kill(%d,%d)\n",(int)target, sig);
#else
#ifdef USE_BLOGD
    bootlog(B_NOTICE, "%s: kill(%d,%d)\n", we_are, (int)target, sig);
#endif
    if (stop) kill(target, SIGSTOP);
    errno = 0;
    if (kill(target, sig) < 0) {
	if (errno != ESRCH) {
	    warn("Can not signal %s to process with pid %d: %s\n",
		    signum_to_signame(sig), (int)proc,  strerror(errno));
	    exit(LSB_FAILED);
	}
    }
    if (stop) kill(target, SIGCONT);
    usleep(1);		/* Force the kernel to run the scheduler and update 
			   the environment of the current processes */
    if (!quiet) {
	if (num++) putchar(' ');
	printf("SIG%s %s(%d)",signum_to_signame(sig),inname,(int)proc);
    }
#endif
    return 0;
}
