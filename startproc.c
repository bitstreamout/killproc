/*
 * startproc.c  Start process(es) of the named program.
 *
 * Was:         daemon [-l log_file] /full/path/to/program
 * Usage:       startproc [+/-<prio>] [-v] [-l log_file|-q] /full/path/to/program
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
 * 1998/05/06 Werner Fink: change name to startproc
 * 1998/05/06 Werner Fink: rework, added "-p" for pid files
 * 1999/08/05 Werner Fink: added "-t" for time to sleep, reenable "-e"
 * 2000/11/10 Werner Fink: LSB specs, logging
 * 2007/11/29 Werner Fink: ignore more than one pid, close existing files on execve,
 *                         do not fork in case of start_daemon
 */

#include <sys/time.h>
#include <sys/resource.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <argz.h>
#include <grp.h>
#include "libinit.h"
#include "statx.h"

#ifndef  SD_LISTEN_FDS_START
# define SD_LISTEN_FDS_START	3
#endif

#define USAGE		"Usage:\n"\
			"    %s [-f] [-L] [[-n ]+/-<prio>] [-s] [-t sec|-T sec] [-u uid] [-g gid] [-v] [-e] \\\n"\
			"        [-l log|-q|-d] [-p pid_file] [-i ignore_file] [-c root] [-w|-W list] /path/to/executable [args]\n"
#define USAGE_SD	"Usage:\n"\
			"    %s [-f] [-L] [-n +/-<prio>] [-u uid] [-g gid] [-v] [-e] \\\n"\
			"        [-l log|-q|-d] [-p pid_file] [-i ignore_file] [-c root] /path/to/executable [args]\n"

static int do_start(const char *name, char *argv[], const char* log_file,
		   const int nicelvl, const int env, const char* root, unsigned short flags);
static void closefds(FILE *not);
static void waiton(const char *list);
static int get_sd_listen_fds(void);
static void fwd_sd_listen_pid(void);

static int quiet = true, supprmsg = false, sess = false, seconds = false;
static int sigchld = false, force = false, dialog = false;
static struct passwd *user = NULL;
static struct group *grp = NULL;
static int syslogd = 0;
static int sdaemon = 0;
static int wpopts = WNOHANG|WUNTRACED;
static char *wlist = NULL;

static volatile sig_atomic_t signaled = 0;
static sighandler_t save_sigquit = SIG_DFL;
static void sig_quit(int nsig)
{
    (void)signal(nsig, save_sigquit);
    signaled = true;
}

static void sig_chld(int nsig)
{
    if (nsig != SIGCHLD)
	return;
    (void)signal(nsig, SIG_DFL);
    seconds = 0;
}

enum {
    IOPRIO_CLASS_NONE,
    IOPRIO_CLASS_RT,
    IOPRIO_CLASS_BE,
    IOPRIO_CLASS_IDLE,
};

enum {
    IOPRIO_WHO_PROCESS = 1,
    IOPRIO_WHO_PGRP,
    IOPRIO_WHO_USER,
};

#define IOPRIO_CLASS_SHIFT	(13)
#define IOPRIO_PRIO_MASK	((1UL << IOPRIO_CLASS_SHIFT) - 1)

#define IOPRIO_PRIO_CLASS(mask)	((mask) >> IOPRIO_CLASS_SHIFT)
#define IOPRIO_PRIO_DATA(mask)	((mask) & IOPRIO_PRIO_MASK)
#define IOPRIO_PRIO_VALUE(class, data)	(((class) << IOPRIO_CLASS_SHIFT) | data)

static inline int ioprio_set(int which, int who, int ioprio)
{
    return syscall(SYS_ioprio_set, which, who, ioprio);
}

static int schedclass = -1, scheddata = 4;
static void inline ioprio_setpid(pid_t pid, int ioclass, int data)
{
    int rc = ioprio_set(IOPRIO_WHO_PROCESS, pid, IOPRIO_PRIO_VALUE(ioclass, data));
    if (rc < 0)
	error(LSB_PROOF, "ioprio_set failed: %m\n");
}

int main(int argc, char **argv)
{
    struct stat st;
    char *fullname = NULL, *basename = NULL;
    char *log_file = NULL, *pid_file = NULL, *ignore_file = NULL;
    char *root = NULL;
    extension char *iargv[argc];
    int c, nicelvl = 0, env = 0, iargc = 0;
    unsigned short flags = (DAEMON|PIDOF);

    we_are = base_name(argv[0]);
    sdaemon = (strcmp("start_daemon", we_are) == 0) ? 1 : 0;
    openlog (we_are, LOG_OPTIONS, LOG_FACILITY);
    for (c = 0; c < argc; c++)
	iargv[c] = (char*)0;

    /*
     *  We should stat() fullname, because only the path identifies the executable.
     *  If there is one hardlink we have only to stat() the orignal executable.
     *  If there is more than one hardlink and we have to distinguish the
     *  executables by their swapname.  Note if the cmdline of some executables
     *  will changed by the running process its self the name is not clearly
     *  defined ... see libinit.c for more information.
     */

    if (*argv && !sdaemon) {
        char **opt = argv;
	if (*(++opt) && (**opt == '-' || **opt == '+') && (nicelvl = atoi(*opt))) {
	    if (nicelvl > PRIO_MAX)
        	nicelvl = PRIO_MAX;
	    if (nicelvl < PRIO_MIN)
	        nicelvl = PRIO_MIN;
	    argc--, argv++;
	}
    }

    opterr = 0;
    while ((c = getopt(argc, argv, "+c:edp:l:hqvsu:g:t:n:o:fLi:T:wW:x")) != -1) { /* `+' is POSIX correct */
	switch (c) {
	    case 'v':
		quiet = 0;
		break;
	    case 'c':
		if (optarg && optarg[0] != '-' && !root) {
		    root = optarg;
		} else
		    error(LSB_WRGSYN,"Option -c requires special root directory\n");
		break;
	    case 'e':
		env = true;
		break;
	    case 'd':
		dialog = true;
		seconds = 15;
		break;
	    case 'x':
		flags |= STSCRPT;
		break;
	    case 'p':		/* Former option -f */
		if (force)
		    warn("option -p does not work in force mode\n");
		/* Allocate here: address optarg (current *argv) isn't freeable */
		if (optarg && optarg[0] != '-' && !pid_file) {
		    pid_file = xstrdup(optarg);
		} else
		    error(LSB_WRGSYN,"Option -p requires pid file to read pid from\n");
		break;
	    case 'f':		/* Newer option -f for force start (LSB specs!) */
		force = true;
		break;
	    case 'l':
		if (optarg && optarg[0] != '-' && !log_file) {
		    log_file = optarg;
		} else
		    error(LSB_WRGSYN,"Option -l requires log file\n");
		break;
	    case 'L':
		flags |= FLWLINK;
		break;
	    case 'n':
		if (optarg && optarg[0] != '/') {
		    char *endptr;
		    int lvl = strtol(optarg, &endptr, 10);

		    if (*endptr != '\0')
			error(LSB_WRGSYN,"Option -n requires a number as nice level\n");

		    if (lvl > PRIO_MAX)
			lvl = PRIO_MAX;
		    if (lvl < PRIO_MIN)
			lvl = PRIO_MIN;
		    nicelvl = lvl;

		} else
		    error(LSB_WRGSYN,"Option -n requires nice level\n");
		break;
	    case 'o':
		if (optarg && optarg[0] != '/' && optarg[0] != '-') {
		    char *endptr, *class = (char*)0, *level = (char*)0;
		    int lvl;

		    if ((endptr = strchr(optarg, ','))) {
			*endptr++ = '\0';
			level = endptr;
			class = &optarg[0];
			if (*level == 'n')
			    level++;
			if (*class == 'c')
			    class++;
		    } else {
			if (optarg[0] == 'c')
			    class = &optarg[1];
			if (optarg[0] == 'n')
			    level = &optarg[1];
			if (optarg[0] >= '0' && optarg[0] <= '3') {
			    class = &optarg[0];
			    printf("%s\n", optarg);
			}
		    }

		    if (!class && !level)
			error(LSB_WRGSYN,"Option -o requires a scheduling class and/or scheduling class data level\n");

		    if (class && *class) {
			lvl = strtol(class, &endptr, 10);
			if (*endptr != '\0')
			    error(LSB_WRGSYN,"Class identifier `c' requires a number as scheduling class\n");
			if (lvl < 0 || lvl > 3)
			    error(LSB_WRGSYN,"Class identifier `c' is out of range\n");
			schedclass = lvl;
		    }
		    if (level && *level) {
			lvl = strtol(level, &endptr, 10);
			if (*endptr != '\0')
			    error(LSB_WRGSYN,"Class data identifier `n' requires a number as scheduling class data\n");
			if (lvl < 0 || lvl > 7)
			    error(LSB_WRGSYN,"Class data identifier `n' is out of range\n");
			scheddata = lvl;
		    }
		} else
		     error(LSB_WRGSYN,"Option -o requires I/O nice level\n");
		break;
	    case 'q':
	        supprmsg = true;
	        break;
	    case 's':
		if (sdaemon) goto fail;
		sess = true;
		break;
	    case 'u':
		if (optarg && optarg[0] != '/' && optarg[0] != '-') {
		    char *endptr;
		    uid_t uid =  (uid_t)strtol(optarg, &endptr, 10);

		    user = getpwnam(optarg);
		    if (!user && (*endptr == '\0')) user = getpwuid(uid);
		    endpwent();

		    if (!user)
			error(LSB_WRGSYN,"No such user or user id: %s\n", optarg);
		} else
		    error(LSB_WRGSYN,"Option -u requires user id or user name\n");
		break;
	    case 'g':
		if (optarg && optarg[0] != '/' && optarg[0] != '-') {
		    char *endptr;
		    gid_t gid =  (gid_t)strtol(optarg, &endptr, 10);

		    grp = getgrnam(optarg);
		    if (!grp && (*endptr == '\0')) grp = getgrgid(gid);
		    endgrent();

		    if (!grp)
			error(LSB_WRGSYN,"No such group or group id: %s\n", optarg);
		} else
		    error(LSB_WRGSYN,"Option -g requires group id or group name\n");
		break;
	    case 'T':
		sigchld++;
	    case 't':
		if (sdaemon) goto fail;
		if (optarg && optarg[0] != '/' && optarg[0] != '-') {
		    char *endptr;
		    seconds = (int)strtol(optarg, &endptr, 10);

		    if (strlen(endptr) == strlen(optarg))
			error(LSB_WRGSYN,"Option -t requires number of seconds\n");

		    switch (*endptr) {
			case 's':
			    endptr++;
			case 'm':
			    endptr++;
			    seconds *= 60;
			    break;
			case 'h':
			    endptr++;
			    seconds *= 60*60;
			    break;
			default:
			    break;
		    }

		    if (strlen(endptr))
			error(LSB_WRGSYN,"Option -t requires number of seconds\n");

		} else
		    error(LSB_WRGSYN,"Option -t requires number of seconds\n");
		break;
	    case 'i':
		if (force)
		    warn("option -i does not work in force mode\n");
		/* Remember: address optarg (current *argv) */
		if (optarg && optarg[0] != '-') {
		    iargv[iargc++] = optarg;
		} else
		    error(LSB_WRGSYN,"Option -i requires pid file to read pid from\n");
		break;
	    case 'w':
		if (sdaemon) goto fail;
		wpopts = WUNTRACED;
		break;
	    case 'W':
		if (sdaemon) goto fail;
		if (optarg && optarg[0] != '-') {
		    wlist = optarg;
		} else
		    error(LSB_WRGSYN,"Option -W requires a file name or list of files separated by colons\n");
		break;
	    case '?':
	    fail:
		error(LSB_WRGSYN, (sdaemon ? USAGE_SD : USAGE), we_are);
		break;
	    case 'h':
		error(0, (sdaemon ? USAGE_SD : USAGE), we_are);
		break;
	    default:
		break;
	}
    }

    argv += optind;
    argc -= optind;

    if (!*argv)
	error(LSB_WRGSYN, (sdaemon ? USAGE_SD : USAGE), we_are);

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
    syslogd = (strncmp("syslogd", basename, 7) == 0);

    if (force)
	goto force;

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
	force = true;

    /* Check and verify the pid file */
    errno = 0;
    if (statn(pid_file, STATX_SIZE, &st) < 0) {
	if (errno != ENOENT)
	    warn("Can not stat %s: %s\n", pid_file, strerror(errno));

	free(pid_file);
	pid_file = NULL;

	if (force && errno == ENOENT)
	    goto force;

	/* No pid file means that we have to search in /proc/ */
    }

    if (pid_file && !st.st_size) {
	warn("Empty pid file %s for %s\n", pid_file, fullname);

	free(pid_file);
	pid_file = NULL;

	if (force)
	    goto force;

	/* No pid file means that we have to search in /proc/ */
    }

    if (pid_file) {		/* The case of having a pid file */
	if (verify_pidfile(pid_file,fullname,root,flags,false) < 0)
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
    if (list_empty(&remember)) {	/* No process found with pid file */
	if (force)
	    goto force;
        if (pidof(fullname,root,flags) < 0)
	    exit(LSB_PROOFX);
    	clear_pids();		/* Remove all pids which should be ignored */
    }

    if (!list_empty(&remember))
	exit(LSB_OK);		/* Accordingly to LSB we have succeed. */

force:
    (void)do_start(fullname, argv, log_file, nicelvl, env, root, flags);

    /* Do we have started it? */

check_again:

    /* Here we have to ignore zombies because a zombie isn't that what
       we want to fire of */
    if (pidof(fullname,root,(flags|NZOMBIE)) < 0)
	exit(LSB_PROOFX);
    clear_pids();		/* Remove all pids which should be ignored */

    if (list_empty(&remember))
	exit(LSB_NOPROC);

    if (seconds > 0) {
	seconds--;
        sleep(1);
	goto check_again;
    }

    if (!quiet) {
	    list_t *list;
	    int nl = 0;
	    list_for_each(list, &remember) {
		PROC *proc = list_entry(list, PROC);
		if (nl++) putchar(' ');
		printf("%ld", (long int)proc->pid);
	    }
	    if (nl) putchar('\n');
    }

    exit(LSB_OK);

} /* end of main */

/* The core function */
static int do_start(const char *inname, char *argv[], const char* log_file,
		   const int nicelvl, const int env, const char* root, unsigned short flags)
{
    extern char * we_are;
    int tty = 255;
    int olderr, status, n = 0;
    FILE *tmp = NULL;
    pid_t pid;
    const char * fullname;
    char proc_exe[6+9+4+1];
    static struct stat itsme;
    sigset_t newset, oldset;
    int fdpipe[2];

    if ((n = snprintf(proc_exe, sizeof(proc_exe) - 1, "/proc/%d/exe", getpid())) > 0) {
	proc_exe[n] = '\0';
	if (stat(proc_exe, &itsme) < 0)
	    error(100, "cannot stat %s: %s\n", proc_exe, strerror(errno));
    } else
	error(100, "error in snprintf: %s\n", strerror(errno));

    if (root) {
	fullname = inname + strlen(root);
    } else {
	fullname = inname;
    }

    if (log_file) {
	errno = 0;
	if ((tmp = fopen(log_file, "a")) == NULL)
	    error(LSB_PROOF," cannot open %s: %s\n", log_file, strerror(errno));
    }

    fflush(stdout);
    fflush(stderr);		/* flush stdout and especially stderr */
    errno = 0;

    /*
     * When used to start service in the init script, update the init
     * script pid to ours first ...
     */
    fwd_sd_listen_pid();

    if (sdaemon)
	pid = 0;
    else {
	sigemptyset(&newset);
	sigaddset(&newset, SIGQUIT);
	sigaddset(&newset, SIGCHLD);
	sigprocmask(SIG_UNBLOCK, &newset, &oldset);
	save_sigquit = signal(SIGQUIT, sig_quit);
	if (sigchld)
	    (void)signal(SIGCHLD, sig_chld);
	else
	    (void)signal(SIGCHLD, SIG_DFL);
	if (pipe2(fdpipe, O_CLOEXEC) < 0) {
	    if (errno == ENOSYS) {
		if (pipe(fdpipe) < 0 ||
		    fcntl(fdpipe[0], F_SETFD, FD_CLOEXEC) < 0 ||
		    fcntl(fdpipe[1], F_SETFD, FD_CLOEXEC) < 0)
		    error(100, "cannot open a pipe: %m\n");
	    }
	}
	if ((pid = fork()) == 0) {
	    /* Update again to point to the child pid */
	    fwd_sd_listen_pid();
	}
    }

    switch (pid) {
    case 0:
    	if (!sdaemon) {
	    sigprocmask(SIG_SETMASK, &oldset, NULL);
	    (void)signal(SIGINT,  SIG_DFL);
	    (void)signal(SIGQUIT, SIG_DFL);
	    (void)signal(SIGSEGV, SIG_DFL);
	    (void)signal(SIGTERM, SIG_DFL);

	    close(fdpipe[1]);
	    read(fdpipe[0], proc_exe, 1);		/* Wait on parent with the pipe here */
	    close(fdpipe[0]);
	}

	if (root) {
	    if (chroot(root) < 0) {
		int lsb = LSB_WRGSYN;
		if (errno == EPERM || errno == EACCES)
		    lsb = LSB_NOPERM;
		error(lsb,"Can not change root directory to %s: %s\n", optarg, strerror(errno));
	    }
	}

	if (env)
	    set_newenv(fullname);
	 else
	    set_environ(fullname);

	if (schedclass >= 0)
	    ioprio_setpid(0, schedclass, scheddata);
	if (nicelvl != 0) {
	    errno = 0;
	    if (setpriority(PRIO_PROCESS, getpid(), nicelvl) < 0)
		error(LSB_PROOF," cannot set nicelevel: %s\n", strerror(errno));
	}
	if (sess && !sdaemon) {
	    errno = 0;
	    if (setsid() < 0)
		error(LSB_PROOF," cannot create session: %s\n", strerror(errno));
	}
	if (grp) {
	    if (setgid(grp->gr_gid) < 0)
		error(LSB_PROOF," cannot set group id %u: %s\n", grp->gr_gid, strerror(errno));
	}
	if (user) {
	    gid_t ngid = user->pw_gid;
	    if (grp)
		ngid = grp->gr_gid;
	    else {
		if (setgid(ngid) < 0)
		    error(LSB_PROOF," cannot set group id %u: %s\n",
			  (unsigned int)ngid, strerror(errno));
	    }
	    if (!getuid()) {
	        if (initgroups(user->pw_name, ngid) < 0)
		    error(LSB_PROOF," cannot set supplemental group ids for user %s: %s\n",
			    user->pw_name, strerror(errno));
	    }
	    if (setuid(user->pw_uid) < 0)
		error(LSB_PROOF," cannot set user id %u: %s\n",
			(unsigned int)user->pw_uid, strerror(errno));
	}
	/*
	 * Close all above stdin, stdout, stderr ... but not fileno(tmp)
	 */
	closefds(tmp);

	if (dialog) {
	    char * redirect;
	    if (!(redirect = getenv("REDIRECT")))
		redirect = "/dev/tty";
	    if ((tty = open(redirect,O_RDWR|O_NONBLOCK,0)) < 0)
		error(LSB_PROOF," cannot open %s: %s\n", redirect, strerror(errno));
	    dup2(tty, fileno(stdin));
	    dup2(tty, fileno(stdout));
	    dup2(tty, fileno(stderr));
	    if (tty > fileno(stderr))
		close(tty);
	} else {
	    int devnull = open("/dev/null",O_RDONLY|O_NONBLOCK|O_NOCTTY,0);
	    if (devnull < 0)
		error(LSB_PROOF," cannot open /dev/null: %s\n", strerror(errno));
	    dup2(devnull, fileno(stdin));
	    if (devnull > fileno(stderr))
		close(devnull);
	}

	if (!dialog && ((log_file && tmp) || supprmsg)) {
	    if (log_file && tmp) {		/* log file for service messages */
		dup2(fileno(tmp), fileno(stdout));
		dup2(fileno(tmp), fileno(stderr));
		fclose(tmp);
	    } else if (supprmsg) {		/* suppress service messages */
		int devnull = open("/dev/null",O_WRONLY|O_NONBLOCK|O_NOCTTY,0);
		if (devnull <0)
		    error(LSB_PROOF," cannot open /dev/null: %s\n", strerror(errno));
		dup2(devnull, fileno(stdout));
		dup2(devnull, fileno(stderr));
		if (devnull > fileno(stderr))
		    close(devnull);
	    }
	}
	fflush(stdout);
	fflush(stderr);		/* flush stdout and especially stderr */
	closelog();
	if (chdir("/") < 0)
	    warn("error in chdir: %s\n", strerror(errno));
	errno = 0;
#if DEBUG
	printf("execve(%s, [", fullname);
	while (argv && *argv) {
	    printf(" %s", *argv);
	    argv++;
	}
	printf(" ], [");
	while (environ && *environ) {
	    printf(" %s", *environ);
	    environ++;
	}
	printf(" ]);\n");
#else
# ifdef USE_BLOGD
	if (bootlog(B_NOTICE, "%s: execve (%s) [", we_are, fullname) == 0) {
	    char ** v = argv;
	    char ** e = environ;
	    while (v && *v) {
		bootlog(-1, " %s", *v);
		v++;
	    }
	    bootlog(-1, " ], [");
	    while (e && *e) {
		bootlog(-1 , " %s", *e);
		e++;
	    }
	    bootlog(-1, " ]\n");
	    closeblog();
	}
# endif
	execve(fullname, argv, environ);
#endif
	olderr = errno;
	close(fileno(stdout));
	close(fileno(stderr));
	if ((tty = open("/dev/tty",O_WRONLY|O_NONBLOCK|O_NOCTTY,0)) >= 0) {
	    dup2(tty, fileno(stdout));
	    dup2(tty, fileno(stderr));
	    if (tty > fileno(stderr))
		close(tty);
	}
	openlog (we_are, LOG_OPTIONS, LOG_FACILITY);
	if (!sdaemon)
	    kill(getppid(), SIGQUIT);
	error(LSB_PROOFE," cannot execute %s: %s\n", fullname, strerror(olderr));
	break;
    case -1:
	if (tmp)
	    fclose(tmp);
	fflush(stdout);
	fflush(stderr);		/* flush stdout and especially stderr */
	error(LSB_PROOFE," cannot execute %s: %s\n", fullname, strerror(errno));
	break;
    default:
	if (tmp)
	    fclose(tmp);
	fflush(stdout);
	fflush(stderr);		/* flush stdout and especially stderr */

	close(fdpipe[0]);

	if ((n = snprintf(proc_exe, sizeof(proc_exe) - 1, "/proc/%d/exe", pid)) > 0) {
	    proc_exe[n] = '\0';

	    /*
	     * On very fast systems we may not see an proc entry because
	     * the daemons parent has already finished (errno == ENOENT),
	     * on slow systems we may read an proc entry for the fork()ed
	     * pid but before the execve() is done by the kernel, in later
	     * case be sure not to run on our own binary.
	     */
	    n = 0;
	    do {
		struct stat serv;

		errno = 0;
		if (statn(proc_exe, STATX_INO, &serv) < 0) {
		    if (errno == ENOENT)
			break;			/* Seems to be a very fast system
						 * should not happen due to the pipe */
		    error(100, "cannot stat %s: %s\n", proc_exe, strerror(errno));
		}

		if (n++ == 0)
		    close(fdpipe[1]);		/* Sync child over the pipe */

		if (itsme.st_dev != serv.st_dev || itsme.st_ino != serv.st_ino)
		    break;			/* Seems to be a slow system */

		usleep(1*1000);

	    } while (true);

	} else {

	    close(fdpipe[1]);			/* Sync child over the pipe */

	    warn("error in snprintf: %s\n", strerror(errno));
	    usleep(100*1000);
	}
	n = 0;
retry:
	errno = 0;
	switch (waitpid(pid, &status, wpopts)) {
	case -1:		/* WNOHANG and hopefully no child but daemon */
	    if (errno == EINTR)
		goto retry;
	    if (errno != ECHILD) /* ECHILD should not happen, should it? (it does) */
		error(LSB_PROOFE," waitpid on %s: %s\n", fullname, strerror(errno));
	    break;
	case 0:			/* WNOHANG and no status available */
	    /*
	     * startproc is a program for starting daemons, therefore we should
	     * not get a process id. If we get one we may wait a bit to be sure
	     * to see a process damage.
	     */
	    usleep(10*1000);	/* 10 ms time for the child and its child */
	    if (++n < 50)
		goto retry;
	    break;
	default:
	    if (WIFEXITED(status) && WEXITSTATUS(status)) {
		if (signaled)
		    exit(WEXITSTATUS(status));
		warn(" exit status of parent of %s: %d\n", fullname, WEXITSTATUS(status));
		return WEXITSTATUS(status);
	    }
	    if (WIFSIGNALED(status)) {
		if (syslogd && WTERMSIG(status) == SIGTERM)
			return 0;
		warn(" signal catched %s: %s\n", fullname, strsignal(WTERMSIG(status)));
	        return WTERMSIG(status) + 128;
	    }
	    break;
	}
	if ((wpopts & WNOHANG) && wlist)
	    waiton(wlist);
	break;
    }
    return 0;
}

/*
 * Close all above stdin, stdout, stderr ... but not fileno(tmp)
 */
static void closefds(FILE *not)
{
    const int fdnot = not ? fileno(not) : -1;
    const int fderr = fileno(stderr);
    const int sdfds = get_sd_listen_fds();
    char dir[128];
    struct dirent *fdd;
    DIR *fds;
    int ret;

    if (((ret = snprintf(dir, sizeof(dir), "/proc/%ld/fd", (long)getpid())) < 0) ||
	(ret == sizeof(dir)))
	error(100, "error in snprintf: %s\n", strerror(errno));
    if ((fds = opendir(dir)) == (DIR*)0)
	error(100, "cannot open dir: %s\n", strerror(errno));

    while ((fdd = readdir(fds))) {
	int fd;
	if (*fdd->d_name == '.')
	    continue;
	if ((fd = atoi(fdd->d_name)) <= fderr) {
	    if ((ret = fcntl(fd, F_GETFD)) < 0)
		continue;
	    fcntl(fd, F_SETFD, ret & ~FD_CLOEXEC);
	    continue;
	}
	if (fd == fdnot) {
	    if ((ret = fcntl(fd, F_GETFD)) < 0)
		continue;
	    fcntl(fd, F_SETFD, ret & ~FD_CLOEXEC);
	    continue;
	}
	if (sdfds > 0 && fd >= SD_LISTEN_FDS_START
		      && fd <  SD_LISTEN_FDS_START + sdfds) {
	    if ((ret = fcntl(fd, F_GETFD)) < 0)
		continue;
	    fcntl(fd, F_SETFD, ret & ~FD_CLOEXEC);
	    continue;
	}
	if (isatty(fd)) {
	    close(fd);
	    continue;
	}
	if ((ret = fcntl(fd, F_GETFD)) < 0)
	    continue;
	fcntl(fd, F_SETFD, ret|FD_CLOEXEC);
    }

    closedir(fds);
}

typedef struct _wait_
{
    struct _wait_ * prev;
    struct _wait_ * next;
    char *restrict name;
    int wd;
} wait_t;

static void waiton(const char *list)
{
    int fd = inotify_init1(IN_CLOEXEC);
    char *buf = strdup(list);
    char *bufp;
    wait_t *restrict p = (wait_t*)0, *n, *l, *wait = (wait_t*)0;

    if (fd < 0)
	error(100, "error in inotify_init(): %s\n", strerror(errno));
    if (!buf)
	error(100, "error in strdup(): %s\n", strerror(errno));

    for (bufp = strsep(&buf, ":"); bufp && *bufp; bufp = strsep(&buf, ":")) {
	char * base, * name;
	struct stat st;
	size_t nlen;

	if (stat(bufp, &st) == 0)
	    continue;
	base = basename(bufp);
	name = dirname(bufp);

	if (stat(name, &st) < 0) {
	    warn("%s: %s\n", bufp, strerror(errno));
	    continue;
	}
	nlen = strlen(base);

	if (posix_memalign((void*)&p, sizeof(void*), alignof(wait_t)+(nlen+1)) != 0)
	    error(100, "malloc(): %s\n", strerror(errno));
	p->name = ((char*)p)+alignof(wait_t);
	strcpy(p->name, base);

	if ((p->wd = inotify_add_watch(fd, name, IN_CREATE|IN_MOVE|IN_DELETE_SELF)) < 0) {
	    warn("cannot add watch point for %s: %s\n", name, strerror(errno));
	    free(p);
	    continue;
	}

	if (wait)
	    wait->prev = p;
	p->next = wait;
	p->prev = (wait_t*)0;
	wait = p;
    }
    free(buf);

    while (wait) {
	char buf[sizeof(struct inotify_event)+PATH_MAX+1];
	struct inotify_event *restrict ie;
	struct timeval tv = {0, 10000};
	fd_set check;
	ssize_t ret;
	int in;

	FD_ZERO (&check);
	FD_SET (fd, &check);
	if ((in = select(fd + 1, &check, (fd_set*)0, (fd_set*)0, &tv)) < 0) {
	    warn("select: %s\n", strerror(errno));
	    break;
	}
	if (in == 0)
	    continue;

	ioctl(fd, FIONREAD, &in);
	if (in == 0)
	    continue;

	ret = read(fd, &buf, in);
	if (ret < 0 && (errno == EINTR))
	    continue;
	ie = (struct inotify_event*)&buf;

	n = wait;
	l = (wait_t*)0;
	for (p = wait; n; p = n) {
	    l = p->prev;
	    n = p->next;

	    if (p->wd != ie->wd)
		continue;
	    if (strcmp(p->name, ie->name) != 0)
		continue;

	    if (p == wait) {
		if (n) n->prev = (wait_t*)0;
		wait = n;
	    } else if (l) {
		if (n) n->prev = l;
		l->next = n;
	    }
	    free(p);
	}
    }

    close(fd);
}

static int get_sd_listen_fds()
{
    const char *env;
    char *ptr = (char*)0;
    long l;

    if ((env = getenv("LISTEN_PID")) == (const char*)0)
	return 0;

    errno = 0;
    l = strtol(env, &ptr, 10);
    if (errno != 0)
	return -errno;
    if (ptr == env)
	return -EINVAL;
    if (*ptr != '\0')
	return -EINVAL;
    if (l < 0)
	return -EINVAL;

    if (getpid() != (pid_t)l)
	return 0;

    if ((env = getenv("LISTEN_FDS")) == (const char*)0)
	return 0;

    errno = 0;
    l = strtol(env, &ptr, 10);
    if (errno != 0)
	return -errno;
    if (ptr == env)
	return -EINVAL;
    if (*ptr != '\0')
	return -EINVAL;
    if (l < 0)
	return -EINVAL;

    return (int)l;
}

static void fwd_sd_listen_pid(void)
{
    const char *env;

    /*
     * fork & systemd socket activation:
     * fetch listen pid and update to ours,
     * when it is set to pid of our parent.
     */
    if ((env = getenv("LISTEN_PID"))) {
	char *ptr;
	long l;

	errno = 0;
	l = strtol(env, &ptr, 10);
	if (errno != 0)
	    return;
	if (ptr == env)
	    return;
	if (*ptr != '\0')
	    return;
	if (l < 0)
	    return;
	if (getppid() == (pid_t)l) {
	    char buf[24];
	    snprintf(buf, sizeof(buf), "%d", getpid());
	    setenv("LISTEN_PID", buf, 1);
	}
    }
}
