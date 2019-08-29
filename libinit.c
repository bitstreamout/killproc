/*
 * Routines for daemon, killproc, killall5, pidof, and runlevel.
 *
 * Version:	2.0 10-Nov-2000 Fink
 *
 * Copyright 1994-2000 Werner Fink, 1996-2000 SuSE GmbH Nuernberg, Germany.
 * Copyright 2005 Werner Fink, 2005 SUSE LINUX Products GmbH, Germany.
 *
 * Some parts of this software are copied out of killall5.c of the
 * sysvinit suite 2.57b, Copyright 1991-1995 Miquel van Smoorenburg.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Author:	Werner Fink <werner@suse.de>, 1994-2000
 *
 * 1998/09/29 Werner Fink: Add kernel thread handling.
 * 1999/02/24 Werner Fink: Advance script search
 * 1999/08/05 Werner Fink: Handle ignoring zombies
 * 2000/11/10 Werner Fink: LSB specs, logging
 */

#include <sys/mount.h>
#include <sys/sysmacros.h>
#include "libinit.h"  /* Now get the inlined functions */
#include "statx.h"
#ifndef  INITDIR
# define INITDIR	"/etc/init.d"
#endif

#undef O_PROCMODE
#ifdef O_CLOEXEC
# define O_PROCMODE O_RDONLY|O_NONBLOCK|O_LARGEFILE|O_CLOEXEC
#else
# define O_PROCMODE O_RDONLY|O_NONBLOCK|O_LARGEFILE
#endif

#ifndef __USE_BSD
extern void vsyslog (int, const char *, va_list);
#endif

char     * newenvp[MAXENV];
unsigned   newenvc = 0;

list_t remember = {&remember, &remember};
list_t doignore = {&doignore, &doignore};

char * we_are;
unsigned short stopped = 0;
pid_t p_pid, p_sid, p_ppid, p_pppid;

static char procbuf[128] = { "/proc/" };
static inline const char * proc(const char * pid, const char * entry)
{
    char * slash = &procbuf[6];
    strcpy(slash, pid);
    strcat(slash, "/");
    strcat(slash, entry);
    return procbuf;
}

static char herebuf[128] = { "" };
static inline const char * here(const char * pid, const char * entry)
{
    char * path = &herebuf[0];
    strcpy(path, pid);
    strcat(path, "/");
    strcat(path, entry);
    return herebuf;
}

static inline const char * strpid(const pid_t pid)
{
    static char buf[128];
    int len = snprintf(buf, 127, "%ld", (long)pid);
    if (len < 1 || len > 127) {
	warn("error in snprintf: %s\n", strerror(errno));
        return (char*)0;
    }
    buf[len] = '\0';
    return buf;
}

static struct _sys_signals {
    int num;
    char const name[10];
} sys_signals[] = {
#define NUMNAME(name) { SIG##name, #name }
#ifdef SIGHUP
    NUMNAME (HUP),
#endif
#ifdef SIGINT
    NUMNAME (INT),
#endif
#ifdef SIGQUIT
    NUMNAME (QUIT),
#endif
#ifdef SIGILL
    NUMNAME (ILL),
#endif
#ifdef SIGTRAP
    NUMNAME (TRAP),
#endif
#ifdef SIGABRT
    NUMNAME (ABRT),
#endif
#ifdef SIGFPE
    NUMNAME (FPE),
#endif
#ifdef SIGKILL
    NUMNAME (KILL),
#endif
#ifdef SIGBUS
    NUMNAME (BUS),
#endif
#ifdef SIGSEGV
    NUMNAME (SEGV),
#endif
#ifdef SIGPIPE
    NUMNAME (PIPE),
#endif
#ifdef SIGALRM
    NUMNAME (ALRM),
#endif
#ifdef SIGTERM
    NUMNAME (TERM),
#endif
#ifdef SIGUSR1
    NUMNAME (USR1),
#endif
#ifdef SIGUSR2
    NUMNAME (USR2),
#endif
#ifdef SIGCHLD
    NUMNAME (CHLD),
#endif
#ifdef SIGURG
    NUMNAME (URG),
#endif
#ifdef SIGSTOP
    NUMNAME (STOP),
#endif
#ifdef SIGTSTP
    NUMNAME (TSTP),
#endif
#ifdef SIGCONT
    NUMNAME (CONT),
#endif
#ifdef SIGTTIN
    NUMNAME (TTIN),
#endif
#ifdef SIGTTOU
    NUMNAME (TTOU),
#endif
#ifdef SIGSYS
    NUMNAME (SYS),
#endif
#ifdef SIGUNUSED
    NUMNAME (UNUSED),
#endif
#ifdef SIGPOLL
    NUMNAME (POLL),
#endif
#ifdef SIGVTALRM
    NUMNAME (VTALRM),
#endif
#ifdef SIGPROF
    NUMNAME (PROF),
#endif
#ifdef SIGXCPU
    NUMNAME (XCPU),
#endif
#ifdef SIGXFSZ
    NUMNAME (XFSZ),
#endif
#ifdef SIGIOT
    NUMNAME (IOT),
#endif
#ifdef SIGEMT
    NUMNAME (EMT),
#endif
#ifdef SIGCLD
    NUMNAME (CLD),
#endif
#ifdef SIGPWR
    NUMNAME (PWR),
#endif
#ifdef SIGCANCEL
    NUMNAME (CANCEL),
#endif
#ifdef SIGLWP
    NUMNAME (LWP),
#endif
#ifdef SIGWAITING
    NUMNAME (WAITING),
#endif
#ifdef SIGFREEZE
    NUMNAME (FREEZE),
#endif
#ifdef SIGTHAW
    NUMNAME (THAW),
#endif
#ifdef SIGLOST
    NUMNAME (LOST),
#endif
#ifdef SIGWINCH
    NUMNAME (WINCH),
#endif
#ifdef SIGINFO
    NUMNAME (INFO),
#endif
#ifdef SIGIO
    NUMNAME (IO),
#endif
#ifdef SIGSTKFLT
    NUMNAME (STKFLT),
#endif
#undef NUMNAME
    { 0, "EXIT" }
};

/*
 * Calculate the depth of a directory, root has zero depth.
 */
size_t dirdepth(const char *const path)
{
    const char *ptr = path;
    size_t cnt = 0;

    do {
	const size_t off = strcspn(ptr, "/");
	ptr += off;
	if (*ptr++ != '/')
	    break;
	if (*ptr)
	    cnt++;
    } while (*ptr);

    return cnt;
}

typedef struct _mntinfo_
{
    list_t   this;
    int id, parid;
    boolean netfs;
    dev_t     dev;
    size_t   nlen;
    char   *point;
} MNTINFO;

static list_t mounts = {&mounts, &mounts};
static list_t save  = {&save, &save};

static inline boolean isnetfs(const char * type)
{
    static const char* netfs[] = {"nfs", "nfs4", "smbfs", "cifs", "afs", "ncpfs", (char*)0};
    int n;
    for (n = 0; netfs[n]; n++)
	if (!strcasecmp(netfs[n], type))
	    return true;
    return false;
}

static void init_mounts(void)
{
    char point[PATH_MAX*4 + 1];
    char fstype[257];
    struct stat st;
    int mid, parid, max = 0;
    uint maj, min;
    FILE * mnt;

    if (!list_empty(&mounts))
	return;

    /* Stat /proc/version to see if /proc is mounted. */
    if (statn("/proc/version", STATX_INO, &st) < 0)
	getproc();

    if ((mnt = fopen("/proc/self/mountinfo", "re")) == (FILE*)0)
	return;
    while (fscanf(mnt, "%i %i %u:%u %*s %s %*[^-] - %s %*s %*[^\n]", &mid, &parid, &maj, &min, &point[0], &fstype[0]) == 6) {
	const size_t nlen = strlen(point);
	MNTINFO *restrict p;
	if (posix_memalign((void*)&p, sizeof(void*), alignof(MNTINFO)+(nlen+1)) != 0) {
	    if (stopped) kill(-1, SIGCONT);
	    error(100, "malloc(): %s\n", strerror(errno));
	}
	append(p, mounts);
	p->point = ((char*)p)+alignof(MNTINFO);
	strcpy(p->point, point);
	p->nlen = nlen;
	p->parid = parid;
	p->dev = makedev(maj, min);
	p->id = mid;
	p->netfs = isnetfs(fstype);
	if (p->id > max)
	    max = p->id;
    }
    fclose(mnt);

    /* Sort mount points accordingly to their reverse mount order */
    initial(&save);
    for (mid = 1; mid <= max; mid++) {
	list_t *this, *cpy;
	list_for_each_safe(this, cpy, &mounts) {
	    MNTINFO *m = list_entry(this, MNTINFO);
	    if (mid != m->id)
		continue;
	    move_head(this, &save);
	    break;
	}
	list_for_each_safe(this, cpy, &mounts) {
	    MNTINFO *m = list_entry(this, MNTINFO);
	    if (mid != m->parid)
		continue;
	    move_head(this, &save);
	}
    }
    if (!list_empty(&mounts)) {
	if (stopped) kill(-1, SIGCONT);
	error(100, "sort(): %s\n", strerror(EBADE));
    }
    join(&save, &mounts);
}

static MNTINFO *find_prefix(const char * path, const dev_t dev)
{
    const size_t nlen = strlen(path);
    list_t *ptr;

    list_for_each(ptr, &mounts) {
	MNTINFO *m = list_entry(ptr, MNTINFO);
	if (m->dev != dev)
	    continue;
	if (nlen < m->nlen)
	    continue;
	if (m->nlen == 1)		/* root fs is the last entry */
	    return m;
	if (strncmp(path, m->point, m->nlen))
	    continue;
	return m;
    }
    return (MNTINFO*)0;
}

static int find_mount(const char * path, MNTINFO *s)
{
    const size_t nlen = strlen(path);
    list_t *ptr;
    int ret = 0;

    list_for_each(ptr, &mounts) {
	MNTINFO *m = list_entry(ptr, MNTINFO);
	if (nlen < m->nlen)
	    continue;
	if (m->nlen == 1 && (m == s)) {		/* root fs is the last entry */
	    ret++;
	    break;
	}
	if (strncmp(path, m->point, m->nlen))
	    continue;
	if (m == s) {
	    ret++;
	    break;
	}
    }
    return ret;
}

extern inline char * handl_buf(char *restrict buf)
{
    char * ptr = strstr(buf, " (deleted)");
    if (ptr)
	*ptr = '\0';

    if ((ptr = strstr(buf, "-RPMDELETE")))
	*ptr = '\0';

    return buf;
}

/* write to syslog file if not open terminal */
static void nsyslog(int pri, const char *fmt, va_list args)
{
    extension char newfmt[strlen(we_are)+2+strlen(fmt)+1];

    strcat(strcat(strcpy(newfmt, we_are), ": "), fmt);

    /* file descriptor of stderr is 2 in most cases */
    if (ttyname(fileno(stderr)) == NULL)
	vsyslog(pri, newfmt, args);
    else
	vfprintf(stderr, newfmt, args);
}

void error(int stat, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    nsyslog(LOG_ERR, fmt, args);
    va_end(args);
    exit(stat);
}

void warn(const char *fmt, ...)
{
    int saveerr = errno;
    va_list args;
    va_start(args, fmt);
    nsyslog(LOG_WARNING, fmt, args);
    va_end(args);
    errno = saveerr;
}

static void dsyslog(int pri, const char *fmt, va_list args)
{
    extension char newfmt[strlen(we_are)+2+strlen(fmt)+1];

    strcat(strcat(strcpy(newfmt, we_are), ": "), fmt);
    vsyslog(pri, newfmt, args);
}

void logprogress(int prio, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    dsyslog(prio, fmt, args);
    va_end(args);
}

/*
 * For mounting the /proc file system if missed
 * and run umount() at exit() for this case.
 */
static void undo_proc(void)
{
#ifdef MNT_DETACH
    umount2("/proc", MNT_DETACH);
#else
    umount("/proc");
#endif
}

void getproc(void)
{
    struct stat st;

    if (mount("proc", "/proc", "proc", 0, NULL) < 0)
	error(100, "cannot mount /proc: %s\n", strerror(errno));

    errno = 0;
    if (statn("/proc/version", STATX_INO, &st) < 0)
	error(100, "/proc not mounted, failed to mount: %s\n", strerror(errno));

    atexit(undo_proc);
}

/* Open the /proc directory, if necessary mounts it */
static DIR * openproc()
{
    struct stat st;
    DIR * dir = NULL;

    /* Stat /proc/version to see if /proc is mounted. */
    if (statn("/proc/version", STATX_INO, &st) < 0)
	getproc();

    errno = 0;
    if ((dir = opendir("/proc")) == (DIR *)0)
	error(100, "cannot opendir(/proc): %s\n", strerror(errno));

    return dir;
}

/* secure read on EINTR */
static ssize_t xread(int fd, void *inbuf, size_t count)
{
    register ssize_t bytes;
    register int olderr = errno;

    memset(inbuf, 0, count);

    while (1) {
	errno = 0;
	bytes = read(fd, inbuf, count);
	if (bytes < 0) {
	    if (errno == EINTR || errno == EAGAIN)
		continue;
	    if (errno == ESRCH)
		goto out;
	    break;
	}
	goto out;
    }
    warn("xread error: %s\n", strerror(errno));
out:
    errno = olderr;
    return bytes;
}

/* proof a given full path name is a script name */
static char * script_exe = NULL;
static boolean isscript(const char* fullname, const char *root)
{
    int fp = 0;
    boolean ret = true;
    char head[MAXNAMLEN];

    if (script_exe)	/* already done */
	goto out;

    ret = false;
    if ((fp = open(fullname, O_RDONLY|O_CLOEXEC, 0)) != -1 ) {
	if (xread(fp, head, sizeof(head)) > 0 && head[0] == '#' && head[1] == '!') {
	    if ((script_exe = strchr(head, '/'))) {
		char * ptr = strpbrk(script_exe, " \t\n");
		if (ptr && *ptr)
		    *ptr = '\0';
		if (root) {
		    char *ptr = (char *)xmalloc(strlen(root)+strlen(script_exe)+1);
		    ptr = strcat(strcpy(ptr,root),script_exe);
		    script_exe = ptr;
		} else {
		    script_exe = xstrdup(script_exe);
		}
	    }
	    ret = true;
	}
	close(fp);
    }
out:
    return ret;
}

/* check a given command line for a full path script name */
static const char * checkscripts(char* ent, const char* root, const size_t len, const char* pid)
{
    char dest[PATH_MAX+1];
    const char *scrpt = ent;
    size_t cnt = len;
    const char * ret = NULL, * name;
    struct stat exe_st;
    struct stat scr_st;
    int search = 0;
    ssize_t rll;

    if (!len || !script_exe)
	/* do not check empty entries */
	goto out;

    if ((rll = readlink(proc(pid, "exe"), dest, PATH_MAX)) < 0)
	goto out;
    dest[rll] = '\0';
    name = handl_buf(dest);

    if (statn(name, STATX_INO, &exe_st) < 0 || statn(script_exe, STATX_INO, &scr_st) < 0)
	goto out;

    if (exe_st.st_dev != scr_st.st_dev || exe_st.st_ino != scr_st.st_ino)
	goto out;

    /* The exe link is our interpreter */
    ret = scrpt;

    /* Some kernels skip the path of the interpreter */
    if (*scrpt != '/')
	search++;

    /* Some kernels use the interpreter as first argument */
    if (*scrpt  == '/' &&
	(strncmp(scrpt, name, PATH_MAX) == 0 ||
	 strncmp(scrpt, script_exe, PATH_MAX) == 0))
	search++;

    if (!search)
	goto out;

    ret = NULL;
    do {
	/* After the first zero we have the first argument
	 * which may be the name of a so what ever script.
	 */
	scrpt = (char *)memchr(scrpt, 0, cnt);
	if (!scrpt || (cnt = len - (++scrpt - ent)) <= 0)
	    break;
	if (*scrpt == '/') {
	    ret = scrpt;
	    goto out;
	}
    } while (scrpt && cnt > 0);
out:
    if (scrpt && root) {
	char *ptr = strdupa(scrpt);
	if (!ptr)
	    error(100, "strdupa(): %s\n", strerror(errno));
	scrpt = strcat(strcpy(ent,root),ptr);
    }
    return ret;
}

/* Gets the parent's pid of the parent. */
static pid_t getpppid(const pid_t ppid)
{
    const char * pid;
    char buf[BUFSIZ];
    pid_t pppid = 1;
    int fp;

    if ((pid = strpid(ppid)) == (char*)0)
	goto out;

    if ((fp = open(proc(pid, "stat"), O_PROCMODE)) != -1) {
	ssize_t len = xread(fp, buf, BUFSIZ);
	close(fp);
	if (len <= 0 || sscanf(buf,"%*d %*s %*c %d %*d %*d", &pppid) != 1)
	    warn("can not read ppid for process %d!\n", ppid);
    }
out:
    return pppid;
}

/* Gets the parent's pid of the parent. */
static pid_t getsession(const pid_t pid)
{
    pid_t session = getsid(pid);
    if ((long)session < 0) {
	if (errno != ESRCH)
	    warn("can not get session id for process %ld!\n", (long)pid);
	session = 1;
    }
    return session;
}

#if 0
/* Remember all pids not being the caller and its parent */
int allpids (void)
{
    DIR *dir;
    struct dirent *d;
    unsigned num = 0;
    pid_t pid, sid;
    list_t *m, *n;

    p_pid  = getpid();
    p_ppid = getppid();

    dir = openproc();
    p_pppid = getpppid(p_ppid);

    list_for_each_safe(m, n, &remember) {
	PROC *p = list_entry(m, PROC);
	delete(m);
	free(p);
    }

    /* Real System5 killall (also known as killall5) need only this one,
     * this case is not used by killproc, daemon/startproc, pidof/pidofproc */
    while((d = readdir(dir)) != (struct dirent *)0) {

	if (*d->d_name == '.')
	    continue;
	if (*d->d_name < '0' || *d->d_name > '9')
	    continue;

	if ((pid = (pid_t)atol(d->d_name)) == 0)
	    continue;

	sid = getsession(pid);
	if (pid == p_pid) p_sid = sid;
	do_list(pid, sid, false);
	num++;

    }
    closedir(dir);
    return num;
}
#endif

/* Search proc table with a gotten full path of a running programm
   and remember it */
int pidof (const char * inname, const char * root, unsigned short flags)
{
    DIR *dir;
    struct dirent *d;
    struct stat full_st, pid_st;
    int fp, dfd;
    boolean isscrpt = false;
    unsigned num = 0;
    pid_t pid;
    uid_t uid;
    char *swapname = NULL;
    char *fullname = (char *)inname;
    char *realname = NULL;
    MNTINFO *prefix = NULL;
    list_t *m, *n;

    p_pid  = getpid();
    p_ppid = getppid();
    uid    = getuid();

    dir = openproc();		/* Open /proc and maybe do mount before */
    p_pppid = getpppid(p_ppid); /* Requires existence of /proc */

    if (!fullname) {
	warn("program or process name required\n");
	return -1;
    }

    list_for_each_safe(m, n, &remember) {
	PROC *p = list_entry(m, PROC);
	delete(m);
	free(p);
    }

    /* killproc, daemon/startproc, pidof/pidofproc: stat fullname if a
     * real program is handled, skip this if we handle a kernel thread */

    if (!(flags & (KTHREAD|KSHORT))) {
	errno = 0;
	if (rlstat(&fullname, &full_st, flags) < 0) {
	    /* stat() follows soft links -> security */
	    warn("cannot stat %s: %s\n", fullname, strerror(errno));
	    return -1;
	}
	realname = expandpath(fullname);
	if (realname) {
	    init_mounts();
	    prefix = find_prefix(realname, full_st.st_dev);
	}
    }

    if (flags & (KTHREAD|KSHORT)) {
	if (flags & KBASE)
	    swapname = swap_name(base_name(fullname));
	else
	    swapname = swap_name(fullname);
    } else {
	isscrpt = isscript(fullname, root);
	swapname = swap_name(base_name(fullname));
    }

    /* killproc, daemon/startproc, pidof/pidofproc */
    dfd = dirfd(dir);
    while((d = readdir(dir)) != (struct dirent *)0) {
	ssize_t rll;

	if (*d->d_name == '.')
	    continue;
	if (*d->d_name < '0' || *d->d_name > '9')
	    continue;

	/* Only directories with pid as names */
	if ((pid = (pid_t)atol(d->d_name)) == 0)
	    continue;

	/* killproc and startproc should not touch calling process */
	if ((pid == p_pid || pid == p_ppid || pid == p_pppid || pid == 1) &&
	    (flags & (KILL|DAEMON)))
	    continue;

	/* Check for kernel threads, zombies or programs */
	if ((fp = openat(dfd, here(d->d_name, "statm"), O_PROCMODE)) != -1) {
	    char entry[3];
	    boolean thread;
	    ssize_t len;

	    len = xread(fp,entry,3);
	    close(fp);

	    if (len <= 0)
		continue;

	    thread = (strncmp(entry, "0 ", 2) == 0);

	    if ((flags & KTHREAD)  && !thread)
		continue; /* Threads do not have any memory size in user space */

	    if (!(flags & KTHREAD) &&  thread)
		continue; /* Programs always show  _memory_ size in user space */
	}

	/*
	 * Kernels 2.1 and above do not lost this link even if the
	 * program is swapped out. But this link is lost if the file
	 * of the program is overwriten during the process. Kernels
	 * 2.2 and above do not lost the link name even if the original
	 * file is deleted. The link is marked as deleted.
	 */
	if (!(flags & (KTHREAD|KSHORT)) && !isscrpt) {
	    char entry[PATH_MAX+1];
	    const char *name = NULL;
	    boolean found;

	    if (prefix) {
		if ((rll = readlinkat(dfd, here(d->d_name, "exe"), entry, PATH_MAX)) < 0) {
		    if (uid && (errno == EACCES || errno == EPERM)) {
			errno = 0;
			if (fstatat(dfd, d->d_name, &pid_st, 0) < 0)
			    continue;
			if (pid_st.st_uid == uid)
			    goto risky;
		    }
		    if (errno != EPERM && errno != EACCES)
			goto risky;
		    continue;
		}
		entry[rll] = '\0';
		name = handl_buf(entry);

		if (!find_mount(name, prefix))
		    continue;
	    }

	    if (fstatat(dfd, here(d->d_name, "exe"), &pid_st, 0) < 0) {
		if (errno != EPERM && errno != EACCES)
		    goto risky;
		continue;
	    }

	    if (pid_st.st_dev != full_st.st_dev)
		continue;		/* No processes below (kernel 2.2 and up) */

	    found = false;
	    switch (pid_st.st_nlink) {
		case 1:			/* One file on disk */

		    if (pid_st.st_ino == full_st.st_ino)
			found = true;
		    break;

		case 0:			/* file was deleted or */
		default:		/* has several hard links */

		    if (strlen(fullname) > PATH_MAX)
			continue;

		    if (!name) {
			if ((rll = readlinkat(dfd, here(d->d_name, "exe"), entry, PATH_MAX)) < 0) {
			    if (uid && (errno == EACCES || errno == EPERM)) {
				errno = 0;
				if (fstatat(dfd, d->d_name, &pid_st, 0) < 0)
				    continue;
				if (pid_st.st_uid == uid)
				    goto risky;
			    }
			    if (errno != EPERM && errno != EACCES)
				goto risky;
			    continue;
			}
			entry[rll] = '\0';
			name = handl_buf(entry);
		    }

		    if (strncmp(fullname, name, PATH_MAX) == 0) {
			found = true;
			break;
		    }

		    if (realname && strncmp(realname, name, PATH_MAX) == 0)
			found = true;

		    break;
	    }

	    if (found) {
		do_list(pid,getsession(pid),false);
		num++;			/* Found */
	    }

	    continue;			/* No processes below (kernel 2.2 and up) */
	}

	/*
	 * Here we check for scripts. Note that the command line gets lost if the
	 * corresponding process is swapped out.  Many script interpreters even
	 * do not hold a file descriptor opened on the script file.
	 */
	if (!(flags & (KTHREAD|KSHORT)) &&  isscrpt &&
	    (fp = openat(dfd, here(d->d_name, "cmdline"), O_PROCMODE)) != -1) {

	    char entry[PATH_MAX+1];
	    const char *scrpt = NULL;
	    ssize_t len;

	    len = xread(fp, entry, PATH_MAX);
	    close(fp);

	    if (len <= 0)
		continue;

	    /* Seek for a script not for a binary */
	    if (!(scrpt = checkscripts(entry, root, len, d->d_name))) {
		if (flags & STSCRPT)
		    goto risky;
		continue;
	    }

	    /* Don't blame our boot scripts having the same name */
	    if (   (flags & (KILL|DAEMON))
		&& (strncmp(scrpt, INITDIR, (sizeof(INITDIR) - 1)) == 0))
		continue;

	    if (scrpt && strcmp(scrpt,fullname) == 0) {
		do_list(pid,getsession(pid),false);
		num++;
		continue;
	    }
	}

    risky:
	/*
	 * High risk ... the name in stat isn't exact enough to identify
	 * a swapped out script process, because only the name without
	 * its path is stated which may not be identical with the
	 * executable script its self.
	 */
	if ((fp = openat(dfd, here(d->d_name, "stat"), O_PROCMODE)) != -1) {

	    char entry[PATH_MAX+1];
	    char *comm, *state;
	    ssize_t len;

	    len = xread(fp, entry, PATH_MAX);
	    close(fp);

	    if (len <= 0)
		continue;

	    comm  = index(entry,  ' ');
	    state = index(++comm, ' ');
	    *state++ = '\0';

	    if ( (flags & NZOMBIE) && state[0] == 'Z' )
		/* This is a zombie, ignore it */
		continue;

	    if ( strcmp(comm, swapname) == 0 ) {
		do_list(pid,getsession(pid),false);
		num++;
		continue;
	    }
	}
    }

    closedir(dir);
    free(swapname);
    return num;
}

/* Verify a given string of pids, and if found remember them */
int remember_pids(const char * pids, const char * inname,
		  const char * root, unsigned short flags)
{
    char *buf = strdupa(pids);
    char *bufp;

    if (!buf)
	error(100, "strdupa(): %s\n", strerror(errno));

    for (bufp = strsep(&buf, " "); bufp && *bufp; bufp = strsep(&buf, " ")) {
	const pid_t pid = (pid_t)atol(bufp);
	if (!pid)
	    continue;
	if (pid == getpid())
	    continue;		/* Don't kill myself */
	do_list(pid,getsession(pid),false);
    }

    return check_pids (inname, root, flags);
}

/* Open, read, and verify pid file, if pid found remember it */
int verify_pidfile (const char * pid_file, const char * inname,
		    const char * root, unsigned short flags,
		    const boolean ignore)
{
    int fp;
    ssize_t cnt;
    boolean isscrpt = false;
    pid_t pid;
    uid_t uid;
    char *swapname = NULL, *bufp;
    char *fullname = (char *)inname;
    char *realname = NULL;
    struct stat pid_st, full_st;
    char buf[BUFSIZ];

    uid = getuid();

    if (!ignore) {
	list_t *m, *n;
	list_for_each_safe(m, n, &remember) {
	    PROC *p = list_entry(m, PROC);
	    delete(m);
	    free(p);
	}
    }

    errno = 0;
    if ((fp = open (pid_file, O_PROCMODE)) < 0 ) {
	warn("Can not open pid file %s: %s\n", pid_file, strerror(errno));
	return -1;
    }

    errno = 0;
    cnt = xread(fp, buf, BUFSIZ);
    close(fp);
    if (cnt < 0) {
	warn("Can not read pid file %s: %s\n", pid_file, strerror(errno));
	return -1;
    }
    buf[cnt] = '\0';

    bufp = buf;
    while (--cnt && isspace(*bufp)) bufp++;
    memmove(buf, bufp, sizeof(char)*(cnt+1));

    if ((bufp = strpbrk(buf, "\r\n\f\t\v \0")))
	*bufp = '\0';

    errno = 0;
    if ((pid = (pid_t)atol(buf)) <= 0) {
	if (errno)
	    warn("Can not handle pid file %s with pid %s: %s\n", pid_file, buf, strerror(errno));
	if (!pid)
	    warn("Can not handle pid file %s with pid `%s\'\n", pid_file, buf);
	return -1;
    }

    if ((kill(pid, 0) < 0) && (errno == ESRCH))
	return 0;

    if (!ignore && pid == getpid())
	return 0;		/* Don't kill myself */

    if (!fullname) {
	warn("program or process name required\n");
	return -1;
    }

    if (!(flags & (KTHREAD|KSHORT))) {
	errno = 0;
	if (rlstat(&fullname, &full_st, flags) < 0) {
	    /* stat() follows soft links -> security */
	    warn("cannot stat %s: %s\n", fullname, strerror(errno));
	    return -1;
	}
	realname = expandpath(fullname);
    }

    if (flags & (KTHREAD|KSHORT)) {
	if (flags & KBASE)
	    swapname = swap_name(base_name(fullname));
	else
	    swapname = swap_name(fullname);
    } else {
	isscrpt = isscript(fullname, root);
	swapname = swap_name(base_name(fullname));
    }

    /* Check for kernel threads, zombies or programs */
    if ((fp = open(proc(buf, "statm"), O_PROCMODE)) != -1) {
	char ent[3];
	boolean thread;
	ssize_t len;

	len = xread(fp, ent, sizeof(ent));
	close(fp);

	if (len <= 0)
	    goto out;

	thread = (strncmp(ent, "0 ", 2) == 0);

	if ((flags & KTHREAD)  && !thread)
	    goto out; /* Threads do not have any memory size in user space */

	if (!(flags & KTHREAD) &&  thread)
	    goto out; /* Programs always show  _memory_ size in user space */
    }

    errno = 0;
    if (!(flags & (KTHREAD|KSHORT)) && !isscrpt) {
	char entry[PATH_MAX+1];
	const char *name;
	boolean found;
	ssize_t rll;

	if (statn(proc(buf, "exe"), STATX_INO|STATX_NLINK|STATX_UID, &pid_st) < 0) {
	    if (uid && (errno == EACCES || errno == EPERM)) {
		errno = 0;
		if (statn(proc(buf, ""), STATX_INO|STATX_NLINK|STATX_UID, &pid_st) < 0)
		    goto out;
		if (pid_st.st_uid == uid)
		    goto risky;
	    }
	    goto out;
	}

	if (pid_st.st_dev != full_st.st_dev)
	    goto out;

	found = false;
	switch (pid_st.st_nlink) {
	    case 1:			/* One file on disk */

		if (pid_st.st_ino == full_st.st_ino)
		    found = true;
		break;

	    case 0:			/* file was deleted or */
	    default:			/* has several hard links */

		if (strlen(fullname) > PATH_MAX)
		    goto out;

		if ((rll = readlink(proc(buf, "exe"), entry, PATH_MAX)) < 0)
		    goto out;
		entry[rll] = '\0';
		name = handl_buf(entry);

		if (strncmp(fullname, name, PATH_MAX) == 0) {
		    found = true;
		    break;
		}

		if (realname && strncmp(realname, name, PATH_MAX) == 0)
		    found = true;

		break;
	}

	if (found)
	    do_list(pid,getsession(pid),ignore);

	goto out;
    }
risky:

    if (errno && errno != ENOENT) {
	warn("Can not read %s: %s\n", procbuf, strerror(errno));
	free(swapname);
	return -1;
    }

    if (!(flags & (KTHREAD|KSHORT)) &&  isscrpt &&
	(fp = open(proc(buf, "cmdline"), O_PROCMODE)) != -1) {

	char entry[PATH_MAX+1];
	const char *scrpt = NULL;
	ssize_t len;

	len = xread(fp, entry, PATH_MAX);
	close(fp);

	if (len <= 0)
	    goto out;

	/* Seek for a script not for a binary */
	if (!(scrpt = checkscripts(entry, root, len, buf))) {
	    if (flags & STSCRPT)
		goto nameonly;
	    goto out;		/* Nothing found */
	}

	if (scrpt && strcmp(scrpt,fullname) == 0) {
	    do_list(pid,getsession(pid),ignore);
	    goto out;		/* Done */
	}
    }
nameonly:
    if ((fp = open(proc(buf, "stat"), O_PROCMODE)) != -1) {

	char entry[PATH_MAX+1];
	char *comm, *state;
	ssize_t len;

	len = xread(fp, entry, PATH_MAX);
	close(fp);

	if (len <= 0)
	    goto out;

	comm  = index(entry,  ' ');
	state = index(++comm, ' ');
	*state++ = '\0';

	if ( (flags & NZOMBIE) && state[0] == 'Z' )
	    /* This is a zombie, ignore it */
	    goto out;		/* This is a zombie, ignore it */

	if (strcmp(comm, swapname) == 0) {
	    do_list(pid,getsession(pid),ignore);
	    goto out;		/* Done */
	}
    }
out:
    if (swapname)
	free(swapname);
    return 0;			/* Nothing found */
}

/*
 * Check remembered pids, every pid will be verified
 * We have to do the full stuff to avoid conflicts with
 * newer processes having similar pids.
 */
int check_pids (const char * inname, const char * root, unsigned short flags)
{
    boolean isscrpt = false;
    char *swapname = (char*)0;
    char *fullname = (char *)inname;
    char *realname = (char*)0;
    const char *pid;
    struct stat pid_st, full_st;
    list_t *m, *n;
    uid_t uid;
    int fp;

    uid = getuid();

    if (!fullname) {
	warn("program or process name required\n");
	return -1;
    }

    if (!(flags & (KTHREAD|KSHORT))) {
	errno = 0;
	if (rlstat(&fullname, &full_st, flags) < 0) {
	    /* stat() follows soft links -> security */
	    warn("cannot stat %s: %s\n", fullname, strerror(errno));
	    return -1;
	}
	realname = expandpath(fullname);
    }

    if (flags & (KTHREAD|KSHORT)) {
	if (flags & KBASE)
	    swapname = swap_name(base_name(fullname));
	else
	    swapname = swap_name(fullname);
    } else {
	isscrpt = isscript(fullname, root);
	swapname = swap_name(base_name(fullname));
    }

    list_for_each_safe(m, n, &remember) {
	PROC *p = list_entry(m, PROC);
	boolean skip = false;

	errno = 0;
	if ((kill(p->pid, 0) < 0) && (errno == ESRCH))
	    goto ignore;

	errno = 0;
	if ((pid = strpid(p->pid)) == (char*)0) {
	    warn("error in snprintf: %s\n", strerror(errno));
	    free(swapname);
	    return -1;
	}

	/* Check for kernel threads, zombies or programs */
	errno = 0;
	if ((fp = open(proc(pid, "statm"), O_PROCMODE)) != -1) {
	    char ent[3];
	    int thread;
	    ssize_t len;

	    len = xread(fp, ent, sizeof(ent));
	    close(fp);

	    if (len <= 0)
		goto ignore;		/* Bogus */

	    thread = (strncmp(ent, "0 ", 2) == 0);

	    if ((flags & KTHREAD)  && !thread)
		continue; /* Threads do not have any memory size in user space */

	    if (!(flags & KTHREAD) &&  thread)
		continue; /* Programs always show  _memory_ size in user space */
	}

	/* killproc and daemon/startproc should use the full path */
	errno = 0;
	if (!(flags & (KTHREAD|KSHORT)) && !isscrpt) {
	    char entry[PATH_MAX+1];
	    const char *name;
	    ssize_t rll;

	    if (statn(proc(pid, "exe"), STATX_INO|STATX_NLINK|STATX_UID, &pid_st) < 0) {
		if (uid && (errno == EACCES || errno == EPERM)) {
		    errno = 0;
		    if (statn(proc(pid, ""), STATX_INO|STATX_NLINK|STATX_UID, &pid_st) < 0)
			goto ignore;
		    if (pid_st.st_uid == uid)
			goto risky;
		}
		goto ignore;
	    }

	    if (pid_st.st_dev != full_st.st_dev)
		goto ignore;		/* Does not belong to rembered list */

	    switch (pid_st.st_nlink) {
		case 1:			/* One file on disk */

		    if (pid_st.st_ino == full_st.st_ino)
			continue;	/* Found */
		    break;

		case 0:			/* file was deleted or */
		default:		/* has several hard links */

		    if (strlen(fullname) > PATH_MAX)
			goto ignore;	/* Bogus */

		    if ((rll = readlink(proc(pid, "exe"), entry, PATH_MAX)) < 0)
			goto ignore;	/* Bogus */
		    entry[rll] = '\0';
		    name = handl_buf(entry);

		    if (strncmp(fullname, name, PATH_MAX) == 0)
			continue;	/* Found */

		    if (realname && strncmp(realname, name, PATH_MAX) == 0)
			continue;	/* Found */

		    break;
	    }

	    skip = true;		/* No stat entry check needed */
	}
    risky:

	if (!(flags & (KTHREAD|KSHORT)) &&  isscrpt &&
	    (fp = open(proc(pid, "cmdline"), O_PROCMODE)) != -1) {

	    char entry[PATH_MAX+1];
	    const char *scrpt;
	    ssize_t len;

	    len = xread(fp, entry, PATH_MAX);
	    close(fp);

	    if (len <= 0)
		goto ignore;		/* Bogus */

	    /* Seek for a script not for a binary */
	    if ((scrpt = checkscripts(entry, root, len, pid))) {
	        if (strcmp(scrpt,fullname) == 0)
		    continue;		/* Found */
		if (!(flags & STSCRPT))
		    skip = true;	/* No stat entry check needed */
	    }
	}

	if (!skip && (fp = open(proc(pid, "stat"), O_PROCMODE)) != -1) {

	    char entry[PATH_MAX+1];
	    char *comm, *state;
	    ssize_t len;

	    len = xread(fp, entry, PATH_MAX);
	    close(fp);

	    if (len <= 0)
		goto ignore;		/* Bogus */

	    comm  = index(entry,  ' ');
	    state = index(++comm, ' ');
	    *state++ = '\0';

	    if ( ((flags & NZOMBIE) ? state[0] != 'Z' : 1) && strcmp(comm, swapname) == 0 ) {
		continue;		/* Found */
	    }
	}
    ignore:

	/* Remove this entry in remember */
	delete(m);
	free(p);
    }

    free(swapname);
    return 0;			/* Nothing found */
}

/*
 * Clear out the ignore proc list from the remember proc list.
 */
void clear_pids (void)
{
    list_t *n, *l;

    list_for_each_safe(n, l, &remember) {
	PROC *p = list_entry(n, PROC);

	if (!check_ignore(p->pid) && !check_ignore(p->sid))
	    continue;

	/* Remove this entry in remember */
	delete(n);
	free(p);
    }
}

void check_su()
{
#if DEBUG
    printf("Real user ID: %d\n",(int)getuid());
#else
    if ( 0 != (int)getuid() )
	error(1, "Only root sould run this program\n");
#endif
    return;
}

/* Used in libinit.h in the inlined function set_newenv */
void addnewenv ( const char * name, const char * entry )
{
    unsigned i, len = strlen(name);
    char *cp = (char*)xmalloc(len+2+strlen(entry));
    extern unsigned newenvc;

    (void)strcat(strcat(strcpy(cp,name),"="),entry);

    for (i=0; i < newenvc; i++)
	if (strncmp (cp, newenvp[i], len) == 0 &&
	    (newenvp[i][len] == '=' || newenvp[i][len] == '\0'))
		break;

    if (i == MAXENV) {
	puts ("Environment overflow");
	return;
    }

    if (i == newenvc) {
	newenvp[newenvc++] = cp;
	newenvp[newenvc] = (char*)0;
    } else {
	free (newenvp[i]);
	newenvp[i] = cp;
    }
}

/* Used in libinit.h in the inlined functions set_newenv set_environ */
char ** runlevel(const char *file)
{
    struct utmp *ut = (struct utmp*)0;
    char **ret = (char**)xmalloc(2 * sizeof(char*));

    if (file)
	utmpname(file);
    else
	utmpname(UTMP_FILE);

    setutent();
    while ( (ut = getutent()) != (struct utmp*)0 )
	if ( ut->ut_type == RUN_LVL )
	    break;
    endutent();

    ret[0] = (char*)xmalloc(sizeof(char[2]));
    ret[1] = (char*)xmalloc(sizeof(char[2]));

    ret[0][1] = ret[1][1] = '\0';
#if DEBUG
    ret[0][0] = '0';
    ret[1][0] = '3';
#else
    if (ut && ut->ut_pid) {
	ret[0][0] = ut->ut_pid / 256;
	ret[1][0] = ut->ut_pid % 256;
    } else {
	ret[0][0] = 'N';
	ret[1][0] = '?';
    }
#endif

    return ret;
}

/* Both used in killproc.c to translate signal names into signal numbers and vice versa */
int signame_to_signum(const char *sig)
{
    long int num = 0;
    if (!strncasecmp (sig, "sig", 3))
        sig += 3;
    while (sys_signals[num].num) {
	if (strcasecmp(sys_signals[num].name, sig) == 0)
	    return sys_signals[num].num;
	num++;
    }
#if defined(SIGRTMIN) && defined(SIGRTMAX)
    {
	const int rtmin = SIGRTMIN;
	const int rtmax = SIGRTMAX;
	char *endp;

	if ((0 < rtmin) && (strncasecmp(sig, "rtmin", 5) == 0)) {
	    sig += 5;
	    num = strtol(sig, &endp, 10);
	    if ((*endp == '\0') && (0 <= num) && (num <= (rtmax - rtmin)))
		return rtmin + num;
	} else if ((0 < rtmax) && (strncasecmp(sig, "rtmax", 5) == 0)) {
	    sig += 5;
	    num = strtol(sig, &endp, 10);
	    if ((*endp == '\0') && ((rtmin - rtmax) <= num) && (num <= 0))
		return rtmax + num;
	}
    }
#endif
    return -1;
}

const char * signum_to_signame(const int sig)
{
    long int num = 0;
    while (sys_signals[num].num) {
	if (sys_signals[num].num == sig)
	    return sys_signals[num].name;
	num++;
    }
#if defined(SIGRTMIN) && defined(SIGRTMAX)
    {
	const int rtmin = SIGRTMIN;
	const int rtmax = SIGRTMAX;
	static char sigrtname[128];

	if ((rtmin > sig) || (sig > rtmax))
	    return (const char*)0;

	if (sig <= (rtmin + (rtmax - rtmin)/2)) {
	    int delta = sig - rtmin;
	    strcpy(sigrtname, "RTMIN");
	    if (delta) snprintf(sigrtname+5, 122, "+%d", delta);
	} else {
	    int delta = rtmax - sig;
	    strcpy(sigrtname, "RTMAX");
	    if (delta) snprintf(sigrtname+5, 122, "-%d", delta);
	}
	return sigrtname;
    }
#endif
    return (const char*)0;
}

/* Used in killproc.c only once to list the signal names */
void list_signames(void)
{
    int sig, line = 0;

    for (sig = 0, line = 0; sig <= NSIG; sig++) {
#if defined(SIGRTMIN) && defined(SIGRTMAX)
	if (sig < SIGRTMIN) {
#endif
	    long int num = 0;
	    while (sys_signals[num].num) {
		if (sys_signals[num].num == sig) {
		    printf("%2d) SIG%-9s", sys_signals[num].num, sys_signals[num].name);
		    line++;
		    if (!(line % 4)) putc('\n', stdout);
		}
		num++;
	    }
#if defined(SIGRTMIN) && defined(SIGRTMAX)
	} else {
	    const int rtmin = SIGRTMIN;
	    const int rtmax = SIGRTMAX;
	    char sigrtname[128];

	    if ((rtmin > sig) || (sig > rtmax))
		continue;

	    if (sig <= (rtmin + (rtmax - rtmin)/2)) {
		int delta = sig - rtmin;
		strcpy(sigrtname, "RTMIN");
		if (delta) snprintf(sigrtname+5, 122, "+%d", delta);
	    } else {
		int delta = rtmax - sig;
		strcpy(sigrtname, "RTMAX");
		if (delta) snprintf(sigrtname+5, 122, "+%d", delta);
	    }
	    printf("%2d) SIG%-9s", sig, sigrtname);
	    line++;
	    if (!(line % 4)) putc('\n', stdout);
	}
#endif
    }

    if (line % 4) putc('\n', stdout);
}

/*
 * Follow the link to its full deep, this because
 * to get the real file name stored in lnk[].
 */
static char lnk[PATH_MAX+1];
int rlstat(char ** file, struct stat *st, const unsigned short flags)
{
    int ret = -1;
    int deep = MAXSYMLINKS;
    char * cur_file = *file;

    if (lstatn(cur_file, STATX_MODE, st) < 0)
	goto out;

    ret = 0;
    if (*file == (void *)&lnk[0])	/* already done that */
	goto out;

    do {
	const char *prev_file;
	int cnt;

	ret = 0;
	if (!S_ISLNK(st->st_mode))
	    goto out;
	ret = -1;

	if ((prev_file = strdupa(cur_file)) == NULL)
	    error(100, "strdupa(): %s\n", strerror(errno));

	if ((cnt = readlink(cur_file, lnk, PATH_MAX)) < 0)
	    goto out;
	lnk[cnt] = '\0';

	if (lnk[0] != '/') {		/* Construct a new valid file name */
	    const char *lastslash;

	    if ((lastslash = strrchr(prev_file, '/'))) {
		size_t dirname_len = lastslash - prev_file + 1;

		if (dirname_len + cnt > PATH_MAX)
		    cnt = PATH_MAX - dirname_len;

		memmove(&lnk[dirname_len], &lnk[0], cnt + 1);
		memcpy(&lnk[0], prev_file, dirname_len);
	    }
	}
	cur_file = &lnk[0];

	if (lstatn(cur_file, STATX_MODE, st) < 0)
	    goto out;

	if (deep-- <= 0) {
	    errno = ELOOP;
	    goto out;
	}

    } while (S_ISLNK(st->st_mode));

    ret = 0;

    if (flags & FLWLINK)
	*file = cur_file;

out:
    return ret;
}

/*
 * Code below is for checking for binaries located on a NFS
 * based file system.  With this help we can switch off the
 * the various stat()'s checks become dead locked if the
 * corresponding NFS servers are not online.
 */

typedef struct _shadow_
{
    list_t this;
    size_t nlen;
    char *point;
} SHADOW;

typedef struct _nfs_
{
    list_t   this;
    SHADOW shadow;		/* Pointer to shadows      */
    size_t   nlen;
    char   *point;
} NFS;

static list_t nfs = {&nfs, &nfs};

void init_nfs(void)
{
    char buffer[LINE_MAX];
    struct stat st;
    struct mntent ent;
    FILE * mnt;

    init_mounts();

    if (!list_empty(&mounts))
	return;

    /* Stat /proc/version to see if /proc is mounted. */
    if (statn("/proc/version", STATX_INO, &st) < 0)
	getproc();

    if ((mnt = setmntent("/proc/mounts", "r")) == (FILE*)0)
	return;

    while (getmntent_r(mnt, &ent, buffer, sizeof(buffer))) {
	if (isnetfs(ent.mnt_type)) {
	    const size_t nlen = strlen(ent.mnt_dir);
	    NFS *restrict p;

	    if (posix_memalign((void*)&p, sizeof(void*), alignof(NFS)+(nlen+1)) != 0) {
		if (stopped) kill(-1, SIGCONT);
		error(100, "malloc(): %s\n", strerror(errno));
	    }
	    append(p, nfs);
	    p->point = ((char*)p)+alignof(NFS);
	    strcpy(p->point, ent.mnt_dir);
	    p->nlen = nlen;
	    initial(&p->shadow.this);
	}
    }
    endmntent(mnt);

    if ((mnt = setmntent("/proc/mounts", "r")) == (FILE*)0)
	return;

    while (getmntent_r(mnt, &ent, buffer, sizeof(buffer))) {
	list_t *ptr;

	list_for_each(ptr, &nfs) {
	    NFS *p = list_entry(ptr, NFS);
	    SHADOW * restrict s;
	    size_t nlen;

	    if (strcmp(ent.mnt_dir, p->point) == 0)
		continue;
	    if (strncmp(ent.mnt_dir, p->point, p->nlen) != 0)
		continue;

	    nlen = strlen(ent.mnt_dir);
	    if (posix_memalign((void*)&s, sizeof(void*), alignof(SHADOW)+(nlen+1))) {
		if (stopped) kill(-1, SIGCONT);
		error(100, "malloc(): %s\n", strerror(errno));
	    }
	    append(s, p->shadow.this);
	    s->point = ((char*)s)+alignof(SHADOW);
	    strcpy(s->point, ent.mnt_dir);
	    s->nlen = nlen;
	}
    }
    endmntent(mnt);
}

static inline boolean shadow(list_t *restrict shadow, const char *restrict name, const size_t nlen)
{
    list_t *ptr;

    if (!shadow || list_empty(shadow))
	goto out;
    list_for_each(ptr, shadow) {
	SHADOW *s =list_entry(ptr, SHADOW);
	if (nlen < s->nlen)
	    continue;
	if (name[s->nlen] != '\0' && name[s->nlen] != '/')
	    continue;
	if (strncmp(name, s->point, s->nlen) == 0)
	    return true;
    }
out:
    return false;
}

boolean check4nfs(const char * path)
{
    char buf[PATH_MAX+1];
    const char *curr;
    int deep = MAXSYMLINKS;

    if (list_empty(&nfs) && list_empty(&mounts))
	goto out;

    curr = path;
    do {
	const char *prev;
	int len;

	if ((prev = strdupa(curr)) == NULL)
	    error(100, "strdupa(): %s\n", strerror(errno));

	errno = 0;
	if ((len = readlink(curr, buf, PATH_MAX)) < 0)
	    break;
	buf[len] = '\0';

	if (buf[0] != '/') {
	    const char *slash;

	    if ((slash = strrchr(prev, '/'))) {
		size_t off = slash - prev + 1;

		if (off + len > PATH_MAX)
		    len = PATH_MAX - off;

		memmove(&buf[off], &buf[0], len + 1);
		memcpy(&buf[0], prev, off);
	    }
	}
	curr = &buf[0];

	if (deep-- <= 0) {
	    errno = ELOOP;
	    return false;
	}

    } while (true);

    if (errno == EINVAL) {
	list_t *ptr;
	const size_t nlen = strlen(curr);
	if (list_empty(&mounts)) {
	    list_for_each(ptr, &nfs) {
		NFS *p = list_entry(ptr, NFS);
		if (nlen < p->nlen)
		    continue;
		if (curr[p->nlen] != '\0' && curr[p->nlen] != '/')
		    continue;
		if (!strncmp(curr, p->point, p->nlen)) {
		    if (shadow(&p->shadow.this, curr, nlen))
			continue;
		    return true;
		}
	    }
	} else {
	    list_for_each(ptr, &mounts) {
		MNTINFO *p = list_entry(ptr, MNTINFO);
		if (nlen < p->nlen)
		    continue;
		if (p->nlen == 1)
		    return p->netfs;
		if (curr[p->nlen] != '\0' && curr[p->nlen] != '/')
		    continue;
		if (!strncmp(curr, p->point, p->nlen))
		    return p->netfs;
	    }
	}
    }
out:
    return false;
}

static void clear_shadow(list_t *restrict shadow)
{
    list_t *this, *ptr;
    list_for_each_safe(this, ptr, shadow) {
	SHADOW *s = list_entry(this, SHADOW);
	delete(this);
	free(s);
    }
}

void clear_nfs(void)
{
    list_t *this, *ptr;

    list_for_each_safe(this, ptr, &nfs) {
	NFS *p = list_entry(this, NFS);
	delete(this);
	if (!list_empty(&p->shadow.this))
	    clear_shadow(&p->shadow.this);
	free(p);
    }
}

/*
 * Somehow the realpath(3) glibc function call, nevertheless
 * it avoids lstat(2) system calls.
 */
static char real[PATH_MAX+1];
char* expandpath(const char * path)
{
    char tmpbuf[PATH_MAX+1];
    const char *start, *end;
    char *curr, *dest;
    int deep = MAXSYMLINKS;

    if (!path || *path == '\0')
	return (char*)0;

    curr = &real[0];

    if (*path != '/') {
	if (!getcwd(curr, PATH_MAX))
	    return (char*)0;
	dest = rawmemchr(curr, '\0');
    } else {
	*curr = '/';
	dest = curr + 1;
    }

    for (start = end = path; *start; start = end) {

	while (*start == '/')
	    ++start;

	for (end = start; *end && *end != '/'; ++end)
	    ;

	if (end - start == 0)
	    break;
	else if (end - start == 1 && start[0] == '.') {
	    ;
	} else if (end - start == 2 && start[0] == '.' && start[1] == '.') {
	    if (dest > curr + 1)
		while ((--dest)[-1] != '/')
		    ;
	} else {
	    char lnkbuf[PATH_MAX+1];
	    size_t len;
	    ssize_t n;

	    if (dest[-1] != '/')
		*dest++ = '/';

	    if (dest + (end - start) > curr + PATH_MAX) {
		errno = ENAMETOOLONG;
		return (char*)0;
	    }

	    dest = mempcpy(dest, start, end - start);
	    *dest = '\0';

	    if (deep-- < 0) {
		errno = ELOOP;
		return (char*)0;
	    }

	    errno = 0;
	    if ((n = readlink(curr, lnkbuf, PATH_MAX)) < 0) {
		deep = MAXSYMLINKS;
		if (errno == EINVAL)
		    continue;    /* Not a symlink */
		return (char*)0;
	    }
	    lnkbuf[n] = '\0';	/* Don't be fooled by readlink(2) */

	    len = strlen(end);
	    if ((n + len) > PATH_MAX) {
		errno = ENAMETOOLONG;
		return (char*)0;
	    }

	    memmove(&tmpbuf[n], end, len + 1);
	    path = end = memcpy(tmpbuf, lnkbuf, n);

	    if (lnkbuf[0] == '/')
		dest = curr + 1;
	    else if (dest > curr + 1)
		while ((--dest)[-1] != '/');

	}
    }

    if (dest > curr + 1 && dest[-1] == '/')
	--dest;
    *dest = '\0';

    return curr;
}

/* libinit.c ends here */
