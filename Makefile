#
# Makefile for compiling all killproc tools
#
# Author: Werner Fink,  <werner@suse.de>
#

DISTRO	 =	SUSE

INITDIR  =	/etc/init.d
#DEBUG	 =	-DDEBUG=1
#DESTDIR =	/tmp/root
PREFIX	 =	/usr
DEBUG	 =
DESTDIR	 =
VERSION	 =	2.23
DATE	 =	$(shell date +'%d%b%y' | tr '[:lower:]' '[:upper:]')
STATX	 =	$(shell (test -d /lib64 && nm -D /lib64/libc.so.* || /lib/libc.so.*)|grep -c statx)
SYSSTATX =      $(shell echo -e '\#include <sys/syscall.h>\nint main () {return SYS_statx;}'|gcc -x c -o /dev/null -P - 2>/dev/null && echo 1 || echo 0)
OSTATX   =

  LIBS  +=	-lblogger -lpthread
  COPTS +=	-std=gnu89 -DUSE_BLOGD
ifeq ($(STATX),1)
  COPTS +=	-DHAVE_STATX
endif
ifeq ($(SYSSTATX),1)
  COPTS +=	-DHAVE_DECL_SYS_STATX
OSTATX  +=      statx.o
endif

#
# Architecture
#
	   ARCH = $(shell uname -m | sed 's@\(i\)[34567]\(86\)@\13\2@')
#
# egcs used with -O2 includes -fno-force-mem which is/was buggy (1998/10/08)
#
	LDFLAGS = -Wl,--as-needed,--hash-size=8599,-O2
	 CFLAGS = $(RPM_OPT_FLAGS) $(COPTS) $(DEBUG) $(INC) -D_GNU_SOURCE -Wall -pipe
	  CLOOP = -funroll-loops
	     CC = gcc
	     RM = rm -f
	  MKDIR = mkdir -p
	  RMDIR = rm -rf
   INSTBINFLAGS = -s -m 0755
	INSTBIN = install $(INSTBINFLAGS)
   INSTDOCFLAGS = -c -m 0444
	INSTDOC = install $(INSTDOCFLAGS)
	   LINK = ln -sf
	     SO = echo .so man8/

#
	SDOCDIR = $(DESTDIR)$(PREFIX)/share/man/man8
	UDOCDIR = $(DESTDIR)$(PREFIX)/share/man/man1
	SBINDIR = $(DESTDIR)/sbin
	UBINDIR = $(DESTDIR)/bin
#
#
#
SBINPRG =	killproc startproc checkproc
UBINPRG =

ifeq ($(DISTRO),SUSE)
   UBINPRG += usleep
   UBINPRG += fsync
   SBINPRG += rvmtab
   SBINPRG += vhangup
   SBINPRG += mkill
endif

all: $(SBINPRG) $(UBINPRG)

libinit.o:	libinit.c libinit.h lists.h
	$(CC) $(CFLAGS) $(CLOOP) -DINITDIR=\"$(INITDIR)\" -c $<

statx.o:	statx.c statx.h
	$(CC) $(CFLAGS) $(CLOOP) -c $<

#		s/#define/#if defined/; \
#		s/(SIG[A-Z]+)$$/\1 \&\& \1 < NSIG\nif (!sys_signame[\1]) sys_signame[\1]=\"\1\";\nelse sys_sigalias[\1]=\"\1\";\n#endif/p; \

sig.def:
	for sig in $$(kill -l); do\
	    case "$$sig" in *\)) continue;; esac; \
	    sig=$${sig#SIG}; \
	    def=$${sig%[+-]*};\
	    echo '#if defined(SIG'$$def')';\
	    echo '    if (!sys_signame['$$sig'])';\
	    echo '	sys_signame ['$$sig'] = "'$$sig'";';\
	    echo '    else';\
	    echo '	sys_sigalias['$$sig'] = "'$$sig'";';\
	    echo '#endif';\
	done

killproc:	killproc.c libinit.o $(OSTATX)
	$(CC) $(CFLAGS) $(CLOOP) $(LDFLAGS) -o $@ $^ $(LIBS)

startproc:	startproc.c libinit.o $(OSTATX)
	$(CC) $(CFLAGS) $(CLOOP) $(LDFLAGS) -o $@ $^ $(LIBS)

checkproc:	checkproc.c libinit.o $(OSTATX)
	$(CC) $(CFLAGS) $(CLOOP) $(LDFLAGS) -o $@ $^ $(LIBS)

usleep:		usleep.c
	$(CC) $(CFLAGS) -o $@ $^

fsync:		fsync.c
	$(CC) $(CFLAGS) -o $@ $^

vhangup:	vhangup.c
	$(CC) $(CFLAGS) -o $@ $^

mkill:	mkill.c libinit.o $(OSTATX)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

rvmtab:	rvmtab.c libinit.o $(OSTATX)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

clean:
	$(RM) *.o *~ $(SBINPRG) $(UBINPRG)

install:	$(TODO)
	if test -n "$(SBINPRG)" ; then	\
	    $(MKDIR)	$(SBINDIR);	\
	    $(MKDIR)	$(SDOCDIR);	\
	fi
	if test -n "$(UBINPRG)" ; then  \
	    $(MKDIR)	$(UBINDIR);	\
	    $(MKDIR)	$(UDOCDIR);	\
	fi
	for p in $(SBINPRG); do 		\
	    $(INSTBIN) $$p	$(SBINDIR)/;	\
	    $(INSTDOC) $$p.8	$(SDOCDIR)/;	\
	done
	if test -e $(SBINDIR)/startproc ; then	\
	    $(LINK) startproc	$(SBINDIR)/start_daemon;	\
	    $(LINK) startproc.8	$(SDOCDIR)/start_daemon.8;	\
	fi
	if test -e $(SBINDIR)/checkproc ; then	\
	    $(LINK) checkproc	$(SBINDIR)/pidofproc;		\
	    $(SO)checkproc.8 >	$(SDOCDIR)/pidofproc.8;		\
	fi
	for p in $(UBINPRG); do 		\
	    $(INSTBIN) $$p	$(UBINDIR)/;	\
	    $(INSTDOC) $$p.1	$(UDOCDIR)/;	\
	done
#
# Make distribution
#
FILES	= README.md   \
	  COPYING     \
	  Makefile    \
	  killproc.8  \
	  killproc.c  \
	  startproc.c \
	  startproc.8 \
	  checkproc.c \
	  checkproc.8 \
	  libinit.c   \
	  libinit.h   \
	  lists.h     \
	  usleep.c    \
	  usleep.1    \
	  fsync.c     \
	  fsync.1     \
	  vhangup.c   \
	  vhangup.8   \
	  mkill.c     \
	  mkill.8     \
	  rvmtab.c    \
	  rvmtab.8    \
	  statx.c     \
	  statx.h     \
	  killproc-$(VERSION).lsm

dest:
	$(MKDIR) killproc-$(VERSION)
	@echo -e "Begin3\n\
Title:		killproc and assorted tools for boot scripts\n\
Version:	$(VERSION)\n\
Entered-date:	$(DATE)\n\
Description:	Some useful programs for a replacment of the shell functions\n\
x 		daemom and killproc found in the Linux System V init suite.\n\
x 		killproc(8) for signaling or terminating, checkproc(8) for\n\
x 		checking and startproc(8) for starting processes.\n\
x 		Each program has its own manual page.\n\
Keywords:	killproc, startproc, checkproc, process control\n\
Author:		Werner Fink <werner@suse.de>\n\
Maintained-by:	Werner Fink <werner@suse.de>\n\
Primary-site:	sunsite.unc.edu /pub/Linux/system/daemons/init\n\
x		@UNKNOWN killproc-$(VERSION).tar.gz\n\
Alternate-site:	ftp.suse.com /pub/projects/init\n\
Platforms:	Linux with System VR2 or higher boot scheme\n\
Copying-policy:	GPL\n\
End" | sed 's@^ @@g;s@^x@@g' > killproc-$(VERSION).lsm
	cp $(FILES) killproc-$(VERSION)
	tar -cp -jf  killproc-$(VERSION).tar.bz2 killproc-$(VERSION)/
	$(RMDIR)    killproc-$(VERSION)
	set -- `find killproc-$(VERSION).tar.bz2 -printf '%s'` ; \
	sed "s:@UNKNOWN:$$1:" < killproc-$(VERSION).lsm > \
	killproc-$(VERSION).lsm.tmp ; \
	mv killproc-$(VERSION).lsm.tmp killproc-$(VERSION).lsm

tar.gz: all
	$(MKDIR) -p tmpr/sbin
	$(MKDIR) -p tmpr/usr/share/man/man8
	chown root:root tmpr/*
	install -s -m 0755 -o root -g root killproc  tmpr/sbin/
	install -s -m 0755 -o root -g root startproc tmpr/sbin/
	install -s -m 0755 -o root -g root checkproc tmpr/sbin/
	ln -sf startproc      tmpr/sbin/start_daemon
	ln -sf checkproc      tmpr/sbin/pidofproc
	gzip -c -9 killproc.8   > tmpr/usr/share/man/man8/killproc.8.gz
	gzip -c -9 startproc.8  > tmpr/usr/share/man/man8/startproc.8.gz
	gzip -c -9 checkproc.8  > tmpr/usr/share/man/man8/checkproc.8.gz
	ln -sf startproc.8.gz tmpr/sbin/start_daemon.8.gz
	ln -sf checkproc.8.gz tmpr/sbin/pidofproc.8.gz
	cd tmpr/; tar cfsSpz ../killproc.tgz sbin/ usr/
	rm -rf tmpr/
