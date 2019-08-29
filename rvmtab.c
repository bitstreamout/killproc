/*
 * rvmtab.c	Sort /proc/mounts or /etc/mtab in the sorting order of
 *		/proc/self/mountinfo usable for sequential umount calls
 *
 * Version:	0.1 01-Feb-2011 Fink
 *
 * Copyright 2011 Werner Fink, 2005 SUSE LINUX Products GmbH, Germany.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Author:	Werner Fink <werner@suse.de>, 2011
 */

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <errno.h>
#include <limits.h>
#include <mntent.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/stat.h>
#include <unistd.h>
#include "libinit.h"
#include "lists.h"
#include "statx.h"

typedef struct mounts_s {
    list_t  this;
    int     freq;
    int   passno;
    size_t  nlen;
    char *device;
    char *mpoint;
    char *fstype;
    char *mntopt;
} mounts_t;

typedef struct mntinfo_s {
    list_t   this;
    int id, parid;
    dev_t     dev;
    char  *mpoint;
} mntinfo_t;

static list_t  mounts = {&mounts, &mounts};
static list_t mntinfo = {&mntinfo, &mntinfo};
static list_t    save = {&save, &save};

int main ()
{
    list_t *ptr;
    FILE *minfo, *mtab;
    struct mntent ent;
    struct stat st;
    char buffer[PATH_MAX*4 + 1];
    int mid, max, parid;
    uint maj, min;

    /* Stat /proc/version to see if /proc is mounted. */
    if (statn("/proc/version", STATX_INO, &st) < 0)
	getproc();

    mtab = setmntent("/proc/mounts", "r");
    if (!mtab) {
	mtab = setmntent("/etc/mtab", "r");
	if (!mtab)
	    goto err;
    }
    while (getmntent_r(mtab, &ent, buffer, sizeof(buffer))) {
	mounts_t *restrict p;
	size_t l1, l2, l3, l4;

	l1 = strlen(ent.mnt_fsname);
	l2 = strlen(ent.mnt_dir);
	l3 = strlen(ent.mnt_type);
	l4 = strlen(ent.mnt_opts);

	if (posix_memalign((void*)&p, sizeof(void*), alignof(mounts_t)+(l1+l2+l3+l4+4)) != 0)
	    goto err;
	append(p, mounts);
	p->freq   = ent.mnt_freq;
	p->passno = ent.mnt_passno;
	p->nlen   = l2;

	p->device = ((char*)p)+alignof(mounts_t);
	p->mpoint = p->device+l1+1;
	p->fstype = p->mpoint+l2+1;
	p->mntopt = p->fstype+l3+1;

	strcpy(p->device, ent.mnt_fsname);
	strcpy(p->mpoint, ent.mnt_dir);
	strcpy(p->fstype, ent.mnt_type);
	strcpy(p->mntopt, ent.mnt_opts);
    }
    endmntent(mtab);

    minfo = fopen("/proc/self/mountinfo", "r");
    if (!minfo)
	goto err;
    max = 1;
    while (fscanf(minfo, "%i %i %u:%u %*s %s %*[^-] - %*s %*s %*[^\n]", &mid, &parid, &maj, &min, &buffer[0]) == 5) {
	mntinfo_t *restrict p;

	if (posix_memalign((void*)&p, sizeof(void*), alignof(mntinfo_t)+(strlen(buffer)+1)) != 0)
	    goto err;
	append(p, mntinfo);
	p->mpoint = ((char*)p)+alignof(mntinfo_t);
	strcpy(p->mpoint, buffer);
	p->parid = parid;
	p->dev = makedev(maj, min);
	p->id = mid;
	if (mid > max)
	    max = mid;
    }
    fclose(minfo);

    initial(&save);
    for (mid = 1; mid <= max; mid++) {
	list_t *this, *cpy;
	list_for_each_safe(this, cpy, &mntinfo) {
	    mntinfo_t * m = list_entry(this, mntinfo_t);
	    if (mid != m->id)
		continue;
	    move_head(this, &save);
	    break;
	}
	list_for_each_safe(this, cpy, &mntinfo) {
	    mntinfo_t * m = list_entry(this, mntinfo_t);
	    if (mid != m->parid)
		continue;
	    move_head(this, &save);
	}
    }
    if (!list_empty(&mntinfo)) {
	    errno = EBADE;
	    goto err;
    }
    join(&save, &mntinfo);

#if 0
    list_for_each(ptr, &mntinfo) {
	mntinfo_t *m = list_entry(ptr, mntinfo_t);
	printf("%d %d 0x%3.3x %s\n", m->id, m->parid, (uint)m->dev, m->mpoint);
    }
    putchar('\n');
#endif
    np_list_for_each(ptr, &mntinfo) {
	mntinfo_t *m = list_entry(ptr, mntinfo_t);
	list_t *tmp;
	list_for_each(tmp, &mounts) {
	    mounts_t *p = list_entry(tmp, mounts_t);
	    if (!p->mpoint || !p->device)
		continue;
	    if (strcmp("rootfs", p->device) == 0)
		continue;
	    if (strcmp(m->mpoint, p->mpoint))
		continue;
	    printf("%s %s %s %s %d %d\n", p->device, p->mpoint, p->fstype,
		   p->mntopt, p->freq, p->passno);
	}
	prefetch(ptr->next);
    }
    return 0;
err:
    fprintf(stderr, "rvmtab: %s\n", strerror(errno));
    return 1;
}
