/*
 *  Copyright (C) 2020-2021 Pascal Lalonde <plalonde@overnet.ca>
 *
 *  This file is part of PotatoFS, a FUSE filesystem implementation.
 *
 *  PotatoFS is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include "config.h"
#include "counters.h"
#include "exlog.h"

struct counter counters[] = {
	/* COUNTER_FS_GETATTR */
	{ PTHREAD_MUTEX_INITIALIZER, 0, "fs_getattr" },

	/* COUNTER_FS_SETATTR */
	{ PTHREAD_MUTEX_INITIALIZER, 0, "fs_setattr" },

	/* COUNTER_FS_OPENDIR */
	{ PTHREAD_MUTEX_INITIALIZER, 0, "fs_opendir" },

	/* COUNTER_FS_READDIR */
	{ PTHREAD_MUTEX_INITIALIZER, 0, "fs_readdir" },

	/* COUNTER_FS_RELEASEDIR */
	{ PTHREAD_MUTEX_INITIALIZER, 0, "fs_releasedir" },

	/* COUNTER_FS_RELEASE */
	{ PTHREAD_MUTEX_INITIALIZER, 0, "fs_release" },

	/* COUNTER_FS_OPEN */
	{ PTHREAD_MUTEX_INITIALIZER, 0, "fs_open" },

	/* COUNTER_FS_READ */
	{ PTHREAD_MUTEX_INITIALIZER, 0, "fs_read" },

	/* COUNTER_FS_WRITE */
	{ PTHREAD_MUTEX_INITIALIZER, 0, "fs_write" },

	/* COUNTER_FS_FLUSH */
	{ PTHREAD_MUTEX_INITIALIZER, 0, "fs_flush" },

	/* COUNTER_FS_FORGET */
	{ PTHREAD_MUTEX_INITIALIZER, 0, "fs_forget" },

	/* COUNTER_FS_FORGET_MULTI */
	{ PTHREAD_MUTEX_INITIALIZER, 0, "fs_forget_multi" },

	/* COUNTER_FS_LOOKUP */
	{ PTHREAD_MUTEX_INITIALIZER, 0, "fs_lookup" },

	/* COUNTER_FS_MKDIR */
	{ PTHREAD_MUTEX_INITIALIZER, 0, "fs_mkdir" },

	/* COUNTER_FS_RMDIR */
	{ PTHREAD_MUTEX_INITIALIZER, 0, "fs_rmdir" },

	/* COUNTER_FS_UNLINK */
	{ PTHREAD_MUTEX_INITIALIZER, 0, "fs_unlink" },

	/* COUNTER_FS_STATFS */
	{ PTHREAD_MUTEX_INITIALIZER, 0, "fs_statfs" },

	/* COUNTER_FS_MKNOD */
	{ PTHREAD_MUTEX_INITIALIZER, 0, "fs_mknod" },

	/* COUNTER_FS_CREATE */
	{ PTHREAD_MUTEX_INITIALIZER, 0, "fs_create" },

	/* COUNTER_FS_FALLOCATE */
	{ PTHREAD_MUTEX_INITIALIZER, 0, "fs_fallocate" },

	/* COUNTER_FS_FSYNC */
	{ PTHREAD_MUTEX_INITIALIZER, 0, "fs_fsync" },

	/* COUNTER_FS_FSYNCDIR */
	{ PTHREAD_MUTEX_INITIALIZER, 0, "fs_fsyncdir" },

	/* COUNTER_FS_LINK */
	{ PTHREAD_MUTEX_INITIALIZER, 0, "fs_link" },

	/* COUNTER_FS_SYMLINK */
	{ PTHREAD_MUTEX_INITIALIZER, 0, "fs_symlink" },

	/* COUNTER_FS_READLINK */
	{ PTHREAD_MUTEX_INITIALIZER, 0, "fs_readlink" },

	/* COUNTER_FS_RENAME */
	{ PTHREAD_MUTEX_INITIALIZER, 0, "fs_rename" },

	/* COUNTER_FS_ERROR */
	{ PTHREAD_MUTEX_INITIALIZER, 0, "fs_error" },

	/* COUNTER_N_OPEN_SLABS */
	{ PTHREAD_MUTEX_INITIALIZER, 0, "fs_n_open_slabs" },

	/* COUNTER_N_SLABS_PURGE */
	{ PTHREAD_MUTEX_INITIALIZER, 0, "fs_n_slabs_purge" },

	/* COUNTER_N_OPEN_INODES */
	{ PTHREAD_MUTEX_INITIALIZER, 0, "fs_n_open_inodes" },

	/* COUNTER_READ_BYTES */
	{ PTHREAD_MUTEX_INITIALIZER, 0, "fs_read_bytes" },

	/* COUNTER_WRITE_BYTES */
	{ PTHREAD_MUTEX_INITIALIZER, 0, "fs_write_bytes" }
};

static char      counters_path[PATH_MAX];
static pthread_t counters_flush;
static int       counters_shutdown = 0;

static void *
counter_flush(void *unused)
{
	struct timespec  t = {1, 0};
	int              c, fd;
	FILE            *f;

	// TODO: this should all happen through a control socket, not
	// a tempfile.
	while (!counters_shutdown) {
		if ((fd = open(counters_path,
		    O_CREAT|O_WRONLY|O_TRUNC, 0644)) == -1) {
			exlog_lerrno(LOG_ERR, errno,
			    "%s: failed to open counters file: %s", __func__,
			    counters_path);
			goto sleep;
		}
		if (flock(fd, LOCK_EX) == -1) {
			exlog_lerrno(LOG_ERR, errno,
			    "%s: failed to lock counters file: %s", __func__,
			    counters_path);
			close(fd);
			goto sleep;
		}
		if ((f = fdopen(fd, "w")) == NULL) {
			exlog_lerrno(LOG_ERR, errno,
			    "%s: failed to fdopen counters file: %s", __func__,
			    counters_path);
			close(fd);
			goto sleep;
		}

		if (fprintf(f, "{\n") == -1)
			goto fail;

		for (c = 0; c < COUNTER_LAST; c++) {
			if (fprintf(f, "    \"%s\": %lu%s\n",
			    counters[c].desc, counter_get(c),
			    (c < COUNTER_LAST - 1) ? "," : "") == -1)
				goto fail;
		}
		if (fprintf(f, "}\n") == -1)
			goto fail;
fail:
		fclose(f);
sleep:
		for (;;) {
			if (nanosleep(&t, NULL) == 0)
				break;
		}
	}
	return NULL;
}

int
counter_init(const char *path, struct exlog_err *e)
{
	int            r;
	pthread_attr_t attr;

	exlog(LOG_NOTICE, "opening counters file at %s", path);

	if (snprintf(counters_path, sizeof(counters_path), "%s/%s",
	    path, COUNTERS_FILE_NAME) >= sizeof(counters_path))
		 return exlog_errf(e, EXLOG_APP, EXLOG_ENAMETOOLONG,
		     "counters file name too long: %s", path);

	if ((r = pthread_attr_init(&attr)) != 0)
		return exlog_errf(e, EXLOG_OS, r,
		    "%s: failed to init pthread attributes", __func__);

	if ((r = pthread_create(&counters_flush, &attr,
	    &counter_flush, NULL)) != 0)
		return exlog_errf(e, EXLOG_OS, r,
		    "%s: failed to init pthread attributes", __func__);

	return 0;
}

int
counter_shutdown(struct exlog_err *e)
{
	int r;

	counters_shutdown = 1;
	if ((r = pthread_join(counters_flush, NULL)) != 0)
		return exlog_errf(e, EXLOG_OS, r, "%s", __func__);
	return 0;
}

void
counter_incr(int c)
{
	counter_add(c, 1);
}

void
counter_add(int c, uint64_t v)
{
	if (pthread_mutex_lock(&counters[c].mtx) != 0)
		exlog(LOG_ERR, "failed to acquire counter lock");
	counters[c].count += v;
	pthread_mutex_unlock(&counters[c].mtx);
}

void
counter_decr(int c)
{
	if (pthread_mutex_lock(&counters[c].mtx) != 0)
		exlog(LOG_ERR, "failed to acquire counter lock");
	counters[c].count--;
	pthread_mutex_unlock(&counters[c].mtx);
}

void
counter_reset(int c)
{
	if (pthread_mutex_lock(&counters[c].mtx) != 0)
		exlog(LOG_ERR, "failed to acquire counter lock");
	counters[c].count = 0;
	pthread_mutex_unlock(&counters[c].mtx);
}

uint64_t
counter_get(int c)
{
	uint64_t v;

	if (pthread_mutex_lock(&counters[c].mtx) != 0)
		exlog(LOG_ERR, "failed to acquire counter lock");
	v = counters[c].count;
	pthread_mutex_unlock(&counters[c].mtx);
	return v;
}
