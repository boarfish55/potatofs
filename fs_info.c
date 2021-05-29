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
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include "config.h"
#include "counters.h"
#include "inodes.h"
#include "fs_info.h"
#include "exlog.h"
#include "util.h"

static rwlk            fs_info_lock;
static struct fs_info  fs_info;
const char            *potatofs_stat_path = "stats";

int
fs_info_create(struct exlog_err *e)
{
	int     fd = -1;
	ssize_t r;
	char    path[PATH_MAX];

	if (fs_config.slab_size < SLAB_SIZE_FLOOR ||
	    fs_config.slab_size > SLAB_SIZE_CEIL ||
	    (fs_config.slab_size & (fs_config.slab_size - 1)) != 0)
		return exlog_errf(e, EXLOG_APP, EXLOG_EINVAL,
		    "slab_size must be a power of two, between %lu and %lu",
		    SLAB_SIZE_FLOOR, SLAB_SIZE_CEIL);

	if (snprintf(path, sizeof(path), "%s/%s", fs_config.data_dir,
	    potatofs_stat_path) >= sizeof(path)) {
		exlog_errf(e, EXLOG_APP, EXLOG_EINVAL,
		    "%s: failed to statvfs file; too long", __func__);
		goto end;
	}

	if ((fd = open(path, O_CREAT|O_RDWR, 0600)) == -1) {
		exlog_errf(e, EXLOG_OS, errno,
		    "%s: fs stat cannot be opened", __func__);
		goto end;
	}

	if (flock(fd, LOCK_EX) == -1) {
		exlog_errf(e, EXLOG_OS, errno,
		    "%s: failed to flock() fs_info %s", __func__, path);
		goto end;
	}

	if ((r = read_x(fd, &fs_info, sizeof(fs_info))) == -1) {
		exlog_errf(e, EXLOG_OS, errno,
		    "%s: fs stat cannot be read", __func__);
		goto end;
	}

	if (r == 0) {
		bzero(&fs_info, sizeof(fs_info));

		fs_info.slab_size = fs_config.slab_size;
		uuid_generate(fs_info.instance_id);

		fs_info.fs_info_version = FS_INFO_VERSION;
		fs_info.stats.f_bsize = FS_BLOCK_SIZE;
		fs_info.stats.f_frsize = FS_BLOCK_SIZE;

		fs_info.stats.f_blocks = 64 * 1024 * 1024;
		fs_info.stats.f_bfree = 64 * 1024 * 1024;
		fs_info.stats.f_bavail = 64 * 1024 * 1024;

		fs_info.stats.f_files = 1024 * 1024;
		fs_info.stats.f_ffree = 1024 * 1024;
		fs_info.stats.f_favail = 1024 * 1024;

		fs_info.stats.f_fsid = 1;
		fs_info.stats.f_flag = 0;
		fs_info.stats.f_namemax = FS_NAME_MAX;
	} else if (r < sizeof(fs_info)) {
		exlog_errf(e, EXLOG_APP, EXLOG_EINVAL,
		    "%s: potatofs_fs_info structure size mismatch; "
		    "incompatible version?", __func__);
		goto end;
	} else {
		if (fs_info.clean != 0)
			fs_info.error = 1;
		fs_info.clean = 0;
	}

	if ((r = write_x(fd, &fs_info, sizeof(fs_info))) < sizeof(fs_info)) {
		exlog_errf(e, EXLOG_APP, EXLOG_EIO,
		    "%s: failed to write potatofs_fs_info structure; "
		    "write() returned %d instead of %d:",
		    __func__, r, sizeof(fs_info));
		goto end;
	}
end:
	if (fd > 0)
		close(fd);
	return exlog_fail(e);
}

int
fs_info_load(struct fs_info *info, const char *data_path,
    size_t slab_size, struct exlog_err *e)
{
	int     fd = -1;
	ssize_t r;
	char    path[PATH_MAX];
	char    instance_id[37];

	if (LK_LOCK_INIT(&fs_info_lock, e) == -1)
		return -1;

	if (snprintf(path, sizeof(path), "%s/%s", fs_config.data_dir,
	    potatofs_stat_path) >= sizeof(path)) {
		exlog_errf(e, EXLOG_APP, EXLOG_EINVAL,
		    "%s: failed to statvfs file; too long", __func__);
		goto end;
	}

	if ((fd = open(path, O_CREAT|O_RDWR, 0600)) == -1) {
		exlog_errf(e, EXLOG_OS, errno,
		    "%s: fs stat cannot be opened", __func__);
		goto end;
	}

	if (flock(fd, LOCK_EX) == -1) {
		exlog_errf(e, EXLOG_OS, errno,
		    "%s: failed to flock() fs_info %s", __func__, path);
		goto end;
	}

	if ((r = read_x(fd, &fs_info, sizeof(fs_info))) == -1) {
		exlog_errf(e, EXLOG_OS, errno,
		    "%s: fs stat cannot be read", __func__);
		goto end;
	}

	if (r < sizeof(fs_info)) {
		exlog_errf(e, EXLOG_APP, EXLOG_EINVAL,
		    "%s: fs_info structure size mismatch; "
		    "incompatible version?", __func__);
		goto end;
	}

	if (fs_info.fs_info_version != FS_INFO_VERSION) {
		exlog_errf(e, EXLOG_APP, EXLOG_EINVAL,
		    "%s: fs_info structure version mismatch; "
		    "incompatible version?", __func__);
		goto end;
	}

	if (fs_info.clean != 0)
		fs_info.error = 1;
	fs_info.clean = 0;

	if ((r = write_x(fd, &fs_info, sizeof(fs_info))) < sizeof(fs_info)) {
		exlog_errf(e, EXLOG_APP, EXLOG_EIO,
		    "%s: failed to write potatofs_fs_info structure; "
		    "write() returned %d instead of %d:",
		    __func__, r, sizeof(fs_info));
		goto end;
	}

	uuid_unparse_lower(fs_info.instance_id, instance_id);
	exlog(LOG_NOTICE, "filesystem statfs initialized, instance_id is %s",
	    instance_id);
end:
	if (fd > 0)
		close(fd);
	if (info != NULL)
		memcpy(info, &fs_info, sizeof(fs_info));
	return exlog_fail(e);
}

int
fs_info_get(struct fs_info *fs, struct exlog_err *e)
{
	LK_RDLOCK(&fs_info_lock);

	// TODO: Probably the easiest way to do this early on is to
	// query the slow backend to know how much space we're using.
	// We could do this asynchronously to avoid stalling.
	memcpy(fs, &fs_info, sizeof(fs_info));

	LK_UNLOCK(&fs_info_lock);

	return 0;
}

void
fs_info_set_error()
{
	counter_incr(COUNTER_FS_ERROR);
	LK_WRLOCK(&fs_info_lock);
	fs_info.error = 1;
	LK_UNLOCK(&fs_info_lock);
}

uint8_t
fs_info_error()
{
	uint8_t error;

	LK_RDLOCK(&fs_info_lock);
	error = fs_info.error;
	LK_UNLOCK(&fs_info_lock);
	return error;
}

int
fs_info_shutdown(int clean, struct exlog_err *e)
{
	int     fd = -1;
	char    path[PATH_MAX];
	ssize_t r;

	LK_WRLOCK(&fs_info_lock);

	if (snprintf(path, sizeof(path), "%s/%s", fs_config.data_dir,
	    potatofs_stat_path) >= sizeof(path)) {
		exlog_errf(e, EXLOG_APP, EXLOG_EINVAL,
		    "%s: failed to statvfs file; too long", __func__);
		goto end;
	}

	fs_info.clean = (fs_info.error != 0) ? 0 : clean;

	if ((fd = open(path, O_RDWR, 0600)) == -1) {
		exlog_errf(e, EXLOG_OS, errno,
		    "%s: fs stat cannot be opened: %s", __func__, path);
		goto end;
	}

	if (flock(fd, LOCK_EX) == -1) {
		exlog_errf(e, EXLOG_OS, errno,
		    "%s: failed to flock() fs_info %s", __func__, path);
		goto end;
	}

	if ((r = write_x(fd, &fs_info, sizeof(fs_info))) < sizeof(fs_info)) {
		exlog_errf(e, EXLOG_APP, EXLOG_EIO,
		    "%s: failed to write potatofs_fs_info structure; "
		    "write() returned %d instead of %d:",
		    __func__, r, sizeof(fs_info));
		goto end;
	}
end:
	if (fd > 0)
		close(fd);

	LK_UNLOCK(&fs_info_lock);
	return exlog_fail(e);
}

int
fs_info_inspect(struct fs_info *fs, struct exlog_err *e)
{
	char    fs_info_path[PATH_MAX];
	int     fd;
	ssize_t r;

	if (snprintf(fs_info_path, sizeof(fs_info_path), "%s/%s",
	    fs_config.data_dir, potatofs_stat_path) >= sizeof(fs_info_path))
		return exlog_errf(e, EXLOG_OS, EXLOG_ENAMETOOLONG,
		    "%s: potatofs base path too long", __func__);

	if ((fd = open(fs_info_path, O_RDONLY)) == -1)
		return exlog_errf(e, EXLOG_OS, errno,
		    "%s: failed to open fs_info", __func__);

	if (flock(fd, LOCK_SH) == -1)
		return exlog_errf(e, EXLOG_OS, errno,
		    "%s: failed to open fs_info", __func__);

	if ((r = read(fd, fs, sizeof(struct fs_info))) == -1)
		return exlog_errf(e, EXLOG_OS, errno,
		    "%s: failed to read fs_info", __func__);

	if (r < sizeof(fs_info))
		return exlog_errf(e, EXLOG_OS, EXLOG_EIO,
		    "%s: short read on fs_info", __func__);

	close(fd);
	return 0;
}
