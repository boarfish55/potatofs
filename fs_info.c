/*
 *  Copyright (C) 2020-2024 Pascal Lalonde <plalonde@overnet.ca>
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
#include "xlog.h"
#include "util.h"

const char *potatofs_stat_path = "stats";

int
fs_info_open(struct fs_info *dst_info, struct xerr *e)
{
	int            fd = -1;
	ssize_t        r;
	char           path[PATH_MAX];
	struct fs_info fs_info;

	if (fs_config.slab_size < SLAB_SIZE_FLOOR ||
	    fs_config.slab_size > SLAB_SIZE_CEIL ||
	    (fs_config.slab_size & (fs_config.slab_size - 1)) != 0)
		return XERRF(e, XLOG_APP, XLOG_INVAL,
		    "slab_size must be a power of two, between %lu and %lu",
		    SLAB_SIZE_FLOOR, SLAB_SIZE_CEIL);

	if (snprintf(path, sizeof(path), "%s/%s", fs_config.data_dir,
	    potatofs_stat_path) >= sizeof(path)) {
		XERRF(e, XLOG_APP, XLOG_NAMETOOLONG,
		    "failed to statvfs file; too long");
		goto end;
	}

	if ((fd = open_wflock(path, O_CREAT|O_RDWR, 0600, LOCK_EX, 0)) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "open_wflock");
		goto end;
	}

	if ((r = pread_x(fd, &fs_info, sizeof(fs_info), 0)) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "fs stat cannot be read");
		goto end;
	}

	if (r == 0) {
		bzero(&fs_info, sizeof(fs_info));

		fs_info.slab_size = fs_config.slab_size;
		uuid_generate(fs_info.instance_id);
		fs_info.clean = 1;

		fs_info.fs_info_version = FS_INFO_VERSION;
		fs_info.stats.f_bsize = FS_BLOCK_SIZE;
		fs_info.stats.f_frsize = FS_BLOCK_SIZE;

		fs_info.stats.f_blocks = 0;
		fs_info.stats.f_bfree = 0;
		fs_info.stats.f_bavail = 0;

		/*
		 * We use the number of inodes to instead track
		 * how many slabs we have allocated in our filesystem.
		 */
		fs_info.stats.f_files = 0;
		fs_info.stats.f_ffree = 0;
		fs_info.stats.f_favail = 0;

		fs_info.stats.f_fsid = 1;
		fs_info.stats.f_flag = 0;
		fs_info.stats.f_namemax = FS_NAME_MAX;
	} else if (r < sizeof(fs_info)) {
		XERRF(e, XLOG_APP, XLOG_MISMATCH,
		    "structure size mismatch; incompatible version?");
		goto end;
	}

	if (fs_info.clean != 1)
		fs_info.error = 1;
	fs_info.clean = 0;

	if ((r = pwrite_x(fd, &fs_info, sizeof(fs_info), 0))
	    < sizeof(fs_info)) {
		XERRF(e, XLOG_APP, XLOG_IO,
		    "failed to write potatofs_fs_info structure; "
		    "write() returned %d instead of %d:", r, sizeof(fs_info));
		goto end;
	}
	if (dst_info != NULL)
		memcpy(dst_info, &fs_info, sizeof(fs_info));
end:
	if (fd > 0)
		CLOSE_X(fd);
	return xerr_fail(e);
}

int
fs_info_read(struct fs_info *fs_info, struct xerr *e)
{
	int     fd = -1;
	ssize_t r;
	char    path[PATH_MAX];

	if (snprintf(path, sizeof(path), "%s/%s", fs_config.data_dir,
	    potatofs_stat_path) >= sizeof(path)) {
		XERRF(e, XLOG_APP, XLOG_NAMETOOLONG,
		    "failed to statvfs file; too long");
		goto end;
	}

	if ((fd = open_wflock(path, O_RDONLY, 0, LOCK_SH, 0)) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "open_wflock");
		goto end;
	}

	if ((r = read_x(fd, fs_info, sizeof(struct fs_info))) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "fs stat cannot be read");
		goto end;
	}

	if (r < sizeof(struct fs_info)) {
		XERRF(e, XLOG_APP, XLOG_MISMATCH,
		    "fs_info structure size mismatch; "
		    "incompatible version?");
		goto end;
	}

	if (fs_info->fs_info_version != FS_INFO_VERSION) {
		XERRF(e, XLOG_APP, XLOG_MISMATCH,
		    "fs_info structure version mismatch; "
		    "incompatible version?");
		goto end;
	}
end:
	if (fd > 0)
		CLOSE_X(fd);
	return xerr_fail(e);
}

int
fs_info_write(const struct fs_info *fs_info, struct xerr *e)
{
	int            fd = -1;
	ssize_t        r;
	char           path[PATH_MAX];

	if (snprintf(path, sizeof(path), "%s/%s", fs_config.data_dir,
	    potatofs_stat_path) >= sizeof(path)) {
		XERRF(e, XLOG_APP, XLOG_NAMETOOLONG,
		    "failed to statvfs file; too long");
		return -1;
	}

	if ((fd = open_wflock(path, O_RDWR, 0, LOCK_EX, 0)) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "open_wflock");
		goto end;
	}

	if ((r = write_x(fd, fs_info, sizeof(struct fs_info))) <
	    sizeof(struct fs_info)) {
		XERRF(e, XLOG_APP, XLOG_IO,
		    "failed to write potatofs_fs_info structure; "
		    "write() returned %d instead of %d:", r, sizeof(fs_info));
	}
end:
	if (fd > 0)
		CLOSE_X(fd);

	return xerr_fail(e);
}

int
fs_info_inspect(struct fs_info *fs, struct xerr *e)
{
	char    path[PATH_MAX];
	int     fd;
	ssize_t r;

	if (snprintf(path, sizeof(path), "%s/%s",
	    fs_config.data_dir, potatofs_stat_path) >= sizeof(path))
		return XERRF(e, XLOG_ERRNO, XLOG_NAMETOOLONG,
		    "potatofs base path too long");

	if ((fd = open_wflock(path, O_RDONLY, 0, LOCK_SH, 0)) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "open_wflock()");

	if ((r = read(fd, fs, sizeof(struct fs_info))) == -1) {
		CLOSE_X(fd);
		return XERRF(e, XLOG_ERRNO, errno, "failed to read fs_info");
	}

	CLOSE_X(fd);

	if (r < sizeof(struct fs_info))
		return XERRF(e, XLOG_ERRNO, XLOG_IO,
		    "short read on fs_info");

	return 0;
}
