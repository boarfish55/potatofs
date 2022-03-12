/*
 *  Copyright (C) 2020-2022 Pascal Lalonde <plalonde@overnet.ca>
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

#ifndef FS_INFO_H
#define FS_INFO_H

#include <sys/types.h>
#include <sys/statvfs.h>
#include <uuid/uuid.h>
#include "xlog.h"
#include "util.h"

struct fs_info {
#define FS_INFO_VERSION 1
	/* Increment the above definition anytime we modify this structure. */
	uint32_t        fs_info_version;

	uuid_t          instance_id;
	size_t          slab_size;

	/*
	 * Note that we use the f_files, f_ffree and f_favail fields
	 * to track how many entries are available in the slabdb.
	 * This essentially tells us how many slabs the filesystem can
	 * hold globally.
	 */
	struct statvfs  stats;
	struct timespec stats_last_update;

	/*
	 * Filesystem was shutdown cleanly; if zero at startup, error
	 * below should be set to 1.
	 */
	uint8_t         clean;

	/* Filesystem encountered errors and needs fsck */
	uint8_t         error;
};

int fs_info_open(struct fs_info *, struct xerr *);
int fs_info_read(struct fs_info *, struct xerr *);
int fs_info_write(const struct fs_info *, struct xerr *);
int fs_info_inspect(struct fs_info *, struct xerr *);

#endif
