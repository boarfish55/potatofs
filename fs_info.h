/*
 *  Copyright (C) 2020 Pascal Lalonde <plalonde@overnet.ca>
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
#include "exlog.h"
#include "util.h"

struct fs_info {
	uuid_t         instance_id;
	struct statvfs stats;
	size_t         slab_size;

	/*
	 * Filesystem was shutdown cleanly; if zero at startup, error
	 * below should be set to 1.
	 */
	uint8_t        clean;

	/* Filesystem encountered errors and needs fsck */
	uint8_t        error;
};

int     fs_info_init(struct fs_info *, const char *, size_t, struct exlog_err *);
int     fs_info_get(struct fs_info *, struct exlog_err *);
void    fs_info_set_error();
uint8_t fs_info_error();
int     fs_info_shutdown(int, struct exlog_err *);
int     fs_info_inspect(struct fs_info *, struct exlog_err *);

#endif
