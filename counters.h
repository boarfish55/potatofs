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

#ifndef COUNTERS_H
#define COUNTERS_H

#include <pthread.h>
#include <stdint.h>
#include "xlog.h"

enum {
	COUNTER_FS_GETATTR = 0,
	COUNTER_FS_SETATTR,
	COUNTER_FS_OPENDIR,
	COUNTER_FS_READDIR,
	COUNTER_FS_RELEASEDIR,
	COUNTER_FS_RELEASE,
	COUNTER_FS_OPEN,
	COUNTER_FS_READ,
	COUNTER_FS_WRITE,
	COUNTER_FS_FLUSH,
	COUNTER_FS_FORGET,
	COUNTER_FS_FORGET_MULTI,
	COUNTER_FS_LOOKUP,
	COUNTER_FS_MKDIR,
	COUNTER_FS_RMDIR,
	COUNTER_FS_UNLINK,
	COUNTER_FS_STATFS,
	COUNTER_FS_MKNOD,
	COUNTER_FS_CREATE,
	COUNTER_FS_FALLOCATE,
	COUNTER_FS_FSYNC,
	COUNTER_FS_FSYNCDIR,
	COUNTER_FS_LINK,
	COUNTER_FS_SYMLINK,
	COUNTER_FS_READLINK,
	COUNTER_FS_RENAME,
	COUNTER_FS_ERROR,
	COUNTER_N_OPEN_SLABS,
	COUNTER_N_OPEN_INODES,
	COUNTER_SLABS_PURGED,
	COUNTER_READ_BYTES,
	COUNTER_WRITE_BYTES,
	COUNTER_LAST
};

enum {
	/* The following exist on the mgr daemon only */
	MGR_COUNTER_BACKEND_IN_BYTES = 0,
	MGR_COUNTER_BACKEND_OUT_BYTES,
	MGR_COUNTER_SLABS_PURGED,
	MGR_COUNTER_LAST
};

struct counter {
	pthread_mutex_t  mtx;
	uint64_t         count;
};

int      counter_init(struct xerr *);
void     counter_incr(int);
void     counter_add(int, uint64_t);
void     counter_decr(int);
void     counter_reset(int);
uint64_t counter_get(int);
int      counter_shutdown(struct xerr *);

#endif
