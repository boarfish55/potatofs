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

#ifndef MGR_H
#define MGR_H

#include <stdint.h>
#include "exlog.h"

struct mgr_msg {
	enum {
		MGR_MSG_CLAIM = 1,
		MGR_MSG_CLAIM_OK,
		MGR_MSG_CLAIM_NOENT,
		MGR_MSG_CLAIM_ERR,

		MGR_MSG_DISOWN,
		MGR_MSG_DISOWN_OK,
		MGR_MSG_DISOWN_ERR,

		MGR_MSG_FS_USAGE,
		MGR_MSG_FS_USAGE_OK,
		MGR_MSG_FS_USAGE_ERR
	} m;

	uint32_t flags;
	uint32_t oflags;
	/*
	 * If SLAB_ITBL is set in flags, ino will be used to
	 * select which inode table to claim, offset will be unused.
	 */
	ino_t    ino;
	off_t    offset;

	/*
	 * In "FS_USAGE" messages, "capacity" is used to record
	 * the total backend capacity, while "offset" stores
	 * the current count of bytes allocated.
	 */
	off_t    capacity;
};

void mgr_init(const char *);
int  mgr_connect(struct exlog_err *);
int  mgr_recv(int, int *, struct mgr_msg *, struct exlog_err *);
int  mgr_send(int, int, struct mgr_msg *, struct exlog_err *);

#endif
