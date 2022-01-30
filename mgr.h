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

#ifndef MGR_H
#define MGR_H

#include <sys/statvfs.h>
#include <stdint.h>
#include "fs_info.h"
#include "exlog.h"

struct mgr_msg {
	enum {
		MGR_MSG_CLAIM = 1,
		MGR_MSG_CLAIM_OK,
		MGR_MSG_CLAIM_NOENT,
		MGR_MSG_CLAIM_ERR,

		MGR_MSG_UNCLAIM,
		MGR_MSG_UNCLAIM_OK,
		MGR_MSG_UNCLAIM_ERR,

		MGR_MSG_SET_FS_ERROR,
		MGR_MSG_SET_FS_ERROR_OK,
		MGR_MSG_SET_FS_ERROR_ERR,

		MGR_MSG_FS_INFO,
		MGR_MSG_FS_INFO_OK,
		MGR_MSG_FS_INFO_ERR,

		MGR_MSG_CLAIM_NEXT_ITBL,
		MGR_MSG_CLAIM_NEXT_ITBL_OK,
		MGR_MSG_CLAIM_NEXT_ITBL_END,
		MGR_MSG_CLAIM_NEXT_ITBL_ERR
	} m;

	union {
		struct {
			uint32_t flags;
			uint32_t oflags;

			/*
			 * If SLAB_ITBL is set in flags, ino will be used to
			 * select which inode table to claim, offset will be
			 * unused.
			 */
			ino_t    ino;
			off_t    offset;
		} claim;

		struct {
			ino_t    ino;
			off_t    offset;
		} unclaim;

		struct fs_info fs_info;

		uint8_t        fs_error;

		struct {
			ino_t    ino;
			uint32_t oflags;
		} claim_next_itbl;
	} v;
};

void mgr_init(const char *);
int  mgr_connect(struct exlog_err *);
int  mgr_recv(int, int *, struct mgr_msg *, struct exlog_err *);
int  mgr_send(int, int, struct mgr_msg *, struct exlog_err *);

#endif
