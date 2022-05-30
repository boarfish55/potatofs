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
#include "counters.h"
#include "fs_info.h"
#include "xlog.h"
#include "slabs.h"

struct mgr_msg {
	enum {
		MGR_MSG_CLAIM = 1,
		MGR_MSG_CLAIM_OK,
		MGR_MSG_CLAIM_NOENT,
		MGR_MSG_CLAIM_ERR,

		MGR_MSG_TRUNCATE,
		MGR_MSG_TRUNCATE_OK,
		MGR_MSG_TRUNCATE_NOENT,
		MGR_MSG_TRUNCATE_ERR,

		MGR_MSG_UNCLAIM,
		MGR_MSG_UNCLAIM_OK,
		MGR_MSG_UNCLAIM_ERR,

		MGR_MSG_SET_FS_ERROR,
		MGR_MSG_SET_FS_ERROR_OK,
		MGR_MSG_SET_FS_ERROR_ERR,

		MGR_MSG_INFO,
		MGR_MSG_INFO_OK,
		MGR_MSG_INFO_ERR,

		MGR_MSG_SHUTDOWN,
		MGR_MSG_SHUTDOWN_OK,
		MGR_MSG_SHUTDOWN_ERR,

		MGR_MSG_SND_COUNTERS,
		MGR_MSG_SND_COUNTERS_OK,
		MGR_MSG_SND_COUNTERS_ERR,

		MGR_MSG_RCV_COUNTERS,
		MGR_MSG_RCV_COUNTERS_OK,
		MGR_MSG_RCV_COUNTERS_ERR,

		// TODO ...
		MGR_MSG_SCRUB,
		MGR_MSG_SCRUB_OK,
		MGR_MSG_SCRUB_ERR,

		MGR_MSG_CLAIM_NEXT_ITBL,
		MGR_MSG_CLAIM_NEXT_ITBL_OK,
		MGR_MSG_CLAIM_NEXT_ITBL_END,
		MGR_MSG_CLAIM_NEXT_ITBL_ERR
	} m;

	union {
		struct {
			struct slab_key key;
			uint32_t        oflags;
			// TODO: support "nowait" when claiming to simply
			// return when someone already has the slab claimed.
			uint8_t         claim_flags;
#define MGR_CLAIM_NOWAIT 0x01
		} claim;

		struct {
			struct slab_key key;
		} unclaim;

		struct {
			struct slab_key key;
			off_t           offset;
		} truncate;

		struct {
			pid_t          mgr_pid;
			char           version_string[16];
			struct fs_info fs_info;
		} info;

		uint8_t fs_error;

		struct {
			ino_t    base;
			uint32_t oflags;
		} claim_next_itbl;

		struct {
			uint64_t c[COUNTER_LAST];
		} snd_counters;

		struct {
			uint64_t c[COUNTER_LAST];
			uint64_t mgr_c[MGR_COUNTER_LAST];
		} rcv_counters;

		struct {
			time_t grace_period;
		} shutdown;

		struct xerr err;
	} v;
};

void mgr_init(const char *);
int  mgr_connect(int, struct xerr *);
int  mgr_recv(int, int *, struct mgr_msg *, struct xerr *);
int  mgr_send(int, int, struct mgr_msg *, struct xerr *);

/* Helpers */
int  mgr_send_shutdown(struct xerr *);
int  mgr_fs_info(struct fs_info *, struct xerr *);

#endif
