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

#ifndef CONFIG_H
#define CONFIG_H

#include <sys/time.h>
#include <sys/resource.h>
#include <stdint.h>

#define PROGNAME     "PotatoFS"
#define MGR_PROGNAME "potatomgr"

#define FS_DEFAULT_ENTRY_TIMEOUTS 120
#define FS_DEFAULT_DATA_PATH      "/var/potatofs"
#define MGR_DEFAULT_PIDFILE_PATH  "/var/potatofs/potatomgr.pid"
#define MGR_DEFAULT_SOCKET_PATH   "/var/potatofs/potatomgr.sock"
#define MGR_DEFAULT_UNPRIV_USER   "potatomgr"
#define MGR_DEFAULT_UNPRIV_GROUP  "potatomgr"
#define MGR_DEFAULT_BACKEND_EXEC  "/usr/local/bin/mgr.pl"
#define DEFAULT_CONFIG_PATH       "/etc/potatofs.conf"
#define DEFAULT_MDB_NAME          "slabs.mdb"

/*
 * This is the maximum size of the slabdb. This size divided by
 * the size of the slab_key + slab_val structures limits the
 * total number of slabs that can exist in the entire filesystem.
 */
#define DEFAULT_MDB_MAPSIZE 67108864

#define ITBL_DIR      "itbl"
#define ITBL_PREFIX   "i"
#define OUTGOING_DIR  "outgoing"
#define INCOMING_DIR  "incoming"
#define SLAB_PREFIX   "b"
#define SLAB_DIRS     256
#define FS_ROOT_INODE 1

#define BACKEND_TIMEOUT_SECONDS 30

/*
 * When unclaiming a slab, if the local cache utilization is over this
 * percentage, purge that slab after sending it to outgoing.
 */
#define DEFAULT_UNCLAIM_PURGE_PCT 90
/*
 * The background purge process will purge slabs, starting with the least
 * recently claimed (see last_claimed_at header attribute), until local
 * cache utilization falls under this percentage.
 */
#define DEFAULT_PURGE_PCT         60

/*
 * The block size is used for block headers and inode table headers.
 * It's the file I/O size used when potatofs is dealing with its own metadata.
 */
#define FS_BLOCK_SIZE 4096

/*
 * Upper/lower bounds on the configured slab size. Must a power of two and
 * no larger than 64 megabytes. Other values might work but require
 * reviewing some of the math in the other structures. A few things to
 * consider:
 *   - The inode table header, which contains a bitmap of all blocks
 *     in a slab, has to fit in the 'data' space left in the slab header,
 *     which is (FS_BLOCK_SIZE - slab header size).
 *   - ...
 */
#define SLAB_SIZE_FLOOR         1048576
#define SLAB_SIZE_CEIL          (1048576 * 64)
#define SLAB_SIZE_DEFAULT       (1048576 * 8)

/*
 * After the max age is reached, slabs are closed to give a chance
 * to copy/sync them to the slow backend.
 */
#define SLAB_MAX_AGE_DEFAULT    300

/* This should fit in most default ulimits and leave extra room. */
#define SLAB_MAX_OPEN_DEFAULT   768

#define FS_PATH_MAX 4096
#define FS_NAME_MAX  255
#define FS_LINK_MAX  127

struct fs_config {
	uid_t       uid;
	gid_t       gid;
	char       *dbg;
	rlim_t      max_open_slabs;
	uint32_t    entry_timeouts;
	uint32_t    slab_max_age;
	size_t      slab_size;
	const char *data_dir;
	int         noatime;
	const char *mgr_sock_path;
	const char *mgr_exec;
	const char *cfg_path;
	size_t      mdb_map_size;
	uint32_t    unclaim_purge_threshold_pct;
	uint32_t    purge_threshold_pct;
};

extern struct fs_config fs_config;

void config_read();

#endif
