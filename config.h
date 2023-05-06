/*
 *  Copyright (C) 2020-2023 Pascal Lalonde <plalonde@overnet.ca>
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
#include <limits.h>

#define PROGNAME     "potatofs"
#define MGR_PROGNAME "potatomgr"

/*
 * Version loosely follows SemVer (semver.org). MAJOR must be updated
 * whenever:
 *   - SLAB_VERSION is incremented in slabs.h
 *   - SLABDB_VERSION is incremented in slabdb.h
 *   - a new dir inode format is introduced and defaulted to in dirinodes.h
 *     (see DIRINODE_FORMAT).
 *
 * MINOR should be updated whenever backward-compatible feature updates
 * are committed, and PATCH for any other backward-compatible change
 * (usually bug fix or minor updates that do not alter functionality).
 */
#define VERSION      "2.12.9-dev"

#define FS_DEFAULT_ENTRY_TIMEOUTS 120
#define FS_DEFAULT_DATA_DIR       "/var/potatofs/data"

#define DEFAULT_CONFIG_PATH       "/etc/potatofs.conf"
#define DEFAULT_DB_NAME           "slabs.db"

#define MGR_DEFAULT_PIDFILE_PATH      "/var/potatofs/potatomgr.pid"
#define MGR_DEFAULT_SOCKET_PATH       "/var/potatofs/potatomgr.sock"
#define MGR_DEFAULT_UNPRIV_USER       "potatomgr"
#define MGR_DEFAULT_UNPRIV_GROUP      "potatomgr"
#define MGR_DEFAULT_BACKEND_EXEC      "/usr/local/bin/potato_backend.sh"
#define MGR_DEFAULT_WORKERS           12
#define MGR_DEFAULT_BGWORKERS         1
#define MGR_DEFAULT_PURGER_INTERVAL   30
#define MGR_DEFAULT_SCRUBBER_INTERVAL 3600
#define MGR_DEFAULT_DF_INTERVAL       60

#define ITBL_DIR      "itbl"
#define ITBL_PREFIX   "i"
#define OUTGOING_DIR  "outgoing"
#define INCOMING_DIR  "incoming"
#define SLAB_PREFIX   "b"
#define SLAB_DIRS     256
#define FS_ROOT_INODE 1

/*
 * Hard deadline for all backend operations. If it is expected that calls
 * to the backend might take longer than those values, the relevant timeouts
 * must be increased.
 *
 * If we receive an INTERRUPT from FUSE, we could be blocked for as long
 * as the duration of the GET timeout before sending back EINTR. With no
 * interrupt from FUSE, the GET operation will be retried indefinitely.
 */
#define DEFAULT_BACKEND_GET_TIMEOUT  15
#define DEFAULT_BACKEND_PUT_TIMEOUT  60
#define DEFAULT_BACKEND_DF_TIMEOUT   30
#define DEFAULT_BACKEND_HINT_TIMEOUT 30

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
 * The block size is used for block headers and inode table headers. It's the
 * file I/O size used when potatofs is dealing with its own metadata. This
 * shouldn't be changed without careful testing. It's closely related to the
 * SLAB_SIZE_* definitions below. See also slabs.h and inodes.h.
 */
#define FS_BLOCK_SIZE 4096

/*
 * Must be a power of two between SLAB_SIZE_FLOOR and SLAB_SIZE_CEIL
 * inclusively. We assume 8MB to be reasonble size when uploading and
 * downloading from the backend, resulting in a wait of a few seconds at
 * most.
 */
#define SLAB_SIZE_DEFAULT (1024 * 1024 * 8)

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
	char     *cfg_path;
	char      log_file_path[PATH_MAX];
	uid_t     uid;
	gid_t     gid;
	char      dbg[LINE_MAX];
	rlim_t    max_open_slabs;
	uint32_t  entry_timeouts;
	uint64_t  slab_max_age;
	size_t    slab_size;
	char      data_dir[PATH_MAX];
	int       noatime;
	char      mgr_sock_path[PATH_MAX];
	char      pidfile_path[PATH_MAX];
	char      mgr_exec[PATH_MAX];
	char      mgr_exec_config[PATH_MAX];
	char      unpriv_user[32];
	char      unpriv_group[32];
	int       workers;
	int       bgworkers;
	int       purger_interval;
	int       scrubber_interval;
	int       df_interval;
	uint64_t  unclaim_purge_threshold_pct;
	uint64_t  purge_threshold_pct;
	uint64_t  backend_get_timeout;
	uint64_t  backend_put_timeout;
	uint64_t  backend_df_timeout;
	uint64_t  backend_hint_timeout;
	time_t    shutdown_grace_period;
};

extern struct fs_config fs_config;

void config_read();

#endif
