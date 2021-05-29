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

#ifndef CONFIG_H
#define CONFIG_H

#include <sys/time.h>
#include <sys/resource.h>
#include <stdint.h>

#define PROGNAME     "PotatoFS"
#define MGR_PROGNAME "potatomgr"

#define FS_DEFAULT_ENTRY_TIMEOUTS 120
#define FS_DEFAULT_DATA_PATH      "/var/potatofs"
#define COUNTERS_FILE_NAME        "counters"
#define MGR_DEFAULT_PIDFILE_PATH  "/var/potatofs/potatomgr.pid"
#define MGR_DEFAULT_SOCKET_PATH   "/var/potatofs/potatomgr.sock"
#define MGR_DEFAULT_UNPRIV_USER   "potatomgr"
#define MGR_DEFAULT_UNPRIV_GROUP  "potatomgr"
#define MGR_DEFAULT_BACKEND_EXEC  "/usr/local/bin/mgr.pl"
#define DEFAULT_CONFIG_PATH       "/etc/potatofs.conf"

#define ITBL_DIR      "itbl"
#define ITBL_PREFIX   "i"
#define SLAB_PREFIX   "b"
#define SLAB_DIRS     256
#define FS_ROOT_INODE 1

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
 * After the max age is reached, slabs are closed even to provide a chance
 * to copy/sync them to the slow backend. The cache size is how many slabs
 * we're allowing to live in our local cache. This should match the size
 * of the filesystem where we store the slabs. This also sets a limit on
 * how many file descriptors we need to keep all local slabs open at once.
 */
#define SLAB_MAX_AGE_DEFAULT    60
#define SLAB_CACHE_SIZE_DEFAULT 10737418240

/* This should fit in most default ulimits and leave extra room. */
#define SLAB_MAX_OPEN_DEFAULT   768

#define FS_PATH_MAX 4096
#define FS_NAME_MAX  255
#define FS_LINK_MAX  127

/*
 * This is needed for header files we snatched from OpenBSD, like tree.h.
 * See OpenBSD's src/sys/sys/cdefs.h for how they usually assign those.
 */
#define __inline inline
#define __unused __attribute__((__unused__))

struct fs_config {
	uid_t       uid;
	gid_t       gid;
	char       *dbg;
	uint64_t    cache_size;
	rlim_t      max_open_slabs;
	uint32_t    entry_timeouts;
	uint32_t    slab_max_age;
	size_t      slab_size;
	const char *data_dir;
	int         noatime;
	const char *mgr_sock_path;
	const char *mgr_exec;
	const char *cfg_path;
};

extern struct fs_config fs_config;

void config_read();

#endif
