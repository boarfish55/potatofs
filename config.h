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

#ifndef CONFIG_H
#define CONFIG_H

#define SLAB_VERSION 1

#define FS_DEFAULT_ENTRY_TIMEOUTS 120
#define FS_DEFAULT_DATA_PATH      "/var/potatofs"
#define COUNTERS_FILE_NAME        "counters"

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

#define FS_PATH_MAX 4096
#define FS_NAME_MAX  255
#define FS_LINK_MAX  127

/*
 * This is needed for header files we snatched from OpenBSD, like tree.h.
 * See OpenBSD's src/sys/sys/cdefs.h for how they usually assign those.
 */
#define __inline inline
#define __unused __attribute__((__unused__))

#endif
