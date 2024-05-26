/*
 *  Copyright (C) 2020-2024 Pascal Lalonde <plalonde@overnet.ca>
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

#ifndef DIRINODES_H
#define DIRINODES_H

#include <sys/param.h>
#include "config.h"
#include "inodes.h"
#include "xlog.h"

struct dir_hdr {
#define DIRINODE_FORMAT 2
	uint32_t dirinode_format;
};

struct dir_hdr_v2 {
	union {
		struct {
			struct dir_hdr hdr;
			ino_t          inode;
			ino_t          parent;
			off_t          free_list_start;
		} h;
		char padding[DEV_BSIZE];
	} v;
};

struct dir_entry {
	char   name[FS_NAME_MAX + 1];
	ino_t  inode;
	/*
	 * When entries are returned by di_readdir(), the position in
	 * the dir entry "stream" will be saved here. This could be used
	 * by callers in telldir() / seekdir().
	 */
	off_t  d_off;
};

struct dir_entry_v1 {
	char   name[FS_NAME_MAX + 1];
	ino_t  inode;
	/* Indicates the next free entry in the file */
	off_t  next;
};

/*
 * The structure is actually serialized before going to disk, unaligned,
 * with only as many bytes as needed to store the name.
 * This is our in-memory struct.
 */
struct dir_entry_v2 {
#define DI_ALLOCATED 0x01
	uint8_t     flags;
	uint32_t    hash;
	ino_t       inode;
	uint8_t     length;
	const char *name;
};
#define DI_DE_PACK_HDR_SZ \
    (sizeof(uint8_t) +    \
     sizeof(uint32_t) +   \
     sizeof(ino_t) +      \
     sizeof(uint8_t))

/*
 * Directory blocks are always DEV_BSIZE bytes. A block is either a leaf or an
 * index (hash table). Hash table entries point to child
 * blocks. Our hash is 32 bits, so each block handles 5 bits of the hash,
 * meaning our tree has a max depth of 6 (6 x 5 = 30 bits).
 *
 * The dir_block_idx_v2 is standalone because it could also be used in
 * the inline inode data, which doesn't allow space for a full fs block size.
 *
 */
#define DI_BLOCK_V2_MAX_DEPTH 6

struct dir_block_v2 {
#define DI_BLOCK_ALLOCATED  0x01
#define DI_BLOCK_LEAF       0x02
	union {
		/*
		 * flags must remain the first field in both
		 * structs, since this is what we use to determine
		 * which one to use.
		 */
		uint8_t flags;
		struct {
			uint8_t  flags;
			off_t    buckets[32];
		} idx;
		struct {
			uint8_t  flags;

			/* How many items in this leaf */
			size_t   entries;

			/* How many bytes are used in the leaf */
			uint16_t length;

			/*
			 * Offset of next leaf when we're at our max
			 * tree depth.
			 */
			off_t    next;

			/* This must be the last field in this struct */
			char     data[1];
		} leaf;
		char padding[DEV_BSIZE];
	} v;
};
#define DI_DIR_BLOCK_HDR_V2_BYTES \
    (sizeof(struct dir_block_v2) - \
    ((size_t)&(((struct dir_block_v2 *)NULL)->v.leaf.data)))

ssize_t  di_pack_v2(char *, size_t, const struct dir_entry_v2 *);
ssize_t  di_unpack_v2(const char *, size_t, struct dir_entry_v2 *);
uint32_t di_fnv1a32(const void *, size_t);

/*
 * None of these acquire the inode lock. Because directories are
 * sensitive to ordering, the inode write-lock must be acquired for all
 * the following.
 */
int     di_create(struct oinode *, ino_t, struct xerr *);
int     di_mkdirent(struct oinode *, const struct dir_entry *, int,
            struct xerr *);
int     di_unlink(struct oinode *, const struct dir_entry *, struct xerr *);
int     di_setparent(struct oinode *, ino_t, struct xerr *);

/*
 * The following must be called with at least the inode read-lock held.
 */
int     di_stat(struct oinode *, struct stat *, struct xerr *);
int     di_isempty(struct oinode *, struct xerr *);
ino_t   di_parent(struct oinode *, struct xerr *);
ssize_t di_readdir(struct oinode *, struct dir_entry *, off_t, size_t,
            struct xerr *);
int     di_lookup(struct oinode *, struct dir_entry *, const char *,
            struct xerr *);

#endif
