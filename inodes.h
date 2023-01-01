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

#ifndef INODES_H
#define INODES_H

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include "openfiles.h"
#include "xlog.h"
#include "slabs.h"

/*
 * For performance, we size inodes to be equal to FS_BLOCK_SIZE.
 * This also leaves almost 4k bytes for the beginning of the file or directory,
 * which can be held directly in the inode, and therefore in the inode table.
 * For a filesystem containing lots of small files, this can save us a lot
 * time by avoiding having to pull many slabs from the backend.
 */
struct inode {
	union {
		struct {
			/*
			 * Increment the SLAB_VERSION (slabs.h) definition
			 * anytime we modify this structure, including
			 * changing how many bytes can be stored inline
			 * through the INODE_INLINE_BYTES macro below.
			 */
			dev_t           dev;
			ino_t           inode;
			mode_t          mode;
			nlink_t         nlink;
			uid_t           uid;
			gid_t           gid;
			dev_t           rdev;
			unsigned long   generation;
			struct timespec atime;
			struct timespec ctime;
			struct timespec mtime;
			/*
			 * Keep size and data last and in this order,
			 * since when flushing inodes we flush both
			 * together with a single write.
			 */
			off_t           size;
			blkcnt_t        blocks;  // 512B
		} f;
		struct {
			/*
			 * The inode_fields size must be large enough to
			 * be able to hold the "f" structure above a be
			 * a multiple of DEV_BSIZE (the device fragment size).
			 * The remaining space is used to store the inode's
			 * inline data.
			 */
			char inode_fields[DEV_BSIZE];
			char inline_data[FS_BLOCK_SIZE - DEV_BSIZE];
		} padding;
	} v;
#define INODE_INLINE_BYTES (sizeof((struct inode *)NULL)->v.padding.inline_data)

#define INODE_ATTR_MODE  (1 << 0)
#define INODE_ATTR_UID   (1 << 1)
#define INODE_ATTR_GID   (1 << 2)
#define INODE_ATTR_SIZE  (1 << 3)
#define INODE_ATTR_ATIME (1 << 4)
#define INODE_ATTR_MTIME (1 << 5)
#define INODE_ATTR_CTIME (1 << 6)
};

struct oinode {
	/* refcnt and entry are protected by the open_inodes lock. */
	SPLAY_ENTRY(oinode)  entry;
	uint64_t             refcnt;

	/*
	 * Used to protect all remaining fields in this structure, with the
	 * exception of inline inode bytes.
	 */
	rwlk                 lock;
	int                  dirty;

	/*
	 * From FUSE, the nlookup count is incremented on every call to
	 * fuse_reply_entry() or fuse_reply_create(). We keep track of it here.
	 */
	unsigned long        nlookup;

	/*
	 * The bytes_dirty field is set to 1 when either the size or blocks
	 * fields, or inline inode data is modified. It doesn't care about
	 * modified slabs.
	 *
	 * It is necessary to have different locks & dirty flags for
	 * bytes and other inode fields because when manipulating directories
	 * it may be necessary to flush directory data _before_ adjusting
	 * nlink.
	 *
	 * The bytes lock is primarily used to prevent races between
	 * write and truncate. It protects bytes_dirty, ino.v.f.size and
	 * ino.v.f.blocks.
	 * It must always be acquired inside the regular lock above.
	 * Reads and writes to inodes only require the inode read lock
	 * since nothing but those two variables are changing (as well
	 * as inline bytes and disk bytes, which are not protected at all).
	 */
	rwlk                 bytes_lock;
	int                  bytes_dirty;
	struct inode         ino;

	/*
	 * The inode table slab in which we are stored.
	 */
	struct oslab        *itbl;

	uint32_t             oflags;
#define INODE_OSYNC    0x00000001
#define INODE_ORO      0x00000002
#define INODE_NOCREATE 0x00000004
};

struct inode_splice_buf {
	size_t        count;
	void         *buf;

	/*
	 * fd is used if *buf is NULL. We keep track of *b so we can
	 * forget it once we're done. rel_offset is so we can seek in
	 * the fd.
	 */
	struct oslab *b;
	int           fd;
	off_t         rel_offset;
};

struct inode_splice_bufvec {
	/* Starting logical offset in the inode */
	off_t                    offset;
	size_t                   nv;
	struct inode_splice_buf *v;
	struct oinode           *oi;
};

/*
 * No locks acquired; static result.
 */
char *inode_data(struct inode *);

/*
 * Only acquires slab locks. The inode isn't actually loaded at any point.
 * Only the inode table bitmap is updated.
 */
int inode_dealloc(ino_t, struct xerr *);

/* The inode lock is public, as opposed to the bytes_lock. */
void inode_lock(struct oinode *, rwlk_flags);
void inode_unlock(struct oinode *);

/*
 * inode_unload() must be called once for every call to inode_load(),
 * as we keep track of how many times it is referenced. Note that
 * inode_unload() will call inode_flush() when the refcnt is 0.
 */
struct oinode *inode_create(ino_t, uint32_t, uid_t, gid_t, mode_t,
                   struct xerr *);
struct oinode *inode_load(ino_t, uint32_t, struct xerr *);
int            inode_unload(struct oinode *, struct xerr *);

/*
 * Those need the inode read lock and acquire the bytes_lock if
 * accessing or modifying bytes_dirty or the inode's size. The inode read lock
 * prevents truncate/fallocate from conflicting with those calls. Since
 * reads/writes can happen concurrently with the read lock, we need another,
 * more fine-grained lock to protect bytes_dirty and the inode size.
 */
ssize_t inode_write(struct oinode *, off_t, const void *,
            size_t, struct xerr *);
ssize_t inode_read(struct oinode *, off_t, void *, size_t, struct xerr *);
int     inode_splice_begin_write(struct inode_splice_bufvec *, struct oinode *,
            off_t, size_t, struct xerr *);
int     inode_splice_end_write(struct inode_splice_bufvec *, size_t,
            struct xerr *);
int     inode_splice_begin_read(struct inode_splice_bufvec *, struct oinode *,
            off_t, size_t, struct xerr *);
void    inode_stat(struct oinode *, struct stat *);
void    inode_cp_stat(struct stat *, const struct inode *);
int     inode_isdir(struct oinode *);
ino_t   inode_ino(struct oinode *);

/*
 * No locks needed; they either acquire only the bytes lock or only
 * deal with slabs.
 */
int     inode_splice_end_read(struct inode_splice_bufvec *, struct xerr *);
off_t   inode_getsize(struct oinode *);
void    inode_shutdown();
int     inode_startup();

/*
 * The following must be called in inode write-lock context.
 */
int     inode_truncate(struct oinode *, off_t, struct xerr *);
int     inode_fallocate(struct oinode *, off_t, off_t, int, struct xerr *);
int     inode_setattr(struct oinode *, struct stat *, uint32_t, struct xerr *);
int     inode_sync(struct oinode *, struct xerr *);
int     inode_flush(struct oinode *, uint8_t, struct xerr *);
#define INODE_FLUSH_DATA_ONLY 0x01
#define INODE_FLUSH_RELEASE   0x02

/*
 * The following must be called with the inode write-lock held, or
 * read-lock if the second argument is zero.
 */
nlink_t       inode_nlink(struct oinode *, int);
unsigned long inode_nlookup(struct oinode *, int);

/* The following place a write lock on the inode. */
int  inode_nlookup_ino(ino_t, int, struct xerr *);
int  inode_nlink_ino(ino_t, int, struct xerr *);

/* For testing only; no locks acquired */
int inode_inspect(int, ino_t, struct inode *, struct xerr *);
int inode_disk_inspect(ino_t, struct inode *, struct xerr *);

#endif
