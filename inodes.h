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

#ifndef INODES_H
#define INODES_H

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
			 * anytime we modify this structure.
			 */
			dev_t           dev;
			ino_t           inode;
			mode_t          mode;
			nlink_t         nlink;
			uid_t           uid;
			gid_t           gid;
			dev_t           rdev;
			blkcnt_t        blocks;  // 512B
			unsigned long   generation;
			struct timespec atime;
			struct timespec ctime;
			struct timespec mtime;
			/*
			 * Keep size and data close by,
			 * since they use the same lock.
			 */
			off_t           size;

			/*
			 * We can fit up to what's left of the full
			 * block size in 'data'. This field must be the
			 * last in this struct, as it will use space
			 * from of the padding.
			 */
			char            data[1];
		} f;
		char padding[FS_BLOCK_SIZE];
	} v;
#define INODE_ATTR_MODE  (1 << 0)
#define INODE_ATTR_UID   (1 << 1)
#define INODE_ATTR_GID   (1 << 2)
#define INODE_ATTR_SIZE  (1 << 3)
#define INODE_ATTR_ATIME (1 << 4)
#define INODE_ATTR_MTIME (1 << 5)
#define INODE_ATTR_CTIME (1 << 6)
};

struct oinode {
	SPLAY_ENTRY(oinode)  entry;

	struct inode         ino;

	/* refcnt may only be modified in open_inodes WRLOCK context. */
	uint64_t             refcnt;

	/*
	 * From FUSE, the nlookup count is incremented on every call to
	 * fuse_reply_entry() or fuse_reply_create(). We keep track of it here.
	 */
	unsigned long        nlookup;

	/*
	 * Used to protect the inode metadata (this structure) except
	 * inode size and the bytes_dirty field. The dirty field is
	 * set to 1 when those same fields are modified.
	 */
	rwlk                 lock;
	int                  dirty;

	/*
	 * Used to protect the bytes_dirty field and inode size. This
	 * lock must *never* be acquired before the inode lock. The
	 * bytes_dirty field is set to 1 when either the size or
	 * inline inode data is modified. It doesn't care about modified
	 * slabs.
	 */
	rwlk                 bytes_lock;
	int                  bytes_dirty;

	uint32_t             oflags;
#define INODE_OSYNC  0x00000001
#define INODE_ORO    0x00000002
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
off_t  inode_max_inline_b();
char  *inode_data(struct inode *);

/*
 * Only acquires slab locks. The inode isn't actually loaded at any point.
 */
int inode_make(ino_t, uid_t, gid_t, mode_t, struct inode *, struct xerr *);
int inode_dealloc(ino_t, struct xerr *);

/* The inode lock is public, as opposed to the bytes_lock. */
void inode_lock(struct oinode *, rwlk_flags);
void inode_unlock(struct oinode *);

/*
 * inode_unload() must be called once for every call to inode_load(),
 * as we keep track of how many times it is referenced. Note that
 * inode_unload() will call inode_flush() when the refcnt is 0.
 */
struct oinode *inode_load(ino_t, uint32_t, struct xerr *);
int            inode_unload(struct oinode *, struct xerr *);

/*
 * The following must be called with the inode write-lock. They all
 * acquire the bytes_lock internally.
 */
int inode_setattr(struct oinode *, struct stat *, uint32_t, struct xerr *);
int inode_flush(struct oinode *, int, struct xerr *);

/*
 * The following do not acquire the inode lock. It's up to the caller
 * to do so, if exclusivity is desired. They all acquire the bytes_lock
 * internally. It is safe to acquire the inode lock *before* these
 * functions acquire the bytes_lock.
 */
ssize_t inode_write(struct oinode *, off_t, const void *,
            size_t, struct xerr *);
ssize_t inode_read(struct oinode *, off_t, void *, size_t, struct xerr *);
off_t   inode_getsize(struct oinode *);
int     inode_truncate(struct oinode *, off_t, struct xerr *);
int     inode_fallocate(struct oinode *, off_t, off_t, int, struct xerr *);
int     inode_splice_begin_read(struct inode_splice_bufvec *, struct oinode *,
            off_t, size_t, struct xerr *);
int     inode_splice_end_read(struct inode_splice_bufvec *, struct xerr *);
int     inode_splice_begin_write(struct inode_splice_bufvec *, struct oinode *,
            off_t, size_t, struct xerr *);
int     inode_splice_end_write(struct inode_splice_bufvec *, size_t,
            struct xerr *);

/*
 * The following must be called with the inode write-lock held.
 */
int   inode_isdir(struct oinode *);
int   inode_sync(struct oinode *, struct xerr *);
void  inode_cp_stat(struct stat *, const struct inode *);
ino_t inode_ino(struct oinode *);

/*
 * The following must be called with the inode read-lock held.
 */
nlink_t       inode_nlink(struct oinode *, int);
unsigned long inode_nlookup(struct oinode *, int);

/* Locking calls; calls interacting on an ino_t get a lock on the inode. */
int inode_nlookup_ino(ino_t, int, struct xerr *);
int inode_nlink_ino(ino_t, int, struct xerr *);
int inode_cp_ino(ino_t, struct inode *, struct xerr *);

/* Free all remaining inodes at filesystem shutdown. No locks required. */
void inode_shutdown();
int  inode_startup();

/* For testing only, acquires no lock */
int inode_inspect(int, ino_t, struct inode *, struct xerr *);
int inode_disk_inspect(ino_t, struct inode *, struct xerr *);

#endif
