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

#ifndef SLABS_H
#define SLABS_H

#include <sys/queue.h>
#include <sys/tree.h>
#include "config.h"
#include "openfiles.h"
#include "exlog.h"
#include "slabs.h"
#include "util.h"

/*
 * Slabs can either contain file data, inode tables or directory
 * entries. the itbl_hdr and dir_hdr fields contain things specific
 * to each when we're dealing with that type of slab, or empty otherwise.
 */
struct slab_hdr {
#define SLAB_VERSION 1
	union {
		struct slab_hdr_fields {
			/*
			 * Increment the SLAB_VERSION definition anytime we
			 * modify this structure.
			 */
			uint32_t slab_version;

			uint32_t checksum;
			uint32_t flags;

			/*
			 * This is populated by the slab manager only, after
			 * successfully claiming ownership.
			 */
			struct timespec last_claimed_at;

			/*
			 * Because at startup multiple instance of potatofs
			 * have to decide who has ownership of a given slab,
			 * whoever has the most recent revision wins. If
			 * a revision is incremented beyond UULONG_MAX, it
			 * should end up being zero, and special action must
			 * be taken to ensure all other instances purge theirs,
			 * as well as on the slow backend.
			 */
			uint64_t revision;

			/*
			 * We can fit up to what's left of the full
			 * block size in 'data'. This field must be the
			 * last in this struct, as it will use space
			 * from of the padding.
			 */
			char     data[1];
		} f;
		char padding[FS_BLOCK_SIZE];
	} v;
/* slab flags */
#define SLAB_ITBL    0x00000001
#define SLAB_DIRTY   0x00000002
#define SLAB_REMOVED 0x00000004
};

struct slab_itbl_hdr {
	/*
	 * Base is the number of the first inode in this
	 * table. Each bit indicates whether the inode is allocated or not.
	 */
	ino_t    base;
	uint32_t bitmap[SLAB_SIZE_CEIL / FS_BLOCK_SIZE / 32];
	uint32_t n_free;
};

struct oslab {
	/*
	 * All the following fields are protected by the global 'owned_slabs'
	 * mutex, and cannot be modified outside that context.
	 */

	/*
	 * ino and base are used as the SPLAY keys, as well as the
	 * SLAB_ITBL hdr flag. ino is always zero in the case
	 * of SLAB_ITBL. base represents either the first inode contained
	 * in an inode table, or the first byte in a slab.
	 *
	 */
	ino_t              ino;
	off_t              base;
	SPLAY_ENTRY(oslab) entry;

	TAILQ_ENTRY(oslab) lru_entry;
	TAILQ_ENTRY(oslab) itbl_entry;

	uint64_t           refcnt;
	int                fd;

	/* Only meaningful when disowning slabs */
	struct timespec    open_since;

	/*
	 * The lock is only for the fields in this structure and
	 * the included slab_hdr. It does not guarantee exclusive
	 * access to bytes via 'fd' (except the slab_hdr).
	 */
	rwlk               lock;

	/* Set to 1 if we have non-fsync()'d data */
	int                dirty;

	struct slab_hdr    hdr;

	/*
	 * Used for inode tables, since they need serialized access
	 * to the slab bytes, since they contain inodes.
	 */
	rwlk               bytes_lock;

	uint32_t           oflags;
#define OSLAB_NOCREATE 0x00000001
#define OSLAB_SYNC     0x00000002
};

int slab_configure(uint64_t, uint32_t, struct exlog_err *);
int slab_shutdown(struct exlog_err *);
int slab_make_dirs(struct exlog_err *);

/*
 * Computes the path/filename of a slab based on the slab type
 * and inode (for data slabs) or base inode (for itbl slabs).
 */
int slab_path(char *, size_t, ino_t, off_t, uint32_t, int, struct exlog_err *);

/*
 * Returns a pointer to a slab which can be passed to other slab_*
 * functions, or NULL on error.
 *
 * Before returning, a reference counter is incremented.
 *
 * This function also acquires an flock() on the actual slab on the
 * filesystem when it is loaded for the first time, until ownership
 * is relinquished. The structure stores the open file descriptor.
 * This is to protect against external processes (such as an integrity
 * check) from obtaining corrupted data.
 *
 * A slab can be "forgotten", which decrements the reference count.
 * When the count reaches zero, the ownership is not relinquished yet,
 * as such further load slab calls will not need to reaquire the
 * flock(). Instead, the slab is moved to an LRU list where they are
 * periodically disowned, at which point the underlying file descriptor is
 * closed.
 */
struct oslab *slab_load(ino_t, off_t, uint32_t, uint32_t, struct exlog_err *);
int           slab_forget(struct oslab *, struct exlog_err *);

/*
 * Similar to the above, but specifically used to load inode tables.
 */
struct oslab *slab_load_itbl(ino_t, rwlk_flags, struct exlog_err *);
int           slab_close_itbl(struct oslab *, struct exlog_err *);

/*
 * Return n inode table bases, which is provided by the caller.
 */
size_t        slab_itbls(ino_t *, size_t, struct exlog_err *);

/* Must be called while the slab bytes_lock is held */
int   slab_inode_free(struct slab_itbl_hdr *, ino_t);
ino_t slab_find_free_inode(struct slab_itbl_hdr *);

/*
 * Used to access the inode-specific header; if any changes are made,
 * slab_hdr_changed() must be called to ensure data integrity;
 * this will cause the header to be written every time the slab is
 * "forgotten", with slab_forget(). Must be called in locked
 * context, of course.
 */
void *slab_hdr_data(struct oslab *);

/*
 * None of the following functions acquire a bytes_lock on the slab, so
 * if multiple threads need to perform I/O on slabs and retain consistency,
 * they should claim the slab's bytes_lock.
 */
int     slab_write_hdr(struct oslab *, struct exlog_err *);
int     slab_write_hdr_nolock(struct oslab *, struct exlog_err *);
ssize_t slab_write(struct oslab *, const void *, off_t,
            size_t, struct exlog_err *);
ssize_t slab_read(struct oslab *, void *, off_t,
            size_t, struct exlog_err *);
int     slab_unlink(struct oslab *, struct exlog_err *);
int     slab_truncate(struct oslab *, off_t, struct exlog_err *);
int     slab_sync(struct oslab *, struct exlog_err *);
void    slab_splice_fd(struct oslab *, off_t, size_t, off_t *,
            size_t *, int *, int);

/*
 * Indicate that this slab was modified. Acquires the inode lock.
 * Does nothing for slabs opened with OSLAB_SYNC.
 */
void    slab_set_dirty(struct oslab *);

/* Returns the size of the slab in bytes, minus the header. */
off_t   slab_size(struct oslab *, struct exlog_err *);

/* Returns the maximum size of a slab in bytes, minus the header. */
size_t  slab_get_max_size();

/* Returns how many inodes at most can be contained in a slab. */
size_t  slab_inode_max();

/* To be used for testing only, acquires no lock */
struct oslab *slab_inspect(ino_t, off_t, uint32_t, struct exlog_err *);

#endif
