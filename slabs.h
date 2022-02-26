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
#include <uuid/uuid.h>
#include "config.h"
#include "openfiles.h"
#include "exlog.h"
#include "slabs.h"
#include "util.h"

struct slab_key {
	/*
	 * Used in structures that index slabs, as the key to be
	 * indexed or sorted.
	 *
	 * When used to reference an inode table, ino is always set to
	 * zero and base is set to the first inode contained in the slab.
	 *
	 * If inode tables can contain 2048 inodes, the first inode table
	 * would have a base of 1, the second a base of 2049 and so on.
	 *
	 * For slab containing file data, the base references the first
	 * zero-indexed byte contained in the slab, e.g. 0, 8388608 and so
	 * on for 8MB-sized slabs. In this case, ino is the inode of the
	 * file.
	 */
	ino_t ino;
	off_t base;
};

/*
 * Slabs can either contain file data or inode tables. The slab_itbl_hdr
 * (see below) holds data specific to inode tables and is stored
 * into the data field. Otherwise data is empty. In any case, we keep
 * the slab header size as FS_BLOCK_SIZE to align with the underlying
 * filesystem to avoid read on write.
 */
struct slab_hdr {
#define SLAB_VERSION 3
	union {
		struct {
			/*
			 * Increment the SLAB_VERSION definition anytime we
			 * modify this structure.
			 */
			uint32_t        slab_version;

			uint32_t        checksum;
			struct slab_key key;
			uint32_t        flags;

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
			 * We save the last owner to avoid using slabs
			 * that were created by an unknown instance.
			 */
			uuid_t   last_owner;

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
#define SLAB_DIRTY   0x00000001
#define SLAB_REMOVED 0x00000002
};

struct slab_itbl_hdr {
	/*
	 * Each bit indicates whether the inode is allocated or not. Because
	 * an inode is sized after our FS_BLOCK_SIZE, the slab can fit as many
	 * inodes as the slab ceiling size, divided by the fs block size.
	 * The bitmap must be be able to fit that many bits.
	 *
	 * Increment the SLAB_VERSION definition anytime we
	 * modify this structure.
	 */
	uint8_t  initialized;
	uint32_t bitmap[SLAB_SIZE_CEIL / FS_BLOCK_SIZE /
	    (sizeof(uint32_t) * 8)];
	uint32_t n_free;
};

struct oslab {
	/*
	 * All the following fields are protected by the global 'owned_slabs'
	 * mutex, and cannot be modified outside that context.
	 */

	SPLAY_ENTRY(oslab) entry;
	TAILQ_ENTRY(oslab) lru_entry;
	TAILQ_ENTRY(oslab) itbl_entry;

	struct slab_hdr    hdr;
	uint64_t           refcnt;
	int                fd;

	/* Only meaningful when unclaiming slabs */
	struct timespec    open_since;

	/*
	 * The lock is only for the fields in this structure and
	 * the included slab_hdr. It does not guarantee exclusive
	 * access to bytes via 'fd' (except the slab_hdr).
	 */
	rwlk               lock;

	/* Set to 1 if we have non-fsync()'d data */
	int                dirty;

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
int slab_path(char *, size_t, struct slab_key *, int, struct exlog_err *);
int slab_parse_path(const char *, struct slab_key *, struct exlog_err *);

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
struct oslab *slab_load(struct slab_key *, uint32_t, struct exlog_err *);
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
int   slab_itbl_is_free(struct oslab *, ino_t);
ino_t slab_find_free_inode(struct oslab *);
ino_t slab_itbl_find_unallocated(struct oslab *);
void  slab_itbl_dealloc(struct oslab *, ino_t);
void  slab_itbl_alloc(struct oslab *, ino_t);

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
int     slab_read_hdr(struct oslab *, struct exlog_err *);
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

/* Populates a slab_key from inode/offset/flags */
struct slab_key *slab_key(struct slab_key *, ino_t, off_t);
int              slab_key_valid(struct slab_key *, struct exlog_err *);

/* Loop over all local slabs and perform a function. */
int     slab_loop_files(void (*)(const char *), struct exlog_err *);

/* To be used for testing only, acquires no lock */
void *slab_disk_inspect(struct slab_key *, struct slab_hdr *, size_t *,
          struct exlog_err *);
void *slab_inspect(int, struct slab_key *, uint32_t, struct slab_hdr *,
          size_t *, struct exlog_err *);

#endif
