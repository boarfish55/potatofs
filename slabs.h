/*
 *  Copyright (C) 2020-2025 Pascal Lalonde <plalonde@overnet.ca>
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

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <uuid/uuid.h>
#include "config.h"
#include "openfiles.h"
#include "xlog.h"
#include "slabs.h"
#include "util.h"

/*
 * Both inode numbers and slab offsets are limited to LONG_MAX. Part of
 * this is that we use an off_t to determine the base of a slab key, which
 * is used both in the context of inodes and file offsets. Also, sqlite
 * cannot deal with 64-bit unsigned integers so we cap our slab keys
 * at this value.
 */
#define SLAB_KEY_MAX LONG_MAX

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
 * filesystem to avoid read on write. slab_hdr fields should be kept
 * under a size of DEV_BSIZE to guarantee consistency when writing.
 */
struct slab_hdr {
#define SLAB_VERSION 5
	union {
		struct {
			/*
			 * NOTE: Increment the SLAB_VERSION definition anytime
			 * we modify this structure, the slab_itbl_hdr below
			 * or the inode structure (see inodes.h).
			 */
			uint32_t        slab_version;

			uint32_t        checksum;
			struct slab_key key;
			uint32_t        flags;

			/*
			 * Because at startup multiple instance of potatofs
			 * have to decide who has ownership of a given slab,
			 * whoever has the most highest revision wins. If
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
		} f;
		struct {
			/*
			 * hdr_hdr size must be large enough to
			 * be able to hold the "f" structure above and be
			 * a multiple of DEV_BSIZE (the device fragment size).
			 * The remaining space is used to store the additional
			 * data about the slab, such as slab_itbl_hdr below.
			 */
			char hdr_fields[DEV_BSIZE];
			char data[FS_BLOCK_SIZE - DEV_BSIZE];
		} padding;
	} v;
/* slab flags */
#define SLAB_DIRTY   0x00000001
#define SLAB_REMOVED 0x00000002
};

/*
 * Upper/lower bounds on the configured slab size. Must a power of two and no
 * larger than 64MB. This is because the data in the padding area of the
 * slab_hdr is used to store the inode table allocation bitmap. This data area
 * is ~3.5KB (FS_BLOCK_SIZE - DEV_BSIZE, minus a few other fields) in size
 * allowing the bitmap to track approximately 28672 inodes. Given that each
 * inode is 4096 bytes, rounding down to the nearest power of two give us 64MB.
 */
#define SLAB_SIZE_FLOOR (1024 * 1024)
#define SLAB_SIZE_CEIL  (1024 * 1024 * 64)

struct slab_itbl_hdr {
	/*
	 * Each bit indicates whether the inode is allocated or not. Because
	 * an inode is sized after our FS_BLOCK_SIZE, the slab can fit as many
	 * inodes as the slab ceiling size, divided by the fs block size.
	 * The bitmap must be be able to fit that many bits.
	 *
	 * Increment the SLAB_VERSION definition anytime we
	 * modify this structure.
	 *
	 * NOTE: Any change to the fields in this structure must be
	 * accompanied by incrementing the SLAB_VERSION macro above.
	 */
	uint32_t bitmap[SLAB_SIZE_CEIL / FS_BLOCK_SIZE /
	    (sizeof(uint32_t) * 8)];
	uint8_t  initialized;
	uint32_t n_free;
};

struct oslab {
	/*
	 * The following fields are protected by the global 'owned_slabs'
	 * mutex, and cannot be modified outside that context:
	 *    - entry
	 *    - lru_entry
	 *    - itbl_entry
	 *    - refcnt
	 *    - sk
	 *    - oflags (it's only set when the slab is allocated)
	 *    - open_since
	 *
	 * If refcnt is zero, claiming the owned_slabs lock lets the caller
	 * do anything. This is how slabs are created and destroyed.
	 *
	 * Lock acquisition order is:
	 *   1) owned_slabs.lock
	 *   3) slab lock
	 *
	 */
	SPLAY_ENTRY(oslab) entry;
	TAILQ_ENTRY(oslab) lru_entry;
	TAILQ_ENTRY(oslab) itbl_entry;
	uint64_t           refcnt;
	struct slab_key    sk;
	uint32_t           oflags;

	/* Only meaningful when unclaiming slabs */
	struct timespec    open_since;

	/*
	 * The slab lock protects the remaining fields.
	 */
	rwlk               lock;

	struct slab_hdr    hdr;

	/*
	 * The open file descriptor for the slab. Multiple threads may
	 * use it at once, so they should all make sure to use the pread()
	 * and pwrite() calls to ensure they are at the right offset.
	 */
	int                fd;

	/* Set to 1 if we have non-fsync()'d data */
	int                dirty;

	/*
	 * Set to 1 if the slab is currently being claimed by the mgr.
	 * We may not issue reads & writes until this is set back to 0.
	 */
	int                pending;

#define OSLAB_NOCREATE  0x00000001
#define OSLAB_SYNC      0x00000002
#define OSLAB_EPHEMERAL 0x00000004
#define OSLAB_NONBLOCK  0x00000008
#define OSLAB_NOHINT    0x00000010
};

int slab_configure(rlim_t, time_t, int, struct xerr *);
int slab_shutdown(struct xerr *);
int slab_make_dirs(struct xerr *);

/*
 * Computes the path/filename of a slab based on the slab type
 * and inode (for data slabs) or base inode (for itbl slabs).
 */
int slab_path(char *, size_t, const struct slab_key *, int, struct xerr *);
int slab_parse_path(const char *, struct slab_key *, struct xerr *);

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
struct oslab *slab_load(const struct slab_key *, uint32_t, struct xerr *);
int           slab_forget(struct oslab *, struct xerr *);

/*
 * Similar to the above, but specifically used to load inode tables.
 */
struct oslab *slab_load_itbl(const struct slab_key *, struct xerr *);

/*
 * Lock/unlock a slab's fields.
 */
void          slab_lock(struct oslab *, rwlk_flags);
void          slab_unlock(struct oslab *);

/*
 * Return n inode table bases, which is provided by the caller.
 */
ssize_t       slab_itbls(off_t *, size_t, struct xerr *);

/* Must be called while the slab lock is held */
int   slab_itbl_is_free(struct oslab *, ino_t);
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
 * Must be called while lock is held.
 */
int     slab_write_hdr(struct oslab *, struct xerr *);
int     slab_read_hdr(struct oslab *, struct xerr *);
ssize_t slab_write(struct oslab *, const void *, off_t,
            size_t, struct xerr *);
ssize_t slab_read(struct oslab *, void *, off_t,
            size_t, struct xerr *);
void    slab_set_dirty(struct oslab *);
int     slab_truncate(struct oslab *, off_t, struct xerr *);
int     slab_unlink(struct oslab *, struct xerr *);
int     slab_sync(struct oslab *, struct xerr *);
void    slab_splice_fd(struct oslab *, off_t, size_t, off_t *,
            size_t *, int *, int);
off_t   slab_size(struct oslab *, struct xerr *);

/*
 * Acquires both the owned_slabs lock and the truncated slabs' lock.
 */
int     slab_delayed_truncate(struct slab_key *, off_t, struct xerr *);

/* Returns the maximum size of a slab in bytes, minus the header. */
off_t   slab_get_max_size();

/* Returns how many inodes at most can be contained in a slab. */
size_t  slab_inode_max();

/* Populates a slab_key from inode/offset/flags */
struct slab_key *slab_key(struct slab_key *, ino_t, off_t);
int              slab_key_valid(const struct slab_key *, struct xerr *);

/* Loop over all local slabs and perform a function. */
int     slab_loop_files(void (*)(const char *), struct xerr *);

/* To be used for testing only, acquires no lock */
void *slab_disk_inspect(struct slab_key *, struct slab_hdr *, size_t *,
          struct xerr *);
void *slab_inspect(int, struct slab_key *, uint32_t, struct slab_hdr *,
          size_t *, struct xerr *);

#endif
