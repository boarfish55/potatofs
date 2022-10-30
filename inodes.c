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

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <uuid/uuid.h>
#include "counters.h"
#include "fs_error.h"
#include "fs_info.h"
#include "inodes.h"
#include "xlog.h"
#include "util.h"

static struct oinodes {
	/*
	 * The tree should contain inodes that have a refcnt greater than
	 * zero. However, for a short time after creation it is possible
	 * that it would be at zero until a dir_entry is created.
	 */
	SPLAY_HEAD(ino_tree, oinode) head;
	pthread_mutex_t              lock;
} open_inodes = {
	SPLAY_INITIALIZER(&open_inodes.head),
        PTHREAD_MUTEX_INITIALIZER
};

static char *slab_zeroes;

static int
inode_cmp(struct oinode *i1, struct oinode *i2)
{
	return i1->ino.v.f.inode - i2->ino.v.f.inode;
}

SPLAY_PROTOTYPE(ino_tree, oinode, entry, inode_cmp);
SPLAY_GENERATE(ino_tree, oinode, entry, inode_cmp);

char *
inode_data(struct inode *ino)
{
	return ino->v.padding.inline_data;
}

/*
 * Returns the slab storing data for a specific offset of an inode,
 * or NULL on error.
 */
static struct oslab *
slab_at(struct oinode *oi, off_t offset, uint32_t oflags, struct xerr *e)
{
	struct oslab    *b;
	struct slab_key  sk;

	if (oi->oflags & INODE_OSYNC)
		oflags |= OSLAB_SYNC;
	if ((b = slab_load(slab_key(&sk, oi->ino.v.f.inode, offset),
	    oflags, xerrz(e))) == NULL) {
		XERR_PREPENDFN(e);
		return NULL;
	}

	return b;
}

static struct oslab *
alloc_inode(ino_t *inode, struct xerr *e)
{
	ino_t            i, ino = 0, max_ino = 0;
	struct oslab    *b;
	off_t            bases[16];
	ssize_t          n_bases, n;
	struct slab_key  sk;

	/*
	 * Even though by the time we loop over it that itbl
	 * could be gone, it's somewhat unlikely. Worst cast it will
	 * be a bit slower to allocate that particular inode.
	 */
	n_bases = slab_itbls(bases, sizeof(bases) / sizeof(off_t), xerrz(e));
	if (n_bases == -1) {
		XERR_PREPENDFN(e);
		return NULL;
	}

	for (n = 0; n < n_bases; n++) {
		if ((b = slab_load_itbl(slab_key(&sk, 0, bases[n]),
		    xerrz(e))) == NULL) {
			XERR_PREPENDFN(e);
			return NULL;
		}
		slab_lock(b, LK_LOCK_RW);
		ino = slab_itbl_find_unallocated(b);
		if (ino > 0) {
			if (inode != NULL)
				*inode = ino;
			return b;
		}
		slab_unlock(b);
		if (slab_forget(b, xerrz(e)) == -1) {
			XERR_PREPENDFN(e);
			return NULL;
		}

		/* This is the highest inode we scanned, +1 */
		if (bases[n] + slab_inode_max() > max_ino)
			max_ino = bases[n] + slab_inode_max();
	}

	/*
	 * If we still haven't found a free inode, scan from the max.
	 */
	for (i = max_ino; i < SLAB_KEY_MAX; i += slab_inode_max()) {
		if ((b = slab_load_itbl(slab_key(&sk, 0, i),
		    xerrz(e))) == NULL) {
			XERR_PREPENDFN(e);
			return NULL;
		}

		slab_lock(b, LK_LOCK_RW);
		ino = slab_itbl_find_unallocated(b);
		if (ino > 0) {
			if (inode != NULL)
				*inode = ino;
			return b;
		}
		slab_unlock(b);

		if (slab_forget(b, xerrz(e)) == -1) {
			XERR_PREPENDFN(e);
			return NULL;
		}
	}

	XERRF(e, XLOG_FS, ENOSPC, "unable to locate free "
	    "inode; we looped up to base %lu", i);
	return NULL;
}

int
inode_startup(struct xerr *e)
{
	if ((slab_zeroes = calloc(slab_get_max_size(), 1)) == NULL)
		return XERRF(e, XLOG_ERRNO, errno,
		    "calloc: failed to allocate zeroes");
	return 0;
}

int
inode_dealloc(ino_t ino, struct xerr *e)
{
	struct oslab    *b;
	struct xerr      e_close_tbl;
	struct slab_key  sk;

	b = slab_load_itbl(slab_key(&sk, 0, ino), xerrz(e));
	if (b == NULL) {
		XERR_PREPENDFN(e);
		return -1;
	}

	slab_lock(b, LK_LOCK_RW);
	xlog_dbg(XLOG_INODE, "%s: deallocating inode %lu", __func__, ino);
	slab_itbl_dealloc(b, ino);
	slab_write_hdr(b, xerrz(e));
	slab_unlock(b);

	if (slab_forget(b, xerrz(&e_close_tbl)) == -1) {
		fs_error_set();
		xlog(LOG_ERR, &e_close_tbl, __func__);
	}

	return xerr_fail(e);
}

off_t
inode_getsize(struct oinode *oi)
{
	off_t size;
	LK_RDLOCK(&oi->bytes_lock);
	size = oi->ino.v.f.size;
	LK_UNLOCK(&oi->bytes_lock);
	return size;
}

static int
inode_incr_size(struct oinode *oi, off_t offset, off_t written,
    struct xerr *e)
{
	if (written > LONG_MAX - offset) {
		return XERRF(e, XLOG_FS, EFBIG,
		    "file size overflow: %lu", oi->ino.v.f.inode);
	}

	if (oi->ino.v.f.size < offset + written) {
		oi->ino.v.f.size = offset + written;
		oi->ino.v.f.blocks = (offset + written) / 512 + 1;
		oi->bytes_dirty = 1;
	}
	return 0;
}

int
inode_make(ino_t ino, uid_t uid, gid_t gid, mode_t mode,
    struct inode *dst, struct xerr *e)
{
	struct timespec  tp;
	struct inode     inode;
	struct oslab    *b;
	ssize_t          r, w;
	struct xerr      e_close_tbl;
	struct slab_key  sk;

	/*
	 * If ino == 0 (that is, the caller expects us to pick an inode),
	 * we call alloc_inode(). Otherwise, just load the exact
	 * inode number and fill it up, if it's available.
	 */
	if (ino == 0) {
		b = alloc_inode(&ino, xerrz(e));
	} else {
		b = slab_load_itbl(slab_key(&sk, 0, ino), xerrz(e));
		slab_lock(b, LK_LOCK_RW);
	}

	if (b == NULL) {
		XERR_PREPENDFN(e);
		return -1;
	}

	if (!slab_itbl_is_free(b, ino)) {
		XERRF(e, XLOG_FS, EEXIST,
		    "inode already allocated: %lu", ino);
		goto fail;
	}

	/*
	 * We read previously allocated inode data here, if any,
	 * so we can increment the generation.
	 */
	r = slab_read(b, &inode,
	    (ino - b->hdr.v.f.key.base) * sizeof(struct inode),
	    sizeof(inode), xerrz(e));
	if (r == 0)
		bzero(&inode, sizeof(inode));
	else if (r < sizeof(inode)) {
		XERRF(e, XLOG_APP, XLOG_IO, "short read for inode: %lu", ino);
		goto fail;
	}

	/*
	 * Most fields should be overwritten at this point, except generation,
	 * which must always increase which each reuse of a specific inode.
	 * It is already set to zero at inode table creation, so we can just
	 * increment it.
	 */
	inode.v.f.generation++;
	inode.v.f.inode = ino;
	inode.v.f.mode = mode;
	inode.v.f.nlink = 0;
	inode.v.f.uid = uid;
	inode.v.f.gid = gid;
	inode.v.f.rdev = 0;
	inode.v.f.dev = 0;
	inode.v.f.size = 0;
	inode.v.f.blocks = 0;

	if (clock_gettime(CLOCK_REALTIME, &tp) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "clock_gettime");
		goto fail;
	}

	memcpy(&inode.v.f.atime, &tp, sizeof(inode.v.f.atime));
	memcpy(&inode.v.f.ctime, &tp, sizeof(inode.v.f.ctime));
	memcpy(&inode.v.f.mtime, &tp, sizeof(inode.v.f.mtime));

	if ((w = slab_write(b, &inode,
	    (ino - b->hdr.v.f.key.base) * sizeof(struct inode),
	    sizeof(struct inode), xerrz(e))) == -1)
		goto fail;

	if (w < sizeof(struct inode)) {
		XERRF(e, XLOG_APP, XLOG_IO,
		    "short write while saving inode %lu", ino);
		// TODO: corrupted at this point; maybe move to lost+found?
		goto fail;
	}

	slab_itbl_alloc(b, ino);

	if (slab_write_hdr(b, xerrz(e)) == -1)
		goto fail;

	slab_unlock(b);
	if (slab_forget(b, xerrz(e)) == -1)
		return -1;

	if (dst != NULL)
		memcpy(dst, &inode, sizeof(struct inode));

	return 0;
fail:
	slab_unlock(b);
	if (slab_forget(b, xerrz(&e_close_tbl)) == -1) {
		fs_error_set();
		xlog(LOG_ERR, &e_close_tbl, __func__);
	}
	return -1;
}

void
inode_lock(struct oinode *oi, rwlk_flags lkf)
{
	LK_LOCK(&oi->lock, lkf);
}

void
inode_unlock(struct oinode *oi)
{
	LK_UNLOCK(&oi->lock);
}

ino_t
inode_ino(struct oinode *oi)
{
	return oi->ino.v.f.inode;
}

void
inode_cp_stat(struct stat *dst, const struct inode *ino)
{
	dst->st_dev = ino->v.f.dev;
	dst->st_ino = ino->v.f.inode;
	dst->st_mode = ino->v.f.mode;
	dst->st_nlink = ino->v.f.nlink;
	dst->st_uid = ino->v.f.uid;
	dst->st_gid = ino->v.f.gid;
	dst->st_blksize = FS_BLOCK_SIZE;

	dst->st_size = ino->v.f.size;
	dst->st_blocks = ino->v.f.blocks;

	memcpy(&dst->st_atim, &ino->v.f.atime, sizeof(dst->st_atim));
	memcpy(&dst->st_mtim, &ino->v.f.mtime, sizeof(dst->st_mtim));
	memcpy(&dst->st_ctim, &ino->v.f.ctime, sizeof(dst->st_ctim));

	// TODO: support devices ... Maybe?
	dst->st_rdev = ino->v.f.rdev;
}

void
inode_stat(struct oinode *oi, struct stat *st)
{
	LK_RDLOCK(&oi->bytes_lock);
	inode_cp_stat(st, &oi->ino);
	LK_UNLOCK(&oi->bytes_lock);
}

/*
 * Must be called in write-lock.
 * See fallocate(2) for the 'mode' parameter.
 */
int
inode_fallocate(struct oinode *oi, off_t offset, off_t len,
    int mode, struct xerr *e)
{
	if (mode != 0)
		return XERRF(e, XLOG_FS, EOPNOTSUPP,
		    "non-zero mode isn't support by fallocate() "
		    "at this time");

	LK_RDLOCK(&oi->bytes_lock);
	if (offset + len <= oi->ino.v.f.size) {
		LK_UNLOCK(&oi->bytes_lock);
		return 0;
	}
	LK_UNLOCK(&oi->bytes_lock);
	return inode_truncate(oi, offset + len, xerrz(e));
}

/*
 * Also updates inode size by holding the size lock.
 */
int
inode_truncate(struct oinode *oi, off_t offset, struct xerr *e)
{
	char            *f_data = inode_data(&oi->ino);
	struct oslab    *b;
	off_t            old_size, zero_start, c_off, truncate_to;
	struct slab_key  sk;

	LK_WRLOCK(&oi->bytes_lock);

	old_size = oi->ino.v.f.size;
	if (old_size == offset)
		goto end;

	/*
	 * Fill in inline data with zeroes. When shrinking the file,
	 * fill from INODE_INLINE_BYTES to offset; when growing the
	 * file, we fill from old_size to offset.
	 */
	zero_start = (old_size < offset) ? old_size : offset;
	if (zero_start < INODE_INLINE_BYTES)
		bzero(f_data + zero_start,
		    INODE_INLINE_BYTES - zero_start);

	oi->bytes_dirty = 1;
	oi->ino.v.f.size = offset;
	oi->ino.v.f.blocks = offset / 512 + 1;

	/*
	 * Then ftruncate() or unlink() anything unnecessary in the backing
	 * files.
	 */
	for (c_off = offset;
	    old_size > INODE_INLINE_BYTES && c_off <= old_size;
	    c_off += slab_get_max_size()) {
		/*
		 * Only the slab within which the new offset falls should be
		 * truncated to a value that's not a multiple of
		 * slab_get_max_size().
		 *
		 * Anything else after should be truncated to zero.
		 *
		 * Also, if all bytes of the inode now fit inline in the
		 * inode, just truncate the first slab to zero as well.
		 */
		if (c_off > offset || oi->ino.v.f.size <= INODE_INLINE_BYTES)
			truncate_to = 0;
		else
			truncate_to = c_off % slab_get_max_size();

		if (slab_delayed_truncate(slab_key(&sk, oi->ino.v.f.inode,
		    c_off), truncate_to, xerrz(e)) == -1) {
			fs_error_set();
			XERR_PREPENDFN(e);
			goto end;
		}
	}

	/*
	 * Create missing slabs if we're extending the file. This is
	 * necessary, even for sparse files, because when looking for
	 * slabs on the backend, other nodes cannot distinguish between
	 * a missing slab due to corruption or sparse file.
	 */
	for (c_off = old_size; c_off <= offset; c_off += slab_get_max_size()) {
		if ((b = slab_at(oi, c_off, 0, xerrz(e))) == NULL) {
			XERR_PREPENDFN(e);
			goto end;
		}
		if (slab_forget(b, xerrz(e)) == -1) {
			XERR_PREPENDFN(e);
			goto end;
		}
	}
end:
	LK_UNLOCK(&oi->bytes_lock);
	return xerr_fail(e);
}

int
inode_setattr(struct oinode *oi, struct stat *st, uint32_t mask,
    struct xerr *e)
{
	if (mask & INODE_ATTR_SIZE) {
		if (inode_truncate(oi, st->st_size, xerrz(e)) == -1)
			return -1;
	}

	if (mask & INODE_ATTR_MODE && oi->ino.v.f.mode != st->st_mode) {
		oi->ino.v.f.mode = st->st_mode;
		oi->dirty = 1;
	}

	if (mask & INODE_ATTR_UID && oi->ino.v.f.uid != st->st_uid) {
		oi->ino.v.f.uid = st->st_uid;
		oi->dirty = 1;
	}

	if (mask & INODE_ATTR_GID && oi->ino.v.f.gid != st->st_gid) {
		oi->ino.v.f.gid = st->st_gid;
		oi->dirty = 1;
	}

	if (mask & INODE_ATTR_ATIME) {
		memcpy(&oi->ino.v.f.atime, &st->st_atim,
		    sizeof(oi->ino.v.f.atime));
		oi->dirty = 1;
	}

	if (mask & INODE_ATTR_MTIME) {
		memcpy(&oi->ino.v.f.mtime, &st->st_mtim,
		    sizeof(oi->ino.v.f.mtime));
		oi->dirty = 1;
	}

	if (mask & INODE_ATTR_CTIME) {
		memcpy(&oi->ino.v.f.ctime, &st->st_ctim,
		    sizeof(oi->ino.v.f.ctime));
		oi->dirty = 1;
	}

	inode_stat(oi, st);
	return 0;
}

unsigned long
inode_nlookup(struct oinode *oi, int nlookup_incr)
{
	unsigned long prev;

	if (nlookup_incr == 0)
		return oi->nlookup;

	prev = oi->nlookup;

	if (nlookup_incr < 0 && abs(nlookup_incr) > oi->nlookup) {
		xlog(LOG_ERR, NULL, "%s: prevented integer underflow for "
		    "ino=%lu (%p); tried to decrement nlookup %lu by %d",
		    __func__, oi->ino.v.f.inode, oi, prev, nlookup_incr);
		oi->nlookup = 0;
	} else
		oi->nlookup += nlookup_incr;

	xlog_dbg(XLOG_INODE, "%s: ino=%lu (%p) nlookup: %lu => %lu",
	    __func__, oi->ino.v.f.inode, oi, prev, oi->nlookup);

	return oi->nlookup;
}

int
inode_nlookup_ino(ino_t ino, int nlookup_incr, struct xerr *e)
{
	struct oinode *oi;

	if ((oi = inode_load(ino, 0, xerrz(e))) == NULL)
		return -1;

	LK_WRLOCK(&oi->lock);
	inode_nlookup(oi, nlookup_incr);
	LK_UNLOCK(&oi->lock);

	if (inode_unload(oi, xerrz(e)) == -1)
		return -1;
	return 0;
}

nlink_t
inode_nlink(struct oinode *oi, int incr)
{
	if (incr == 0)
		return oi->ino.v.f.nlink;
	if (incr < 0 && abs(incr) > oi->ino.v.f.nlink) {
		xlog(LOG_ERR, NULL, "%s: prevented integer underflow for "
		    "ino=%lu (%p); tried to decrement nlink %ld by %d",
		    __func__, oi->ino.v.f.inode, oi, oi->ino.v.f.nlink, incr);
		oi->ino.v.f.nlink = 0;
	} else
		oi->ino.v.f.nlink += incr;
	oi->dirty = 1;
	return oi->ino.v.f.nlink;
}

int
inode_nlink_ino(ino_t ino, int incr, struct xerr *e)
{
	struct oinode *oi;

	if ((oi = inode_load(ino, 0, xerrz(e))) == NULL)
		return -1;

	LK_WRLOCK(&oi->lock);
	inode_nlink(oi, incr);
	LK_UNLOCK(&oi->lock);

	if (inode_unload(oi, xerrz(e)) == -1)
		return -1;
	return 0;
}

int
inode_isdir(struct oinode *oi)
{
	return (oi->ino.v.f.mode & S_IFDIR) ? 1 : 0;
}

struct oinode *
inode_load(ino_t ino, uint32_t oflags, struct xerr *e)
{
	int              r;
	struct oinode   *oi;
	struct oinode    needle;
	struct oslab    *b = NULL;
	struct xerr      e_close_itbl;
	struct slab_key  sk;

	/* 
	 * Need exclusive in case we need to load from disk and insert
	 * into the splay_tree. Otherwise there could be a race of who
	 * tries to insert in the tree after two or more threads find out
	 * the inode isn't loaded yet.
	 */
	MTX_LOCK(&open_inodes.lock);

	bzero(&needle, sizeof(needle));
	needle.ino.v.f.inode = ino;
	if ((oi = SPLAY_FIND(ino_tree, &open_inodes.head, &needle)) != NULL) {
		oi->refcnt++;
		xlog_dbg(XLOG_INODE, "%s: found inode in-memory: "
		    "inode %lu refcnt %llu nlookup %lu",
		    __func__, ino, oi->refcnt, oi->nlookup);
		MTX_UNLOCK(&open_inodes.lock);
		return oi;
	}

	if ((b = slab_load_itbl(slab_key(&sk, 0, ino), xerrz(e))) == NULL) {
		XERR_PREPENDFN(e);
		goto end;
	}
	slab_lock(b, LK_LOCK_RD);

	if (slab_itbl_is_free(b, ino)) {
		XERRF(e, XLOG_FS, ENOENT,
		    "no such inode allocated: %lu", ino);
		goto fail_close_itbl;
	}

	if ((oi = malloc(sizeof(struct oinode))) == NULL) {
		XERRF(e, XLOG_ERRNO, errno, "malloc");
		goto fail_close_itbl;
	}
	bzero(oi, sizeof(struct oinode));

	if (LK_LOCK_INIT(&oi->lock, xerrz(e)) == -1)
		goto fail_free_oi;
	if (LK_LOCK_INIT(&oi->bytes_lock, xerrz(e)) == -1)
		goto fail_destroy_lock;
	oi->refcnt = 1;
	oi->oflags = oflags;
	oi->itbl = b;
	r = slab_read(b, &oi->ino,
	    (ino - b->hdr.v.f.key.base) * sizeof(struct inode),
	    sizeof(struct inode), xerrz(e));
	if (r == -1) {
		goto fail_destroy_bytes_lock;
	} else if (r < sizeof(struct inode)) {
		XERRF(e, XLOG_APP, XLOG_IO,
		    "short read while reading inode %lu", ino);
		goto fail_destroy_bytes_lock;
	}

	if (oi->ino.v.f.mode & S_IFDIR)
		oi->oflags |= INODE_OSYNC;

	if (SPLAY_INSERT(ino_tree, &open_inodes.head, oi) != NULL) {
		XERRF(e, XLOG_APP, XLOG_IO, "inode already loaded %lu", ino);
		goto fail_destroy_bytes_lock;
	}

	xlog_dbg(XLOG_INODE, "%s: loaded inode %lu refcnt %llu nlookup %lu "
	    "nlink %ld", __func__, ino, oi->refcnt, oi->nlookup,
	    oi->ino.v.f.nlink);

	counter_incr(COUNTER_N_OPEN_INODES);

	slab_unlock(b);

	goto end;
fail_destroy_bytes_lock:
	LK_LOCK_DESTROY(&oi->bytes_lock);
fail_destroy_lock:
	LK_LOCK_DESTROY(&oi->lock);
fail_free_oi:
	free(oi);
	oi = NULL;
fail_close_itbl:
	slab_unlock(b);
	if (slab_forget(b, xerrz(&e_close_itbl)) == -1)
		xlog(LOG_ERR, &e_close_itbl, __func__);
end:
	MTX_UNLOCK(&open_inodes.lock);
	return oi;
}

/*
 * Unloading the inode will be the last thing to happen in all the following
 * cases:
 *   1) An inode is being unlinked
 *   2) An inode is being "forgotten" by the kernel VFS (i.e. unreferenced)
 *
 * Therefore, this function is in charge the doing the following things:
 *   - Remove the inode from the memory structure if both the refcnt
 *     and nlookup fall to zero (nlookup should normally never get to zero
 *     if refcnt > 0).
 *   - Deallocate the inode if nlink == 0, as well as the above conditions.
 */
int
inode_unload(struct oinode *oi, struct xerr *e)
{
	struct oinode needle;
	ino_t         ino;

	MTX_LOCK(&open_inodes.lock);

	ino = oi->ino.v.f.inode;

	if (oi->refcnt == 0) {
		xlog(LOG_ERR, NULL, "%s: prevented integer underflow for "
		    "ino=%lu (%p); tried to decrement refcnt 0 by 1",
		    __func__, oi->ino.v.f.inode, oi);
	} else
		oi->refcnt--;

	xlog_dbg(XLOG_INODE, "%s: inode %lu refcnt %llu",
	    __func__, ino, oi->refcnt);

	if (oi->nlookup == 0) {
		bzero(&needle, sizeof(needle));
		needle.ino.v.f.inode = ino;

		if (oi->ino.v.f.nlink == 0) {
			xlog_dbg(XLOG_INODE, "%s: inode %lu: deallocating",
			    __func__, ino);
			if (inode_dealloc(ino, xerrz(e)) == -1)
				xlog(LOG_ERR, e, __func__);
			/*
			 * Truncate all file data, and we keep the slab header
			 * to update the slow backend in the background.
			 */
			if (inode_truncate(oi, 0, xerrz(e)) == -1)
				xlog(LOG_ERR, e, __func__);
		}

		if (oi->refcnt == 0) {
			if (inode_flush(oi, INODE_FLUSH_RELEASE,
			    xerrz(e)) == -1) {
				XERR_PREPENDFN(e);
				goto end;
			}

			SPLAY_REMOVE(ino_tree, &open_inodes.head, &needle);
			LK_LOCK_DESTROY(&oi->lock);
			LK_LOCK_DESTROY(&oi->bytes_lock);
			free(oi);
			oi = NULL;
			counter_decr(COUNTER_N_OPEN_INODES);
		}
	}
end:
	MTX_UNLOCK(&open_inodes.lock);
	return xerr_fail(e);
}

int
inode_sync(struct oinode *oi, struct xerr *e)
{
	off_t         offset, size;
	struct oslab *b;

	/*
	 * This should take care of syncing inode metadata and
	 * inline data.
	 */
	if (inode_flush(oi, 0, xerrz(e)) == -1)
		return -1;

	/* Nothing else to do, since we're O_SYNC */
	if (oi->oflags & INODE_OSYNC)
		return 0;

	LK_RDLOCK(&oi->bytes_lock);
	size = oi->ino.v.f.size;

	if (size < INODE_INLINE_BYTES) {
		LK_UNLOCK(&oi->bytes_lock);
		return 0;
	}

	/*
	 * Then sync any data living in subsequent slabs.
	 */
	for (offset = 0; !xerr_fail(e) && offset < size;
	    offset += slab_get_max_size()) {
		b = slab_at(oi, offset, OSLAB_NOCREATE, xerrz(e));
		if (b == NULL) {
			if (xerr_is(e, XLOG_APP, XLOG_NOSLAB)) {
				xerrz(e);
				continue;
			}
			LK_UNLOCK(&oi->bytes_lock);
			return -1;
		}

		slab_lock(b, LK_LOCK_RW);
		if (slab_sync(b, xerrz(e)) == -1) {
			fs_error_set();
			xlog(LOG_ERR, e, "%s: ino=%lu (%p)", __func__,
			    oi->ino, oi);
		}
		slab_unlock(b);

		slab_forget(b, xerrz(e));
	}
	LK_UNLOCK(&oi->bytes_lock);
	return xerr_fail(e);
}

/*
 * Write inode to underlying file; if flag INODE_FLUSH_DATA_ONLY is set,
 * we only write inline data and the inode size, not the inode structure.
 * This is useful if we must order things so that the inode size must be
 * increased before other attributes are updated, such as when dealing with
 * directory inode writes.
 *
 * If INODE_FLUSH_RELEASE is set, we decrement the slab's refcnt to inform
 * the mgr that it is safe to purge the slab to free up space.
 *
 * This is typically called on fd close().
 */
int
inode_flush(struct oinode *oi, uint8_t flags, struct xerr *e)
{
	ssize_t          w;
	off_t            sz_off;
	ino_t            ino = oi->ino.v.f.inode;
	struct xerr      e_close_itbl;

	xlog_dbg(XLOG_INODE, "%s: ino=%lu (%p); flags=%u",
	    __func__, ino, oi, flags);

	LK_WRLOCK(&oi->bytes_lock);
	if (!oi->dirty && !oi->bytes_dirty) {
		if (!(flags & INODE_FLUSH_RELEASE)) {
			LK_UNLOCK(&oi->bytes_lock);
			return 0;
		}

		if (slab_forget(oi->itbl, xerrz(e)) == -1) {
			LK_UNLOCK(&oi->bytes_lock);
			return XERR_PREPENDFN(e);
		}
		LK_UNLOCK(&oi->bytes_lock);
		return 0;
	}

	slab_lock(oi->itbl, LK_LOCK_RW);

	if (flags & INODE_FLUSH_DATA_ONLY) {
		/*
		 * Syncing data only means it is safe to do so without the
		 * inode lock. Note that inode table slabs are always O_SYNC,
		 * so no need to fsync() after. Sadly, this will cause
		 * read-modify-write, but, hopefully one day we can do
		 * without O_SYNC for inodes.
		 *
		 * This will write the size (last field) plus the
		 * inline data that follows.
		 *
		 * In some cases we want to make sure inline data
		 * is written _before_ we commit nlink to disk.
		 */
		sz_off = (char *)&oi->ino.v.f.size - (char *)&oi->ino;
		if ((w = slab_write(oi->itbl, &oi->ino.v.f.size,
		    ((ino - oi->itbl->hdr.v.f.key.base) * sizeof(struct inode))
		    + sz_off, sizeof(struct inode) - sz_off, xerrz(e))) ==
		    (sizeof(struct inode) - sz_off))
			oi->bytes_dirty = 0;
	} else {
		if ((w = slab_write(oi->itbl, &oi->ino,
		    (ino - oi->itbl->hdr.v.f.key.base) * sizeof(struct inode),
		    sizeof(struct inode), xerrz(e))) == sizeof(struct inode)) {
			oi->bytes_dirty = 0;
			oi->dirty = 0;
		}
	}

	if (w == -1) {
		goto end;
	} else if (w < ((flags & INODE_FLUSH_DATA_ONLY)
	    ?  INODE_INLINE_BYTES
	    : sizeof(struct inode))) {
		XERRF(e, XLOG_APP, XLOG_IO,
		    "short write while saving inode %lu", ino);
		goto end;
	}
end:
	LK_UNLOCK(&oi->bytes_lock);
	slab_unlock(oi->itbl);
	if (!xerr_fail(e) && (flags & INODE_FLUSH_RELEASE)) {
		if (slab_forget(oi->itbl, xerrz(&e_close_itbl)) == -1)
			xlog(LOG_ERR, &e_close_itbl, __func__);
	}
	// TODO: save to lost & found ?
	return xerr_fail(e);
}

void
inode_shutdown()
{
	struct oinode *oi;
	struct xerr    e;

	for (;;) {
		MTX_LOCK(&open_inodes.lock);
		if ((oi = SPLAY_ROOT(&open_inodes.head)) == NULL) {
			MTX_UNLOCK(&open_inodes.lock);
			break;
		}

		if (oi->refcnt > 0)
			xlog(LOG_ERR, NULL, "forcibly freeing inode %lu "
			    "with refcnt > 0 (nlookup=%lu, refcnt=%llu); "
			    "lazy umount?", oi->ino.v.f.inode,
			    oi->nlookup, oi->refcnt);

		SPLAY_REMOVE(ino_tree, &open_inodes.head, oi);

		/* As per FUSE, nlookup becomes zero implicitly at unmount. */
		if (oi->ino.v.f.nlink == 0) {
			xlog(LOG_ERR, NULL, "%s: ino=%lu had nlink=0 but "
			    "was still in-memory due to nlookup=%lu; "
			    "deallocating now", __func__, oi->ino.v.f.inode,
			    oi->nlookup);

			if (inode_dealloc(inode_ino(oi), xerrz(&e)) == -1)
				xlog(LOG_ERR, &e, __func__);
			/*
			 * Truncate all file data, and we keep the slab header
			 * to update the slow backend in the background.
			 */
			if (inode_truncate(oi, 0, xerrz(&e)) == -1)
				xlog(LOG_ERR, &e, __func__);
		}

		if (inode_flush(oi, INODE_FLUSH_RELEASE, xerrz(&e)) == -1)
			xlog(LOG_ERR, &e, __func__);

		LK_LOCK_DESTROY(&oi->lock);
		LK_LOCK_DESTROY(&oi->bytes_lock);
		free(oi);
		counter_decr(COUNTER_N_OPEN_INODES);

		MTX_UNLOCK(&open_inodes.lock);
	}
	free(slab_zeroes);
}

/*
 * Also updates inode size by holding the size lock.
 */
ssize_t
inode_write(struct oinode *oi, off_t offset, const void *buf,
    size_t count, struct xerr *e)
{
	size_t        c;
	char         *f_data = inode_data(&oi->ino);
	off_t         rel_offset;
	ssize_t       written = 0;
	ssize_t       w;
	struct oslab *b;

	if (oi->oflags & INODE_ORO)
		return XERRF(e, XLOG_FS, EBADF,
		    "write attemped on read-only open inode %lu",
		    oi->ino.v.f.inode);

	if (offset < INODE_INLINE_BYTES) {
		c = (count > INODE_INLINE_BYTES - offset)
		    ? INODE_INLINE_BYTES - offset
		    : count;
		memcpy(f_data + offset, buf, c);
		written += c;
		LK_WRLOCK(&oi->bytes_lock);
		oi->bytes_dirty = 1;
		if (inode_incr_size(oi, offset, written, xerrz(e)) == -1) {
			LK_UNLOCK(&oi->bytes_lock);
			return -1;
		}
		LK_UNLOCK(&oi->bytes_lock);
		if ((oi->oflags & INODE_OSYNC) &&
		    inode_flush(oi, INODE_FLUSH_DATA_ONLY, xerrz(e)) == -1)
			return -1;
	}

	if (written == count)
		return written;

	/*
	 * We rewrite everything from the start in the slab because then
	 * we get a backup of the inode's inline data, and we want to
	 * do aligner writes anyway.
	 */
	for (written = 0; written < count; ) {
		b = slab_at(oi, offset + written, 0, xerrz(e));
		if (b == NULL)
			return -1;

		rel_offset = (offset + written) % slab_get_max_size();
		c = (count - written > slab_get_max_size() - rel_offset)
		    ? slab_get_max_size() - rel_offset
		    : count - written;
		slab_lock(b, LK_LOCK_RW);
		w = slab_write(b, buf + written, rel_offset, c, xerrz(e));
		slab_unlock(b);

		if (slab_forget(b, xerrz(e)) == -1)
			return -1;

		if (w == -1)
			return -1;

		written += w;
		LK_WRLOCK(&oi->bytes_lock);
		if (inode_incr_size(oi, offset, written, xerrz(e)) == -1) {
			LK_UNLOCK(&oi->bytes_lock);
			return -1;
		}
		LK_UNLOCK(&oi->bytes_lock);

		if (w < c)
			break;
	}
	return written;
}

/*
 * Reads that go past the already allocated slabs will end up creating
 * empty slabs, which is necessary for allowing the potatofs instance
 * to claim ownership of the slab and save its metadata.
 * These reads will however return zeroes.
 */
ssize_t
inode_read(struct oinode *oi, off_t offset, void *buf,
    size_t count, struct xerr *e)
{
	size_t        c;
	char         *f_data = inode_data(&oi->ino);
	off_t         rel_offset, size;
	ssize_t       rd = 0;
	ssize_t       r;
	struct oslab *b;

	LK_RDLOCK(&oi->bytes_lock);
	size = oi->ino.v.f.size;
	LK_UNLOCK(&oi->bytes_lock);

	if (offset >= size)
		return 0;

	if (offset + count > size)
		count = size - offset;

	if (offset < INODE_INLINE_BYTES) {
		c = (count > INODE_INLINE_BYTES - offset)
		    ? INODE_INLINE_BYTES - offset
		    : count;
		memcpy(buf, f_data + offset, c);
		rd += c;
	}

	if (rd == count)
		return rd;

	while (rd < count) {
		b = slab_at(oi, offset + rd, 0, xerrz(e));
		if (b == NULL)
			return -1;

		rel_offset = (offset + rd) % slab_get_max_size();
		c = (count - rd > slab_get_max_size() - rel_offset)
		    ? slab_get_max_size() - rel_offset
		    : count - rd;

		slab_lock(b, LK_LOCK_RD);
		r = slab_read(b, buf + rd, rel_offset, c, xerrz(e));
		slab_unlock(b);

		if (slab_forget(b, xerrz(e)) == -1)
			return -1;

		if (r == -1) {
			return -1;
		} else if (r == 0) {
			/*
			 * If a file was truncated or allocated to a longer
			 * size, we haven't created the backing bytes yet.
			 * So just return zeroes.
			 */
			if (offset + rd < size) {
				c = ((count - rd) < (size - (offset + rd)))
				    ? count - rd
				    : size - (offset + rd);
				bzero(buf + rd, c);
			}
			return rd;
		}

		rd += r;
		if (rd < c)
			break;
	}
	return rd;
}

int
inode_splice_begin_read(struct inode_splice_bufvec *si,
    struct oinode *oi, off_t offset, size_t count, struct xerr *e)
{
	char         *f_data = inode_data(&oi->ino);
	off_t         size, b_size;
	struct oslab *b;

	LK_RDLOCK(&oi->bytes_lock);
	size = oi->ino.v.f.size;
	LK_UNLOCK(&oi->bytes_lock);

	si->oi = oi;
	si->offset = offset;

	if (offset >= size) {
		si->nv = 0;
		si->v = NULL;
		return 0;
	}

	if (offset + count > size)
		count = size - offset;

	si->nv = 0;
	si->v = calloc(count / slab_get_max_size() + 2,
	    sizeof(struct inode_splice_buf));
	if (si->v == NULL)
		return XERRF(e, XLOG_ERRNO, errno, "calloc");

	if (offset < INODE_INLINE_BYTES) {
		if (count > INODE_INLINE_BYTES - offset)
			si->v[0].count = INODE_INLINE_BYTES - offset;
		else
			si->v[0].count = count;
		si->v[0].rel_offset = 0;
		si->v[0].buf = f_data + si->offset;
		si->v[0].fd = -1;
		si->v[0].b = NULL;
		offset += si->v[0].count;
		count -= si->v[0].count;
		si->nv++;
	}

	for (; count > 0; si->nv++) {
		if ((b = slab_at(oi, offset, 0, xerrz(e))) == NULL) {
			free(si->v);
			return -1;
		}

		slab_lock(b, LK_LOCK_RD);
		if ((b_size = slab_size(b, xerrz(e))) == -1) {
			slab_unlock(b);
			free(si->v);
			return -1;
		}
		if (offset % slab_get_max_size() < b_size) {
			slab_splice_fd(b, offset, count,
			    &si->v[si->nv].rel_offset,
			    &si->v[si->nv].count, &si->v[si->nv].fd, 0);
			slab_unlock(b);
			si->v[si->nv].buf = NULL;
			si->v[si->nv].b = b;
		} else {
			slab_unlock(b);
			if (slab_forget(b, xerrz(e)) == -1) {
				free(si->v);
				return -1;
			}
			/*
			 * Return zeroes if we don't have the bytes backing
			 * the file size in our slab, most likely as a result
			 * of fallocate().
			 */
			si->v[si->nv].count = (count > slab_get_max_size())
			    ? slab_get_max_size()
			    : count;
			si->v[si->nv].rel_offset = 0;
			si->v[si->nv].buf = slab_zeroes;
			si->v[si->nv].fd = -1;
			si->v[si->nv].b = NULL;
		}
		offset += si->v[si->nv].count;
		count -= si->v[si->nv].count;
	}
	return 0;
}

int
inode_splice_end_read(struct inode_splice_bufvec *si, struct xerr *e)
{
	for (; si->nv > 0; si->nv--)
		if (si->v[si->nv - 1].b != NULL &&
		    slab_forget(si->v[si->nv - 1].b, xerrz(e)) == -1)
			return -1;
	free(si->v);
	return 0;
}

int
inode_splice_begin_write(struct inode_splice_bufvec *si,
    struct oinode *oi, off_t offset, size_t count, struct xerr *e)
{
	char         *f_data = inode_data(&oi->ino);
	struct oslab *b;

	if (oi->oflags & INODE_ORO)
		return XERRF(e, XLOG_FS, EBADF,
		    "write attemped on read-only open inode %lu",
		    oi->ino.v.f.inode);

	si->oi = oi;
	si->offset = offset;
	si->nv = 0;
	si->v = calloc(count / slab_get_max_size() + 2,
	    sizeof(struct inode_splice_buf));
	if (si->v == NULL)
		return XERRF(e, XLOG_ERRNO, errno, "calloc");

	if (offset < INODE_INLINE_BYTES) {
		if (count > INODE_INLINE_BYTES - offset)
			si->v[0].count = INODE_INLINE_BYTES - offset;
		else
			si->v[0].count = count;
		si->v[0].rel_offset = 0;
		si->v[0].buf = f_data + si->offset;
		si->v[0].fd = -1;
		si->v[0].b = NULL;
		offset += si->v[0].count;
		count -= si->v[0].count;
		si->nv++;
	}

	for (; count > 0; si->nv++) {
		if ((b = slab_at(oi, offset, 0, xerrz(e))) == NULL) {
			free(si->v);
			return -1;
		}
		slab_lock(b, LK_LOCK_RW);
		slab_splice_fd(b, offset, count, &si->v[si->nv].rel_offset,
		    &si->v[si->nv].count, &si->v[si->nv].fd, 1);
		slab_unlock(b);
		si->v[si->nv].buf = NULL;
		si->v[si->nv].b = b;
		offset += si->v[si->nv].count;
		count -= si->v[si->nv].count;
	}
	return 0;
}

int
inode_splice_end_write(struct inode_splice_bufvec *si,
    size_t written, struct xerr *e)
{
	LK_WRLOCK(&si->oi->bytes_lock);
	if (inode_incr_size(si->oi, si->offset, written, xerrz(e)) == -1) {
		LK_UNLOCK(&si->oi->bytes_lock);
		goto fail;
	}
	if (si->offset < INODE_INLINE_BYTES) {
		si->oi->bytes_dirty = 1;
		LK_UNLOCK(&si->oi->bytes_lock);
		if ((si->oi->oflags & INODE_OSYNC) &&
		    inode_flush(si->oi, INODE_FLUSH_DATA_ONLY, xerrz(e)) == -1)
			goto fail;
	} else {
		LK_UNLOCK(&si->oi->bytes_lock);
	}

	for (; si->nv > 0; si->nv--) {
		if (si->v[si->nv - 1].b != NULL) {
			slab_lock(si->v[si->nv - 1].b, LK_LOCK_RW);
			slab_set_dirty(si->v[si->nv - 1].b);
			slab_unlock(si->v[si->nv - 1].b);
			if (slab_forget(si->v[si->nv - 1].b, xerrz(e)) == -1)
				goto fail;
		}
	}
	free(si->v);
	return 0;
fail:
	free(si->v);
	return -1;
}

/*
 * Inspect the inode fields and inline data.
 */
int
inode_disk_inspect(ino_t ino, struct inode *inode, struct xerr *e)
{
	struct oslab     b;
	char            *data;
	size_t           data_sz;
	struct slab_key  sk;

	bzero(inode, sizeof(struct inode));
	bzero(&b, sizeof(struct oslab));

	if ((data = slab_disk_inspect(slab_key(&sk, 0, ino), &b.hdr,
	    &data_sz, xerrz(e))) == NULL)
		return -1;

	if (slab_itbl_is_free(&b, ino)) {
		XERRF(e, XLOG_FS, ENOENT,
		    "no such inode allocated: %lu", ino);
		goto fail;
	}

	if ((data + (ino - b.hdr.v.f.key.base) + sizeof(struct inode) >
	    data + data_sz)) {
		XERRF(e, XLOG_APP, XLOG_IO,
		    "short read while reading inode %lu", ino);
		goto fail;
	}
	memcpy(inode, data + (ino - b.hdr.v.f.key.base) *
	    sizeof(struct inode), sizeof(struct inode));
	free(data);
	return 0;
fail:
	free(data);
	return -1;
}

int
inode_inspect(int mgr, ino_t ino, struct inode *inode, struct xerr *e)
{
	struct oslab     b;
	char            *data;
	size_t           data_sz;
	struct slab_key  sk;

	bzero(inode, sizeof(struct inode));
	bzero(&b, sizeof(struct oslab));

	if ((data = slab_inspect(mgr, slab_key(&sk, 0, ino),
	    OSLAB_NOCREATE|OSLAB_EPHEMERAL, &b.hdr, &data_sz, xerrz(e))) == NULL)
		return xerr_prepend(e, __func__);

	if (slab_itbl_is_free(&b, ino)) {
		XERRF(e, XLOG_FS, ENOENT,
		    "no such inode allocated: %lu", ino);
		goto fail;
	}

	if ((data + (ino - b.hdr.v.f.key.base) + sizeof(struct inode) >
	    data + data_sz)) {
		XERRF(e, XLOG_APP, XLOG_IO,
		    "short read while reading inode %lu", ino);
		goto fail;
	}
	memcpy(inode, data + (ino - b.hdr.v.f.key.base) *
	    sizeof(struct inode), sizeof(struct inode));
	free(data);
	return 0;
fail:
	free(data);
	return -1;
}
