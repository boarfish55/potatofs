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
#include "exlog.h"
#include "util.h"

static struct oinodes {
	/*
	 * The tree should contain inodes that have a refcnt greater than
	 * zero. However, for a short time after creation it is possible
	 * that it would be at zero until a dir_entry is created.
	 */
	SPLAY_HEAD(ino_tree, oinode) head;
	pthread_mutex_t                      lock;
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

static char *
inode_data(struct inode *ino)
{
	return ino->v.data + sizeof(struct inode_fields);
}

/*
 * Returns the slab storing data for a specific offset of an inode,
 * or NULL on error.
 */
static struct oslab *
slab_at(struct oinode *oi, off_t offset, uint32_t bflags,
    struct exlog_err *e)
{
	struct oslab *b;

	if (oi->oflags & INODE_OSYNC)
		bflags |= OSLAB_SYNC;
	if ((b = slab_load(oi->ino.v.f.inode, offset, 0,
	    bflags, e)) == NULL)
		return NULL;

	return b;
}

static struct oslab *
alloc_inode(ino_t *inode, struct exlog_err *e)
{
	ino_t         i, ino = 0, max_ino = 0;
	struct oslab *b;
	ino_t         bases[16];
	size_t        n_bases, n;

	/*
	 * Even though by the time we loop over it that itbl
	 * could be gone, it's somewhat unlikely. Worst cast it will
	 * be a bit slower to allocate that particular inode.
	 */
	n_bases = slab_itbls(bases, sizeof(bases) / sizeof(ino_t), e);
	if (n_bases == -1)
		return NULL;

	for (n = 0; n < n_bases; n++) {
		if ((b = slab_load_itbl(bases[n], LK_LOCK_RW, e)) == NULL)
			return NULL;
		ino = slab_find_free_inode(
		    (struct slab_itbl_hdr *)slab_hdr_data(b));
		if (ino > 0) {
			if (inode != NULL)
				*inode = ino;
			return b;
		}
		if (slab_close_itbl(b, e) == -1)
			return NULL;

		/* This is the highest inode we scanned, +1 */
		if (bases[n] + slab_inode_max() > max_ino)
			max_ino = bases[n] + slab_inode_max();
	}

	/*
	 * If we still haven't found a free inode, scan from the max.
	 */
	for (i = max_ino; i < ULONG_MAX; i += slab_inode_max()) {
		if ((b = slab_load_itbl(i, LK_LOCK_RW, e)) == NULL)
			return NULL;

		ino = slab_find_free_inode(
		    (struct slab_itbl_hdr *)slab_hdr_data(b));
		if (ino > 0) {
			if (inode != NULL)
				*inode = ino;
			return b;
		}

		if (slab_close_itbl(b, e) == -1)
			return NULL;
	}

	exlog_errf(e, EXLOG_APP, EXLOG_RES, "%s: unable to locate free "
	    "inode; we looped up to base %lu", __func__, i);
	return NULL;
}

int
inode_startup(struct exlog_err *e)
{
	if ((slab_zeroes = calloc(slab_get_max_size(), 1)) == NULL)
		return exlog_errf(e, EXLOG_OS, errno,
		    "%s: failed to allocate zeroes", __func__);
	return 0;
}

off_t
inode_max_inline_b()
{
	return sizeof(struct inode) - sizeof(struct inode_fields);
}

int
inode_dealloc(ino_t ino, struct exlog_err *e)
{
	struct oslab         *b;
	struct slab_itbl_hdr *hdr;
	struct exlog_err      e_close_tbl = EXLOG_ERR_INITIALIZER;

	b = slab_load_itbl(ino, LK_LOCK_RW, e);
	if (b == NULL)
		return -1;

	exlog_dbg(EXLOG_INODE, "deallocating inode %lu", ino);

	hdr = (struct slab_itbl_hdr *)slab_hdr_data(b);
	hdr->bitmap[(ino - hdr->base) / 32] &=
	    ~(1 << (32 - ino % 32));
	hdr->n_free++;
	slab_write_hdr(b, e);

	if (slab_close_itbl(b, &e_close_tbl) == -1) {
		fs_error_set();
		exlog(LOG_ERR, &e_close_tbl, __func__);
	}

	return exlog_fail(e);
}

off_t
inode_getsize(struct oinode *oi)
{
	off_t sz;

	LK_RDLOCK(&oi->bytes_lock);
	sz = oi->ino.v.f.size;
	LK_UNLOCK(&oi->bytes_lock);
	return sz;
}

static void
inode_set_bytes_dirty(struct oinode *oi)
{
	LK_WRLOCK(&oi->bytes_lock);
	oi->bytes_dirty = 1;
	LK_UNLOCK(&oi->bytes_lock);
}

static int
inode_incr_size(struct oinode *oi, off_t offset, off_t written,
    struct exlog_err *e)
{
	LK_WRLOCK(&oi->bytes_lock);

	if (written > ULLONG_MAX - offset) {
		LK_UNLOCK(&oi->bytes_lock);
		return exlog_errf(e, EXLOG_APP, EXLOG_OVERFLOW,
		    "%s: inode max size overflow: %lu", __func__,
		    oi->ino.v.f.inode);
	}

	if (oi->ino.v.f.size < offset + written) {
		oi->ino.v.f.size = offset + written;
		oi->ino.v.f.blocks = (offset + written) / 512 + 1;
		oi->bytes_dirty = 1;
	}
	LK_UNLOCK(&oi->bytes_lock);
	return 0;
}

int
inode_make(ino_t ino, uid_t uid, gid_t gid, mode_t mode,
    struct inode *dst, struct exlog_err *e)
{
	struct timespec       tp;
	struct inode          inode;
	struct oslab         *b;
	struct slab_itbl_hdr *hdr;
	ssize_t               r, w;
	struct exlog_err      e_close_tbl = EXLOG_ERR_INITIALIZER;

	/*
	 * If ino == 0 (that is, the caller expects us to pick an inode),
	 * we call alloc_inode(). Otherwise, just load the exact
	 * inode number and fill it up, if it's available.
	 */
	if (ino == 0)
		b = alloc_inode(&ino, e);
	else
		b = slab_load_itbl(ino, LK_LOCK_RW, e);

	if (b == NULL)
		return -1;

	hdr = (struct slab_itbl_hdr *)slab_hdr_data(b);
	if (!slab_inode_free(hdr, ino)) {
		exlog_errf(e, EXLOG_APP, EXLOG_EXIST,
		    "%s: inode already allocated: %lu", __func__, ino);
		goto fail;
	}

	/*
	 * We read previously allocated inode data here, if any,
	 * so we can increment the generation.
	 */
	r = slab_read(b, &inode,
	    (ino - hdr->base) * sizeof(struct inode), sizeof(inode), e);
	if (r == 0)
		bzero(&inode, sizeof(inode));
	else if (r < sizeof(inode)) {
		exlog_errf(e, EXLOG_APP, EXLOG_IO,
		    "%s: short read for inode: %lu", __func__, ino);
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
		exlog_errf(e, EXLOG_OS, errno,
		    "%s: failed to get time for inode creation", __func__);
		goto fail;
	}

	memcpy(&inode.v.f.atime, &tp, sizeof(inode.v.f.atime));
	memcpy(&inode.v.f.ctime, &tp, sizeof(inode.v.f.ctime));
	memcpy(&inode.v.f.mtime, &tp, sizeof(inode.v.f.mtime));

	if ((w = slab_write(b, &inode,
	    (ino - hdr->base) * sizeof(struct inode),
	    sizeof(struct inode), e)) == -1)
		goto fail;

	if (w < sizeof(struct inode)) {
		exlog_errf(e, EXLOG_APP, EXLOG_IO,
		    "%s: short write while saving inode %lu", __func__, ino);
		// TODO: corrupted at this point; maybe move to lost+found?
		goto fail;
	}

	hdr->bitmap[(ino - hdr->base) / 32] |=
	    (1 << (32 - ino % 32));
	hdr->n_free--;

	if (slab_write_hdr(b, e) == -1)
		goto fail;

	if (slab_close_itbl(b, e) == -1)
		return -1;

	if (dst != NULL)
		memcpy(dst, &inode, sizeof(struct inode));

	return 0;
fail:
	if (slab_close_itbl(b, &e_close_tbl) == -1) {
		fs_error_set();
		exlog(LOG_ERR, &e_close_tbl, __func__);
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

	// TODO: support devices ... Maybe?
	dst->st_rdev = ino->v.f.rdev;

	dst->st_size = ino->v.f.size;
	dst->st_blksize = FS_BLOCK_SIZE;
	dst->st_blocks = ino->v.f.blocks;
	memcpy(&dst->st_atim, &ino->v.f.atime, sizeof(dst->st_atim));
	memcpy(&dst->st_mtim, &ino->v.f.mtime, sizeof(dst->st_mtim));
	memcpy(&dst->st_ctim, &ino->v.f.ctime, sizeof(dst->st_ctim));
}

int
inode_cp_ino(ino_t ino, struct inode *inode, struct exlog_err *e)
{
	struct oinode *oi;

	if ((oi = inode_load(ino, 0, e)) == NULL)
		return -1;

	LK_RDLOCK(&oi->lock);
	LK_RDLOCK(&oi->bytes_lock);
	memcpy(inode, &oi->ino, sizeof(struct inode));
	LK_UNLOCK(&oi->bytes_lock);
	LK_UNLOCK(&oi->lock);

	if (inode_unload(oi, e) == -1)
		return -1;

	return 0;
}

/*
 * Must be called in write-lock.
 * See fallocate(2) for the 'mode' parameter.
 */
int
inode_fallocate(struct oinode *oi, off_t offset, off_t len,
    int mode, struct exlog_err *e)
{
	off_t old_size;
	int   done = 0;

	if (mode != 0)
		return exlog_errf(e, EXLOG_APP, EXLOG_OPNOTSUPP,
		    "%s: non-zero mode isn't support by fallocate() "
		    "at this time", __func__);

	LK_WRLOCK(&oi->bytes_lock);
	old_size = oi->ino.v.f.size;
	if (offset + len <= old_size)
		done = 1;
	LK_UNLOCK(&oi->bytes_lock);

	if (done)
		return 0;

	return inode_truncate(oi, offset + len, e);
}

/*
 * Also updates inode size by holding the size lock.
 */
int
inode_truncate(struct oinode *oi, off_t offset, struct exlog_err *e)
{
	char         *f_data = inode_data(&oi->ino);
	struct oslab *b;
	off_t         old_size, zero_start, c_off;

	LK_WRLOCK(&oi->bytes_lock);
	old_size = oi->ino.v.f.size;
	if (old_size == offset)
		goto end;

	/* Fill in inline data with zeroes. */
	zero_start = (old_size < offset) ? old_size : offset;
	if (zero_start < inode_max_inline_b())
		bzero(f_data + zero_start,
		    inode_max_inline_b() - zero_start);

	oi->bytes_dirty = 1;
	oi->ino.v.f.size = offset;
	oi->ino.v.f.blocks = offset / 512 + 1;

	/*
	 * Then ftruncate() or unlink() anything unnecessary in the backing
	 * files.
	 */
	for (c_off = offset; c_off <= old_size && !exlog_fail(e);
	    c_off += slab_get_max_size()) {
		b = slab_at(oi, c_off, OSLAB_NOCREATE, e);
		if (b == NULL) {
			if (!exlog_err_is(e, EXLOG_APP, EXLOG_NOENT)) {
				fs_error_set();
				exlog(LOG_ERR, e, __func__);
			}
			exlog_zerr(e);
			continue;
		}

		/*
		 * We only need to truncate the first file; trash the
		 * rest.
		 */
		if ((c_off / slab_get_max_size())
		    > (oi->ino.v.f.size / slab_get_max_size())
		    || (c_off % slab_get_max_size() == 0)) {
			if (slab_unlink(b, e) == -1) {
				fs_error_set();
				exlog(LOG_ERR, e, __func__);
				exlog_zerr(e);
			}
		} else {
			if (slab_truncate(b,
			    c_off % slab_get_max_size(), e) == -1) {
				fs_error_set();
				exlog(LOG_ERR, e, __func__);
				exlog_zerr(e);
			}
		}
		if (slab_forget(b, e) == -1) {
			fs_error_set();
			exlog(LOG_ERR, e, __func__);
			exlog_zerr(e);
		}
	}

	/*
	 * Create missing slabs if we're extending the file. This is
	 * necessary, even for sparse files, because when looking for
	 * slabs on the backend, other nodes cannot distinguish between
	 * a missing slab due to corruption or sparse file.
	 */
	for (c_off = old_size; c_off <= offset; c_off += slab_get_max_size()) {
		if ((b = slab_at(oi, c_off, 0, e)) == NULL)
			goto end;
		if (slab_forget(b, e) == -1)
			goto end;
	}
end:
	LK_UNLOCK(&oi->bytes_lock);
	return exlog_fail(e);
}

int
inode_setattr(struct oinode *oi, struct stat *st, uint32_t mask,
    struct exlog_err *e)
{
	if (mask & INODE_ATTR_SIZE) {
		if (inode_truncate(oi, st->st_size, e) == -1)
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

	inode_cp_stat(st, &oi->ino);
	return 0;
}

unsigned long
inode_nlookup(struct oinode *oi, int nlookup_incr)
{
	unsigned long prev;

	prev = oi->nlookup;
	oi->nlookup += nlookup_incr;

	exlog_dbg(EXLOG_INODE, "%s: ino=%lu (%p) nlookup: %lu => %lu",
	    __func__, oi->ino.v.f.inode, oi, prev, prev + nlookup_incr);

	return oi->nlookup;
}

int
inode_nlookup_ino(ino_t ino, int nlookup_incr, struct exlog_err *e)
{
	struct oinode *oi;

	if ((oi = inode_load(ino, 0, e)) == NULL)
		return -1;

	LK_WRLOCK(&oi->lock);
	inode_nlookup(oi, nlookup_incr);
	LK_UNLOCK(&oi->lock);

	if (inode_unload(oi, e) == -1)
		return -1;
	return 0;
}

nlink_t
inode_nlink(struct oinode *oi, int incr)
{
	oi->ino.v.f.nlink += incr;
	oi->dirty = 1;
	return oi->ino.v.f.nlink;
}

int
inode_nlink_ino(ino_t ino, int incr, struct exlog_err *e)
{
	struct oinode *oi;

	if ((oi = inode_load(ino, 0, e)) == NULL)
		return -1;

	LK_WRLOCK(&oi->lock);
	inode_nlink(oi, incr);
	LK_UNLOCK(&oi->lock);

	if (inode_unload(oi, e) == -1)
		return -1;
	return 0;
}

int
inode_isdir(struct oinode *oi)
{
	return (oi->ino.v.f.mode & S_IFDIR) ? 1 : 0;
}

struct oinode *
inode_load(ino_t ino, uint32_t oflags, struct exlog_err *e)
{
	int                   r;
	struct slab_itbl_hdr *hdr;
	struct oinode        *oi;
	struct oinode         needle;
	struct oslab         *b = NULL;
	struct exlog_err      e_close_itbl = EXLOG_ERR_INITIALIZER;

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
		exlog_dbg(EXLOG_INODE, "inode %d refcnt %d nlookup %d",
		    ino, oi->refcnt, oi->nlookup);
		MTX_UNLOCK(&open_inodes.lock);
		return oi;
	}

	if ((b = slab_load_itbl(ino, LK_LOCK_RD, e)) == NULL)
		goto end;

	hdr = (struct slab_itbl_hdr *)slab_hdr_data(b);
	if (slab_inode_free(hdr, ino)) {
		exlog_errf(e, EXLOG_APP, EXLOG_NOENT,
		    "%s: no such inode allocated: %lu", __func__, ino);
		goto fail_close_itbl;
	}

	if ((oi = malloc(sizeof(struct oinode))) == NULL) {
		exlog_errf(e, EXLOG_OS, errno, __func__);
		goto fail_close_itbl;
	}

	if (LK_LOCK_INIT(&oi->bytes_lock, e) == -1)
		goto fail_free_oi;
	if (LK_LOCK_INIT(&oi->lock, e) == -1)
		goto fail_destroy_bytes_lock;
	oi->nlookup = 0;
	oi->dirty = 0;
	oi->bytes_dirty = 0;
	oi->refcnt = 1;
	oi->oflags = oflags;
	exlog_dbg(EXLOG_INODE, "inode %d refcnt %d nlookup %d",
	    ino, oi->refcnt, oi->nlookup);

	r = slab_read(b, &oi->ino,
	    (ino - hdr->base) * sizeof(struct inode),
	    sizeof(struct inode), e);
	if (r == -1) {
		goto fail_destroy_lock;
	} else if (r < sizeof(struct inode)) {
		exlog_errf(e, EXLOG_APP, EXLOG_IO,
		    "%s: short read while reading inode %lu", __func__, ino);
		goto fail_destroy_lock;
	}

	if (oi->ino.v.f.mode & S_IFDIR)
		oi->oflags |= INODE_OSYNC;

	if (slab_close_itbl(b, e) == -1)
		goto fail_destroy_lock;

	if (SPLAY_INSERT(ino_tree, &open_inodes.head, oi) != NULL) {
		exlog_errf(e, EXLOG_APP, EXLOG_BUSY,
		    "%s: inode already loaded %lu", __func__, ino);
		goto fail_destroy_lock;
	}

	counter_incr(COUNTER_N_OPEN_INODES);

	goto end;
fail_destroy_lock:
	LK_LOCK_DESTROY(&oi->lock);
fail_destroy_bytes_lock:
	LK_LOCK_DESTROY(&oi->bytes_lock);
fail_free_oi:
	free(oi);
	oi = NULL;
fail_close_itbl:
	if (slab_close_itbl(b, &e_close_itbl) == -1)
		exlog(LOG_ERR, &e_close_itbl, __func__);
end:
	MTX_UNLOCK(&open_inodes.lock);
	exlog_dbg(EXLOG_INODE, "%s: ino=%lu (%p)", __func__, ino, oi);
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
 *     and nlookup fall to zero (refcnt should normally never get to zero
 *     if nlookup > 0).
 *   - Deallocate the inode if nlink == 0, as well as the above conditions.
 */
int
inode_unload(struct oinode *oi, struct exlog_err *e)
{
	struct oinode needle;
	ino_t         ino;

	MTX_LOCK(&open_inodes.lock);

	ino = oi->ino.v.f.inode;

	oi->refcnt--;
	exlog_dbg(EXLOG_INODE, "inode %d refcnt %d nlookup %d",
	    ino, oi->refcnt, oi->nlookup);

	if (oi->nlookup == 0) {
		bzero(&needle, sizeof(needle));
		needle.ino.v.f.inode = ino;

		if (oi->ino.v.f.nlink == 0) {
			if (inode_dealloc(ino, e) == -1)
				exlog(LOG_ERR, e, __func__);
			/*
			 * Truncate all file data, and we keep the slab header
			 * to update the slow backend in the background.
			 */
			if (inode_truncate(oi, 0, e) == -1)
				exlog(LOG_ERR, e, __func__);
		}

		if (oi->refcnt == 0) {
			if (inode_flush(oi, 0, e) == -1)
				goto end;

			SPLAY_REMOVE(ino_tree, &open_inodes.head, &needle);
			LK_LOCK_DESTROY(&oi->bytes_lock);
			LK_LOCK_DESTROY(&oi->lock);
			free(oi);
			oi = NULL;
			counter_decr(COUNTER_N_OPEN_INODES);
		}
	}
end:
	exlog_dbg(EXLOG_INODE, "%s: ino=%lu (%p)", __func__, ino, oi);
	MTX_UNLOCK(&open_inodes.lock);
	return exlog_fail(e);
}

/* Must be called in inode write-lock context. */
int
inode_sync(struct oinode *oi, struct exlog_err *e)
{
	off_t         offset, size;
	struct oslab *b;

	/*
	 * This should take care of syncing inode metadata and
	 * inline data.
	 */
	if (inode_flush(oi, 0, e) == -1)
		return -1;

	/* Nothing else to do, since we're O_SYNC */
	if (oi->oflags & INODE_OSYNC)
		return 0;

	size = inode_getsize(oi);

	if (size < inode_max_inline_b())
		return 0;

	/*
	 * Then sync any data living in subsequent slabs.
	 */
	for (offset = 0; !exlog_fail(e) && offset < size;
	    offset += slab_get_max_size()) {
		b = slab_at(oi, offset, OSLAB_NOCREATE, e);
		if (b == NULL) {
			if (exlog_err_is(e, EXLOG_APP, EXLOG_NOENT)) {
				exlog_zerr(e);
				continue;
			}
			return -1;
		}

		if (slab_sync(b, e) == -1) {
			fs_error_set();
			exlog(LOG_ERR, e, "%s: ino=%lu (%p)", __func__,
			    oi->ino, oi);
		}

		slab_forget(b, e);
	}
	return exlog_fail(e);
}

/*
 * Write inode to underlying file; if 'data_only' is non-zero,
 * we only write inline data, thus waiving the inode lock requirement.
 *
 * If data_only is 0, we flush the entire inode, both inline data and metadata,
 * meaning the caller must acquire the inode lock.
 *
 * We still get the bytes_lock, no matter what. This is typically called
 * on fd close().
 */
int
inode_flush(struct oinode *oi, int data_only, struct exlog_err *e)
{
	struct oslab         *b;
	ssize_t               s;
	struct slab_itbl_hdr *hdr;
	ino_t                 ino;
	off_t                 sz_off;

	LK_WRLOCK(&oi->bytes_lock);
	if (!oi->dirty && !oi->bytes_dirty) {
		LK_UNLOCK(&oi->bytes_lock);
		return 0;
	}

	ino = oi->ino.v.f.inode;

	if ((b = slab_load_itbl(ino, LK_LOCK_RW, e)) == NULL)
		return -1;

	hdr = (struct slab_itbl_hdr *)slab_hdr_data(b);

	if (data_only) {
		/*
		 * Syncing data only means it is safe to do so without the
		 * inode lock. Note that inode table slabs are always O_SYNC,
		 * so no need to fsync() after. Sadly, this will cause
		 * read-modify-write, but, hopefully one day we can do
		 * without O_SYNC for inodes.
		 *
		 * This will write the size (last field) plus the
		 * inline data that immediately follows.
		 */
		sz_off = (char *)&oi->ino.v.f.size - (char *)&oi->ino;
		if ((s = slab_write(b, &oi->ino.v.f.size,
		    ((ino - hdr->base) * sizeof(struct inode)) + sz_off,
		    sizeof(struct inode) - sz_off, e)) ==
		    (sizeof(struct inode) - sz_off))
			oi->bytes_dirty = 0;
	} else {
		if ((s = slab_write(b, &oi->ino,
		    (ino - hdr->base) * sizeof(struct inode),
		    sizeof(struct inode), e)) == sizeof(struct inode)) {
			oi->bytes_dirty = 0;
			oi->dirty = 0;
		}
	}
	LK_UNLOCK(&oi->bytes_lock);

	if (s == -1) {
		goto end;
	} else if (s < ((data_only)
	    ?  inode_max_inline_b()
	    : sizeof(struct inode))) {
		exlog_errf(e, EXLOG_APP, EXLOG_IO,
		    "%s: short write while saving inode %lu", __func__, ino);
		goto end;
	}

	exlog_dbg(EXLOG_INODE, "inode_flush: ino=%lu (%p)", ino, oi);
end:
	slab_close_itbl(b, e);
	// TODO: save to lost & found ?
	return exlog_fail(e);
}

void
inode_shutdown()
{
	struct oinode    *oi;
	struct exlog_err  e = EXLOG_ERR_INITIALIZER;

	for (;;) {
		MTX_LOCK(&open_inodes.lock);
		if ((oi = SPLAY_ROOT(&open_inodes.head)) == NULL) {
			MTX_UNLOCK(&open_inodes.lock);
			break;
		}

		if (oi->refcnt > 0)
			exlog(LOG_ERR, NULL, "forcibly freeing inode %lu "
			    "(nlookup=%lu, refcnt=%lu); lazy umount?",
			    oi->ino.v.f.inode, oi->nlookup, oi->refcnt);

		SPLAY_REMOVE(ino_tree, &open_inodes.head, oi);

		/* As per FUSE, nlookup becomes zero implicitly at unmount. */
		if (oi->ino.v.f.nlink == 0) {
			if (inode_dealloc(inode_ino(oi), &e) == -1)
				exlog(LOG_ERR, &e, __func__);
			/*
			 * Truncate all file data, and we keep the slab header
			 * to update the slow backend in the background.
			 */
			if (inode_truncate(oi, 0, &e) == -1)
				exlog(LOG_ERR, &e, __func__);
		}

		if (inode_flush(oi, 0, &e) == -1)
			exlog(LOG_ERR, &e, __func__);

		LK_LOCK_DESTROY(&oi->bytes_lock);
		LK_LOCK_DESTROY(&oi->lock);
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
    size_t count, struct exlog_err *e)
{
	size_t        c;
	char         *f_data = inode_data(&oi->ino);
	off_t         rel_offset;
	ssize_t       written = 0;
	ssize_t       w;
	struct oslab *b;

	if (oi->oflags & INODE_ORO)
		return exlog_errf(e, EXLOG_APP, EXLOG_BADF,
		    "%s: write attemped on read-only open inode %lu",
		    __func__, oi->ino.v.f.inode);

	if (offset < inode_max_inline_b()) {
		c = (count > inode_max_inline_b() - offset)
		    ? inode_max_inline_b() - offset
		    : count;
		memcpy(f_data + offset, buf, c);
		written += c;
		inode_set_bytes_dirty(oi);
		if (inode_incr_size(oi, offset, written, e) == -1)
			return -1;
		if ((oi->oflags & INODE_OSYNC) &&
		    inode_flush(oi, 1, e) == -1)
			return -1;
	}

	if (written == count)
		return written;

	/*
	 * We can restart from written = 0 since it's better to write
	 * a full aligned block. We waste a bit of space, but that's fine.
	 * Plus for files larger than what we can hold inline, I guess that
	 * means we have a backup copy? Yay I guess?
	 */
	for (written = 0; written < count; ) {
		b = slab_at(oi, offset + written, 0, e);
		if (b == NULL)
			return -1;

		rel_offset = (offset + written) % slab_get_max_size();
		c = (count - written > slab_get_max_size() - rel_offset)
		    ? slab_get_max_size() - rel_offset
		    : count - written;
		w = slab_write(b, buf + written, rel_offset, c, e);

		if (slab_forget(b, e) == -1)
			return -1;

		if (w == -1)
			return -1;

		written += w;
		if (inode_incr_size(oi, offset, written, e) == -1)
			return -1;

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
    size_t count, struct exlog_err *e)
{
	size_t        c;
	char         *f_data = inode_data(&oi->ino);
	off_t         rel_offset, size;
	ssize_t       rd = 0;
	ssize_t       r;
	struct oslab *b;

	size = inode_getsize(oi);

	if (offset >= size)
		return 0;

	if (offset + count > size)
		count = size - offset;

	if (offset < inode_max_inline_b()) {
		c = (count > inode_max_inline_b() - offset)
		    ? inode_max_inline_b() - offset
		    : count;
		memcpy(buf, f_data + offset, c);
		rd += c;
	}

	if (rd == count)
		return rd;

	while (rd < count) {
		b = slab_at(oi, offset + rd, 0, e);
		if (b == NULL)
			return -1;

		rel_offset = (offset + rd) % slab_get_max_size();
		c = (count - rd > slab_get_max_size() - rel_offset)
		    ? slab_get_max_size() - rel_offset
		    : count - rd;
		r = slab_read(b, buf + rd, rel_offset, c, e);

		if (slab_forget(b, e) == -1)
			return -1;

		if (r == -1) {
			return -1;
		} else if (r == 0) {
			/*
			 * If a file was truncated or allocated to a longer
			 * size, we haven't created the backing bytes yet.
			 * So just return zeroes.
			 */
			size = inode_getsize(oi);
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
    struct oinode *oi, off_t offset, size_t count, struct exlog_err *e)
{
	char         *f_data = inode_data(&oi->ino);
	off_t         size, b_size;
	struct oslab *b;

	size = inode_getsize(oi);

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
		return exlog_errf(e, EXLOG_OS, errno, __func__);

	if (offset < inode_max_inline_b()) {
		if (count > inode_max_inline_b() - offset)
			si->v[0].count = inode_max_inline_b() - offset;
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
		if ((b = slab_at(oi, offset, 0, e)) == NULL) {
			free(si->v);
			return -1;
		}
		if ((b_size = slab_size(b, e)) == -1) {
			free(si->v);
			return -1;
		}
		if (offset % slab_get_max_size() < b_size) {
			slab_splice_fd(b, offset, count,
			    &si->v[si->nv].rel_offset,
			    &si->v[si->nv].count, &si->v[si->nv].fd, 0);
			si->v[si->nv].buf = NULL;
			si->v[si->nv].b = b;
		} else {
			if (slab_forget(b, e) == -1) {
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
inode_splice_end_read(struct inode_splice_bufvec *si, struct exlog_err *e)
{
	for (; si->nv > 0; si->nv--)
		if (si->v[si->nv - 1].b != NULL &&
		    slab_forget(si->v[si->nv - 1].b, e) == -1)
			return -1;
	free(si->v);
	return 0;
}

int
inode_splice_begin_write(struct inode_splice_bufvec *si,
    struct oinode *oi, off_t offset, size_t count, struct exlog_err *e)
{
	char         *f_data = inode_data(&oi->ino);
	struct oslab *b;

	if (oi->oflags & INODE_ORO)
		return exlog_errf(e, EXLOG_APP, EXLOG_BADF,
		    "%s: write attemped on read-only open inode %lu",
		    __func__, oi->ino.v.f.inode);

	si->oi = oi;
	si->offset = offset;
	si->nv = 0;
	si->v = calloc(count / slab_get_max_size() + 2,
	    sizeof(struct inode_splice_buf));
	if (si->v == NULL)
		return exlog_errf(e, EXLOG_OS, errno, __func__);

	if (offset < inode_max_inline_b()) {
		if (count > inode_max_inline_b() - offset)
			si->v[0].count = inode_max_inline_b() - offset;
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
		if ((b = slab_at(oi, offset, 0, e)) == NULL) {
			free(si->v);
			return -1;
		}
		slab_splice_fd(b, offset, count, &si->v[si->nv].rel_offset,
		    &si->v[si->nv].count, &si->v[si->nv].fd, 1);
		si->v[si->nv].buf = NULL;
		si->v[si->nv].b = b;
		offset += si->v[si->nv].count;
		count -= si->v[si->nv].count;
	}
	return 0;
}

int
inode_splice_end_write(struct inode_splice_bufvec *si,
    size_t written, struct exlog_err *e)
{
	if (inode_incr_size(si->oi, si->offset, written, e) == -1)
		goto fail;

	for (; si->nv > 0; si->nv--) {
		if (si->v[si->nv - 1].b != NULL) {
			slab_set_dirty(si->v[si->nv - 1].b);
			if (slab_forget(si->v[si->nv - 1].b, e) == -1)
				goto fail;
		}
	}

	if (si->offset < inode_max_inline_b()) {
		inode_set_bytes_dirty(si->oi);
		if ((si->oi->oflags & INODE_OSYNC) &&
		    inode_flush(si->oi, 1, e) == -1)
			goto fail;
	}

	free(si->v);
	return 0;
fail:
	free(si->v);
	return -1;
}

int
inode_inspect(ino_t ino, struct inode *inode, struct exlog_err *e)
{
	struct slab_itbl_hdr *itbl_hdr;
	struct slab_hdr       hdr;
	char                 *data;
	ssize_t               data_sz;

	bzero(inode, sizeof(struct inode));

	if ((data = slab_inspect(ino, 0, SLAB_ITBL, OSLAB_NOCREATE, &hdr,
	    &data_sz, e)) == NULL)
		return -1;

	itbl_hdr = (struct slab_itbl_hdr *)hdr.v.f.data;
	if (itbl_hdr->base == 0) {
		bzero(itbl_hdr->bitmap, sizeof(itbl_hdr->bitmap));
		itbl_hdr->n_free = slab_inode_max();
		itbl_hdr->base = ((ino - 1) / slab_inode_max()) *
		    slab_inode_max() + 1;
	}

	if (slab_inode_free(itbl_hdr, ino)) {
		exlog_errf(e, EXLOG_APP, EXLOG_NOENT,
		    "%s: no such inode allocated: %lu", __func__, ino);
		goto fail;
	}

	if ((data + (ino - itbl_hdr->base) + sizeof(struct inode) >
	    data + data_sz)) {
		exlog_errf(e, EXLOG_APP, EXLOG_IO,
		    "%s: short read while reading inode %lu", __func__, ino);
		goto fail;
	}
	memcpy(inode, data + (ino - itbl_hdr->base) * sizeof(struct inode),
	    sizeof(struct inode));
	free(data);
	return 0;
fail:
	free(data);
	return -1;
}
