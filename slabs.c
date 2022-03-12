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

#include <sys/file.h>
#include <sys/resource.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"
#include "counters.h"
#include "fs_error.h"
#include "fs_info.h"
#include "inodes.h"
#include "xlog.h"
#include "mgr.h"
#include "slabs.h"

static struct {
	/*
	 * Opened slabs are those that have an open file descriptor
	 * and possibly getting reads/writes.
	 */
	SPLAY_HEAD(slab_tree, oslab) head;

	/*
	 * Least recently used slabs. All slabs in this list should
	 * have a refcnt of 0.
	 */
	TAILQ_HEAD(slab_lru, oslab)  lru_head;

	/*
	 * Keep track of in-memory slabs that are actually inode tables.
	 * This is used during inode allocation to avoid having to look
	 * on-disk if we already have inode tables in memory that might
	 * have free inodes.
	 */
	TAILQ_HEAD(slab_itbl, oslab) itbl_head;

	pthread_mutex_t lock;
	rlim_t          max_open;
	int             do_shutdown;

	/*
	 * Slabs that have been opened for that many seconds will
	 * be closed by the background "flusher" threads, or on the next
	 * forget for that slab.
	 */
	time_t          max_age;
} owned_slabs = {
	SPLAY_INITIALIZER(&owned_slabs.head),
	TAILQ_HEAD_INITIALIZER(owned_slabs.lru_head),
	TAILQ_HEAD_INITIALIZER(owned_slabs.itbl_head),
	PTHREAD_MUTEX_INITIALIZER,
	0,
	0,
	0
};

static pthread_t slab_purger;

static int
slab_cmp(struct oslab *b1, struct oslab *b2)
{
	if (b1->hdr.v.f.key.ino < b2->hdr.v.f.key.ino)
		return -1;
	if (b1->hdr.v.f.key.ino > b2->hdr.v.f.key.ino)
		return 1;
	if (b1->hdr.v.f.key.base < b2->hdr.v.f.key.base)
		return -1;
	if (b1->hdr.v.f.key.base > b2->hdr.v.f.key.base)
		return 1;
	return 0;
}

SPLAY_PROTOTYPE(slab_tree, oslab, entry, slab_cmp);
SPLAY_GENERATE(slab_tree, oslab, entry, slab_cmp);

int
slab_read_hdr(struct oslab *b, struct xerr *e)
{
	ssize_t r;
	if ((r = pread_x(b->fd, &b->hdr, sizeof(b->hdr), 0)) < sizeof(b->hdr)) {
		if (r == -1)
			return XERRF(e, XLOG_ERRNO, errno,
			    "short read on slab header");
		return XERRF(e, XLOG_APP, XLOG_SHORTIO,
		    "short read on slab header; read %d bytes", r);
	}
	return 0;
}

/*
 * Should be called *before* any writes. If we die before the write,
 * happens, there is little harm. We'll just sync a slab with no changes.
 * The opposite could result in local changes that are never synced to the
 * backend.
 */
static int
slab_set_dirty_hdr(struct oslab *b, struct xerr *e)
{
	LK_WRLOCK(&b->lock);
	if (!(b->hdr.v.f.flags & SLAB_DIRTY)) {
		if (slab_write_hdr_nolock(b, e) == -1) {
			LK_UNLOCK(&b->lock);
			return -1;
		}
	}
	LK_UNLOCK(&b->lock);
	return 0;
}

/* Must be called in write-lock context */
static int
slab_realloc(struct oslab *b, struct xerr *e)
{
	if ((ftruncate(b->fd, sizeof(b->hdr))) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "ftruncate");
	b->hdr.v.f.flags &= ~SLAB_REMOVED;
	if (slab_write_hdr_nolock(b, e) == -1)
		return -1;
	return 0;
}

/*
 * Disown must be called when no other thread is able to lookup
 * the slab. Essentially, when the slab isn't referenced in owned_slabs,
 * or when destroying the slab tree.
 */
static void
slab_unclaim(struct oslab *b)
{
	struct xerr     e = XLOG_ERR_INITIALIZER;
	int             mgr = -1;
	struct mgr_msg  m;
	struct timespec tp = {1, 0};

	if (b->fd == -1) {
		xlog(LOG_ERR, NULL, "%s: fd is -1", __func__);
		fs_error_set();
		return;
	}

	for (;;) {
		if ((mgr = mgr_connect(1, &e)) == -1) {
			xlog(LOG_ERR, &e, __func__);
			goto fail;
		}

		m.m = MGR_MSG_UNCLAIM;
		memcpy(&m.v.unclaim.key, &b->hdr.v.f.key,
		    sizeof(struct slab_key));

		if (mgr_send(mgr, b->fd, &m, &e) == -1) {
			xlog(LOG_ERR, &e, "%s", __func__);
			goto fail;
		}

		if (mgr_recv(mgr, NULL, &m, &e) == -1) {
			xlog(LOG_ERR, &e, "%s", __func__);
			goto fail;
		}

		if (m.m != MGR_MSG_UNCLAIM_OK) {
			xlog(LOG_ERR, NULL, "%s: bad manager response %d "
			    "for slab sk=%lu/%lu",
			    __func__, m.m, b->hdr.v.f.key.ino,
			    b->hdr.v.f.key.base);
			goto fail;
		} else if (memcmp(&m.v.unclaim.key, &b->hdr.v.f.key,
		    sizeof(struct slab_key))) {
			/* We close the fd here to avoid deadlocks. */
			close(b->fd);
			xlog(LOG_ERR, NULL,
			    "%s: bad manager response for unclaim; "
			    "ino: expected=%lu, received=%lu"
			    "base: expected=%lu, received=%lu", __func__,
			    b->hdr.v.f.key.ino, m.v.unclaim.key.ino,
			    b->hdr.v.f.key.base, m.v.unclaim.key.base);
			goto fail;
		}

		close(mgr);
		close(b->fd);
		LK_LOCK_DESTROY(&b->lock);
		LK_LOCK_DESTROY(&b->bytes_lock);
		free(b);
		return;
fail:
		/*
		 * Disowning is important and hard to recover from
		 * in case of failure. Loop until things recover,
		 * or until an external action is taken.
		 */
		if (mgr != -1)
			close(mgr);
		fs_error_set();
		nanosleep(&tp, NULL);
	}
}

static void *
slab_purge(void *unused)
{
	struct oslab    *b, *b2;
	struct timespec  now, t = {10, 0};
	struct statvfs   stv;
	int              purge;

	while (!owned_slabs.do_shutdown) {
		for (;;) {
			if (nanosleep(&t, NULL) == 0)
				break;
		}

		if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
			fs_error_set();
			xlog_strerror(LOG_ERR, errno,
			    "%s: failed to get current time", __func__);
			continue;
		}

		purge = 0;
		if (statvfs(fs_config.data_dir, &stv) == -1) {
			xlog_strerror(LOG_ERR, errno, "%s: statvfs", __func__);
		} else {
			if (stv.f_bfree < stv.f_blocks *
			    (100 - fs_config.unclaim_purge_threshold_pct) / 100)
				/*
				 * Purge more aggressively if we're are getting
				 * tight on space.
				 */
				purge = 1;
		}

		MTX_LOCK(&owned_slabs.lock);
		b = TAILQ_FIRST(&owned_slabs.lru_head);
		while (b != NULL) {
			if (!purge && (now.tv_sec <
			    (b->open_since.tv_sec + owned_slabs.max_age)))
				break;
			b2 = TAILQ_NEXT(b, lru_entry);
			xlog_dbg(XLOG_SLAB, "%s: purging slab%s, "
			    "ino=%lu, base=%lu", __func__,
			    (purge) ? " (forced)" : "",
			    b->hdr.v.f.key.ino, b->hdr.v.f.key.base);
			SPLAY_REMOVE(slab_tree, &owned_slabs.head, b);
			TAILQ_REMOVE(&owned_slabs.lru_head, b, lru_entry);
			if (!b->hdr.v.f.key.ino)
				TAILQ_REMOVE(&owned_slabs.itbl_head, b,
				    itbl_entry);
			slab_unclaim(b);
			counter_decr(COUNTER_N_OPEN_SLABS);
			b = b2;
		}
		MTX_UNLOCK(&owned_slabs.lock);
	}
	return NULL;
}

void
slab_set_dirty(struct oslab *b)
{
	if (b->oflags & OSLAB_SYNC)
		return;

	LK_WRLOCK(&b->lock);
	b->dirty = 1;
	LK_UNLOCK(&b->lock);
}

int
slab_write_hdr_nolock(struct oslab *b, struct xerr *e)
{
	b->hdr.v.f.flags |= SLAB_DIRTY;
	if (pwrite_x(b->fd, &b->hdr, sizeof(b->hdr), 0) < sizeof(b->hdr))
		return XERRF(e, XLOG_ERRNO, errno,
		    "short write on slab header");
	if (!(b->oflags & OSLAB_SYNC))
		b->dirty = 1;
	return 0;
}

int
slab_write_hdr(struct oslab *b, struct xerr *e)
{
	LK_WRLOCK(&b->lock);
	if (slab_write_hdr_nolock(b, e) == -1) {
		LK_UNLOCK(&b->lock);
		return -1;
	}
	LK_UNLOCK(&b->lock);
	return 0;
}

void *
slab_hdr_data(struct oslab *b)
{
	return b->hdr.v.f.data;
}

/*
 * Loop over all local slabs, that is:
 *    - All inode tables
 *    - All slabs in the hashed dirs
 */
int
slab_loop_files(void (*fn)(const char *), struct xerr *e)
{
	char           path[PATH_MAX], f[PATH_MAX];
	int            i;
	DIR           *dir;
	struct dirent *de;

	if (snprintf(path, sizeof(path), "%s/%s", fs_config.data_dir, ITBL_DIR)
	    >= sizeof(path))
		return XERRF(e, XLOG_APP, XLOG_NAMETOOLONG,
		    "bad inode table dir; too long");

	if ((dir = opendir(path)) == NULL)
		return XERRF(e, XLOG_ERRNO, errno, "opendir");
	while ((de = readdir(dir))) {
		if (de->d_name[0] == '.')
			continue;
		if (snprintf(f, sizeof(f), "%s/%s", path,
		    de->d_name) >= sizeof(f)) {
			xlog(LOG_ERR, NULL, "%s: name too long", __func__);
			goto fail_closedir;
		}
		fn(f);
	}
	closedir(dir);

	for (i = 0; i < SLAB_DIRS; i++) {
		if (snprintf(path, sizeof(path), "%s/%02x",
		    fs_config.data_dir, i) >= sizeof(path))
			return XERRF(e, XLOG_APP, XLOG_NAMETOOLONG,
			    "bad slab dir; too long");
		if ((dir = opendir(path)) == NULL)
			return XERRF(e, XLOG_ERRNO, errno, "opendir");
		while ((de = readdir(dir))) {
			if (de->d_name[0] == '.')
				continue;
			if (snprintf(f, sizeof(f), "%s/%s", path,
			    de->d_name) >= sizeof(f)) {
				xlog(LOG_ERR, NULL, "%s: name too long",
				    __func__);
				goto fail_closedir;
			}
			fn(f);
		}
		closedir(dir);
	}
	return 0;
fail_closedir:
	closedir(dir);
	return -1;
}

int
slab_make_dirs(struct xerr *e)
{
	char path[PATH_MAX];
	int  i;

	if (snprintf(path, sizeof(path), "%s/%s", fs_config.data_dir, ITBL_DIR)
	    >= sizeof(path))
		return XERRF(e, XLOG_APP, XLOG_NAMETOOLONG,
		    "bad inode table dir; too long");
	if (mkdir_x(path, 0700) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "mkdir_x");

	if (snprintf(path, sizeof(path), "%s/%s",
	    fs_config.data_dir, OUTGOING_DIR) >= sizeof(path))
		return XERRF(e, XLOG_APP, XLOG_NAMETOOLONG,
		    "bad inode table dir; too long");
	if (mkdir_x(path, 0700) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "mkdir_x");

	if (snprintf(path, sizeof(path), "%s/%s",
	    fs_config.data_dir, INCOMING_DIR) >= sizeof(path))
		return XERRF(e, XLOG_APP, XLOG_NAMETOOLONG,
		    "bad inode table dir; too long");
	if (mkdir_x(path, 0700) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "mkdir_x");

	for (i = 0; i < SLAB_DIRS; i++) {
		if (snprintf(path, sizeof(path), "%s/%02x",
		    fs_config.data_dir, i) >= sizeof(path))
			return XERRF(e, XLOG_APP, XLOG_NAMETOOLONG,
			    "bad slab dir; too long");
		if (mkdir_x(path, 0700) == -1)
			return XERRF(e, XLOG_ERRNO, errno, "mkdir_x");
	}

	return 0;
}

int
slab_configure(rlim_t max_open, time_t max_age, struct xerr *e)
{
	int            r;
	pthread_attr_t attr;
	struct rlimit  nofile, locks;

	owned_slabs.max_open = max_open;

	/*
	 * Keep a few descriptors for other things, such as the
	 * stats FIFO, communication with the mgr, the fuse channel,
	 * syslog. It seems like FUSE is using a few FIFOs under the hood
	 * too.
	 */
	if (getrlimit(RLIMIT_NOFILE, &nofile) == -1)
		return XERRF(e, XLOG_ERRNO, errno,
		    "failed to get RLIMIT_NOFILE");
	if (nofile.rlim_cur != RLIM_INFINITY &&
	    nofile.rlim_cur < owned_slabs.max_open + 100) {
		nofile.rlim_cur = owned_slabs.max_open + 100;
		if (setrlimit(RLIMIT_NOFILE, &nofile) == -1) {
			return XERRF(e, XLOG_ERRNO, errno,
			    "could not increase RLIMIT_NOFILE to %lu",
			    nofile.rlim_cur);
		}
	}

	if (getrlimit(RLIMIT_LOCKS, &locks) == -1)
		return XERRF(e, XLOG_ERRNO, errno,
		    "failed to get RLIMIT_LOCKS");
	if (locks.rlim_cur != RLIM_INFINITY &&
	    locks.rlim_cur < owned_slabs.max_open) {
		locks.rlim_cur = owned_slabs.max_open;
		if (setrlimit(RLIMIT_LOCKS, &locks) == -1) {
			return XERRF(e, XLOG_ERRNO, errno,
			    "could not increase RLIMIT_LOCKS to %lu",
			    locks.rlim_cur);
		}
	}

	owned_slabs.max_age = (max_age == 0) ? owned_slabs.max_age : max_age;

	xlog(LOG_NOTICE, NULL, "max open slabs is %lu (RLIMIT_NOFILE is %u, "
	    "RLIMIT_LOCKS is %u)", owned_slabs.max_open, nofile.rlim_cur,
	    locks.rlim_cur);
	xlog(LOG_NOTICE, NULL, "slab max age is %lu seconds",
	    owned_slabs.max_age);

	if ((r = pthread_attr_init(&attr)) != 0)
		return XERRF(e, XLOG_ERRNO, r, "pthread_attr_init");
	if ((r = pthread_create(&slab_purger, &attr,
	    &slab_purge, NULL)) != 0)
		return XERRF(e, XLOG_ERRNO, r, "pthread_create");
	return 0;
}

/*
 * Holds a lock on the returned slab. If the function fails, it
 * is guaranteed that it will not be holding a lock.
 * An inode lock must never be acquired while holding the itbl lock.
 */
struct oslab *
slab_load_itbl(const struct slab_key *sk, rwlk_flags lkf, struct xerr *e)
{
	struct oslab         *b;
	struct slab_itbl_hdr *ihdr;

	if (!(lkf & (LK_LOCK_RD|LK_LOCK_RW))) {
		XERRF(e, XLOG_APP, XLOG_INVAL,
		    "neither read nor write lock requested");
		return NULL;
	}

	if ((b = slab_load(sk, OSLAB_SYNC, e)) == NULL)
		return NULL;

	ihdr = (struct slab_itbl_hdr *)slab_hdr_data(b);

	LK_LOCK(&b->bytes_lock, LK_LOCK_RW);
	if (ihdr->initialized == 0) {
		ihdr->initialized = 1;
		bzero(ihdr->bitmap, sizeof(ihdr->bitmap));
		ihdr->n_free = slab_inode_max();
	}
	LK_UNLOCK(&b->bytes_lock);

	LK_LOCK(&b->bytes_lock, lkf);

	return b;
}

int
slab_close_itbl(struct oslab *b, struct xerr *e)
{
	LK_UNLOCK(&b->bytes_lock);
	return slab_forget(b, e);
}

ino_t
slab_itbl_find_unallocated(struct oslab *b)
{
	int                   i;
	uint32_t             *p;
	uint32_t              mask;
	struct slab_itbl_hdr *ihdr = (struct slab_itbl_hdr *)slab_hdr_data(b);


	if (ihdr->n_free == 0)
		return 0;
	for (p = ihdr->bitmap;
	    p - ihdr->bitmap < (slab_inode_max() / 32); p++) {
		if (*p == 0xFFFFFFFF)
			continue;
		for (i = 1; i <= 32; i++) {
			mask = 1 << (32 - i);
			if ((*p & mask) == 0)
				return (p - ihdr->bitmap) * 32 + i +
				    (b->hdr.v.f.key.base - 1);
		}
	}
	return 0;
}

int
slab_itbl_is_free(struct oslab *b, ino_t ino)
{
	struct slab_itbl_hdr *ihdr = (struct slab_itbl_hdr *)slab_hdr_data(b);
	return !(ihdr->bitmap[(ino - b->hdr.v.f.key.base) / 32]
	    & (1 << (32 - ino % 32)));
}

void
slab_itbl_alloc(struct oslab *b, ino_t ino)
{
	struct slab_itbl_hdr *ihdr = (struct slab_itbl_hdr *)slab_hdr_data(b);
	ihdr->bitmap[(ino - b->hdr.v.f.key.base) / 32] |=
	    (1 << (32 - ino % 32));
	ihdr->n_free--;
}

void
slab_itbl_dealloc(struct oslab *b, ino_t ino)
{
	struct slab_itbl_hdr *ihdr = (struct slab_itbl_hdr *)slab_hdr_data(b);
	ihdr->bitmap[(ino - b->hdr.v.f.key.base) / 32] &=
	    ~(1 << (32 - ino % 32));
	ihdr->n_free++;
}

off_t
slab_get_max_size()
{
	return fs_config.slab_size;
}

ino_t
slab_inode_max()
{
	return fs_config.slab_size / sizeof(struct inode);
}

struct slab_key *
slab_key(struct slab_key *sk, ino_t ino, off_t base)
{
	bzero(sk, sizeof(struct slab_key));
	if (ino == 0) {
		sk->base = (base - 1) - ((base - 1) % slab_inode_max()) + 1;
	} else {
		sk->ino = ino;
		sk->base = base - (base % slab_get_max_size());
	}
	return sk;
}

int
slab_key_valid(const struct slab_key *sk, struct xerr *e)
{
	if (sk->base > SLAB_KEY_MAX || sk->base < 0)
		return XERRF(e, XLOG_APP, XLOG_INVAL,
		    "base %ld is out of range", sk->base);
	if (sk->ino > SLAB_KEY_MAX)
		return XERRF(e, XLOG_APP, XLOG_INVAL,
		    "ino %lu is out of range", sk->ino);
	if (sk->ino == 0) {
		if (sk->base < 1)
			return XERRF(e, XLOG_APP, XLOG_INVAL,
			    "base is less than 1 for an inode table");
		if ((sk->base - 1) % slab_inode_max() != 0)
			return XERRF(e, XLOG_APP, XLOG_INVAL,
			    "inode table has base %lu that does not fall "
			    "on a multiple of slab_inode_max() plus one (%lu)",
			    sk->base, slab_inode_max());
	} else {
		if (sk->base % slab_get_max_size() != 0)
			return XERRF(e, XLOG_APP, XLOG_INVAL,
			    "inode %lu has base %lu that is not a multiple "
			    "of slab_get_max_size() (%lu)",
			    sk->ino, sk->base, slab_get_max_size());
	}
	return 0;
}

int
slab_shutdown(struct xerr *e)
{
	struct oslab *b, *next;
	int           r;

	MTX_LOCK(&owned_slabs.lock);
	for (b = SPLAY_MIN(slab_tree, &owned_slabs.head); b != NULL; b = next) {
		next = SPLAY_NEXT(slab_tree, &owned_slabs.head, b);
		if (b->refcnt != 0)
			xlog(LOG_ERR, NULL, "%s: slab has non-zero refcnt: "
			    "ino=%lu, base=%lu, refcnt %d",
			    __func__, b->hdr.v.f.key.ino,
			    b->hdr.v.f.key.base, b->refcnt);
		else
			TAILQ_REMOVE(&owned_slabs.lru_head, b, lru_entry);
		SPLAY_REMOVE(slab_tree, &owned_slabs.head, b);
		if (!b->hdr.v.f.key.ino)
			TAILQ_REMOVE(&owned_slabs.itbl_head, b, itbl_entry);
		slab_unclaim(b);
		counter_decr(COUNTER_N_OPEN_SLABS);
	}
	owned_slabs.do_shutdown = 1;
	MTX_UNLOCK(&owned_slabs.lock);

	if ((r = pthread_join(slab_purger, NULL)) != 0)
		return XERRF(e, XLOG_ERRNO, r, "pthread_join");
	return 0;
}

int
slab_path(char *path, size_t len, const struct slab_key *sk, int name_only,
    struct xerr *e)
{
	size_t l;

	if (slab_key_valid(sk, e) == -1)
		return -1;
	if (name_only) {
		if (sk->ino == 0) {
			l = snprintf(path, len, "%s%020ld", ITBL_PREFIX,
			    sk->base);
		} else {
			l = snprintf(path, len, "%s%020lu-%020ld",
			    SLAB_PREFIX, sk->ino, sk->base);
		}
	} else {
		if (sk->ino == 0) {
			l = snprintf(path, len, "%s/%s/%s%020lu",
			    fs_config.data_dir, ITBL_DIR, ITBL_PREFIX,
			    sk->base);
		} else {
			l = snprintf(path, len, "%s/%02lx/%s%020lu-%020ld",
			    fs_config.data_dir, sk->ino % SLAB_DIRS,
			    SLAB_PREFIX, sk->ino, sk->base);
		}
	}

	if (l >= len)
		return XERRF(e, XLOG_APP, XLOG_NAMETOOLONG,
		    "bad inode table name; too long");
	return 0;
}

int
slab_parse_path(const char *path, struct slab_key *sk, struct xerr *e)
{
	char p[PATH_MAX];

	bzero(sk, sizeof(struct slab_key));
	strlcpy(p, path, sizeof(p));
	if (strncmp(basename(p), ITBL_PREFIX, 1) == 0) {
		sk->ino = 0;
		if (sscanf(basename(p), ITBL_PREFIX "%020ld",
		    &sk->base) < 1)
			return XERRF(e, XLOG_APP, XLOG_INVAL,
			    "unparseable itbl slab name %s", path);
	} else {
		if (sscanf(basename(p), SLAB_PREFIX "%020lu-%020ld",
		    &sk->ino, &sk->base) < 2)
			return XERRF(e, XLOG_APP, XLOG_INVAL,
			    "unparseable slab name %s", path);
	}
	return slab_key_valid(sk, e);
}

struct oslab *
slab_load(const struct slab_key *sk, uint32_t oflags, struct xerr *e)
{
	struct oslab    *b, needle;
	struct oslab    *purged;
	struct timespec  t = {5, 0};
	int              mgr = -1;
	struct mgr_msg   m;

	if (slab_key_valid(sk, e) == -1)
		return NULL;

	memcpy(&needle.hdr.v.f.key, sk, sizeof(struct slab_key));

	MTX_LOCK(&owned_slabs.lock);

	if ((b = SPLAY_FIND(slab_tree, &owned_slabs.head, &needle)) != NULL) {
		/*
		 * No need to check for NOCREATE, because if it's loaded
		 * it must already have been created.
		 */
		LK_WRLOCK(&b->lock);
		if (b->hdr.v.f.flags & SLAB_REMOVED) {
			if (slab_realloc(b, e) == -1) {
				LK_UNLOCK(&b->lock);
				b = NULL;
				goto end;
			}
		}
		LK_UNLOCK(&b->lock);
		if (b->refcnt == 0)
			TAILQ_REMOVE(&owned_slabs.lru_head, b, lru_entry);
		b->refcnt++;
		goto end;
	}

	if ((b = malloc(sizeof(struct oslab))) == NULL) {
		XERRF(e, XLOG_ERRNO, errno, "malloc");
		goto end;
	}

	if (clock_gettime(CLOCK_MONOTONIC, &b->open_since) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "clock_gettime");
		goto fail_free_b;
	}

	b->oflags = oflags;

	if (LK_LOCK_INIT(&b->bytes_lock, e) == -1)
		goto fail_free_b;
	if (LK_LOCK_INIT(&b->lock, e) == -1)
		goto fail_destroy_bytes_lock;

	if ((mgr = mgr_connect(1, e)) == -1)
		goto fail_destroy_locks;

	m.m = MGR_MSG_CLAIM;
	memcpy(&m.v.claim.key, sk, sizeof(struct slab_key));
	m.v.claim.oflags = oflags;

	if (mgr_send(mgr, -1, &m, e) == -1)
		goto fail_destroy_locks;

	if (mgr_recv(mgr, &b->fd, &m, e) == -1)
		goto fail_destroy_locks;

	if (m.m == MGR_MSG_CLAIM_NOENT) {
		XERRF(e, XLOG_APP, XLOG_NOENT, "no such slab");
		goto fail_destroy_locks;
	} else if (m.m != MGR_MSG_CLAIM_OK) {
		XERRF(e, XLOG_APP, ((m.err != 0) ? m.err : XLOG_MGR),
		    "bad manager response for claim on slab sk=%lu/%lu",
		    sk->ino, sk->base);
		goto fail_destroy_locks;
	} else if (memcmp(&m.v.claim.key, sk, sizeof(struct slab_key))) {
		XERRF(e, XLOG_APP, XLOG_MGR, "bad manager response; "
		    "ino: expected=%lu, received=%lu base: expected=%lu, "
		    "received=%lu", sk->ino, m.v.claim.key.ino, sk->base,
		    m.v.claim.key.base);
		goto fail_destroy_locks;
	} else if (b->fd == -1) {
		XERRF(e, XLOG_APP, XLOG_MGR,
		    "bad manager response; mgr returned fd -1 on slab "
		    "sk=%lu/%lu", sk->ino, sk->base);
		goto fail_destroy_locks;
	}

	b->dirty = 0;

	/*
	 * While slab_read_hdr() will fill this up, if it fails we'll
	 * need it to unclaim.
	 */
	memcpy(&b->hdr.v.f.key, sk, sizeof(struct slab_key));

	if (slab_read_hdr(b, e) == -1)
		goto fail_unclaim;
	if (b->hdr.v.f.flags & SLAB_REMOVED) {
		if (oflags & OSLAB_NOCREATE) {
			XERRF(e, XLOG_APP, XLOG_NOENT, "slab was removed and "
			    "OSLAB_NOCREATE is set");
			goto fail_unclaim;
		}
		if (slab_realloc(b, e) == -1)
			goto fail_unclaim;
	}

	b->refcnt = 1;

	if (memcmp(&b->hdr.v.f.key, sk, sizeof(struct slab_key))) {
		XERRF(e, XLOG_APP, XLOG_IO,
		    "the key in the slab we just claimed "
		    "(ino=%lu / base=%lu) does not "
		    "match what was requested (ino=%lu / base=%lu)",
		    b->hdr.v.f.key.ino, b->hdr.v.f.key.base, sk->ino, sk->base);
		goto fail_unclaim;
	}

	if (SPLAY_INSERT(slab_tree, &owned_slabs.head, b) != NULL) {
		/* We're in a pretty bad situation here, let's unclaim. */
		XERRF(e, XLOG_ERRNO, errno, "SPLAY_INSERT");
		goto fail_unclaim;
	}
	if (!b->hdr.v.f.key.ino)
		TAILQ_INSERT_TAIL(&owned_slabs.itbl_head, b, itbl_entry);
	counter_incr(COUNTER_N_OPEN_SLABS);

	if (counter_get(COUNTER_N_OPEN_SLABS) >= owned_slabs.max_open) {
		xlog_dbg(XLOG_SLAB, "%s: cache full; purging slabs", __func__);
		while (TAILQ_EMPTY(&owned_slabs.lru_head)) {
			xlog(LOG_WARNING, NULL,
			    "%s: cache full; failed to find "
			    "unreferenced slab; sleeping %lu seconds",
			    __func__, t.tv_sec);
			nanosleep(&t, NULL);
		}
		purged = TAILQ_FIRST(&owned_slabs.lru_head);
		TAILQ_REMOVE(&owned_slabs.lru_head, purged, lru_entry);
		if (!purged->hdr.v.f.key.ino)
			TAILQ_REMOVE(&owned_slabs.itbl_head, purged,
			    itbl_entry);
		SPLAY_REMOVE(slab_tree, &owned_slabs.head, purged);
		slab_unclaim(purged);
		counter_incr(COUNTER_SLABS_PURGED);
		counter_decr(COUNTER_N_OPEN_SLABS);
		goto end;
	}

	goto end;
fail_unclaim:
	slab_unclaim(b);
	b = NULL;
	goto end;
fail_destroy_locks:
	LK_LOCK_DESTROY(&b->lock);
fail_destroy_bytes_lock:
	LK_LOCK_DESTROY(&b->bytes_lock);
fail_free_b:
	if (b != NULL) {
		free(b);
		b = NULL;
	}
end:
	if (mgr != -1)
		close(mgr);
	MTX_UNLOCK(&owned_slabs.lock);
	return b;
}

/*
 * Reduces a slabs refcnt by 1.
 *
 * If we reach zero, the intent of forget is to write the slab's header to
 * disk, but keep the file descriptor open to reduce the amount of
 * open()/close() that we need to perform for slabs that were recently used.
 *
 * If another instance would like to claim the ownership of a closed slab,
 * we should be able to do so quickly.
 */
int
slab_forget(struct oslab *b, struct xerr *e)
{
	struct timespec t;

	MTX_LOCK(&owned_slabs.lock);
	b->refcnt--;
	if (b->refcnt == 0) {
		if (clock_gettime(CLOCK_MONOTONIC, &t) == -1) {
			XERRF(e, XLOG_ERRNO, errno, "clock_gettime");
		} else if (b->open_since.tv_sec
		    <= t.tv_sec - owned_slabs.max_age) {
			SPLAY_REMOVE(slab_tree, &owned_slabs.head, b);
			if (!b->hdr.v.f.key.ino)
				TAILQ_REMOVE(&owned_slabs.itbl_head, b,
				    itbl_entry);
			slab_unclaim(b);
			counter_decr(COUNTER_N_OPEN_SLABS);
		} else
			TAILQ_INSERT_TAIL(&owned_slabs.lru_head, b, lru_entry);
	}
	MTX_UNLOCK(&owned_slabs.lock);
	return xerr_fail(e);
}

ssize_t
slab_itbls(off_t *bases, size_t n, struct xerr *e)
{
	struct oslab         *b;
	size_t                i = 0, j;
	struct slab_itbl_hdr *ihdr;
	DIR                  *itbl_dir;
	char                  path[PATH_MAX];
	struct dirent        *de;
	int                   found;
	struct slab_key       sk;

	if (n > SSIZE_MAX)
		return XERRF(e, XLOG_APP, XLOG_INVAL, "n is too large");

	MTX_LOCK(&owned_slabs.lock);
	TAILQ_FOREACH(b, &owned_slabs.itbl_head, itbl_entry) {
		ihdr = (struct slab_itbl_hdr *)slab_hdr_data(b);

		/*
		 * If the itbl base is zero, this could be because
		 * this slab is being initialized. Skip it.
		 */
		if (b->hdr.v.f.key.base == 0 || ihdr->n_free == 0)
			continue;

		bases[i++] = b->hdr.v.f.key.base;

		if (i >= n)
			break;
	}
	MTX_UNLOCK(&owned_slabs.lock);

	if (i >= n)
		return i;

	if (snprintf(path, sizeof(path), "%s/%s",
	    fs_config.data_dir, ITBL_DIR) >= sizeof(path))
		return XERRF(e, XLOG_APP, XLOG_NAMETOOLONG,
		    "bad inode table name; too long");
	if ((itbl_dir = opendir(path)) == NULL)
		return XERRF(e, XLOG_ERRNO, errno, "opendir");
	while (i < n && (de = readdir(itbl_dir))) {
		if (de->d_name[0] == '.')
			continue;
		if (slab_parse_path(de->d_name, &sk, e) == -1) {
			xlog(LOG_ERR, e, "%s: an unrecognized file was "
			    "found in the itbl dir: %s; skipping", __func__,
			    de->d_name);
			xerrz(e);
			continue;
		}

		/* Check if we have this base in our results already */
		found = 0;
		for (j = 0; j < i; j++) {
			if (bases[j] == sk.base) {
				found = 1;
				break;
			}
		}
		if (!found)
			bases[i++] = sk.base;
	}
	closedir(itbl_dir);

	return i;
}

ssize_t
slab_write(struct oslab *b, const void *buf, off_t offset,
    size_t count, struct xerr *e)
{
	ssize_t w;

	if (count > SSIZE_MAX)
		return XERRF(e, XLOG_APP, XLOG_INVAL,
		    "count (%lu) cannot exceed SSIZE_MAX", count);

	if (slab_set_dirty_hdr(b, e) == -1)
		return -1;
	offset += sizeof(b->hdr);
	if ((w = pwrite_x(b->fd, buf, count, offset)) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "pwrite_x");
	slab_set_dirty(b);
	return w;
}

ssize_t
slab_read(struct oslab *b, void *buf, off_t offset,
    size_t count, struct xerr *e)
{
	ssize_t r;

	if (count > SSIZE_MAX)
		return XERRF(e, XLOG_APP, XLOG_INVAL,
		    "count (%lu) cannot exceed SSIZE_MAX", count);

	offset += sizeof(b->hdr);
	if ((r = pread_x(b->fd, buf, count, offset)) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "pread_x");
	return r;
}

int
slab_truncate(struct oslab *b, off_t offset, struct xerr *e)
{
	if (slab_set_dirty_hdr(b, e) == -1)
		return -1;
	offset += sizeof(b->hdr);
	if ((ftruncate(b->fd, offset)) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "ftruncate");
	slab_set_dirty(b);
	return 0;
}

int
slab_unlink(struct oslab *b, struct xerr *e)
{
	LK_WRLOCK(&b->lock);
	b->hdr.v.f.flags |= SLAB_REMOVED;
	if ((ftruncate(b->fd, sizeof(struct slab_hdr))) == -1) {
		LK_UNLOCK(&b->lock);
		return XERRF(e, XLOG_ERRNO, errno, "ftruncate");
	}
	if (slab_write_hdr_nolock(b, e) == -1) {
		LK_UNLOCK(&b->lock);
		return -1;
	}
	LK_UNLOCK(&b->lock);
	return 0;
}

off_t
slab_size(struct oslab *b, struct xerr *e)
{
	struct stat st;
	if (fstat(b->fd, &st) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "fstat");
		return ULONG_MAX;
	}
	return st.st_size - sizeof(struct slab_hdr);
}

/* Must be called in lock context */
int
slab_sync(struct oslab *b, struct xerr *e)
{
	if (b->oflags & OSLAB_SYNC)
		return 0;

	LK_WRLOCK(&b->lock);
	if (b->dirty) {
		if (fsync(b->fd) == -1) {
			LK_UNLOCK(&b->lock);
			return XERRF(e, XLOG_ERRNO, errno, "fsync");
		}
		b->dirty = 0;
	}
	LK_UNLOCK(&b->lock);
	return 0;
}

void
slab_splice_fd(struct oslab *b, off_t offset, size_t count,
    off_t *rel_offset, size_t *b_count, int *fd, int write_fd)
{
	struct xerr e = XLOG_ERR_INITIALIZER;

	*rel_offset = offset % slab_get_max_size();
	*b_count = (count > slab_get_max_size() - *rel_offset)
	    ? slab_get_max_size() - *rel_offset
	    : count;
	*fd = b->fd;
	*rel_offset += sizeof(b->hdr);
	if (write_fd && slab_set_dirty_hdr(b, &e) == -1) {
		fs_error_set();
		xlog(LOG_ERR, &e, __func__);
	}
}

void *
slab_disk_inspect(struct slab_key *sk, struct slab_hdr *hdr,
    size_t *slab_sz, struct xerr *e)
{
	char         path[PATH_MAX];
	int          fd;
	struct stat  st;
	ssize_t      r;
	void        *data;

	if (slab_path(path, sizeof(path), sk, 0, e) == -1)
		return NULL;

	if ((fd = open(path, O_RDONLY)) == -1) {
		if (errno == ENOENT)
			XERRF(e, XLOG_APP, XLOG_NOENT, "no such slab");
		else
			XERRF(e, XLOG_ERRNO, errno,
			    "failed to load slab %s", path);
		return NULL;
	}

	if (read_x(fd, hdr, sizeof(struct slab_hdr)) <
	    sizeof(struct slab_hdr)) {
		XERRF(e, XLOG_ERRNO, errno, "short read on slab header");
		goto fail;
	}

	if (fstat(fd, &st) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "fstat");
		goto fail;
	}
	*slab_sz = st.st_size - sizeof(struct slab_hdr);

	if ((data = malloc(*slab_sz)) == NULL) {
		XERRF(e, XLOG_ERRNO, errno, "malloc");
		goto fail;
	}

	if ((r = read_x(fd, data, *slab_sz)) < *slab_sz) {
		if (r == -1)
			XERRF(e, XLOG_ERRNO, errno, "read");
		else
			XERRF(e, XLOG_APP, XLOG_SHORTIO,
			    "short read on slab; expected size from "
			    "fstat() is %lu, read_x() returned %lu",
			    *slab_sz, r);
		free(data);
		goto fail;
	}
	close(fd);

	return data;
fail:
	close(fd);
	return NULL;
}

void *
slab_inspect(int mgr, struct slab_key *sk, uint32_t oflags,
    struct slab_hdr *hdr, size_t *slab_sz, struct xerr *e)
{
	int             fd;
	struct mgr_msg  m;
	struct oslab   *b;
	void           *data = NULL;
	ssize_t         r;

	m.m = MGR_MSG_CLAIM;
	memcpy(&m.v.claim.key, sk, sizeof(struct slab_key));
	m.v.claim.oflags = oflags;

	if (mgr_send(mgr, -1, &m, e) == -1) {
		xerr_prepend(e, __func__);
		return NULL;
	}

	if (mgr_recv(mgr, &fd, &m, e) == -1) {
		xerr_prepend(e, __func__);
		return NULL;
	}

	if (m.m == MGR_MSG_CLAIM_NOENT) {
		XERRF(e, XLOG_APP, XLOG_NOENT, "no such slab");
		return NULL;
	} else if (m.m != MGR_MSG_CLAIM_OK) {
		XERRF(e, XLOG_APP, ((m.err != 0) ? m.err : XLOG_MGR),
		    "bad manager response");
		return NULL;
	} else if (memcmp(&m.v.claim.key, sk, sizeof(struct slab_key))) {
		XERRF(e, XLOG_APP, XLOG_MGR,
		    "bad manager response; ino expected=%lu, received=%lu "
		    "base expected=%lu, received=%lu",
		    sk->ino, m.v.claim.key.ino, sk->base, m.v.claim.key.base);
		return NULL;
	} else if (fd == -1) {
		XERRF(e, XLOG_APP, XLOG_MGR,
		    "bad manager response; mgr returned fd -1");
		return NULL;
	}

	if ((b = calloc(1, sizeof(struct oslab))) == NULL) {
		XERRF(e, XLOG_ERRNO, errno, "calloc");
		return NULL;
	}

	b->fd = fd;

	if (slab_read_hdr(b, e) == -1) {
		xerr_prepend(e, __func__);
		goto fail_free_slab;
	}
	memcpy(hdr, &b->hdr, sizeof(struct slab_hdr));

	if ((*slab_sz = slab_size(b, e)) == ULONG_MAX) {
		xerr_prepend(e, __func__);
		goto fail_free_slab;
	}

	if ((data = malloc(*slab_sz)) == NULL) {
		XERRF(e, XLOG_ERRNO, errno, "malloc");
		goto fail_free_slab;
	}

	if ((r = slab_read(b, data, 0, *slab_sz, e)) < *slab_sz) {
		if (r != -1)
			XERRF(e, XLOG_APP, XLOG_SHORTIO,
			    "short read on slab; expected size from "
			    "fstat() is %lu, slab_read() returned %lu",
			    *slab_sz, r);
		xerr_prepend(e, __func__);
		goto fail_free_data;
	}

	m.m = MGR_MSG_UNCLAIM;
	memcpy(&m.v.unclaim.key, sk, sizeof(struct slab_key));
	if (mgr_send(mgr, b->fd, &m, e) == -1) {
		xerr_prepend(e, __func__);
		goto fail_free_data;
	}

	if (mgr_recv(mgr, NULL, &m, e) == -1) {
		xerr_prepend(e, __func__);
		goto fail_free_data;
	}

	if (m.m != MGR_MSG_UNCLAIM_OK) {
		XERRF(e, XLOG_APP, XLOG_MGR, "bad manager response: %d", m.m);
		goto fail_free_data;
	} else if (memcmp(&m.v.unclaim.key, sk, sizeof(struct slab_key))) {
		XERRF(e, XLOG_APP, XLOG_MGR,
		    "bad manager response for unclaim; "
		    "ino expected=%lu, received=%lu"
		    "base expected=%lu, received=%lu",
		    sk->ino, m.v.unclaim.key.ino,
		    sk->base, m.v.unclaim.key.base);
		goto fail_free_data;
	}

	close(b->fd);
	free(b);
	return data;
fail_free_data:
	free(data);
fail_free_slab:
	close(fd);
	free(b);
	return NULL;
}
