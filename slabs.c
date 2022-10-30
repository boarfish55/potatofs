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
	if (b1->sk.ino < b2->sk.ino)
		return -1;
	if (b1->sk.ino > b2->sk.ino)
		return 1;
	if (b1->sk.base < b2->sk.base)
		return -1;
	if (b1->sk.base > b2->sk.base)
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
		return XERRF(e, XLOG_APP, XLOG_IO,
		    "short read on slab header; read %d bytes", r);
	}
	return 0;
}

/*
 * Should be called *before* any writes. If we die before the write,
 * happens, there is little harm. We'll just sync a slab with no changes.
 * The opposite could result in local changes that are never synced to the
 * backend. Must be called with the write-lock held.
 */
static int
slab_set_dirty_hdr(struct oslab *b, struct xerr *e)
{
	if (!(b->hdr.v.f.flags & SLAB_DIRTY)) {
		if (slab_write_hdr(b, e) == -1)
			return -1;
	}
	return 0;
}

static int
slab_realloc(struct oslab *b, struct xerr *e)
{
	b->hdr.v.f.flags &= ~SLAB_REMOVED;
	if (slab_write_hdr(b, e) == -1)
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
	int             mgr = -1, i;
	struct mgr_msg  m;
	struct timespec tp = {1, 0};

	if (b->fd == -1) {
		xlog(LOG_ERR, NULL, "%s: fd is -1 on slab sk=%lu/%ld",
		    __func__, b->sk.ino, b->sk.base);
		fs_error_set();
		LK_LOCK_DESTROY(&b->lock);
		free(b);
		return;
	}

	/*
	 * Retry a few times, but don't block here forever since
	 * failed unclaims can always be cleaned up by scrub later.
	 */
	for (i = 0; i < 3; i++) {
		if ((mgr = mgr_connect(0, &e)) == -1) {
			xlog(LOG_ERR, &e, __func__);
			goto fail;
		}

		bzero(&m, sizeof(m));
		m.m = MGR_MSG_UNCLAIM;
		memcpy(&m.v.unclaim.key, &b->sk,
		    sizeof(struct slab_key));

		if (mgr_send(mgr, b->fd, &m, &e) == -1) {
			xlog(LOG_ERR, &e, __func__);
			goto fail;
		}

		if (mgr_recv(mgr, NULL, &m, &e) == -1) {
			xlog(LOG_ERR, &e, "%s: failed to receive response "
			    "for unclaim of slab sk=%lu/%lu, but "
			    "closing it anyway", __func__,
			    b->sk.ino, b->sk.base);
		} else if (m.m == MGR_MSG_UNCLAIM_ERR) {
			xlog(LOG_ERR, &m.v.err,
			    "%s: failed to unclaim slab sk=%lu/%lu, but "
			    "closing it anyway: mgr_recv", __func__,
			    b->sk.ino, b->sk.base);
		} else if (m.m != MGR_MSG_UNCLAIM_OK) {
			xlog(LOG_ERR, NULL, "%s: mgr_recv: "
			    "unexpected response: %d for slab sk=%lu/%lu",
			    __func__, m.m, b->sk.ino, b->sk.base);
			goto fail;
		} else if (memcmp(&m.v.unclaim.key, &b->sk,
		    sizeof(struct slab_key))) {
			/* We close the fd here to avoid deadlocks. */
			if (close(b->fd) == -1)
				xlog_strerror(LOG_ERR, errno,
				    "%s: close(b->fd)", __func__);
			xlog(LOG_ERR, NULL,
			    "%s: bad manager response for unclaim; "
			    "ino: expected=%lu, received=%lu"
			    "base: expected=%lu, received=%lu", __func__,
			    b->sk.ino, m.v.unclaim.key.ino,
			    b->sk.base, m.v.unclaim.key.base);
			goto fail;
		}
		break;
fail:
		/*
		 * Disowning is important and hard to recover from
		 * in case of failure. Loop until things recover,
		 * or until an external action is taken.
		 */
		if (mgr != -1)
			close_x(mgr, __func__);
		nanosleep(&tp, NULL);
	}
	close_x(mgr, __func__);
	close_x(b->fd, __func__);
	LK_LOCK_DESTROY(&b->lock);
	free(b);
}

static void *
slab_purge(void *unused)
{
	struct oslab    *b, *b2;
	struct timespec  now, t = {1, 0};
	int              i;
	struct statvfs   stv;
	int              purge, do_shutdown = 0;

	while (!do_shutdown) {
		for (i = 0; i < 10 && !do_shutdown; i++) {
			nanosleep(&t, NULL);
			MTX_LOCK(&owned_slabs.lock);
			if (owned_slabs.do_shutdown)
				do_shutdown = 1;
			MTX_UNLOCK(&owned_slabs.lock);
		}
		if (do_shutdown)
			break;

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
			    b->sk.ino, b->sk.base);
			SPLAY_REMOVE(slab_tree, &owned_slabs.head, b);
			TAILQ_REMOVE(&owned_slabs.lru_head, b, lru_entry);
			if (!b->sk.ino)
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
	if (!(b->oflags & OSLAB_SYNC))
		b->dirty = 1;
}

int
slab_write_hdr(struct oslab *b, struct xerr *e)
{
	b->hdr.v.f.flags |= SLAB_DIRTY;
	if (pwrite_x(b->fd, &b->hdr, sizeof(b->hdr), 0) < sizeof(b->hdr))
		return XERRF(e, XLOG_ERRNO, errno,
		    "short write on slab header");
	if (!(b->oflags & OSLAB_SYNC))
		b->dirty = 1;
	return 0;
}

void *
slab_hdr_data(struct oslab *b)
{
	return b->hdr.v.padding.data;
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
	int           r;
	struct rlimit nofile, locks;

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

	if ((r = pthread_create(&slab_purger, NULL, &slab_purge, NULL)) != 0)
		return XERRF(e, XLOG_ERRNO, r, "pthread_create");
	return 0;
}

/*
 * Holds a lock on the returned slab. If the function fails, it
 * is guaranteed that it will not be holding a lock.
 * An inode lock must never be acquired while holding the itbl lock.
 */
struct oslab *
slab_load_itbl(const struct slab_key *sk, struct xerr *e)
{
	struct oslab         *b;
	struct slab_itbl_hdr *ihdr;

	if ((b = slab_load(sk, OSLAB_SYNC, e)) == NULL) {
		XERR_PREPENDFN(e);
		return NULL;
	}

	ihdr = (struct slab_itbl_hdr *)slab_hdr_data(b);

	LK_LOCK(&b->lock, LK_LOCK_RW);
	if (ihdr->initialized == 0) {
		ihdr->initialized = 1;
		bzero(ihdr->bitmap, sizeof(ihdr->bitmap));
		ihdr->n_free = slab_inode_max();
	}
	LK_UNLOCK(&b->lock);

	return b;
}

void
slab_lock(struct oslab *b, rwlk_flags lkf)
{
	LK_LOCK(&b->lock, lkf);
}

void
slab_unlock(struct oslab *b)
{
	LK_UNLOCK(&b->lock);
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
			    __func__, b->sk.ino,
			    b->sk.base, b->refcnt);
		else
			TAILQ_REMOVE(&owned_slabs.lru_head, b, lru_entry);
		SPLAY_REMOVE(slab_tree, &owned_slabs.head, b);
		if (!b->sk.ino)
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

	if (slab_key_valid(sk, e) == -1) {
		xerr_prepend(e, __func__);
		return -1;
	}
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

static int
slab_claim(const struct slab_key *sk, struct oslab *b, struct xerr *e)
{
	int              mgr = -1;
	struct mgr_msg   m;

	xlog_dbg(XLOG_SLAB, "%s: claiming sk=%lu/%ld",
	    __func__, sk->ino, sk->base);

	bzero(&m, sizeof(m));
	m.m = MGR_MSG_CLAIM;
	memcpy(&m.v.claim.key, sk, sizeof(struct slab_key));
	m.v.claim.oflags = b->oflags;

	if ((mgr = mgr_connect(1, e)) == -1)
		return XERR_PREPENDFN(e);

	if (mgr_send(mgr, -1, &m, e) == -1)
		goto fail;

	if (mgr_recv(mgr, &b->fd, &m, e) == -1)
		goto fail;

	if (m.m == MGR_MSG_CLAIM_NOENT) {
		XERRF(e, XLOG_APP, XLOG_NOSLAB, "no such slab");
		goto fail;
	} else if (m.m == MGR_MSG_CLAIM_ERR) {
		memcpy(e, &m.v.err, sizeof(struct xerr));
		XERR_PREPENDFN(e);
		goto fail;
	} else if (m.m != MGR_MSG_CLAIM_OK) {
		XERRF(e, XLOG_APP, XLOG_MGRERROR, "mgr_recv: "
		    "unexpected response: %d", m.m);
		goto fail;
	} else if (memcmp(&m.v.claim.key, sk, sizeof(struct slab_key))) {
		XERRF(e, XLOG_APP, XLOG_MGRERROR,
		    "unexpected slab key in response; "
		    "ino: expected=%lu, received=%lu base: expected=%lu, "
		    "received=%lu", sk->ino, m.v.claim.key.ino, sk->base,
		    m.v.claim.key.base);
		goto fail;
	} else if (b->fd == -1) {
		XERRF(e, XLOG_APP, XLOG_MGRERROR,
		    "mgr returned fd -1 on slab sk=%lu/%lu", sk->ino, sk->base);
		goto fail;
	}

	if (slab_read_hdr(b, e) == -1)
		goto fail;
	if (b->hdr.v.f.flags & SLAB_REMOVED) {
		if (b->oflags & OSLAB_NOCREATE) {
			XERRF(e, XLOG_APP, XLOG_NOSLAB, "slab was removed and "
			    "OSLAB_NOCREATE is set");
			goto fail;
		}
		if (slab_realloc(b, e) == -1)
			goto fail;
	}

	if (memcmp(&b->hdr.v.f.key, sk, sizeof(struct slab_key))) {
		XERRF(e, XLOG_APP, XLOG_IO,
		    "the key in the slab we just claimed "
		    "(ino=%lu / base=%lu) does not "
		    "match what was requested (ino=%lu / base=%lu)",
		    b->hdr.v.f.key.ino, b->hdr.v.f.key.base, sk->ino, sk->base);
		goto fail;
	}

	b->pending = 0;
	close(mgr);
	return 0;
fail:
	if (close(mgr) == -1)
		xlog_strerror(LOG_ERR, errno, "%s: close(mgr)", __func__);
	return -1;
}

/*
 * Notable errors from this function are:
 *
 *   XLOG_APP / XLOG_BUSY: timed out trying to acquire slab lock
 *   XLOG_APP / XLOG_BEERROR: backend script error
 *   XLOG_APP / XLOG_BETIMEOUT: backend script timer expired
 *   XLOG_APP / XLOG_NOSPC: backend is at full capacity
 *
 * Those should be passed up to the fs layer, where they can be
 * converted to standard errno and exposed to the user.
 */
struct oslab *
slab_load(const struct slab_key *sk, uint32_t oflags, struct xerr *e)
{
	struct oslab    *b, needle;
	struct timespec  t = {1, 0};

	if (slab_key_valid(sk, e) == -1) {
		XERR_PREPENDFN(e);
		return NULL;
	}

	memcpy(&needle.sk, sk, sizeof(struct slab_key));

	xlog_dbg(XLOG_SLAB, "%s: loading sk=%lu/%ld",
	    __func__, sk->ino, sk->base);
error_retry:
	MTX_LOCK(&owned_slabs.lock);
	if ((b = SPLAY_FIND(slab_tree, &owned_slabs.head, &needle)) == NULL) {
		if (counter_get(COUNTER_N_OPEN_SLABS) >= owned_slabs.max_open) {
			MTX_UNLOCK(&owned_slabs.lock);
			xlog(LOG_NOTICE, NULL, "%s: cache full; "
			    "waiting for purge thread", __func__);
			nanosleep(&t, NULL);
			goto error_retry;
		}

		if ((b = malloc(sizeof(struct oslab))) == NULL) {
			MTX_UNLOCK(&owned_slabs.lock);
			xlog_strerror(LOG_ERR, errno, "%s: malloc", __func__);
			goto error_retry;
		}
		bzero(b, sizeof(struct oslab));

		if (clock_gettime(CLOCK_MONOTONIC, &b->open_since) == -1) {
			MTX_UNLOCK(&owned_slabs.lock);
			free(b);
			xlog_strerror(LOG_ERR, errno, "%s: clock_gettime",
			    __func__);
			goto error_retry;
		}

		memcpy(&b->sk, sk, sizeof(struct slab_key));
		b->oflags = oflags;

		if (LK_LOCK_INIT(&b->lock, e) == -1) {
			MTX_UNLOCK(&owned_slabs.lock);
			free(b);
			xlog(LOG_ERR, e, __func__);
			xerrz(e);
			goto error_retry;
		}

		b->refcnt++;
		b->pending = 1;

		if (SPLAY_INSERT(slab_tree, &owned_slabs.head, b) != NULL) {
			MTX_UNLOCK(&owned_slabs.lock);
			XERRF(e, XLOG_ERRNO, errno, "SPLAY_INSERT");
			free(b);
			goto error_retry;
		}
		if (!b->sk.ino)
			TAILQ_INSERT_TAIL(&owned_slabs.itbl_head, b, itbl_entry);
		counter_incr(COUNTER_N_OPEN_SLABS);
	} else {
		if (b->refcnt == 0)
			TAILQ_REMOVE(&owned_slabs.lru_head, b, lru_entry);
		b->refcnt++;
	}
	MTX_UNLOCK(&owned_slabs.lock);

	/*
	 * We must grab the slab lock here in case we're in the
	 * process of claiming it in another thread. This will
	 * unlock once the claim is complete.
	 */
	LK_WRLOCK(&b->lock);

	if (b->pending) {
		/*
		 * A previous attempt to claim the slab from
		 * the mgr failed. We can try again.
		 */
		xlog_dbg(XLOG_SLAB, "%s: slab sk=%lu/%ld is pending",
		    __func__, sk->ino, sk->base);
	} else {

		/*
		 * No need to check for NOCREATE, because if it's loaded
		 * it must already have been created.
		 */
		if ((b->hdr.v.f.flags & SLAB_REMOVED) &&
		    slab_realloc(b, e) == -1) {
			XERR_PREPENDFN(e);
			LK_UNLOCK(&b->lock);
			return NULL;
		}
		LK_UNLOCK(&b->lock);
		return b;
	}

	if (slab_claim(sk, b, xerrz(e)) == -1) {
		LK_UNLOCK(&b->lock);
		/*
		 * We weren't able to claim our slab from
		 * the mgr. Drop out refcnt, and if we're at
		 * zero, meaning no other thread is attempting
		 * to claim, we can finally completely free it.
		 */
		MTX_LOCK(&owned_slabs.lock);
		if (--b->refcnt == 0) {
			xlog_dbg(XLOG_SLAB, "%s: unclaiming slab "
			    "ino=%lu, base=%lu", __func__,
			    sk->ino, sk->base);
			SPLAY_REMOVE(slab_tree, &owned_slabs.head, b);
			if (!b->sk.ino)
				TAILQ_REMOVE(&owned_slabs.itbl_head, b,
				    itbl_entry);
			slab_unclaim(b);
			counter_decr(COUNTER_N_OPEN_SLABS);
		}
		MTX_UNLOCK(&owned_slabs.lock);
		XERR_PREPENDFN(e);
		return NULL;
	}
	LK_UNLOCK(&b->lock);
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
	xlog_dbg(XLOG_SLAB, "%s: forgetting sk=%lu/%ld, refcnt=%lu",
	    __func__, b->sk.ino, b->sk.base, b->refcnt);
	b->refcnt--;
	if (b->refcnt == 0) {
		if (clock_gettime(CLOCK_MONOTONIC, &t) == -1) {
			XERRF(e, XLOG_ERRNO, errno, "clock_gettime");
		} else if (b->open_since.tv_sec
		    <= t.tv_sec - owned_slabs.max_age) {
			SPLAY_REMOVE(slab_tree, &owned_slabs.head, b);
			if (!b->sk.ino)
				TAILQ_REMOVE(&owned_slabs.itbl_head, b,
				    itbl_entry);
			xlog_dbg(XLOG_SLAB,
			    "%s: unclaiming slab %lu/%ld", __func__,
			    b->sk.ino, b->sk.base);
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
		LK_RDLOCK(&b->lock);
		if (b->hdr.v.f.key.base == 0 || ihdr->n_free == 0) {
			LK_UNLOCK(&b->lock);
			continue;
		}
		bases[i++] = b->hdr.v.f.key.base;
		LK_UNLOCK(&b->lock);

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

	/*
	 * We mark the slab as dirty on-disk before performing the write.
	 * If we marked it dirty after instead, and the system crashed
	 * before we had the chance to mark it dirty, we could lose data
	 * by purging that slab thinking that nothing was written to it.
	 *
	 * There is no risk of purging the slab before the actual write
	 * goes into it since we are holding the flock(), preventing the
	 * purger from touching it.
	 */
	if (slab_set_dirty_hdr(b, e) == -1)
		return -1;

	offset += sizeof(b->hdr);
	if ((w = pwrite_x(b->fd, buf, count, offset)) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "pwrite_x");

	/*
	 * Then finally mark the open slab structure as having
	 * non-fsync'd data (unless O_SYNC).
	 */
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
slab_delayed_truncate(struct slab_key *sk, off_t offset, struct xerr *e)
{
	int             mgr, truncated = 0;
	struct mgr_msg  m;
	struct oslab    needle, *b;
	struct timespec tp = {5, 0};

	if (slab_key_valid(sk, e) == -1)
		return XERR_PREPENDFN(e);

	/*
	 * If we have the slab loaded in-memory, just truncate now.
	 */
	memcpy(&needle.sk, sk, sizeof(struct slab_key));
	MTX_LOCK(&owned_slabs.lock);
	if ((b = SPLAY_FIND(slab_tree, &owned_slabs.head, &needle)) != NULL) {
		LK_WRLOCK(&b->lock);
		if (offset == 0)
			b->hdr.v.f.flags |= SLAB_REMOVED;
		if ((ftruncate(b->fd, offset + sizeof(b->hdr))) == -1) {
			LK_UNLOCK(&b->lock);
			MTX_UNLOCK(&owned_slabs.lock);
			return XERRF(e, XLOG_ERRNO, errno, "ftruncate");
		}
		if (slab_write_hdr(b, xerrz(e)) != -1)
			truncated = 1;
		LK_UNLOCK(&b->lock);
	}

	/*
	 * Unless slab_write_hdr() failed, we can just stop here.
	 */
	if (truncated) {
		MTX_UNLOCK(&owned_slabs.lock);
		return xerr_fail(e);
	}

	for (;;) {
		if ((mgr = mgr_connect(0, e)) == -1) {
			xlog(LOG_ERR, e, __func__);
			goto fail;
		}

		bzero(&m, sizeof(m));
		m.m = MGR_MSG_TRUNCATE;
		m.v.truncate.offset = offset;
		memcpy(&m.v.truncate.key, sk, sizeof(struct slab_key));

		if (mgr_send(mgr, -1, &m, e) == -1) {
			xlog(LOG_ERR, e, __func__);
			goto fail;
		}

		if (mgr_recv(mgr, NULL, &m, e) == -1) {
			xlog(LOG_ERR, e, "%s: failed to receive response "
			    "for truncate of slab sk=%lu/%ld", __func__,
			    sk->ino, sk->base);
			goto fail;
		} else if (m.m == MGR_MSG_TRUNCATE_NOENT) {
			xlog_dbg(XLOG_SLAB,
			    "%s: tried to truncate slab sk=%lu/%ld which does "
			    "no exist, continuing", __func__,
			    sk->ino, sk->base);
		} else if (m.m == MGR_MSG_TRUNCATE_ERR) {
			xlog(LOG_ERR, &m.v.err,
			    "%s: failed to truncate slab sk=%lu/%ld: mgr_recv",
			    __func__, sk->ino, sk->base);
			goto fail;
		} else if (m.m != MGR_MSG_TRUNCATE_OK) {
			xlog(LOG_ERR, NULL, "%s: mgr_recv: "
			    "unexpected response: %d for slab sk=%lu/%ld",
			    __func__, m.m, sk->ino, sk->base);
			goto fail;
		} else if (memcmp(&m.v.truncate.key, sk,
		    sizeof(struct slab_key))) {
			/* We close the fd here to avoid deadlocks. */
			xlog(LOG_ERR, NULL,
			    "%s: bad manager response for truncate; "
			    "ino: expected=%lu, received=%lu"
			    "base: expected=%ld, received=%ld", __func__,
			    sk->ino, m.v.truncate.key.ino,
			    sk->base, m.v.truncate.key.base);
			goto fail;
		} else {
			xlog_dbg(XLOG_SLAB, "%s: marked slab sk=%lu/%ld",
			    __func__, sk->ino, sk->base);
			counter_incr(COUNTER_FS_DELAYED_TRUNCATE);
		}

		if (close(mgr) == -1)
			xlog_strerror(LOG_ERR, errno,
			    "%s: close(mgr)", __func__);
		break;
fail:
		/*
		 * Delayed truncation cannot be aborted as this could pose
		 * security concerns where someone recreating this inode
		 * could possibly see past file contents.
		 * Loop until things recover, or until an external action is
		 * taken.
		 */
		if (mgr != -1)
			close_x(mgr, __func__);
		fs_error_set();
		nanosleep(&tp, NULL);
	}
	MTX_UNLOCK(&owned_slabs.lock);
	return 0;
}

int
slab_truncate(struct oslab *b, off_t offset, struct xerr *e)
{
	if (slab_set_dirty_hdr(b, e) == -1)
		return XERR_PREPENDFN(e);
	offset += sizeof(b->hdr);
	if ((ftruncate(b->fd, offset)) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "ftruncate");
	slab_set_dirty(b);
	return 0;
}

int
slab_unlink(struct oslab *b, struct xerr *e)
{
	b->hdr.v.f.flags |= SLAB_REMOVED;
	if ((ftruncate(b->fd, sizeof(struct slab_hdr))) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "ftruncate");
	if (slab_write_hdr(b, xerrz(e)) == -1)
		return XERR_PREPENDFN(e);
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

int
slab_sync(struct oslab *b, struct xerr *e)
{
	if (b->oflags & OSLAB_SYNC || !b->dirty)
		return 0;

	if (fsync(b->fd) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "fsync");
	b->dirty = 0;
	return 0;
}

/*
 * An inode read-lock is sufficient if write_fd is zero.
 */
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
			XERRF(e, XLOG_APP, XLOG_NOSLAB, "no such slab");
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
			XERRF(e, XLOG_APP, XLOG_IO,
			    "short read on slab; expected size from "
			    "fstat() is %lu, read_x() returned %lu",
			    *slab_sz, r);
		free(data);
		goto fail;
	}
	if (close(fd) == -1)
		xlog_strerror(LOG_ERR, errno, "%s: close(fd)", __func__);

	return data;
fail:
	if (close(fd) == -1)
		xlog_strerror(LOG_ERR, errno, "%s: close(fd)", __func__);
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

	bzero(&m, sizeof(m));
	m.m = MGR_MSG_CLAIM;
	memcpy(&m.v.claim.key, sk, sizeof(struct slab_key));
	m.v.claim.oflags = oflags;

	if (mgr_send(mgr, -1, &m, e) == -1) {
		XERR_PREPENDFN(e);
		return NULL;
	}

	if (mgr_recv(mgr, &fd, &m, e) == -1) {
		XERR_PREPENDFN(e);
		return NULL;
	}

	if (m.m == MGR_MSG_CLAIM_NOENT) {
		XERRF(e, XLOG_APP, XLOG_NOSLAB,
		    "no such slab; ino=%llu, base=%lu", sk->ino, sk->base);
		return NULL;
	} else if (m.m == MGR_MSG_CLAIM_ERR) {
		// TODO: handle backend unavailability
		memcpy(e, &m.v.err, sizeof(struct xerr));
		XERR_PREPENDFN(e);
		return NULL;
	} else if (m.m != MGR_MSG_CLAIM_OK) {
		XERRF(e, XLOG_APP, XLOG_MGRERROR,
		    "mgr_recv: unexpected response: %d", m.m);
		return NULL;
	} else if (memcmp(&m.v.claim.key, sk, sizeof(struct slab_key))) {
		XERRF(e, XLOG_APP, XLOG_MGRERROR,
		    "bad manager response; ino expected=%llu, received=%llu "
		    "base expected=%lu, received=%lu",
		    sk->ino, m.v.claim.key.ino, sk->base, m.v.claim.key.base);
		return NULL;
	} else if (fd == -1) {
		XERRF(e, XLOG_APP, XLOG_MGRERROR, "mgr returned fd -1");
		return NULL;
	}

	if ((b = malloc(sizeof(struct oslab))) == NULL) {
		XERRF(e, XLOG_ERRNO, errno, "malloc");
		return NULL;
	}
	bzero(b, sizeof(struct oslab));

	b->fd = fd;

	if (slab_read_hdr(b, e) == -1) {
		XERR_PREPENDFN(e);
		goto fail_free_slab;
	}
	memcpy(hdr, &b->hdr, sizeof(struct slab_hdr));

	if ((*slab_sz = slab_size(b, e)) == ULONG_MAX) {
		XERR_PREPENDFN(e);
		goto fail_free_slab;
	}

	if ((data = malloc(*slab_sz)) == NULL) {
		XERRF(e, XLOG_ERRNO, errno, "malloc");
		goto fail_free_slab;
	}

	if ((r = slab_read(b, data, 0, *slab_sz, e)) < *slab_sz) {
		if (r != -1)
			XERRF(e, XLOG_APP, XLOG_IO,
			    "short read on slab; expected size from "
			    "fstat() is %lu, slab_read() returned %lu",
			    *slab_sz, r);
		XERR_PREPENDFN(e);
		goto fail_free_data;
	}

	m.m = MGR_MSG_UNCLAIM;
	memcpy(&m.v.unclaim.key, sk, sizeof(struct slab_key));
	if (mgr_send(mgr, b->fd, &m, e) == -1) {
		XERR_PREPENDFN(e);
		goto fail_free_data;
	}

	if (mgr_recv(mgr, NULL, &m, e) == -1) {
		XERR_PREPENDFN(e);
		goto fail_free_data;
	}

	if (m.m == MGR_MSG_UNCLAIM_ERR) {
		memcpy(e, &m.v.err, sizeof(struct xerr));
		XERR_PREPENDFN(e);
		goto fail_free_data;
	} else if (m.m != MGR_MSG_UNCLAIM_OK) {
		XERRF(e, XLOG_APP, XLOG_MGRERROR,
		    "mgr_recv: unexpected response: %d", m.m);
		goto fail_free_data;
	} else if (memcmp(&m.v.unclaim.key, sk, sizeof(struct slab_key))) {
		XERRF(e, XLOG_APP, XLOG_MGRERROR,
		    "bad manager response for unclaim; "
		    "ino expected=%lu, received=%lu"
		    "base expected=%lu, received=%lu",
		    sk->ino, m.v.unclaim.key.ino,
		    sk->base, m.v.unclaim.key.base);
		goto fail_free_data;
	}

	if (close(b->fd) == -1)
		xlog_strerror(LOG_ERR, errno, "%s: close", __func__);
	free(b);
	return data;
fail_free_data:
	free(data);
fail_free_slab:
	if (close(fd) == -1)
		xlog_strerror(LOG_ERR, errno, "%s: close(fd)", __func__);
	free(b);
	return NULL;
}
