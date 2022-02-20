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
#include "exlog.h"
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
	uint64_t        max_open;
	int             do_shutdown;

	/*
	 * Slabs that have been opened for that many seconds will
	 * be closed by the background "flusher" threads, or on the next
	 * forget for that slab.
	 */
	uint32_t        max_age;
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
slab_read_hdr(struct oslab *b, struct exlog_err *e)
{
	if (pread_x(b->fd, &b->hdr, sizeof(b->hdr), 0) < sizeof(b->hdr))
		return exlog_errf(e, EXLOG_OS, errno,
		    "%s: short read on slab header", __func__);
	return 0;
}

/*
 * Should be called *before* any writes. If we die before the write,
 * happens, there is little harm. We'll just sync a slab with no changes.
 * The opposite could result in local changes that are never synced to the
 * backend.
 */
static int
slab_set_dirty_hdr(struct oslab *b, struct exlog_err *e)
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
slab_realloc(struct oslab *b, struct exlog_err *e)
{
	if ((ftruncate(b->fd, sizeof(b->hdr))) == -1)
		return exlog_errf(e, EXLOG_OS, errno, __func__);
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
	struct exlog_err e = EXLOG_ERR_INITIALIZER;
	int              mgr = -1;
	struct mgr_msg   m;
	struct timespec  tp = {1, 0};

	if (b->fd == -1) {
		exlog(LOG_ERR, NULL, "%s: fd is -1", __func__);
		fs_error_set();
		return;
	}

	for (;;) {
		if ((mgr = mgr_connect(&e)) == -1) {
			exlog(LOG_ERR, &e, __func__);
			goto fail;
		}

		m.m = MGR_MSG_UNCLAIM;
		memcpy(&m.v.unclaim.key, &b->hdr.v.f.key,
		    sizeof(struct slab_key));

		if (mgr_send(mgr, b->fd, &m, &e) == -1) {
			exlog(LOG_ERR, &e, "%s", __func__);
			goto fail;
		}

		if (mgr_recv(mgr, NULL, &m, &e) == -1) {
			exlog(LOG_ERR, &e, "%s", __func__);
			goto fail;
		}

		if (m.m != MGR_MSG_UNCLAIM_OK) {
			exlog(LOG_ERR, NULL, "%s: bad manager response: %d",
			    __func__, m.m);
			goto fail;
		} else if (memcmp(&m.v.unclaim.key, &b->hdr.v.f.key,
		    sizeof(struct slab_key))) {
			/* We close the fd here to avoid deadlocks. */
			close(b->fd);
			exlog(LOG_ERR, NULL,
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

	while (!owned_slabs.do_shutdown) {
		for (;;) {
			if (nanosleep(&t, NULL) == 0)
				break;
		}

		if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
			fs_error_set();
			exlog_strerror(LOG_ERR, errno,
			    "%s: failed to get current time", __func__);
			continue;
		}

		MTX_LOCK(&owned_slabs.lock);
		b = TAILQ_FIRST(&owned_slabs.lru_head);
		while (b != NULL) {
			if (now.tv_sec <
			    (b->open_since.tv_sec + owned_slabs.max_age))
				break;
			b2 = TAILQ_NEXT(b, lru_entry);
			exlog_dbg(EXLOG_SLAB, "%s: purging slab, "
			    "ino=%lu, base=%lu", __func__,
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
slab_write_hdr_nolock(struct oslab *b, struct exlog_err *e)
{
	b->hdr.v.f.flags |= SLAB_DIRTY;
	if (pwrite_x(b->fd, &b->hdr, sizeof(b->hdr), 0) < sizeof(b->hdr))
		return exlog_errf(e, EXLOG_OS, errno,
		    "%s: short write on slab header", __func__);
	if (!(b->oflags & OSLAB_SYNC))
		b->dirty = 1;
	return 0;
}

int
slab_write_hdr(struct oslab *b, struct exlog_err *e)
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
slab_loop_files(void (*fn)(const char *), struct exlog_err *e)
{
	char           path[PATH_MAX], f[PATH_MAX];
	int            i;
	DIR           *dir;
	struct dirent *de;

	if (snprintf(path, sizeof(path), "%s/%s", fs_config.data_dir, ITBL_DIR)
	    >= sizeof(path))
		return exlog_errf(e, EXLOG_APP, EXLOG_NAMETOOLONG,
		    "%s: bad inode table dir; too long", __func__);

	if ((dir = opendir(path)) == NULL)
		return exlog_errf(e, EXLOG_OS, errno, "%s: opendir", __func__);
	while ((de = readdir(dir))) {
		if (de->d_name[0] == '.')
			continue;
		if (snprintf(f, sizeof(f), "%s/%s", path,
		    de->d_name) >= sizeof(f)) {
			exlog(LOG_ERR, NULL, "%s: name too long", __func__);
			goto fail_closedir;
		}
		fn(f);
	}
	closedir(dir);

	for (i = 0; i < SLAB_DIRS; i++) {
		if (snprintf(path, sizeof(path), "%s/%02x",
		    fs_config.data_dir, i) >= sizeof(path))
			return exlog_errf(e, EXLOG_APP, EXLOG_NAMETOOLONG,
			    "%s: bad slab dir; too long", __func__);
		if ((dir = opendir(path)) == NULL)
			return exlog_errf(e, EXLOG_OS, errno, "%s: opendir",
			    __func__);
		while ((de = readdir(dir))) {
			if (de->d_name[0] == '.')
				continue;
			if (snprintf(f, sizeof(f), "%s/%s", path,
			    de->d_name) >= sizeof(f)) {
				exlog(LOG_ERR, NULL, "%s: name too long",
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
slab_make_dirs(struct exlog_err *e)
{
	char path[PATH_MAX];
	int  i;

	if (snprintf(path, sizeof(path), "%s/%s", fs_config.data_dir, ITBL_DIR)
	    >= sizeof(path))
		return exlog_errf(e, EXLOG_APP, EXLOG_NAMETOOLONG,
		    "%s: bad inode table dir; too long", __func__);
	if (mkdir_x(path, 0700) == -1)
		return exlog_errf(e, EXLOG_OS, errno, __func__);

	if (snprintf(path, sizeof(path), "%s/%s",
	    fs_config.data_dir, OUTGOING_DIR) >= sizeof(path))
		return exlog_errf(e, EXLOG_APP, EXLOG_NAMETOOLONG,
		    "%s: bad inode table dir; too long", __func__);
	if (mkdir_x(path, 0700) == -1)
		return exlog_errf(e, EXLOG_OS, errno, __func__);

	if (snprintf(path, sizeof(path), "%s/%s",
	    fs_config.data_dir, INCOMING_DIR) >= sizeof(path))
		return exlog_errf(e, EXLOG_APP, EXLOG_NAMETOOLONG,
		    "%s: bad inode table dir; too long", __func__);
	if (mkdir_x(path, 0700) == -1)
		return exlog_errf(e, EXLOG_OS, errno, __func__);

	for (i = 0; i < SLAB_DIRS; i++) {
		if (snprintf(path, sizeof(path), "%s/%02x",
		    fs_config.data_dir, i) >= sizeof(path))
			return exlog_errf(e, EXLOG_APP, EXLOG_NAMETOOLONG,
			    "%s: bad slab dir; too long", __func__);
		if (mkdir_x(path, 0700) == -1)
			return exlog_errf(e, EXLOG_OS, errno, __func__);
	}

	return 0;
}

int
slab_configure(uint64_t max_open, uint32_t max_age, struct exlog_err *e)
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
		return exlog_errf(e, EXLOG_OS, errno,
		    "%s: failed to get RLIMIT_NOFILE", __func__);
	if (nofile.rlim_cur != RLIM_INFINITY &&
	    nofile.rlim_cur < owned_slabs.max_open + 100) {
		nofile.rlim_cur = owned_slabs.max_open + 100;
		if (setrlimit(RLIMIT_NOFILE, &nofile) == -1) {
			return exlog_errf(e, EXLOG_OS, errno,
			    "could not increase RLIMIT_NOFILE to %lu",
			    nofile.rlim_cur);
		}
	}

	if (getrlimit(RLIMIT_LOCKS, &locks) == -1)
		return exlog_errf(e, EXLOG_OS, errno,
		    "%s: failed to get RLIMIT_LOCKS", __func__);
	if (locks.rlim_cur != RLIM_INFINITY &&
	    locks.rlim_cur < owned_slabs.max_open) {
		locks.rlim_cur = owned_slabs.max_open;
		if (setrlimit(RLIMIT_LOCKS, &locks) == -1) {
			return exlog_errf(e, EXLOG_OS, errno,
			    "could not increase RLIMIT_LOCKS to %lu",
			    locks.rlim_cur);
		}
	}

	owned_slabs.max_age = (max_age == 0) ? owned_slabs.max_age : max_age;

	exlog(LOG_NOTICE, NULL, "max open slabs is %lu (RLIMIT_NOFILE is %u, "
	    "RLIMIT_LOCKS is %u)", owned_slabs.max_open, nofile.rlim_cur,
	    locks.rlim_cur);
	exlog(LOG_NOTICE, NULL, "slab max age is %lu seconds",
	    owned_slabs.max_age);

	if ((r = pthread_attr_init(&attr)) != 0)
		return exlog_errf(e, EXLOG_OS, r,
		    "%s: failed to init pthread attributes", __func__);
	if ((r = pthread_create(&slab_purger, &attr,
	    &slab_purge, NULL)) != 0)
		return exlog_errf(e, EXLOG_OS, r,
		    "%s: failed to init pthread attributes", __func__);
	return 0;
}

/*
 * Holds a lock on the returned slab. If the function fails, it
 * is guaranteed that it will not be holding a lock.
 * An inode lock must never be acquired while holding the itbl lock.
 */
struct oslab *
slab_load_itbl(ino_t ino, rwlk_flags lkf, struct exlog_err *e)
{
	struct oslab         *b;
	struct slab_itbl_hdr *ihdr;
	struct slab_key       sk;

	if (!(lkf & (LK_LOCK_RD|LK_LOCK_RW))) {
		exlog_errf(e, EXLOG_APP, EXLOG_INVAL,
		    "%s: neither read nor write lock requested", __func__);
		return NULL;
	}

	if ((b = slab_load(slab_key(&sk, 0, ino), OSLAB_SYNC, e)) == NULL)
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
slab_close_itbl(struct oslab *b, struct exlog_err *e)
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

size_t
slab_get_max_size()
{
	return fs_config.slab_size;
}

size_t
slab_inode_max()
{
	return fs_config.slab_size / sizeof(struct inode);
}

struct slab_key *
slab_key(struct slab_key *sk, ino_t ino, off_t offset)
{
	bzero(sk, sizeof(struct slab_key));
	if (ino == 0) {
		sk->base = (offset - 1) - ((offset - 1) % slab_inode_max()) + 1;
	} else {
		sk->ino = ino;
		sk->base = offset - (offset % slab_get_max_size());
	}
	return sk;
}

int
slab_key_valid(struct slab_key *sk, struct exlog_err *e)
{
	if (sk->ino == 0) {
		if ((sk->base - 1) % slab_inode_max() != 0)
			return exlog_errf(e, EXLOG_APP, EXLOG_INVAL,
			    "%s: inode table has base %lu that does not fall "
			    "on a multiple of slab_inode_max() plus one (%lu)",
			    __func__, sk->base, slab_inode_max());
	} else {
		if (sk->base % slab_get_max_size() != 0)
			return exlog_errf(e, EXLOG_APP, EXLOG_INVAL,
			    "%s: inode %lu has base %lu that is not a multiple "
			    "of slab_get_max_size() (%lu)",
			    __func__, sk->ino, sk->base, slab_get_max_size());
	}
	return 0;
}

int
slab_shutdown(struct exlog_err *e)
{
	struct oslab *b, *next;
	int           r;

	MTX_LOCK(&owned_slabs.lock);
	for (b = SPLAY_MIN(slab_tree, &owned_slabs.head); b != NULL; b = next) {
		next = SPLAY_NEXT(slab_tree, &owned_slabs.head, b);
		if (b->refcnt != 0)
			exlog(LOG_ERR, NULL, "%s: slab has non-zero refcnt: "
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
		return exlog_errf(e, EXLOG_OS, r, "%s", __func__);
	return 0;
}

int
slab_path(char *path, size_t len, struct slab_key *sk, int name_only,
    struct exlog_err *e)
{
	size_t l;

	if (name_only) {
		if (sk->ino == 0) {
			l = snprintf(path, len, "%s%020lu", ITBL_PREFIX,
			    sk->base);
		} else {
			l = snprintf(path, len, "%s%020lu-%020lu",
			    SLAB_PREFIX, sk->ino, sk->base);
		}
	} else {
		if (sk->ino == 0) {
			l = snprintf(path, len, "%s/%s/%s%020lu",
			    fs_config.data_dir, ITBL_DIR, ITBL_PREFIX,
			    sk->base);
		} else {
			l = snprintf(path, len, "%s/%02lx/%s%020lu-%020lu",
			    fs_config.data_dir, sk->ino % SLAB_DIRS,
			    SLAB_PREFIX, sk->ino, sk->base);
		}
	}

	if (l >= len)
		return exlog_errf(e, EXLOG_APP, EXLOG_NAMETOOLONG,
		    "%s: bad inode table name; too long", __func__);
	return 0;
}

int
slab_parse_path(const char *path, struct slab_key *key, struct exlog_err *e)
{
	char p[PATH_MAX];

	bzero(key, sizeof(struct slab_key));
	strlcpy(p, path, sizeof(p));
	if (strncmp(basename(p), ITBL_PREFIX, 1) == 0) {
		key->ino = 0;
		if (sscanf(basename(p), ITBL_PREFIX "%020lu",
		    &key->base) < 1)
			return exlog_errf(e, EXLOG_APP, EXLOG_INVAL,
			    "%s: unparseable itbl slab name %s",
			    __func__, path);
	} else {
		if (sscanf(basename(p), SLAB_PREFIX "%020lu-%020lu",
		    &key->ino, &key->base) < 2)
			return exlog_errf(e, EXLOG_APP, EXLOG_INVAL,
			    "%s: unparseable slab name %s", __func__, path);
	}
	return slab_key_valid(key, e);
}

struct oslab *
slab_load(struct slab_key *sk, uint32_t oflags, struct exlog_err *e)
{
	struct oslab    *b, needle;
	struct oslab    *purged;
	struct timespec  t = {5, 0};
	int              mgr = -1;
	struct mgr_msg   m;

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
		exlog_errf(e, EXLOG_OS, errno, __func__);
		goto end;
	}

	if (clock_gettime(CLOCK_MONOTONIC, &b->open_since) == -1) {
		exlog_errf(e, EXLOG_OS, errno,
		    "%s: failed to set 'open_since' on slab");
		goto fail_free_b;
	}

	b->oflags = oflags;

	if (LK_LOCK_INIT(&b->bytes_lock, e) == -1)
		goto fail_free_b;
	if (LK_LOCK_INIT(&b->lock, e) == -1)
		goto fail_destroy_bytes_lock;

	if ((mgr = mgr_connect(e)) == -1)
		goto fail_destroy_locks;

	m.m = MGR_MSG_CLAIM;
	memcpy(&m.v.claim.key, sk, sizeof(struct slab_key));
	m.v.claim.oflags = oflags;

	if (mgr_send(mgr, -1, &m, e) == -1)
		goto fail_destroy_locks;

	if (mgr_recv(mgr, &b->fd, &m, e) == -1)
		goto fail_destroy_locks;

	if (m.m == MGR_MSG_CLAIM_NOENT) {
		exlog_errf(e, EXLOG_APP, EXLOG_NOENT,
		    "%s: no such slab", __func__);
		goto fail_destroy_locks;
	} else if (m.m != MGR_MSG_CLAIM_OK) {
		exlog_errf(e, EXLOG_APP, ((m.err != 0) ? m.err : EXLOG_MGR),
		    "%s: bad manager response", __func__);
		goto fail_destroy_locks;
	} else if (memcmp(&m.v.claim.key, sk, sizeof(struct slab_key))) {
		exlog_errf(e, EXLOG_APP, EXLOG_MGR,
		    "%s: bad manager response; "
		    "ino: expected=%lu, received=%lu "
		    "base: expected=%lu, received=%lu",
		    __func__, sk->ino, m.v.claim.key.ino,
		    sk->base, m.v.claim.key.base);
		goto fail_destroy_locks;
	} else if (b->fd == -1) {
		exlog_errf(e, EXLOG_APP, EXLOG_MGR,
		    "%s: bad manager response; mgr returned fd -1", __func__);
		goto fail_destroy_locks;
	}

	b->dirty = 0;

	if (slab_read_hdr(b, e) == -1)
		goto fail_unclaim;
	if (b->hdr.v.f.flags & SLAB_REMOVED) {
		if (oflags & OSLAB_NOCREATE) {
			exlog_errf(e, EXLOG_APP, EXLOG_NOENT,
			    "%s: slab was removed and "
			    "OSLAB_NOCREATE is set",
			    __func__);
			goto fail_unclaim;
		}
		if (slab_realloc(b, e) == -1)
			goto fail_unclaim;
	}

	b->refcnt = 1;

	if (memcmp(&b->hdr.v.f.key, sk, sizeof(struct slab_key))) {
		exlog_errf(e, EXLOG_APP, EXLOG_IO,
		    "%s: the key in the slab we just claimed "
		    "(ino=%lu / base=%lu) does not "
		    "match what was requested (ino=%lu / base=%lu)", __func__,
		    b->hdr.v.f.key.ino, b->hdr.v.f.key.base, sk->ino, sk->base);
		goto fail_unclaim;
	}

	if (SPLAY_INSERT(slab_tree, &owned_slabs.head, b) != NULL) {
		/* We're in a pretty bad situation here, let's unclaim. */
		exlog_errf(e, EXLOG_OS, errno, __func__);
		goto fail_unclaim;
	}
	if (!b->hdr.v.f.key.ino)
		TAILQ_INSERT_TAIL(&owned_slabs.itbl_head, b, itbl_entry);
	counter_incr(COUNTER_N_OPEN_SLABS);

	if (counter_get(COUNTER_N_OPEN_SLABS) >= owned_slabs.max_open) {
		exlog_dbg(EXLOG_SLAB, "%s: cache full; purging slabs", __func__);
		counter_incr(COUNTER_N_SLABS_PURGE);
		for (;;) {
			if (TAILQ_EMPTY(&owned_slabs.lru_head)) {
				exlog(LOG_WARNING, NULL,
				    "%s: cache full; failed to find "
				    "unreferenced slab; sleeping %lu seconds",
				    __func__, t.tv_sec);
				nanosleep(&t, NULL);
				continue;
			}
			purged = TAILQ_FIRST(&owned_slabs.lru_head);
			TAILQ_REMOVE(&owned_slabs.lru_head, purged, lru_entry);
			if (!b->hdr.v.f.key.ino)
				TAILQ_REMOVE(&owned_slabs.itbl_head, purged,
				    itbl_entry);
			SPLAY_REMOVE(slab_tree, &owned_slabs.head, purged);
			slab_unclaim(purged);
			counter_decr(COUNTER_N_OPEN_SLABS);
			goto end;
		}
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
slab_forget(struct oslab *b, struct exlog_err *e)
{
	struct timespec t;

	MTX_LOCK(&owned_slabs.lock);
	b->refcnt--;
	if (b->refcnt == 0) {
		if (clock_gettime(CLOCK_MONOTONIC, &t) == -1) {
			exlog_errf(e, EXLOG_OS, errno,
			    "%s: failed to set 'open_since' on slab");
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
	return exlog_fail(e);
}

size_t
slab_itbls(ino_t *bases, size_t n, struct exlog_err *e)
{
	struct oslab         *b;
	size_t                i = 0, j;
	struct slab_itbl_hdr *ihdr;
	DIR                  *itbl_dir;
	char                  path[PATH_MAX];
	struct dirent        *de;
	ino_t                 base;
	int                   found;

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
		return exlog_errf(e, EXLOG_APP, EXLOG_NAMETOOLONG,
		    "%s: bad inode table name; too long");
	if ((itbl_dir = opendir(path)) == NULL)
		return exlog_errf(e, EXLOG_OS, errno, "opendir");
	while (i < n && (de = readdir(itbl_dir))) {
		if (sscanf(de->d_name,
		    ITBL_PREFIX "%020lu", &base) != 1)
			continue;

		/* Check if we have this base in our results already */
		found = 0;
		for (j = 0; j < i; j++) {
			if (bases[j] == base) {
				found = 1;
				break;
			}
		}
		if (!found)
			bases[i++] = base;
	}
	closedir(itbl_dir);

	return i;
}

ssize_t
slab_write(struct oslab *b, const void *buf, off_t offset,
    size_t count, struct exlog_err *e)
{
	ssize_t w;

	if (slab_set_dirty_hdr(b, e) == -1)
		return -1;
	offset += sizeof(b->hdr);
	if ((w = pwrite_x(b->fd, buf, count, offset)) == -1)
		return exlog_errf(e, EXLOG_OS, errno, "pwrite_x");
	slab_set_dirty(b);
	return w;
}

ssize_t
slab_read(struct oslab *b, void *buf, off_t offset,
    size_t count, struct exlog_err *e)
{
	ssize_t r;

	offset += sizeof(b->hdr);
	if ((r = pread_x(b->fd, buf, count, offset)) == -1)
		return exlog_errf(e, EXLOG_OS, errno, "pread_x");
	return r;
}

int
slab_truncate(struct oslab *b, off_t offset, struct exlog_err *e)
{
	if (slab_set_dirty_hdr(b, e) == -1)
		return -1;
	offset += sizeof(b->hdr);
	if ((ftruncate(b->fd, offset)) == -1)
		return exlog_errf(e, EXLOG_OS, errno, __func__);
	slab_set_dirty(b);
	return 0;
}

int
slab_unlink(struct oslab *b, struct exlog_err *e)
{
	LK_WRLOCK(&b->lock);
	b->hdr.v.f.flags |= SLAB_REMOVED;
	if (slab_write_hdr_nolock(b, e) == -1) {
		LK_UNLOCK(&b->lock);
		return -1;
	}
	LK_UNLOCK(&b->lock);
	return 0;
}

off_t
slab_size(struct oslab *b, struct exlog_err *e)
{
	struct stat st;
	if (fstat(b->fd, &st) == -1) {
		exlog_errf(e, EXLOG_OS, errno, "%s: fstat", __func__);
		return ULONG_MAX;
	}
	return st.st_size - sizeof(struct slab_hdr);
}

/* Must be called in lock context */
int
slab_sync(struct oslab *b, struct exlog_err *e)
{
	if (b->oflags & OSLAB_SYNC)
		return 0;

	LK_WRLOCK(&b->lock);
	if (b->dirty) {
		if (fsync(b->fd) == -1) {
			LK_UNLOCK(&b->lock);
			return exlog_errf(e, EXLOG_OS, errno, "%s: fsync",
			    __func__);
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
	struct exlog_err e = EXLOG_ERR_INITIALIZER;

	*rel_offset = offset % slab_get_max_size();
	*b_count = (count > slab_get_max_size() - *rel_offset)
	    ? slab_get_max_size() - *rel_offset
	    : count;
	*fd = b->fd;
	*rel_offset += sizeof(b->hdr);
	if (write_fd && slab_set_dirty_hdr(b, &e) == -1) {
		fs_error_set();
		exlog(LOG_ERR, &e, __func__);
	}
}

void *
slab_disk_inspect(struct slab_key *sk, struct slab_hdr *hdr,
    size_t *slab_sz, struct exlog_err *e)
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
			exlog_errf(e, EXLOG_APP, EXLOG_NOENT,
			    "%s: no such slab", __func__);
		else
			exlog_errf(e, EXLOG_OS, errno, "%s: failed "
			    "to load slab %s", __func__, path);
		return NULL;
	}

	if (read_x(fd, hdr, sizeof(struct slab_hdr)) <
	    sizeof(struct slab_hdr)) {
		exlog_errf(e, EXLOG_OS, errno,
		    "%s: short read on slab header", __func__);
		goto fail;
	}

	if (fstat(fd, &st) == -1) {
		exlog_errf(e, EXLOG_OS, errno, "%s: fstat", __func__);
		goto fail;
	}
	*slab_sz = st.st_size - sizeof(struct slab_hdr);

	if ((data = malloc(*slab_sz)) == NULL) {
		exlog_errf(e, EXLOG_OS, errno, "%s: malloc", __func__);
		goto fail;
	}

	if ((r = read_x(fd, data, *slab_sz)) < *slab_sz) {
		if (r == -1)
			exlog_errf(e, EXLOG_OS, errno, "%s: read", __func__);
		else
			exlog_errf(e, EXLOG_APP, EXLOG_SHORTIO,
			    "%s: short read on slab; expected size from "
			    "fstat() is %lu, read_x() returned %lu",
			    __func__, *slab_sz, r);
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
    struct slab_hdr *hdr, size_t *slab_sz, struct exlog_err *e)
{
	int             fd;
	struct mgr_msg  m;
	struct oslab   *b;
	void           *data = NULL;
	ssize_t         r;

	m.m = MGR_MSG_CLAIM;
	memcpy(&m.v.claim.key, sk, sizeof(struct slab_key));
	m.v.claim.oflags = oflags;

	if (mgr_send(mgr, -1, &m, e) == -1)
		return NULL;

	if (mgr_recv(mgr, &fd, &m, e) == -1)
		return NULL;

	if (m.m == MGR_MSG_CLAIM_NOENT) {
		exlog_errf(e, EXLOG_APP, EXLOG_NOENT,
		    "%s: no such slab", __func__);
		return NULL;
	} else if (m.m != MGR_MSG_CLAIM_OK) {
		exlog_errf(e, EXLOG_APP, ((m.err != 0) ? m.err : EXLOG_MGR),
		    "%s: bad manager response", __func__);
		return NULL;
	} else if (memcmp(&m.v.claim.key, sk, sizeof(struct slab_key))) {
		exlog_errf(e, EXLOG_APP, EXLOG_MGR,
		    "%s: bad manager response; "
		    "ino expected=%lu, received=%lu "
		    "base expected=%lu, received=%lu", __func__,
		    sk->ino, m.v.claim.key.ino, sk->base, m.v.claim.key.base);
		return NULL;
	} else if (fd == -1) {
		exlog_errf(e, EXLOG_APP, EXLOG_MGR,
		    "%s: bad manager response; mgr returned fd -1", __func__);
		return NULL;
	}

	if ((b = calloc(1, sizeof(struct oslab))) == NULL) {
		exlog_errf(e, EXLOG_OS, errno, __func__);
		return NULL;
	}

	b->fd = fd;

	if (slab_read_hdr(b, e) == -1)
		goto fail_free_slab;
	memcpy(hdr, &b->hdr, sizeof(struct slab_hdr));

	if ((*slab_sz = slab_size(b, e)) == ULONG_MAX)
		goto fail_free_slab;

	if ((data = malloc(*slab_sz)) == NULL) {
		exlog_errf(e, EXLOG_OS, errno, "%s: malloc", __func__);
		goto fail_free_slab;
	}

	if ((r = slab_read(b, data, 0, slab_get_max_size(), e)) < *slab_sz) {
		if (r != -1)
			exlog_errf(e, EXLOG_APP, EXLOG_SHORTIO,
			    "%s: short read on slab; expected size from "
			    "fstat() is %lu, slab_read() returned %lu",
			    __func__, *slab_sz, r);
		goto fail_free_data;
	}

	m.m = MGR_MSG_UNCLAIM;
	memcpy(&m.v.unclaim.key, sk, sizeof(struct slab_key));
	if (mgr_send(mgr, b->fd, &m, e) == -1)
		goto fail_free_data;

	if (mgr_recv(mgr, NULL, &m, e) == -1)
		goto fail_free_data;

	if (m.m != MGR_MSG_UNCLAIM_OK) {
		exlog_errf(e, EXLOG_APP, EXLOG_MGR,
		    "%s: bad manager response: %d", __func__, m.m);
		goto fail_free_data;
	} else if (memcmp(&m.v.unclaim.key, sk, sizeof(struct slab_key))) {
		exlog_errf(e, EXLOG_APP, EXLOG_MGR,
		    "%s: bad manager response for unclaim; "
		    "ino expected=%lu, received=%lu"
		    "base expected=%lu, received=%lu", __func__,
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
