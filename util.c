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
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "exlog.h"
#include "util.h"

void
lk_lock(rwlk *lock, rwlk_flags flags, const char *lockname,
    const char *file, int line)
{
	struct exlog_err e;
	int              r;

	exlog_dbg(EXLOG_LOCK, "locking %p (%s, flags=%u) at %s:%d",
	    lock, lockname, flags, file, line);

	if (flags & LK_LOCK_RW) {
		r = pthread_rwlock_wrlock(lock);
	} else if (flags & LK_LOCK_RD) {
		r = pthread_rwlock_rdlock(lock);
	} else {
		exlog_errf(&e, EXLOG_APP, EXLOG_INVAL,
		    "%s: neither read or write lock specified: %d",
		    __func__, flags);
		goto fail;
	}

	if (r != 0) {
		/*
		 * This could fail in the event of a deadlock or
		 * if the number of readers overflows the integer used
		 * by the lock.
		 */
		exlog_errf(&e, EXLOG_OS, r,
		    "failed to acquire lock: flags=%d, %s:%d",
		    flags, file, line);
		goto fail;
	}
	return;
fail:
	exlog(LOG_ERR, &e, __func__);
	abort();
}

void
lk_rdlock(rwlk *lock, const char *lockname, const char *file, int line)
{
	lk_lock(lock, LK_LOCK_RD, lockname, file, line);
}

void
lk_wrlock(rwlk *lock, const char *lockname, const char *file, int line)
{
	lk_lock(lock, LK_LOCK_RW, lockname, file, line);
}

void
lk_unlock(rwlk *lock, const char *lockname, const char *file, int line)
{
	int r;
	exlog_dbg(EXLOG_LOCK, "unlocking %p (%s) at %s:%d", lock,
	    lockname, file, line);
	if ((r = pthread_rwlock_unlock(lock)) != 0) {
		exlog_strerror(LOG_CRIT, r,
		    "failed to release lock: %s:%d", file, line);
		abort();
	}
}

void
mtx_lock(pthread_mutex_t *lock, const char *lockname, const char *file,
    int line)
{
	int              r;
	struct exlog_err e;

	exlog_dbg(EXLOG_LOCK, "locking %p (%s, flags=%u) at %s:%d",
	    lock, lockname, file, line);

	if ((r = pthread_mutex_lock(lock)) != 0) {
		/*
		 * This could fail in the event of a deadlock or
		 * if the number of readers overflows the integer used
		 * by the lock.
		 */
		exlog_errf(&e, EXLOG_OS, r,
		    "failed to acquire mutex: %s:%d", file, line);
		exlog(LOG_ERR, &e, __func__);
		abort();
	}
}

void
mtx_unlock(pthread_mutex_t *lock, const char *lockname, const char *file,
    int line)
{
	int r;

	exlog_dbg(EXLOG_LOCK, "unlocking %p (%s) at %s:%d", lock,
	    lockname, file, line);
	if ((r = pthread_mutex_unlock(lock)) != 0) {
		exlog_strerror(LOG_CRIT, r,
		    "failed to release lock: %s:%d", file, line);
		abort();
	}
}

int
lk_init(rwlk *lock, const char *lockname, const char *file,
    int line, struct exlog_err *e)
{
	int                  r;
	pthread_rwlockattr_t a;

	exlog_dbg(EXLOG_LOCK, "initializing lock %p (%s) at %s:%d",
	    lock, lockname, file, line);

	if ((r = pthread_rwlockattr_init(&a)) != 0)
		return exlog_errf(e, EXLOG_OS, r,
		    "failed to initialize rwlock attributes");

	if ((r = pthread_rwlockattr_setpshared(&a,
	    PTHREAD_PROCESS_SHARED)) != 0)
		return exlog_errf(e, EXLOG_OS, r,
		    "failed to set attribute PTHREAD_PROCESS_SHARED "
		    "while initializing lock");

	if ((r = pthread_rwlock_init(lock, &a)) != 0)
		return exlog_errf(e, EXLOG_OS, r,
		    "failed to initialize rwlock");

	return 0;
}

void
lk_destroy(rwlk *lock, const char *lockname, const char *file, int line)
{
	int r;

	exlog_dbg(EXLOG_LOCK, "destroying lock %p (%s) at %s:%d",
	    lock, lockname, file, line);
	if ((r = pthread_rwlock_destroy(lock)) != 0) {
		exlog_strerror(LOG_ERR, r,
		    "failed to destroy lock: %s:%d", file, line);
		abort();
	}
}

/*
 * "Exact" variants of read() and write(), i.e., will never return
 * short read/writes unless we're reading EOF, or on error.
 * Although those calls should never produce EINTR on local disk, it is
 * really the same for NFS, or other network or FUSE filesystem?
 */
ssize_t
read_x(int fd, void *buf, size_t count)
{
	ssize_t r;
	ssize_t n = 0;

	while (n < count) {
		r = read(fd, buf + n, count - n);
		if (r == -1) {
			if (errno == EINTR)
				continue;
			return -1;
		} else if (r == 0) {
			return n;
		}
		n += r;
	}
	return n;
}

ssize_t
pread_x(int fd, void *buf, size_t count, off_t offset)
{
	ssize_t r;
	ssize_t n = 0;

	while (n < count) {
		r = pread(fd, buf + n, count - n, offset + n);
		if (r == -1) {
			if (errno == EINTR)
				continue;
			return -1;
		} else if (r == 0) {
			return n;
		}
		n += r;
	}
	return n;
}

ssize_t
write_x(int fd, const void *buf, size_t count)
{
	ssize_t w;
	ssize_t n = 0;

	while (n < count) {
		w = write(fd, buf + n, count - n);
		if (w == -1) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		n += w;
	}
	return n;
}

ssize_t
pwrite_x(int fd, const void *buf, size_t count, off_t offset)
{
	ssize_t w;
	ssize_t n = 0;

	while (n < count) {
		w = pwrite(fd, buf + n, count - n, offset + n);
		if (w == -1) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		n += w;
	}
	return n;
}

int
mkdir_x(const char *path, mode_t mode)
{
	if (mkdir(path, mode) == -1) {
		if (errno != EEXIST)
			return -1;
	}
	return 0;
}

/*
 * If wait_seconds is 0, don't set LOCK_NB. We behave like plain open() + flock().
 * If wait_seconds is >0, we will sleep for a maximum of this many seconds in
 * 10ms increments until we can either grab the lock or run out of time. We try
 * to re-open the file every time in case the previous lock holder unlink'd it.
 */
int
open_wflock(const char *path, int flags, mode_t mode, int lk,
    uint32_t wait_seconds)
{
	int    fd, retries;
	struct timespec tp = {0, 10000000}, req, rem;  /* 10ms */

	if (wait_seconds > 0)
		lk |= LOCK_NB;

	for (retries = (wait_seconds * 1000000000) / tp.tv_nsec;
	    retries > 0 || !wait_seconds; retries--) {
		if (flags & O_CREAT) {
			if ((fd = open(path, flags, mode)) == -1)
				return -1;
		} else if ((fd = open(path, flags)) == -1)
			return -1;

		if (flock(fd, lk) == -1) {
			if (wait_seconds > 0 && errno == EWOULDBLOCK) {
				memcpy(&req, &tp, sizeof(req));
				while (nanosleep(&req, &rem) == -1)
					memcpy(&req, &rem, sizeof(req));
				close(fd);
				continue;
			}
			close(fd);
			return -1;
		}
		break;
	}

	return fd;
}
