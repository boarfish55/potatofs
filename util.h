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

#ifndef UTIL_H
#define UTIL_H

#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <stdint.h>
#include "xlog.h"

typedef pthread_rwlock_t rwlk;
typedef uint16_t         rwlk_flags;

#define RWLK_INITIALIZER PTHREAD_RWLOCK_INITIALIZER

/* Lock flags */
#define LK_LOCK_NONE 0x0000
#define LK_LOCK_RD   0x0001
#define LK_LOCK_RW   0x0002

void lk_lock(rwlk *, rwlk_flags, const char *, const char *, int);
void lk_rdlock(rwlk *, const char *, const char *, int);
void lk_wrlock(rwlk *, const char *, const char *, int);
void lk_unlock(rwlk *, const char *, const char *, int);
int  lk_init(rwlk *, const char *, const char *, int, struct xerr *);
void lk_destroy(rwlk *, const char *, const char *, int);
void mtx_lock(pthread_mutex_t *, const char *, const char *, int);
void mtx_unlock(pthread_mutex_t *, const char *, const char *, int );

#define LK_LOCK(lock, flags) \
    lk_lock(lock, flags, #lock, __FILE__, __LINE__)
#define LK_RDLOCK(lock) lk_rdlock(lock, #lock, __FILE__, __LINE__)
#define LK_WRLOCK(lock) lk_wrlock(lock, #lock, __FILE__, __LINE__)
#define LK_UNLOCK(lock) lk_unlock(lock, #lock, __FILE__, __LINE__)
#define LK_LOCK_INIT(lock, e) \
    lk_init(lock, #lock, __FILE__, __LINE__, e)
#define LK_LOCK_DESTROY(lock) \
    lk_destroy(lock, #lock, __FILE__, __LINE__)
#define MTX_LOCK(lock) mtx_lock(lock, #lock, __FILE__, __LINE__)
#define MTX_UNLOCK(lock) mtx_unlock(lock, #lock, __FILE__, __LINE__)

ssize_t read_x(int, void *, size_t);
ssize_t pread_x(int, void *, size_t, off_t);
ssize_t write_x(int, const void *, size_t);
ssize_t pwrite_x(int, const void *, size_t, off_t);
int     mkdir_x(const char *, mode_t);
int     open_wflock(const char *, int, mode_t, int, uint32_t);

#define CLOSE_X(fd) close_x(fd, #fd, __func__, __LINE__)
void    close_x(int, const char *, const char *, int);
void    clock_gettime_x(int, struct timespec *);

#endif
