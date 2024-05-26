/*
 *  Copyright (C) 2020-2024 Pascal Lalonde <plalonde@overnet.ca>
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
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include "config.h"
#include "counters.h"
#include "xlog.h"
#include "mgr.h"
#include "util.h"

struct counter         counters[COUNTER_LAST];
static pthread_t       counters_flush;
static int             counters_shutdown = 0;
static pthread_mutex_t counters_shutdown_lock = PTHREAD_MUTEX_INITIALIZER;

static void *
counter_flush(void *unused)
{
	struct timespec t = {1, 0};
	int             c, mgr, do_shutdown = 0;
	struct xerr     e;
	struct mgr_msg  m;

	for (;;) {
		MTX_LOCK(&counters_shutdown_lock);
		if (counters_shutdown)
			do_shutdown = 1;
		MTX_UNLOCK(&counters_shutdown_lock);
		if (do_shutdown)
			break;

		if ((mgr = mgr_connect(1, xerrz(&e))) == -1) {
			xlog(LOG_ERR, &e, __func__);
			goto fail;
		}

		bzero(&m, sizeof(m));
		m.m = MGR_MSG_SND_COUNTERS;
		for (c = 0; c < COUNTER_LAST; c++)
			m.v.snd_counters.c[c] = counter_get(c);

		if (mgr_send(mgr, -1, &m, xerrz(&e)) == -1) {
			xlog(LOG_ERR, &e, "%s", __func__);
			goto fail;
		}

		if (mgr_recv(mgr, NULL, &m, xerrz(&e)) == -1) {
			xlog(LOG_ERR, &e, "%s", __func__);
			goto fail;
		}

		if (m.m == MGR_MSG_SND_COUNTERS_ERR) {
			xlog(LOG_ERR, &m.v.err, __func__);
			goto fail;
		} else if (m.m != MGR_MSG_SND_COUNTERS_OK) {
			xlog(LOG_ERR, NULL, "%s: mgr_recv: unexpected response: %d",
			    __func__, m.m);
			goto fail;
		}
fail:
		CLOSE_X(mgr);
		for (;;) {
			if (nanosleep(&t, NULL) == 0)
				break;
		}
	}
	return NULL;
}

int
counter_init(struct xerr *e)
{
	int            r, c;
	pthread_attr_t attr;

	for (c = 0; c < COUNTER_LAST; c++) {
		if ((r = pthread_mutex_init(&counters[c].mtx, NULL)) != 0)
			return XERRF(e, XLOG_ERRNO, r, "pthread_mutex_init");
		if (pthread_mutex_lock(&counters[c].mtx) != 0)
			return XERRF(e, XLOG_ERRNO, r, "pthread_mutex_lock");
		counters[c].count = 0;
		pthread_mutex_unlock(&counters[c].mtx);
	}

	if ((r = pthread_attr_init(&attr)) != 0)
		return XERRF(e, XLOG_ERRNO, r,
		    "failed to init pthread attributes");

	if ((r = pthread_create(&counters_flush, &attr,
	    &counter_flush, NULL)) != 0)
		return XERRF(e, XLOG_ERRNO, r,
		    "failed to init pthread attributes");

	return 0;
}

int
counter_shutdown(struct xerr *e)
{
	int r;

	MTX_LOCK(&counters_shutdown_lock);
	counters_shutdown = 1;
	MTX_UNLOCK(&counters_shutdown_lock);
	if ((r = pthread_join(counters_flush, NULL)) != 0)
		return XERRF(e, XLOG_ERRNO, r, "pthread_join");
	return 0;
}

void
counter_incr(int c)
{
	counter_add(c, 1);
}

void
counter_add(int c, uint64_t v)
{
	if (pthread_mutex_lock(&counters[c].mtx) != 0)
		xlog(LOG_ERR, NULL, "failed to acquire counter lock");
	counters[c].count += v;
	pthread_mutex_unlock(&counters[c].mtx);
}

void
counter_decr(int c)
{
	if (pthread_mutex_lock(&counters[c].mtx) != 0)
		xlog(LOG_ERR, NULL, "failed to acquire counter lock");
	counters[c].count--;
	pthread_mutex_unlock(&counters[c].mtx);
}

void
counter_reset(int c)
{
	if (pthread_mutex_lock(&counters[c].mtx) != 0)
		xlog(LOG_ERR, NULL, "failed to acquire counter lock");
	counters[c].count = 0;
	pthread_mutex_unlock(&counters[c].mtx);
}

uint64_t
counter_get(int c)
{
	uint64_t v;

	if (pthread_mutex_lock(&counters[c].mtx) != 0)
		xlog(LOG_ERR, NULL, "failed to acquire counter lock");
	v = counters[c].count;
	pthread_mutex_unlock(&counters[c].mtx);
	return v;
}
