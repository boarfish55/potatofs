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
#include "exlog.h"
#include "mgr.h"
#include "util.h"

struct counter   counters[COUNTER_LAST];
static pthread_t counters_flush;
static int       counters_shutdown = 0;

static void *
counter_flush(void *unused)
{
	struct timespec   t = {1, 0};
	int               c, mgr;
	struct exlog_err  e = EXLOG_ERR_INITIALIZER;
	struct mgr_msg    m;

	while (!counters_shutdown) {
		exlog_zerr(&e);
		if ((mgr = mgr_connect(1, &e)) == -1) {
			exlog(LOG_ERR, &e, __func__);
			goto fail;
		}

		m.m = MGR_MSG_SND_COUNTERS;
		for (c = 0; c < COUNTER_LAST; c++)
			m.v.snd_counters.c[c] = counter_get(c);

		if (mgr_send(mgr, -1, &m, &e) == -1) {
			exlog(LOG_ERR, &e, "%s", __func__);
			goto fail;
		}

		if (mgr_recv(mgr, NULL, &m, &e) == -1) {
			exlog(LOG_ERR, &e, "%s", __func__);
			goto fail;
		}

		if (m.m != MGR_MSG_SND_COUNTERS_OK) {
			exlog(LOG_ERR, NULL, "%s: bad manager response: %d",
			    __func__, m.m);
			goto fail;
		}
fail:
		close(mgr);
		for (;;) {
			if (nanosleep(&t, NULL) == 0)
				break;
		}
	}
	return NULL;
}

int
counter_init(struct exlog_err *e)
{
	int            r, c;
	pthread_attr_t attr;

	for (c = 0; c < COUNTER_LAST; c++) {
		counters[c].count = 0;
		if ((r = pthread_mutex_init(&counters[c].mtx, NULL)) != 0)
			return exlog_errf(e, EXLOG_OS, r,
			    "%s: pthread_mutex_init", __func__);
	}

	if ((r = pthread_attr_init(&attr)) != 0)
		return exlog_errf(e, EXLOG_OS, r,
		    "%s: failed to init pthread attributes", __func__);

	if ((r = pthread_create(&counters_flush, &attr,
	    &counter_flush, NULL)) != 0)
		return exlog_errf(e, EXLOG_OS, r,
		    "%s: failed to init pthread attributes", __func__);

	return 0;
}

int
counter_shutdown(struct exlog_err *e)
{
	int r;

	counters_shutdown = 1;
	if ((r = pthread_join(counters_flush, NULL)) != 0)
		return exlog_errf(e, EXLOG_OS, r, "%s", __func__);
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
		exlog(LOG_ERR, NULL, "failed to acquire counter lock");
	counters[c].count += v;
	pthread_mutex_unlock(&counters[c].mtx);
}

void
counter_decr(int c)
{
	if (pthread_mutex_lock(&counters[c].mtx) != 0)
		exlog(LOG_ERR, NULL, "failed to acquire counter lock");
	counters[c].count--;
	pthread_mutex_unlock(&counters[c].mtx);
}

void
counter_reset(int c)
{
	if (pthread_mutex_lock(&counters[c].mtx) != 0)
		exlog(LOG_ERR, NULL, "failed to acquire counter lock");
	counters[c].count = 0;
	pthread_mutex_unlock(&counters[c].mtx);
}

uint64_t
counter_get(int c)
{
	uint64_t v;

	if (pthread_mutex_lock(&counters[c].mtx) != 0)
		exlog(LOG_ERR, NULL, "failed to acquire counter lock");
	v = counters[c].count;
	pthread_mutex_unlock(&counters[c].mtx);
	return v;
}
