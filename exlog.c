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

#include <err.h>
#include <errno.h>
#include <limits.h>
#include <locale.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"
#include "counters.h"
#include "exlog.h"

const struct module_dbg_map_entry module_dbg_map[] = {
	{ "inodes",    EXLOG_INODE },
	{ "slabs",     EXLOG_SLAB },
	{ "locks",     EXLOG_LOCK },
	{ "ops",       EXLOG_OP },
	{ "openfiles", EXLOG_OF },
	{ "sladb",     EXLOG_SLABDB },
	{ "all",       0xFFFF },
	{ "",          0x0000 }
};

static exlog_mask_t  debug_mask = 0;
locale_t             log_locale;
static const char   *exlog_trunc_mark = " ...";

struct exlog_err *
exlog_zerr(struct exlog_err *e)
{
	if (e == NULL)
		return NULL;

	e->layer = 0;
	e->err = 0;
	e->msg[0] = '\0';
	return e;
}

int
exlog_errf(struct exlog_err *e, int err, int c_err, const char *fmt, ...)
{
	va_list ap;
	int     written;
	int     status = (err || c_err) ? -1 : 0;

	if (e == NULL)
		return status;

	e->layer = err;
	e->err = c_err;
	e->msg[0] = '\0';

	if (fmt == NULL)
		return status;

	va_start(ap, fmt);
	written = vsnprintf(e->msg, sizeof(e->msg), fmt, ap);
	va_end(ap);

	if (written >= sizeof(e->msg)) {
		strncpy(e->msg + (sizeof(e->msg) - 1) -
		    strlen(exlog_trunc_mark), exlog_trunc_mark,
		    strlen(exlog_trunc_mark));
	}

	return status;
}

int
exlog_fail(const struct exlog_err *e)
{
	if (e == NULL)
		return 0;

	return (e->layer || e->err) ? -1 : 0;
}

int
exlog_err_is(const struct exlog_err *e, int code, int subcode)
{
	if (e == NULL)
		return 0;

	if (e->layer == code && e->err == subcode)
		return subcode;

	return 0;
}

int
exlog_init(const char *progname, const char *dbg_spec, int perror)
{
	char                              *dbg, *module, *save;
	const struct module_dbg_map_entry *map;
	int                                opt = (LOG_PERROR|LOG_PID);

	if (perror)
		opt |= LOG_PERROR;

	if ((log_locale = newlocale(LC_CTYPE_MASK, "C", 0)) == 0)
		return -1;

	openlog(progname, opt, LOG_USER);
	if (dbg_spec == NULL || *dbg_spec == '\0') {
		setlogmask(LOG_UPTO(LOG_INFO));
		return 0;
	}

	dbg = strdup(dbg_spec);
	if (dbg == NULL)
		return -1;

	setlogmask(LOG_UPTO(LOG_DEBUG));
	for ((module = strtok_r(dbg, ",", &save)); module;
	    (module = strtok_r(NULL, ",", &save))) {
		for (map = module_dbg_map; *map->name; map++) {
			if (strcmp(map->name, module) == 0) {
				debug_mask |= map->flag;
				syslog(LOG_DEBUG, "enabling %s debug logging",
				    map->name);
			}
		}
	}
	free(dbg);
	return 0;
}

void
exlog_dbg(exlog_mask_t module, const char *fmt, ...)
{
	va_list ap;

	if (fmt == NULL || (module & debug_mask) == 0)
		return;

	va_start(ap, fmt);
	vsyslog(LOG_DEBUG, fmt, ap);
	va_end(ap);
}

void
exlog(int priority, const struct exlog_err *e, const char *fmt, ...)
{
	va_list ap;
	char    msg[LINE_MAX];
	size_t  written;

	if (e == NULL) {
		if (fmt == NULL)
			return;
		va_start(ap, fmt);
		vsyslog(priority, fmt, ap);
		va_end(ap);
		return;
	}

	va_start(ap, fmt);
	written = vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);

	if (written >= sizeof(msg)) {
		strncpy(msg + sizeof(msg) - strlen(exlog_trunc_mark) - 1,
		    exlog_trunc_mark, strlen(exlog_trunc_mark));
	}

	if (e->layer == EXLOG_OS && e->err != 0)
		syslog(priority, "[err=%d, c_err=%d]: %s: %s: %s",
		    e->layer, e->err, msg, e->msg,
		    strerror_l(e->err, log_locale));
	else
		syslog(priority, "[err=%d, c_err=%d]: %s: %s",
		    e->layer, e->err, msg, e->msg);
}

void
exlog_strerror(int priority, int err, const char *fmt, ...)
{
	va_list ap;
	char    msg[LINE_MAX];

	if (fmt == NULL)
		return;

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);

	syslog(priority, "%s: %s", msg, strerror_l(err, log_locale));
}

void
exlog_prt(const struct exlog_err *e)
{
	if (e == NULL)
		return;

	if (e->layer == EXLOG_OS && e->err != 0)
		warnx("[err=%d, c_err=%d]: %s: %s",
		    e->layer, e->err, e->msg,
		    strerror_l(e->err, log_locale));
	else
		warnx("[err=%d, c_err=%d]: %s", e->layer, e->err, e->msg);
}

int
exlog_prepend(struct exlog_err *e, const char *prefix)
{
	char msg[LINE_MAX];

	if (e == NULL)
		return 0;

	strlcpy(msg, e->msg, sizeof(msg));
	if (snprintf(e->msg, sizeof(e->msg), "%s: %s", prefix, msg) >=
	    sizeof(e->msg))
		e->msg[sizeof(e->msg) - 2] = '*';
	return exlog_fail(e);
}
