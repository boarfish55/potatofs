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
#include "xlog.h"

const struct module_dbg_map_entry module_dbg_map[] = {
	{ "inodes",    XLOG_INODE },
	{ "slabs",     XLOG_SLAB },
	{ "locks",     XLOG_LOCK },
	{ "ops",       XLOG_OP },
	{ "openfiles", XLOG_OF },
	{ "sladb",     XLOG_SLABDB },
	{ "mgr",       XLOG_MGR },
	{ "all",       0xFFFF },
	{ "",          0x0000 }
};

static xlog_mask_t  debug_mask = 0;
locale_t            log_locale;

struct xerr *
xerrz(struct xerr *e)
{
	if (e == NULL)
		return NULL;

	e->sp = 0;
	e->code = 0;
	e->msg[0] = '\0';
	return e;
}

int
xerrf(struct xerr *e, int space, int code, const char *fmt, ...)
{
	va_list  ap;
	int      written;
	int      status = (space || code) ? -1 : 0;

	if (e == NULL)
		return status;

	e->sp = space;
	e->code = code;
	e->msg[0] = '\0';

	if (fmt == NULL)
		return status;

	va_start(ap, fmt);
	written = vsnprintf(e->msg, sizeof(e->msg), fmt, ap);
	va_end(ap);

	if (written >= sizeof(e->msg))
		e->msg[sizeof(e->msg) - 2] = '*';

	return status;
}

int
xerrfn(struct xerr *e, int space, int code, const char *fn,
    const char *fmt, ...)
{
	va_list  ap;
	int      written;
	int      status = (space || code) ? -1 : 0;
	char     pfmt[LINE_MAX];

	if (e == NULL)
		return status;

	e->sp = space;
	e->code = code;
	e->msg[0] = '\0';

	if (fmt == NULL)
		return status;

	written = snprintf(pfmt, sizeof(pfmt), "%s: %s", fn, fmt);
	if (written >= sizeof(pfmt))
		pfmt[sizeof(pfmt) - 2] = '*';
	va_start(ap, fmt);
	written = vsnprintf(e->msg, sizeof(e->msg), pfmt, ap);
	va_end(ap);

	if (written >= sizeof(e->msg))
		e->msg[sizeof(e->msg) - 2] = '*';

	return status;
}

int
xerr_fail(const struct xerr *e)
{
	if (e == NULL)
		return 0;

	return (e->sp || e->code) ? -1 : 0;
}

int
xerr_is(const struct xerr *e, int code, int subcode)
{
	if (e == NULL)
		return 0;

	if (e->sp == code && e->code == subcode)
		return subcode;

	return 0;
}

int
xlog_init(const char *progname, const char *dbg_spec, int perror)
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
xlog_dbg(xlog_mask_t module, const char *fmt, ...)
{
	va_list ap;

	if (fmt == NULL || (module & debug_mask) == 0)
		return;

	va_start(ap, fmt);
	vsyslog(LOG_DEBUG, fmt, ap);
	va_end(ap);
}

void
xlog(int priority, const struct xerr *e, const char *fmt, ...)
{
	va_list ap;
	char    msg[LINE_MAX];
	size_t  written;

	if (e == NULL) {
		if (fmt != NULL) {
			va_start(ap, fmt);
			vsyslog(priority, fmt, ap);
			va_end(ap);
		}
		return;
	}

	if (fmt != NULL) {
		va_start(ap, fmt);
		written = vsnprintf(msg, sizeof(msg), fmt, ap);
		va_end(ap);

		if (written >= sizeof(msg))
			msg[sizeof(e->msg) - 2] = '*';
	}

	if (e->sp == XLOG_ERRNO && e->code != 0) {
		if (fmt) {
			syslog(priority, "[sp=%d, code=%d]: %s: %s: %s",
			    e->sp, e->code, msg, e->msg,
			    strerror_l(e->code, log_locale));
		} else {
			syslog(priority, "[sp=%d, code=%d]: %s: %s",
			    e->sp, e->code, e->msg, strerror_l(e->code,
			    log_locale));
		}
	} else {
		if (fmt) {
			syslog(priority, "[sp=%d, code=%d]: %s: %s",
			    e->sp, e->code, msg, e->msg);
		} else {
			syslog(priority, "[sp=%d, code=%d]: %s",
			    e->sp, e->code, e->msg);
		}
	}
}

void
xlog_strerror(int priority, int err, const char *fmt, ...)
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
xerr_print(const struct xerr *e)
{
	if (e == NULL)
		return;

	if (e->sp == XLOG_ERRNO && e->code != 0)
		warnx("[err=%d, c_err=%d]: %s: %s",
		    e->sp, e->code, e->msg,
		    strerror_l(e->code, log_locale));
	else
		warnx("[err=%d, c_err=%d]: %s", e->sp, e->code, e->msg);
}

int
xerr_prepend(struct xerr *e, const char *prefix)
{
	char msg[LINE_MAX];

	if (e == NULL)
		return 0;

	strlcpy(msg, e->msg, sizeof(msg));
	if (snprintf(e->msg, sizeof(e->msg), "%s: %s", prefix, msg) >=
	    sizeof(e->msg))
		e->msg[sizeof(e->msg) - 2] = '*';
	return xerr_fail(e);
}
