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

#ifndef EXLOG_H
#define EXLOG_H

#include <limits.h>
#include <stdint.h>
#include <syslog.h>

enum exlog_errcode {
	EXLOG_NONE = 0,
	EXLOG_APP,      /* App-level error */
	EXLOG_OS,       /* OS-level error */
	EXLOG_DB        /* DB error */
};

enum exlog_cerrcode {
	EXLOG_SUCCESS = 0,
	EXLOG_INVAL,        /* An invalid value was obtained */
	EXLOG_NOENT,        /* An entity doesn't exist */
	EXLOG_EXIST,        /* An entity already exists */
	EXLOG_NOTDIR,       /* Attempted to readdir() on a non-directory */
	EXLOG_IO,           /* Something abnormal happened during I/O op */
	EXLOG_RES,          /* Resource is exhausted, or limit reached */
	EXLOG_BUSY,         /* Resource is busy, or already loaded */
	EXLOG_OPNOTSUPP,    /* The operation is not supported */
	EXLOG_NAMETOOLONG,  /* File name too long */
	EXLOG_LOCKBUSY,     /* A lock is already claimed */
	EXLOG_BADF,         /* Bad file descriptor, or conflicting
			       open flags */
	EXLOG_OVERFLOW,     /* Variable size overflow */
	EXLOG_SHORTIO,      /* Data sent or received is shorter than expected */
	EXLOG_EOF,          /* End-of-file */
	EXLOG_EXEC,         /* Error while running backend executable */
	EXLOG_JSON,         /* JSON error */
	EXLOG_CRC_MISMATCH, /* CRC mismatch in slab */
	EXLOG_NOSPC,        /* No space left on device */
	EXLOG_MGR           /* Issue arised during communication with
	                       slab manager */
};

#define EXLOG_INODE 0x0001
#define EXLOG_SLAB  0x0002
#define EXLOG_LOCK  0x0004
#define EXLOG_OP    0x0008
#define EXLOG_OF    0x0010

typedef uint16_t exlog_mask_t;

extern const struct module_dbg_map_entry {
	char         *name;
	exlog_mask_t  flag;
} module_dbg_map[];

// If both err and c_err are zero, all other fields should be ignored
struct exlog_err {
	/* App-specific error */
	int  layer;
	char msg[LINE_MAX];

	/* Contextual error (e.g. errno, etc.) */
	int  err;
};
#define EXLOG_ERR_INITIALIZER {0, "", 0}

struct exlog_err *exlog_zerr(struct exlog_err *);

/*
 * Fills the exlog_err structure with PotatoFS-specific error code, as well
 * as underlying library's or OS's context-specific error.
 * Formats an error message appropriate to the situation.
 * Returns -1 if either err or c_err is non-zero, or 0 if both are 0 as well.
 * As such, it can be used directly as part of the caller's return.
 *
 * If 'c_err' is non-zero, strerror_l() is called to fill the 'c_msg' field.
 * If fmt is non-NULL, 'msg' is filled up with the appropriate string.
 * 
 * Example:
 *   return exlog_errf(e, EXLOG_SOME_ERR, errno, "stuff failed: %s", details);
 */
int  exlog_errf(struct exlog_err *, int, int, const char *, ...);

/*
 * Returns non-zero if any error is contained in the exlog_err structure.
 */
int  exlog_fail(const struct exlog_err *);

int  exlog_err_is(const struct exlog_err *, int, int);

int  exlog_init(const char *, const char *, int);

void exlog_dbg(exlog_mask_t, const char *, ...);
void exlog(int, const struct exlog_err *, const char *, ...);
void exlog_strerror(int, int, const char *, ...);
void exlog_prt(const struct exlog_err *);

#endif
