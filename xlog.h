/*
 *  Copyright (C) 2020-2023 Pascal Lalonde <plalonde@overnet.ca>
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

#ifndef XLOG_H
#define XLOG_H

#include <limits.h>
#include <stdint.h>
#include <syslog.h>

enum xerr_space {
	XLOG_NONE = 0,
	XLOG_APP,      /* App-internal error */
	XLOG_FS,       /* Standard errno code meant to be returned to FUSE */
	XLOG_ERRNO,    /* Standard errno code used internally only */
	XLOG_DB        /* DB error */
};

enum xerr_code {
	XLOG_SUCCESS = 0,
	XLOG_INVAL,        /* An invalid value was obtained */
	XLOG_IO,           /* Something abnormal happened during I/O op */
	XLOG_NAMETOOLONG,  /* File name too long */
	XLOG_EOF,          /* End-of-file */

	/* The following are temporary and the operation may be retried. */
	XLOG_NOSLAB,       /* Requested slab doesn't exist */
	XLOG_BUSY,         /* Resource/lock is busy */
	XLOG_MISMATCH,     /* CRC/revision/size does not match expectations */
	XLOG_NOSPC,        /* No space left on device */
	XLOG_BETIMEOUT,    /* Backend timeout */
	XLOG_BEERROR,      /* Backend error */
	XLOG_MGRERROR      /* Issue arised during communication with
	                      slab manager */
};

#define XLOG_INODE   0x0001
#define XLOG_SLAB    0x0002
#define XLOG_LOCK    0x0004
#define XLOG_OP      0x0008
#define XLOG_OF      0x0010
#define XLOG_SLABDB  0x0020
#define XLOG_MGR     0x0040

typedef uint16_t xlog_mask_t;

extern const struct module_dbg_map_entry {
	char        *name;
	xlog_mask_t  flag;
} module_dbg_map[];

struct xerr {
	char            msg[LINE_MAX];
	enum xerr_space sp;
	enum xerr_code  code;
};
#define XLOG_ERR_INITIALIZER {"", 0, 0}

/*
 * Zero the structure; common usage pattern is to zero the structure
 * each time we pass it to a function, e.g.:
 *
 *   struct xerr e;
 *   ...
 *   some_function(xerrz(&e));
 */
struct xerr *xerrz(struct xerr *);

/*
 * Fills the xlog_err structure with PotatoFS-specific error code, as well
 * as underlying library's or OS's context-specific error.
 * Formats an error message appropriate to the situation.
 * Returns -1 if either err or c_err is non-zero, or 0 if both are 0 as well.
 * As such, it can be used directly as part of the caller's return.
 *
 * If 'c_err' is non-zero, strerror_l() is called to fill the 'c_msg' field.
 * If fmt is non-NULL, 'msg' is filled up with the appropriate string.
 * 
 * Example:
 *   return xerrf(e, XLOG_ERRNO, errno, "stuff failed: %s", details);
 */
int  xerrf(struct xerr *, int, int, const char *, ...);
#define XERRF(e, sp, code, fmt, ...) \
    xerrfn(e, sp, code, __func__, fmt, ##__VA_ARGS__)
int  xerrfn(struct xerr *, int, int, const char *, const char *, ...);

/*
 * Returns non-zero if any error is contained in the xlog_err structure.
 */
int  xerr_fail(const struct xerr *);

int  xerr_is(const struct xerr *, int, int);

int  xlog_init(const char *, const char *, const char *, int);

void xlog_dbg(xlog_mask_t, const char *, ...);
void xlog(int, const struct xerr *, const char *, ...);
void xlog_strerror(int, int, const char *, ...);
void xerr_print(const struct xerr *);
int  xerr_prepend(struct xerr *, const char *);
#define XERR_PREPENDFN(e) xerr_prepend(e, __func__)

#endif
