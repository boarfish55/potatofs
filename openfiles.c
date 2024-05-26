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
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/time.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "openfiles.h"
#include "inodes.h"
#include "slabs.h"

struct open_file *
openfile_alloc(ino_t ino, int flags, struct xerr *e)
{
	struct open_file *of;
	uint32_t          oflags = 0;

	if ((of = malloc(sizeof(struct open_file))) == NULL) {
		XERRF(e, XLOG_FS, errno, "malloc");
		return NULL;
	}
	if (LK_LOCK_INIT(&of->lock, xerrz(e)) == -1) {
		if (xerr_is(e, XLOG_ERRNO, ENOMEM))
			XERRF(e, XLOG_FS, ENOMEM, "LK_LOCK_INIT");
		else
			XERR_PREPENDFN(e);
		return NULL;
	}

	if (flags & O_SYNC)
		oflags |= INODE_OSYNC;
	if ((flags & (O_WRONLY|O_RDWR)) == 0)
		oflags |= INODE_ORO;

	LK_WRLOCK(&of->lock);
	if ((of->oi = inode_load(ino, oflags, xerrz(e))) == NULL) {
		LK_UNLOCK(&of->lock);
		free(of);
		return NULL;
	}
	of->flags = flags;
	LK_UNLOCK(&of->lock);

	xlog_dbg(XLOG_OF, "%s: (%p), inode=%lu, flags=(%d)",
	    __func__, of, ino, flags);

	return of;
}

struct oinode *
openfile_inode(struct open_file *of)
{
	struct oinode *oi;
	LK_RDLOCK(&of->lock);
	oi = of->oi;
	LK_UNLOCK(&of->lock);
	return oi;
}

int
openfile_free(struct open_file *of, struct xerr *e)
{
	LK_WRLOCK(&of->lock);
	if (inode_unload(of->oi, xerrz(e)) == -1) {
		LK_UNLOCK(&of->lock);
		return -1;
	}
	LK_UNLOCK(&of->lock);
	LK_LOCK_DESTROY(&of->lock);
	free(of);
	return 0;
}
