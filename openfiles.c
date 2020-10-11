/*
 *  Copyright (C) 2020 Pascal Lalonde <plalonde@overnet.ca>
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
openfile_alloc(ino_t ino, int flags, struct exlog_err *e)
{
	struct open_file *of;
	uint32_t          oflags = 0;

	if ((of = malloc(sizeof(struct open_file))) == NULL) {
		exlog_errf(e, EXLOG_OS, errno, __func__);
		return NULL;
	}

	if (flags & O_SYNC)
		oflags |= INODE_OSYNC;
	if (flags & O_RDONLY)
		oflags |= INODE_ORO;

	if ((of->oi = inode_load(ino, oflags, e)) == NULL) {
		free(of);
		return NULL;
	}
	of->flags = flags;

	exlog_dbg(EXLOG_OF, "%s: (%p), inode=%lu, flags=(%d)",
	    __func__, of, ino, flags);

	return of;
}

int
openfile_free(struct open_file *of, struct exlog_err *e)
{
	if (inode_unload(of->oi, e) == -1)
		return -1;
	free(of);
	return 0;
}
