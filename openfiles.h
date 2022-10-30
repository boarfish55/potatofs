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

#ifndef OPENFILES_H
#define OPENFILES_H

#include <stdint.h>
#include "util.h"
#include "xlog.h"

struct open_file {
	rwlk           lock;
	struct oinode *oi;
	int            flags;
};

struct open_file *openfile_alloc(ino_t, int, struct xerr *);
int               openfile_free(struct open_file *, struct xerr *);
struct oinode    *openfile_inode(struct open_file *);

#endif
