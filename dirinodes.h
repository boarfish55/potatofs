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

#ifndef DIRINODES_H
#define DIRINODES_H

#include "config.h"
#include "inodes.h"

struct dir_hdr {
#define DIRINODE_FORMAT 1
	uint32_t dirinode_format;
};

struct dir_entry {
	char   name[FS_NAME_MAX + 1];
	ino_t  inode;
	/*
	 * When entries are returned by di_readdir(), the position in
	 * the dir entry "stream" will be saved here. This could be used
	 * by callers in telldir() / seekdir().
	 */
	off_t  pos;
};

struct dir_entry_v1 {
	char   name[FS_NAME_MAX + 1];
	ino_t  inode;
	/* Indicates the next free entry in the file */
	off_t  next;
};

/* None of these acquire any lock */
int     di_create(struct oinode *, ino_t, struct xerr *);
ssize_t di_readdir(struct oinode *, struct dir_entry *, off_t,
            size_t, struct xerr *);
int     di_lookup(struct oinode *, struct dir_entry *, const char *,
            struct xerr *);
int     di_mkdirent(struct oinode *, const struct dir_entry *, int,
            struct xerr *);
int     di_unlink(struct oinode *, const struct dir_entry *,
            struct xerr *);
int     di_stat(struct oinode *, struct stat *, struct xerr *);
int     di_isempty(struct oinode *, struct xerr *);
ino_t   di_parent(struct oinode *, struct xerr *);
int     di_setparent(struct oinode *, ino_t, struct xerr *);

#endif
