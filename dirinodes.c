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

#include <errno.h>
#include <string.h>
#include "inodes.h"
#include "dirinodes.h"

/*
 * Returns how entries were read so far. Can be used to resume
 * where we left off. *offset must always be set to the *end* of
 * the allocated dirent we've just read, or if there are any more
 * records to read, the next starting offset.
 */
ssize_t
di_readdir(struct oinode *oi, struct dir_entry *dirs,
    off_t *offset, size_t count, struct xerr *e)
{
	ssize_t r;
	ssize_t entries = 0;

	if (!inode_isdir(oi))
		return XERRF(e, XLOG_FS, ENOTDIR, "not a directory");

	while (entries < count) {
		r = inode_read(oi, *offset, dirs + entries,
		    sizeof(struct dir_entry), e);
		if (r == 0) {
		    break;
		} else if (r < sizeof(struct dir_entry)) {
			return XERRF(e, XLOG_APP, XLOG_IO,
			    "corrupted directory; incomplete entries");
		} else if (r == -1)
			return -1;

		/*
		 * If we hit a zero'd inode, maybe the offset
		 * where we were at got removed between successive readdir()
		 * calls. So, just try reading further.
		 */
		if (dirs[entries].inode == 0) {
			*offset += sizeof(struct dir_entry);
			continue;
		}

		if (dirs[entries].next == 0) {
			*offset += sizeof(struct dir_entry);
			entries++;
			break;
		}

		*offset = dirs[entries].next;
		entries++;
	}
	return entries;
}

/*
 * Fills 'de' with the dirent of 'name', if it exists. Returns
 * 0 on success, -1 with ENOENT if it doesn't exist, or
 * any other error if encountered.
 */
int
di_lookup(struct oinode *oi, struct dir_entry *de,
    const char *name, struct xerr *e)
{
	ssize_t r;
	off_t   offset;

	bzero(de, sizeof(struct dir_entry));
	for (offset = 0;; offset = de->next) {
		r = inode_read(oi, offset, de,
		    sizeof(struct dir_entry), e);
		if (r == 0) {
			break;
		} else if (r < sizeof(struct dir_entry)) {
			return XERRF(e, XLOG_APP, XLOG_IO,
			    "corrupted directory; incomplete entries");
		} else if (r == -1)
			return -1;

		if (strcmp(de->name, name) == 0)
			return 0;

		if (de->next == 0)
			break;
	}
	return XERRF(e, XLOG_FS, ENOENT,
	    "no such directory entry: %s (inode=%d)", name, inode_ino(oi));
}

/*
 * Write a new dirent, along with updating the previous used dirent
 * with the offset of the newly added entry. This make it easier to
 * traverse the list of used dirents.
 *
 * If 'replaced' is not NULL, we replace the named entry with the
 * new dirent, and copy the previous dirent in 'replaced'.
 * The caller should decrease nlink accordingly.
 */
int
di_mkdirent(struct oinode *parent, const struct dir_entry *de,
    struct dir_entry *replaced, struct xerr *e)
{
	ssize_t          r;
	off_t            offset = sizeof(struct dir_entry);
	off_t            prev_off = 0;
	struct dir_entry n_de, r_de, prev_used;

	memcpy(&n_de, de, sizeof(n_de));
	bzero(&prev_used, sizeof(prev_used));
	if (replaced)
		bzero(replaced, sizeof(struct dir_entry));

	/*
	 * Loop through our dirents, keep track of last used entry,
	 * because we'll insert after that. Also check if the new name
	 * already exists.
	 */
	for (;;) {
		r = inode_read(parent, offset, &r_de,
		    sizeof(struct dir_entry), e);
		if (r == 0) {
			break;
		} else if (r < sizeof(struct dir_entry)) {
			return XERRF(e, XLOG_APP, XLOG_IO,
			    "corrupted directory; incomplete entries");
		} else if (r == -1)
			return -1;

		if (strcmp(r_de.name, n_de.name) == 0) {
			if (!replaced) {
				return XERRF(e, XLOG_FS, EEXIST,
				    "file %s already exists", de->name);
			}
			memcpy(replaced, &r_de, sizeof(r_de));
			break;
		}

		if (r_de.inode == 0)
			break;
		else {
			memcpy(&prev_used, &r_de, sizeof(prev_used));
			prev_off = offset;
		}

		offset += r;
	}

	if (replaced != NULL && replaced->inode > 0)
		n_de.next = replaced->next;
	else
		n_de.next = prev_used.next;
	prev_used.next = offset;

	/*
	 * Write the new inode first to make sure it can be referenced. Only
	 * then can we finish writing the previous inode, or dir header.
	 */
	r = inode_write(parent, offset, &n_de, sizeof(n_de), e);
	if (r < sizeof(struct dir_entry)) {
		return XERRF(e, XLOG_APP, XLOG_IO,
		    "partial dirent write, this directory might "
		    "be corrupted");
	} else if (r == -1)
		return -1;

	r = inode_write(parent, prev_off, &prev_used, sizeof(prev_used), e);
	if (r < sizeof(struct dir_entry)) {
		return XERRF(e, XLOG_APP, XLOG_IO,
		    "partial dirent write, this directory "
		    "might be corrupted");
	}

	return 0;
}

/*
 * Returns 0 if the directory is not empty, 1 if empty, -1 on error.
 */
int
di_isempty(struct oinode *oi, struct xerr *e)
{
	if (inode_getsize(oi) == (sizeof(struct dir_entry) * 2))
		return 1;

	return 0;
}

/*
 * Remove a dirent and update the previous used dirent
 * with the offset of the next used entry, preserving our chain.
 */
int
di_unlink(struct oinode *parent, const struct dir_entry *de,
    struct xerr *e)
{
	ssize_t          r;
	off_t            offset = 0, prev_off = 0;
	struct dir_entry z_de, r_de, prev_used;

	bzero(&prev_used, sizeof(prev_used));

	for (;;) {
		r = inode_read(parent, offset, &r_de,
		    sizeof(struct dir_entry), xerrz(e));
		if (r == 0) {
			goto noent;
		} else if (r < sizeof(struct dir_entry)) {
			return XERRF(e, XLOG_APP, XLOG_IO,
			    "corrupted directory; incomplete entries");
		} else if (r == -1)
			return -1;

		if (strcmp(r_de.name, de->name) == 0)
			break;

		if (r_de.next == 0)
			goto noent;

		memcpy(&prev_used, &r_de, sizeof(prev_used));
		prev_off = offset;
		offset = r_de.next;
	}

	prev_used.next = r_de.next;

	r = inode_write(parent, prev_off, &prev_used, sizeof(prev_used),
	    xerrz(e));
	if (r < sizeof(struct dir_entry)) {
		return XERRF(e, XLOG_APP, XLOG_IO,
		    "partial dirent write while removing dirent; "
		    "used dirent list corrupted");
	}

	if (prev_used.next == 0) {
		if (inode_truncate(parent,
		    prev_off + sizeof(prev_used), xerrz(e)) == -1) {
			return xerr_prepend(e, __func__);
		}
		return 0;
	}

	bzero(&z_de, sizeof(z_de));
	r = inode_write(parent, offset, &z_de, sizeof(z_de), xerrz(e));
	if (r == -1) {
		return -1;
	} else if (r < sizeof(z_de)) {
		return XERRF(e, XLOG_APP, XLOG_IO,
		    "partial dirent write, this directory might be corrupted");
	}

	return 0;
noent:
	return XERRF(e, XLOG_FS, ENOENT, "no such dirent");
}

ino_t
di_parent(struct oinode *oi, struct xerr *e)
{
	ssize_t          r;
	struct dir_entry de;

	r = inode_read(oi, sizeof(struct dir_entry), &de,
	    sizeof(struct dir_entry), e);
	if (r == -1)
		return -1;
	else if (r < sizeof(struct dir_entry))
		return XERRF(e, XLOG_APP, XLOG_IO,
		    "corrupted directory; incomplete entries");

	return de.inode;
}

int
di_setparent(struct oinode *oi, ino_t parent, struct xerr *e)
{
	ssize_t          r;
	struct dir_entry de;

	r = inode_read(oi, sizeof(struct dir_entry), &de,
	    sizeof(struct dir_entry), e);
	if (r == -1)
		return -1;
	else if (r < sizeof(struct dir_entry))
		return XERRF(e, XLOG_APP, XLOG_IO,
		    "corrupted directory; incomplete entries");
	de.inode = parent;
	r = inode_write(oi, sizeof(struct dir_entry), &de,
	    sizeof(struct dir_entry), e);
	if (r == -1)
		return -1;
	else if (r < sizeof(struct dir_entry))
		return XERRF(e, XLOG_APP, XLOG_IO,
		    "partial dirent write, this directory might be corrupted");

	return de.inode;
}
