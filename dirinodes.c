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

static uint32_t di_check_format(struct oinode *, struct xerr *);
static int      di_create_v1(struct oinode *, ino_t, struct xerr *);
static ssize_t  di_readdir_v1(struct oinode *, struct dir_entry *,
                    off_t, size_t, struct xerr *);
static int      di_lookup_v1(struct oinode *, struct dir_entry *,
                    const char *, struct xerr *);
static int      di_mkdirent_v1(struct oinode *, const struct dir_entry *,
                    int , struct xerr *);
static int      di_isempty_v1(struct oinode *, struct xerr *);
static int      di_unlink_v1(struct oinode *, const struct dir_entry *,
                    struct xerr *);
static ino_t    di_parent_v1(struct oinode *, struct xerr *);
static int      di_setparent_v1(struct oinode *, ino_t, struct xerr *);

static struct {
	ssize_t (*readdir)(struct oinode *, struct dir_entry *,
	            off_t, size_t, struct xerr *);
	int     (*lookup)(struct oinode *, struct dir_entry *,
	            const char *, struct xerr *);
	int     (*mkdirent)(struct oinode *, const struct dir_entry *,
	            int, struct xerr *);
	int     (*isempty)(struct oinode *, struct xerr *);
	int     (*unlink)(struct oinode *, const struct dir_entry *,
                    struct xerr *);
	ino_t   (*parent)(struct oinode *, struct xerr *);
	int     (*setparent)(struct oinode *, ino_t, struct xerr *);
} di_fn[DIRINODE_FORMAT + 1] = {
	{
		/* There's no "v0" */
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	},
	{
		&di_readdir_v1,
		&di_lookup_v1,
		&di_mkdirent_v1,
		&di_isempty_v1,
		&di_unlink_v1,
		&di_parent_v1,
		&di_setparent_v1
	}
};

static uint32_t
di_check_format(struct oinode *oi, struct xerr *e)
{
	ssize_t         r;
	struct  dir_hdr hdr;

	r = inode_read(oi, 0, &hdr, sizeof(struct dir_hdr), xerrz(e));
	if (r == -1) {
		XERR_PREPENDFN(e);
		return 0;
	} else if (r < sizeof(struct dir_hdr)) {
		XERRF(e, XLOG_APP, XLOG_IO,
		    "corrupted dir_hdr");
		return 0;
	}
	if (!hdr.dirinode_format || hdr.dirinode_format > DIRINODE_FORMAT) {
		XERRF(e, XLOG_APP, XLOG_MISMATCH,
		    "unsupported dirinode format");
		return 0;
	}

	return hdr.dirinode_format;
}

int
di_create(struct oinode *oi, ino_t parent, struct xerr *e)
{
	return di_create_v1(oi, parent, e);
}

static int
di_create_v1(struct oinode *oi, ino_t parent, struct xerr *e)
{
	ssize_t             w;
	struct dir_hdr      hdr = { DIRINODE_FORMAT };
	struct dir_entry_v1 default_dir[2] = {
		{ ".", inode_ino(oi), sizeof(struct dir_entry_v1) },
		{ "..", parent, 0 }
	};

	w = inode_write(oi, 0, &hdr, sizeof(hdr), e);
	if (w == -1)
		return XERR_PREPENDFN(e);
	if (w < sizeof(hdr))
		return XERRF(e, XLOG_APP, XLOG_IO,
		    "partial dir_hdr write, this directory might "
		    "be corrupted");

	w = inode_write(oi, w, default_dir, sizeof(default_dir), e);
	if (w == -1)
		return XERR_PREPENDFN(e);

	if (w < sizeof(default_dir))
		return XERRF(e, XLOG_APP, XLOG_IO,
		    "partial dirent write, this directory might "
		    "be corrupted");

	return 0;
}

ssize_t
di_readdir(struct oinode *oi, struct dir_entry *dirs,
    off_t offset, size_t count, struct xerr *e)
{
	uint32_t dfmt;

	if (!inode_isdir(oi))
		return XERRF(e, XLOG_FS, ENOTDIR, "not a directory");

	if (!(dfmt = di_check_format(oi, e)))
		return XERR_PREPENDFN(e);
	else if (offset > 0 && offset < sizeof(struct dir_hdr))
		return XERRF(e, XLOG_APP, XLOG_INVAL,
		    "cannot do a partial read inside dir_hdr");

	return di_fn[dfmt].readdir(oi, dirs, offset, count, e);
}

/*
 * Returns how entries were read so far. Can be used to resume
 * where we left off. *offset must always be set to the *end* of
 * the allocated dirent we've just read, or if there are any more
 * records to read, the next starting offset.
 */
static ssize_t
di_readdir_v1(struct oinode *oi, struct dir_entry *dirs,
    off_t offset, size_t count, struct xerr *e)
{
	ssize_t  r;
	ssize_t  entries = 0;
	struct   dir_entry_v1 dirs_v1[count];

	while (entries < count) {
		r = inode_read(oi, sizeof(struct dir_hdr) + offset,
		    dirs_v1 + entries, sizeof(struct dir_entry_v1), xerrz(e));
		if (r == 0) {
		    break;
		} else if (r == -1) {
			return XERR_PREPENDFN(e);
		} else if (r < sizeof(struct dir_entry_v1)) {
			return XERRF(e, XLOG_APP, XLOG_IO,
			    "corrupted directory; incomplete entries");
		}

		/*
		 * If we hit a zero'd inode, maybe the offset
		 * where we were at got removed between successive readdir()
		 * calls. So, just try reading further.
		 */
		if (dirs_v1[entries].inode == 0) {
			offset += r;
			continue;
		}

		dirs[entries].inode = dirs_v1[entries].inode;
		strlcpy(dirs[entries].name, dirs_v1[entries].name,
		    sizeof(dirs[entries].name));

		if (dirs_v1[entries].next == 0) {
			dirs[entries].pos = offset +
			    sizeof(struct dir_entry_v1);
			entries++;
			break;
		}

		offset = dirs_v1[entries].next;
		dirs[entries].pos = offset;
		entries++;
	}
	return entries;
}

int
di_lookup(struct oinode *oi, struct dir_entry *de,
    const char *name, struct xerr *e)
{
	uint32_t dfmt;
	if (!(dfmt = di_check_format(oi, e)))
		return XERR_PREPENDFN(e);
	return di_fn[dfmt].lookup(oi, de, name, e);
}

/*
 * Fills 'de' with the dirent of 'name', if it exists. Returns
 * 0 on success, -1 with ENOENT if it doesn't exist, or
 * any other error if encountered.
 */
static int
di_lookup_v1(struct oinode *oi, struct dir_entry *de,
    const char *name, struct xerr *e)
{
	ssize_t             r;
	off_t               offset;
	struct dir_entry_v1 de_v1;

	bzero(de, sizeof(struct dir_entry));
	for (offset = 0;; offset = de_v1.next) {
		r = inode_read(oi, sizeof(struct dir_hdr) + offset, &de_v1,
		    sizeof(struct dir_entry_v1), xerrz(e));
		if (r == 0) {
			break;
		} else if (r < sizeof(struct dir_entry_v1)) {
			return XERRF(e, XLOG_APP, XLOG_IO,
			    "corrupted directory; incomplete entries");
		} else if (r == -1)
			return XERR_PREPENDFN(e);

		if (strcmp(de_v1.name, name) == 0) {
			de->inode = de_v1.inode;
			strlcpy(de->name, de_v1.name, sizeof(de->name));
			de->pos = (de_v1.next) ? de_v1.next :
			    offset + sizeof(struct dir_entry_v1);
			return 0;
		}

		if (de_v1.next == 0)
			break;
	}
	return XERRF(e, XLOG_FS, ENOENT,
	    "no such directory entry: %s (inode=%d)", name, inode_ino(oi));
}

int
di_mkdirent(struct oinode *parent, const struct dir_entry *de,
    int replace, struct xerr *e)
{
	uint32_t dfmt;
	if (!(dfmt = di_check_format(parent, e)))
		return XERR_PREPENDFN(e);
	return di_fn[dfmt].mkdirent(parent, de, replace, e);
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
static int
di_mkdirent_v1(struct oinode *parent, const struct dir_entry *de,
    int replace, struct xerr *e)
{
	ssize_t             r;
	off_t               offset = sizeof(struct dir_entry_v1);
	off_t               prev_off = 0;
	struct dir_entry_v1 n_de, r_de, prev_used, replaced;

	strlcpy(n_de.name, de->name, sizeof(n_de.name));
	n_de.inode = de->inode;
	n_de.next = 0;

	bzero(&prev_used, sizeof(prev_used));
	if (replace)
		bzero(&replaced, sizeof(replaced));

	/*
	 * Loop through our dirents, keep track of last used entry,
	 * because we'll insert after that. Also check if the new name
	 * already exists.
	 */
	for (;;) {
		r = inode_read(parent, offset + sizeof(struct dir_hdr), &r_de,
		    sizeof(r_de), xerrz(e));
		if (r == 0) {
			break;
		} else if (r < sizeof(r_de)) {
			return XERRF(e, XLOG_APP, XLOG_IO,
			    "corrupted directory; incomplete entries");
		} else if (r == -1)
			return XERR_PREPENDFN(e);

		if (strcmp(r_de.name, n_de.name) == 0) {
			if (!replace) {
				return XERRF(e, XLOG_FS, EEXIST,
				    "file %s already exists", de->name);
			}
			memcpy(&replaced, &r_de, sizeof(r_de));
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

	if (replace && replaced.inode > 0)
		n_de.next = replaced.next;
	else
		n_de.next = prev_used.next;
	prev_used.next = offset;

	/*
	 * Write the new inode first to make sure it can be referenced. Only
	 * then can we finish writing the previous inode, or dir header.
	 */
	r = inode_write(parent, offset + sizeof(struct dir_hdr), &n_de,
	    sizeof(n_de), xerrz(e));
	if (r < sizeof(n_de)) {
		return XERRF(e, XLOG_APP, XLOG_IO,
		    "partial dirent write, this directory might "
		    "be corrupted");
	} else if (r == -1)
		return XERR_PREPENDFN(e);

	r = inode_write(parent, prev_off + sizeof(struct dir_hdr),
	    &prev_used, sizeof(prev_used), e);
	if (r < sizeof(prev_used)) {
		return XERRF(e, XLOG_APP, XLOG_IO,
		    "partial dirent write, this directory "
		    "might be corrupted");
	}

	return 0;
}

int
di_isempty(struct oinode *oi, struct xerr *e)
{
	uint32_t dfmt;
	if (!(dfmt = di_check_format(oi, e)))
		return XERR_PREPENDFN(e);
	return di_fn[dfmt].isempty(oi, e);
}

/*
 * Returns 0 if the directory is not empty, 1 if empty, -1 on error.
 */
static int
di_isempty_v1(struct oinode *oi, struct xerr *e)
{
	if ((inode_getsize(oi) - sizeof(struct dir_hdr)) ==
	    (sizeof(struct dir_entry_v1) * 2))
		return 1;

	return 0;
}

int
di_unlink(struct oinode *parent, const struct dir_entry *de,
    struct xerr *e)
{
	uint32_t dfmt;
	if (!(dfmt = di_check_format(parent, e)))
		return XERR_PREPENDFN(e);
	return di_fn[dfmt].unlink(parent, de, e);
}

/*
 * Remove a dirent and update the previous used dirent
 * with the offset of the next used entry, preserving our chain.
 */
static int
di_unlink_v1(struct oinode *parent, const struct dir_entry *de,
    struct xerr *e)
{
	ssize_t             r;
	off_t               offset = 0, prev_off = 0;
	struct dir_entry_v1 z_de, r_de, prev_used;

	bzero(&prev_used, sizeof(prev_used));

	for (;;) {
		r = inode_read(parent, offset + sizeof(struct dir_hdr), &r_de,
		    sizeof(r_de), xerrz(e));
		if (r == 0) {
			goto noent;
		} else if (r < sizeof(r_de)) {
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

	r = inode_write(parent, prev_off + sizeof(struct dir_hdr), &prev_used,
	    sizeof(prev_used), xerrz(e));
	if (r < sizeof(prev_used)) {
		return XERRF(e, XLOG_APP, XLOG_IO,
		    "partial dirent write while removing dirent; "
		    "used dirent list corrupted");
	}

	if (prev_used.next == 0) {
		if (inode_truncate(parent,
		    sizeof(struct dir_hdr) + prev_off + sizeof(prev_used),
		    xerrz(e)) == -1)
			return XERR_PREPENDFN(e);
		return 0;
	}

	bzero(&z_de, sizeof(z_de));
	r = inode_write(parent, offset + sizeof(struct dir_hdr), &z_de,
	    sizeof(z_de), xerrz(e));
	if (r == -1) {
		return XERR_PREPENDFN(e);
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
	uint32_t dfmt;
	if (!(dfmt = di_check_format(oi, e)))
		return XERR_PREPENDFN(e);
	return di_fn[dfmt].parent(oi, e);
}

static ino_t
di_parent_v1(struct oinode *oi, struct xerr *e)
{
	ssize_t             r;
	struct dir_entry_v1 de;

	r = inode_read(oi, sizeof(struct dir_hdr) +
	    sizeof(struct dir_entry_v1), &de, sizeof(de), xerrz(e));
	if (r == -1)
		return XERR_PREPENDFN(e);
	else if (r < sizeof(de))
		return XERRF(e, XLOG_APP, XLOG_IO,
		    "corrupted directory; incomplete entries");

	return de.inode;
}

int
di_setparent(struct oinode *oi, ino_t parent, struct xerr *e)
{
	uint32_t dfmt;
	if (!(dfmt = di_check_format(oi, e)))
		return XERR_PREPENDFN(e);
	return di_fn[dfmt].setparent(oi, parent, e);
}

static int
di_setparent_v1(struct oinode *oi, ino_t parent, struct xerr *e)
{
	ssize_t             r;
	struct dir_entry_v1 de;

	r = inode_read(oi, sizeof(struct dir_hdr) + sizeof(struct dir_entry_v1),
	    &de, sizeof(de), xerrz(e));
	if (r == -1)
		return XERR_PREPENDFN(e);
	else if (r < sizeof(de))
		return XERRF(e, XLOG_APP, XLOG_IO,
		    "corrupted directory; incomplete entries");
	de.inode = parent;
	r = inode_write(oi, sizeof(struct dir_hdr) +
	    sizeof(struct dir_entry_v1), &de, sizeof(de), xerrz(e));
	if (r == -1)
		return XERR_PREPENDFN(e);
	else if (r < sizeof(de))
		return XERRF(e, XLOG_APP, XLOG_IO,
		    "partial dirent write, this directory might be corrupted");

	return 0;
}
