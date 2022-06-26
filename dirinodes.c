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
#include <stdlib.h>
#include "inodes.h"
#include "dirinodes.h"

static uint32_t di_check_format(struct oinode *, struct xerr *);
static int      di_create_v1(struct oinode *, ino_t, struct xerr *);
static int      di_create_v2(struct oinode *, ino_t, struct xerr *);
static ssize_t  di_readdir_v1(struct oinode *, struct dir_entry *,
                    off_t, size_t, struct xerr *);
static ssize_t  di_readdir_v2(struct oinode *, struct dir_entry *,
                    off_t, size_t, struct xerr *);
static int      di_lookup_v1(struct oinode *, struct dir_entry *,
                    const char *, struct xerr *);
static int      di_lookup_v2(struct oinode *, struct dir_entry *,
                    const char *, struct xerr *);
static int      di_mkdirent_v1(struct oinode *, const struct dir_entry *,
                    int , struct xerr *);
static int      di_mkdirent_v2(struct oinode *, const struct dir_entry *,
                    int , struct xerr *);
static int      di_isempty_v1(struct oinode *, struct xerr *);
static int      di_isempty_v2(struct oinode *, struct xerr *);
static int      di_unlink_v1(struct oinode *, const struct dir_entry *,
                    struct xerr *);
static int      di_unlink_v2(struct oinode *, const struct dir_entry *,
                    struct xerr *);
static ino_t    di_parent_v1(struct oinode *, struct xerr *);
static ino_t    di_parent_v2(struct oinode *, struct xerr *);
static int      di_setparent_v1(struct oinode *, ino_t, struct xerr *);
static int      di_setparent_v2(struct oinode *, ino_t, struct xerr *);
static ssize_t  di_pack_v2(char *, size_t, struct dir_entry_v2 *);
static ssize_t  di_unpack_v2(char *, size_t , struct dir_entry_v2 *);

static struct {
	int     (*create)(struct oinode *, ino_t, struct xerr *);
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
		NULL,
		NULL
	},
	{
		&di_create_v1,
		&di_readdir_v1,
		&di_lookup_v1,
		&di_mkdirent_v1,
		&di_isempty_v1,
		&di_unlink_v1,
		&di_parent_v1,
		&di_setparent_v1
	},
	{
		&di_create_v2,
		&di_readdir_v2,
		&di_lookup_v2,
		&di_mkdirent_v2,
		&di_isempty_v2,
		&di_unlink_v2,
		&di_parent_v2,
		&di_setparent_v2
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

static ssize_t
di_pack_v2(char *buf, size_t sz, struct dir_entry_v2 *de)
{
	char   *p = buf;

	if (sz < (sizeof(de->flags) +
	    sizeof(de->length) +
	    sizeof(de->inode) +
	    strlen(de->name) + 1))
		return -1;

	*(uint8_t *)p++ = de->flags;
	*(uint8_t *)p++ = de->length;
	*(ino_t *)p++ = de->inode;
	p += strlcpy(p, de->name, sz -
	    (sizeof(de->flags) + sizeof(de->length) + sizeof(de->inode)));

	return p - buf;
}

static ssize_t
di_unpack_v2(char *buf, size_t sz, struct dir_entry_v2 *de)
{
	char *p = buf;

	if (sz < (sizeof(de->flags) +
	    sizeof(de->length) +
	    sizeof(de->inode)))
		return -1;

	bzero(de, sizeof(struct dir_entry_v2));
	de->flags = *(uint8_t *)p++;
	de->length = *(uint8_t *)p++;
	de->inode = *(ino_t *)p++;

	if (sz < ((p - buf) + de->length))
		return -1;

	if (de->flags & DI_ALLOCATED) {
		memcpy(de->name, p, de->length);
		de->name[de->length] = '\0';
	}
	p += de->length;

	return p - buf;
}

int
di_create(struct oinode *oi, ino_t parent, struct xerr *e)
{
	return di_fn[DIRINODE_FORMAT].create(oi, parent, e);
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

static int
di_create_v2(struct oinode *oi, ino_t parent, struct xerr *e)
{
	ssize_t              w;
	struct dir_hdr       hdr = { DIRINODE_FORMAT };
	char                 buf[sizeof(struct dir_entry_v2) * 2];
	char                *p;
	struct dir_entry_v2  default_dir[3] = {
		{DI_ALLOCATED, 2, inode_ino(oi), "."},
		{DI_ALLOCATED, 3, parent, ".."}
	};

	w = inode_write(oi, 0, &hdr, sizeof(hdr), e);
	if (w == -1)
		return XERR_PREPENDFN(e);
	if (w < sizeof(hdr))
		return XERRF(e, XLOG_APP, XLOG_IO,
		    "partial dir_hdr write, this directory might "
		    "be corrupted");

	bzero(buf, sizeof(buf));
	p = buf;
	p += di_pack_v2(buf, sizeof(buf), &default_dir[0]);
	p += di_pack_v2(p, sizeof(buf) - (p - buf), &default_dir[1]);

	w = inode_write(oi, w, buf, p - buf, e);
	if (w == -1)
		return XERR_PREPENDFN(e);

	if (w < sizeof(p - buf))
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

static ssize_t
di_readdir_v2(struct oinode *oi, struct dir_entry *dirs,
    off_t offset, size_t count, struct xerr *e)
{
	return XERRF(e, XLOG_FS, EOPNOTSUPP, "%s: not implemented", __func__);
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

static int
di_lookup_v2(struct oinode *oi, struct dir_entry *de,
    const char *name, struct xerr *e)
{
	ssize_t              r, buf_sz;
	struct dir_entry_v2  de_v2;
	char                 buf[FS_BLOCK_SIZE];
	char                *p;

	buf_sz = inode_read(oi, sizeof(struct dir_hdr), buf,
	    inode_max_inline_b(), e);
	if (buf_sz == 0) {
		return XERRF(e, XLOG_FS, ENOENT,
		    "no such directory entry: %s (inode=%d)",
		    name, inode_ino(oi));
	} else if (buf_sz == -1)
		return XERR_PREPENDFN(e);

	for (p = buf; p - buf < buf_sz; p += r) {
		/*
		 * Dir entries in the inode are always contiguous.
		 * If we see one that's not allocated, it means there
		 * are no more after.
		 */
		if ((r = di_unpack_v2(p, buf_sz - (p - buf), &de_v2)) == -1)
			break;
		if (!(de_v2.flags & DI_ALLOCATED))
			break;

		if (strcmp(de->name, de_v2.name) == 0) {
			de->inode = de_v2.inode;
			de->pos = (p - buf) + r;
			strlcpy(de->name, de_v2.name, sizeof(de->name));
			return 0;
		}
	}

	// TODO: when going beyond inline data
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

static int
di_mkdirent_v2(struct oinode *parent, const struct dir_entry *de,
    int replace, struct xerr *e)
{
	ssize_t              r, buf_sz;
	struct dir_entry_v2 *de_v2;
	size_t               n = 16;
	char                 buf[FS_BLOCK_SIZE];
	char                *p;

	buf_sz = inode_read(parent, sizeof(struct dir_hdr), buf,
	    inode_max_inline_b(), e);
	if (buf_sz == -1)
		return XERR_PREPENDFN(e);

	de_v2 = malloc(sizeof(struct dir_entry_v2) * n);
	if (de_v2 == NULL)
		return XERRF(e, XLOG_ERRNO, errno, "%s: malloc", __func__);

	for (p = buf; p - buf < buf_sz; p += r) {
		/*
		 * Dir entries in the inode are always contiguous.
		 * If we see one that's not allocated, it means there
		 * are no more after.
		 */
		if ((r = di_unpack_v2(p, buf_sz - (p - buf), &de_v2[0])) == -1)
			break;
		if (!(de_v2[0].flags & DI_ALLOCATED))
			break;

		if (strcmp(de->name, de_v2[0].name) == 0) {
			if (!replace) {
				free(de_v2);
				return XERRF(e, XLOG_FS, EEXIST,
				    "file %s already exists", de->name);
			}
			de_v2[0].inode = de->inode;
			de_v2[0].length = strlcpy(de_v2[0].name, de->name,
			    sizeof(de_v2[0].name));
			// TODO: from that point on, load up the rest of
			// the dir into de_v2, then overwrite.
			// Leftovers will go in the hash tree.

			// TODO: what to do for replace?
			free(de_v2);
			return XERRF(e, XLOG_FS, EOPNOTSUPP,
			    "%s: not implemented", __func__);
		}
	}

	free(de_v2);
	// TODO: when going beyond inline data
	return XERRF(e, XLOG_FS, EOPNOTSUPP, "%s: not implemented", __func__);
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

static int
di_isempty_v2(struct oinode *oi, struct xerr *e)
{
	return XERRF(e, XLOG_FS, EOPNOTSUPP, "%s: not implemented", __func__);
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

static int
di_unlink_v2(struct oinode *parent, const struct dir_entry *de,
    struct xerr *e)
{
	return XERRF(e, XLOG_FS, EOPNOTSUPP, "%s: not implemented", __func__);
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

static ino_t
di_parent_v2(struct oinode *oi, struct xerr *e)
{
	return XERRF(e, XLOG_FS, EOPNOTSUPP, "%s: not implemented", __func__);
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

static int
di_setparent_v2(struct oinode *oi, ino_t parent, struct xerr *e)
{
	return XERRF(e, XLOG_FS, EOPNOTSUPP, "%s: not implemented", __func__);
}
