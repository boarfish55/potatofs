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
static int      di_readdir_buf_v2(const char *, size_t, struct dir_entry *,
                    size_t, off_t, struct xerr *);
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

/*
 * FNV-1a hash:
 *   http://isthe.com/chongo/tech/comp/fnv/index.html
 *   http://tools.ietf.org/html/draft-eastlake-fnv-03
 */
static uint32_t
fnv1a32(const void *s, size_t klen)
{
	size_t         i;
	const size_t   prime32 = 16777619;
	const size_t   offset32 = 2166136261;
	size_t         h = offset32;
	unsigned char *p = (unsigned char *)s;

	for (i = 0; i < klen; i++, p++) {
		h *= prime32;
		h ^= *p;
	}

	return h;
}

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

static int
di_read_dir_hdr_v2(struct oinode *oi, struct dir_hdr_v2 *hdr, struct xerr *e)
{
	ssize_t r;

	if ((r = inode_read(oi, 0, hdr, sizeof(struct dir_hdr_v2), e)) == -1)
		return XERR_PREPENDFN(e);
	else if (r < sizeof(struct dir_hdr_v2))
		return XERRF(e, XLOG_APP, XLOG_IO,
		    "short read on dir_hdr_v2 for inode=%lu", inode_ino(oi));
	return 0;
}

ssize_t
di_pack_v2(char *buf, size_t sz, const struct dir_entry_v2 *de)
{
	char   *p = buf;

	if (sz < (sizeof(de->flags) +
	    sizeof(de->length) +
	    sizeof(de->hash) +
	    sizeof(de->inode) +
	    de->length))
		return SSIZE_MAX;

	*(uint8_t *)p = de->flags;
	p += sizeof(uint8_t);

	*(uint32_t *)p = de->hash;
	p += sizeof(uint32_t);

	*(ino_t *)p = de->inode;
	p += sizeof(ino_t);

	*(uint8_t *)p = de->length;
	p += sizeof(uint8_t);

	p += strlcpy(p, de->name, sz -
	    (sizeof(de->flags) + sizeof(de->hash) +
	     sizeof(de->length) + sizeof(de->inode)));

	return p - buf;
}

ssize_t
di_unpack_v2(const char *buf, size_t sz, struct dir_entry_v2 *de)
{
	const char *p = buf;

	if (sz < (sizeof(de->flags) +
	    sizeof(de->length) +
	    sizeof(de->hash) +
	    sizeof(de->inode)))
		return SSIZE_MAX;

	bzero(de, sizeof(struct dir_entry_v2));
	de->flags = *(uint8_t *)p;
	p += sizeof(uint8_t);

	de->hash = *(uint32_t *)p;
	p += sizeof(uint32_t);

	de->inode = *(ino_t *)p;
	p += sizeof(ino_t);

	de->length = *(uint8_t *)p;
	p += sizeof(uint8_t);

	if (sz < ((p - buf) + de->length))
		return (p - buf) + de->length;

	if (de->flags & DI_ALLOCATED)
		de->name = p;
	else
		de->name = NULL;

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
	ssize_t           w;
	struct dir_hdr_v2 hdr;

	bzero(&hdr, sizeof(hdr));
	hdr.hdr.dirinode_format = DIRINODE_FORMAT;
	hdr.flags = DI_INLINE;
	hdr.inode = inode_ino(oi);
	hdr.parent = parent;

	if ((w = inode_write(oi, 0, &hdr, sizeof(hdr), e)) == -1)
		return XERR_PREPENDFN(e);

	if (w < sizeof(hdr))
		return XERRF(e, XLOG_APP, XLOG_IO,
		    "partial dir_hdr write, this directory might "
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

	if (offset > 0 && offset < sizeof(struct dir_hdr))
		return XERRF(e, XLOG_APP, XLOG_INVAL,
		    "cannot do a partial read inside dir_hdr");

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
			dirs[entries].d_off = offset +
			    sizeof(struct dir_entry_v1);
			entries++;
			break;
		}

		offset = dirs_v1[entries].next;
		dirs[entries].d_off = offset;
		entries++;
	}
	return entries;
}

int
di_readdir_buf_v2(const char *buf, size_t sz, struct dir_entry *dirs,
    size_t count, off_t d_off, struct xerr *e)
{
	ssize_t              r;
	struct dir_entry_v2  de_v2;
	const char          *p;
	uint32_t             i;
	/*
	 * If d_off is 2 or less, then we are reading from the start
	 * of this buffer. Otherwise we need to match the "virtual offset"
	 * composed of the hash and current item index in the buffer.
	 */
	//int                  found_d_off = (d_off <= 2) ? 1 : 0;

	for (p = buf, i = 0; i < count && p - buf < sz; p += r) {
		/*
		 * Dir entries in the inode are always contiguous.
		 * If we see one that's not allocated, it means there
		 * are no more after.
		 */
		if ((r = di_unpack_v2(p, sz - (p - buf), &de_v2)) >
		    sz - (p - buf))
			break;

		if (!(de_v2.flags & DI_ALLOCATED))
			break;

		if ((p - buf) + 2 >= d_off) {
			strlcpy(dirs[i].name, de_v2.name, de_v2.length + 1);
			dirs[i].inode = de_v2.inode;
			dirs[i].d_off = (p - buf) + r;
			i++;
		}
	}

	return i;
}

static ssize_t
di_readdir_v2(struct oinode *oi, struct dir_entry *dirs,
    off_t d_off, size_t count, struct xerr *e)
{
	ssize_t              buf_sz;
	char                 buf[FS_BLOCK_SIZE];
	struct dir_hdr_v2    hdr;
	int                  i = 0;

	if (di_read_dir_hdr_v2(oi, &hdr, e) == -1)
		return XERR_PREPENDFN(e);

	if (d_off == 0 && i < count) {
		dirs[i].inode = hdr.inode;
		strlcpy(dirs[i].name, ".", sizeof(dirs[i].name));
		dirs[i].d_off = 1;
		d_off = 1;
		i++;
	}

	if (d_off == 1 && i < count) {
		dirs[i].inode = hdr.parent;
		strlcpy(dirs[i].name, "..", sizeof(dirs[i].name));
		dirs[i].d_off = 2;
		d_off = 2;
		i++;
	}

	buf_sz = inode_read(oi, sizeof(hdr), buf,
	    inode_max_inline_b() - sizeof(hdr), e);
	if (buf_sz == 0) {
		return i;
	} else if (buf_sz == -1)
		return XERR_PREPENDFN(e);

	if (hdr.flags & DI_INLINE)
		return i + di_readdir_buf_v2(buf, buf_sz, dirs + i,
		    count, d_off, e);

	// TODO: when going beyond inline data
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
			de->d_off = (de_v1.next) ? de_v1.next :
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
di_lookup_buf_v2(const char *buf, size_t sz, struct dir_entry *de,
    uint32_t hash, const char *name, struct xerr *e)
{
	ssize_t              r;
	struct dir_entry_v2  de_v2;
	const char          *p;

	for (p = buf; p - buf < sz; p += r) {
		/*
		 * Dir entries in the inode are always contiguous.
		 * If we see one that's not allocated, it means there
		 * are no more after.
		 */
		if ((r = di_unpack_v2(p, sz - (p - buf), &de_v2)) >
		    sz - (p - buf))
			break;
		if (!(de_v2.flags & DI_ALLOCATED))
			break;

		if (de_v2.hash != hash || strlen(name) != de_v2.length)
			continue;

		if (strncmp(name, de_v2.name, de_v2.length) == 0) {
			strlcpy(de->name, de_v2.name, de_v2.length + 1);
			de->inode = de_v2.inode;
			de->d_off = (p - buf) + r;
			return 0;
		}
	}

	return XERRF(e, XLOG_FS, ENOENT, "no such directory entry: %s",
	    de->name);
}

static int
di_lookup_v2(struct oinode *oi, struct dir_entry *de, const char *name,
    struct xerr *e)
{
	ssize_t              buf_sz;
	char                 buf[FS_BLOCK_SIZE];
	struct dir_hdr_v2    hdr;
	uint32_t             hash = fnv1a32(name, strlen(name));

	if (di_read_dir_hdr_v2(oi, &hdr, e) == -1)
		return XERR_PREPENDFN(e);

	if (strcmp(name, ".") == 0) {
		strlcpy(de->name, name, sizeof(de->name));
		de->inode = hdr.inode;
		de->d_off = 0;
		return 0;
	} else if (strcmp(name, "..") == 0) {
		strlcpy(de->name, name, sizeof(de->name));
		de->inode = hdr.parent;
		de->d_off = 0;
		return 0;
	}

	buf_sz = inode_read(oi, sizeof(hdr), buf,
	    inode_max_inline_b() - sizeof(hdr), e);
	if (buf_sz == 0) {
		goto end;
	} else if (buf_sz == -1)
		return XERR_PREPENDFN(e);

	if (hdr.flags & DI_INLINE)
		return di_lookup_buf_v2(buf, buf_sz, de, hash, name, e);

	// TODO: when going beyond inline data
end:
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
	ssize_t              r;
	struct dir_entry_v2  de_v2;
	struct dir_hdr_v2    hdr;
	char                 buf[inode_max_inline_b() - sizeof(hdr)];
	char                *p;

	if (di_read_dir_hdr_v2(parent, &hdr, e) == -1)
		return XERR_PREPENDFN(e);

	if (strcmp(de->name, ".") == 0 || strcmp(de->name, "..") == 0)
		return XERRF(e, XLOG_FS, (replace) ? EBUSY : EEXIST,
		    "file %s already exists", de->name);

	if ((r = inode_read(parent, sizeof(hdr), buf, sizeof(buf), e)) == -1)
		return XERR_PREPENDFN(e);

	de_v2.flags = DI_ALLOCATED;
	de_v2.length = strlen(de->name);
	de_v2.name = de->name;
	de_v2.inode = de->inode;
	de_v2.hash = fnv1a32(de_v2.name, de_v2.length);

	if (hdr.flags & DI_INLINE) {
		p = buf + r;
		p += di_pack_v2(p, sizeof(buf), &de_v2);
		if (p > buf + sizeof(buf)) {
			// TODO: clear hdr.flags DI_INLINE
			//       convert to hash tree
			return XERRF(e, XLOG_FS, EOPNOTSUPP,
			    "%s: not implemented", __func__);
		}
		r = inode_write(parent, sizeof(hdr), buf, p - buf, e);
		if (r < sizeof(p - buf)) {
			return XERRF(e, XLOG_APP, XLOG_IO,
			    "partial dirent write, this directory "
			    "might be corrupted");
		}
		hdr.entries++;
		if ((r = inode_write(parent, 0, &hdr, sizeof(hdr), e)) <
		    sizeof(hdr)) {
			return XERRF(e, XLOG_APP, XLOG_IO,
			    "partial dir_hdr_v2 write, this directory "
			    "might be corrupted");
		}
		return 0;
	}

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
	struct dir_hdr_v2 hdr;
	if (di_read_dir_hdr_v2(oi, &hdr, e) == -1)
		return XERR_PREPENDFN(e);
	return (hdr.entries == 0) ? 1 : 0;
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

/*
 * Returns the new buffer size after removing the dir entry, or -1 on error.
 */
static ssize_t
di_unlink_buf_v2(char *buf, size_t sz, const struct dir_entry *de,
    uint32_t hash, const char *name, struct xerr *e)
{
	ssize_t              r;
	struct dir_entry_v2  de_v2;
	char                *p;

	for (p = buf; p - buf < sz; p += r) {
		/*
		 * Dir entries in the inode are always contiguous.
		 * If we see one that's not allocated, it means there
		 * are no more after.
		 */
		if ((r = di_unpack_v2(p, sz - (p - buf), &de_v2)) >
		    sz - (p - buf))
			break;
		if (!(de_v2.flags & DI_ALLOCATED))
			break;

		if (de_v2.hash != hash || strlen(name) != de_v2.length)
			continue;

		if (strncmp(name, de_v2.name, de_v2.length) == 0) {
			memmove(p, p + r, sz - ((p - buf) + r));
			return sz - r;
		}
	}

	return XERRF(e, XLOG_FS, ENOENT, "no such directory entry: %s",
	    de->name);
}

static int
di_unlink_v2(struct oinode *parent, const struct dir_entry *de,
    struct xerr *e)
{
	ssize_t              r;
	struct dir_hdr_v2    hdr;
	char                 buf[inode_max_inline_b() - sizeof(hdr)];
	ssize_t              buf_sz;
	uint32_t             hash = fnv1a32(de->name, strlen(de->name));

	if (di_read_dir_hdr_v2(parent, &hdr, e) == -1)
		return XERR_PREPENDFN(e);

	if (strcmp(de->name, ".") == 0 || strcmp(de->name, "..") == 0)
		return XERRF(e, XLOG_FS, EBUSY,
		    "file %s cannot be removed", de->name);

	buf_sz = inode_read(parent, sizeof(hdr), buf,
	    inode_max_inline_b() - sizeof(hdr), e);
	if (buf_sz == 0) {
		goto end;
	} else if (buf_sz == -1)
		return XERR_PREPENDFN(e);

	if (hdr.flags & DI_INLINE) {
		buf_sz = di_unlink_buf_v2(buf, buf_sz, de, hash, de->name, e);
		if (buf_sz == -1)
			return XERR_PREPENDFN(e);

		r = inode_write(parent, sizeof(hdr), buf, buf_sz, e);
		if (r == -1) {
			return XERR_PREPENDFN(e);
		} else if (r < buf_sz) {
			return XERRF(e, XLOG_APP, XLOG_IO,
			    "partial dirent write, this directory "
			    "might be corrupted");
		}
		if (inode_truncate(parent, sizeof(hdr) + buf_sz,
		    xerrz(e)) == -1)
			return XERR_PREPENDFN(e);

		hdr.entries--;
		if ((r = inode_write(parent, 0, &hdr, sizeof(hdr), e)) <
		    sizeof(hdr)) {
			return XERRF(e, XLOG_APP, XLOG_IO,
			    "partial dir_hdr_v2 write, this directory "
			    "might be corrupted");
		}
		return 0;
	}

	// TODO: when going beyond inline data
end:
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
	struct dir_hdr_v2 hdr;
	if (di_read_dir_hdr_v2(oi, &hdr, e) == -1)
		return XERR_PREPENDFN(e);
	return hdr.parent;
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
	struct dir_hdr_v2 hdr;
	ssize_t           r;

	if (di_read_dir_hdr_v2(oi, &hdr, e) == -1)
		return XERR_PREPENDFN(e);

	hdr.parent = parent;
	if ((r = inode_write(oi, 0, &hdr, sizeof(hdr), e)) < sizeof(hdr)) {
		return XERRF(e, XLOG_APP, XLOG_IO,
		    "partial dir_hdr_v2 write, this directory "
		    "might be corrupted");
	}
	return 0;
}
