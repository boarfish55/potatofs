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
#include <stddef.h>
#include <stdlib.h>
#include "inodes.h"
#include "dirinodes.h"

static uint32_t di_check_format(struct oinode *, struct xerr *);
static int      di_create_v1(struct oinode *, ino_t, struct xerr *);
static int      di_create_v2(struct oinode *, ino_t, struct xerr *);
static ssize_t  di_readdir_v1(struct oinode *, struct dir_entry *,
                    off_t, size_t, struct xerr *);
static int      di_readdir_buf_v2(const char *, size_t, struct dir_entry *,
                    size_t, off_t, off_t, struct xerr *);
static ssize_t  di_readdir_deep_v2(struct oinode *, off_t, int,
                    struct dir_entry *, size_t, off_t, struct xerr *);
static ssize_t  di_readdir_v2(struct oinode *, struct dir_entry *,
                    off_t, size_t, struct xerr *);
static int      di_lookup_v1(struct oinode *, struct dir_entry *,
                    const char *, struct xerr *);
static int      di_lookup_buf_v2(const char *, size_t, struct dir_entry *,
                    uint32_t, const char *, struct xerr *);
static int      di_lookup_deep_v2(struct oinode *, off_t, int,
                    struct dir_entry *, uint32_t, const char *, struct xerr *);
static int      di_lookup_v2(struct oinode *, struct dir_entry *,
                    const char *, struct xerr *);
static int      di_mkdirent_v1(struct oinode *, const struct dir_entry *,
                    int , struct xerr *);
static int      di_to_hash_v2(struct oinode *, struct dir_hdr_v2 *,
                    struct dir_block_v2 *, off_t, int, struct xerr *);
static off_t    di_mkdirent_getblock_v2(struct oinode *, struct dir_hdr_v2 *,
                    struct xerr *);
static int      di_mkdirent_deep_v2(struct oinode *, struct dir_hdr_v2 *, off_t,
                    int, struct dir_entry_v2 *, int, struct xerr *);
static int      di_mkdirent_v2(struct oinode *, const struct dir_entry *,
                    int , struct xerr *);
static int      di_isempty_v1(struct oinode *, struct xerr *);
static int      di_isempty_v2(struct oinode *, struct xerr *);
static int      di_unlink_v1(struct oinode *, const struct dir_entry *,
                    struct xerr *);
static int      di_unlink_freelist_add_v2(struct oinode *, struct dir_hdr_v2 *,
                    off_t, struct dir_block_v2 *, struct xerr *);
static ssize_t  di_unlink_buf_v2(char *, size_t, uint32_t, const char *,
                    struct xerr *e);
static int      di_unlink_deep_v2(struct oinode *, struct dir_hdr_v2 *, off_t,
                    struct dir_block_v2 *, off_t, int, const struct dir_entry *,
                    uint32_t, const char *, struct xerr *);
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
uint32_t
di_fnv1a32(const void *s, size_t klen)
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
		XERRF(e, XLOG_APP, XLOG_IO, "corrupted dir_hdr");
		return 0;
	}
	if (!hdr.dirinode_format || hdr.dirinode_format > DIRINODE_FORMAT) {
		XERRF(e, XLOG_APP, XLOG_MISMATCH, "unsupported dirinode format");
		return 0;
	}

	return hdr.dirinode_format;
}

static ssize_t
di_read_dir_hdr_v2(struct oinode *oi, struct dir_hdr_v2 *hdr, struct xerr *e)
{
	ssize_t r;

	if ((r = inode_read(oi, 0, hdr,
	    sizeof(struct dir_hdr_v2), xerrz(e))) == -1)
		return XERR_PREPENDFN(e);
	else if (r == 0)
		return XERRF(e, XLOG_APP, XLOG_EOF,
		    "tried to read a dir_hdr_v2 past the end of the file: "
		    "inode=%lu", inode_ino(oi));
	else if (r < sizeof(struct dir_hdr_v2))
		return XERRF(e, XLOG_APP, XLOG_IO,
		    "short read on dir_hdr_v2 for inode=%lu", inode_ino(oi));
	return 0;
}

static ssize_t
di_read_dir_block_v2(struct oinode *oi, off_t b_off, struct dir_block_v2 *b,
    struct xerr *e)
{
	ssize_t r;

	if ((r = inode_read(oi, b_off, b,
	    sizeof(struct dir_block_v2), xerrz(e))) == -1)
		return XERR_PREPENDFN(e);
	else if (r == 0)
		return XERRF(e, XLOG_APP, XLOG_EOF,
		    "tried to read a dir_block_v2 past the end of the file: "
		    "inode=%lu", inode_ino(oi));
	else if (r < sizeof(struct dir_block_v2))
		return XERRF(e, XLOG_APP, XLOG_IO,
		    "short read on dir_block_v2; possible corruption: "
		    "inode=%lu", inode_ino(oi));
	return r;
}

static ssize_t
di_write_dir_block_v2(struct oinode *oi, off_t b_off, struct dir_block_v2 *b,
    struct xerr *e)
{
	ssize_t w;
	if ((w = inode_write(oi, b_off, b,
	    sizeof(struct dir_block_v2), xerrz(e))) == -1)
		return XERR_PREPENDFN(e);
	else if (w < sizeof(struct dir_block_v2))
		return XERRF(e, XLOG_APP, XLOG_IO,
		    "partial dir_block_v2 write, this directory might "
		    "be corrupted");
	return w;
}

ssize_t
di_pack_v2(char *buf, size_t sz, const struct dir_entry_v2 *de)
{
	char         *p = buf;

	if (sz < (DI_DE_PACK_HDR_SZ + de->length))
		return DI_DE_PACK_HDR_SZ + de->length;

	*(uint8_t *)p = de->flags;
	p += sizeof(uint8_t);

	*(uint32_t *)p = de->hash;
	p += sizeof(uint32_t);

	*(ino_t *)p = de->inode;
	p += sizeof(ino_t);

	*(uint8_t *)p = de->length;
	p += sizeof(uint8_t);

	memcpy(p, de->name, de->length);
	p += de->length;

	return p - buf;
}

ssize_t
di_unpack_v2(const char *buf, size_t sz, struct dir_entry_v2 *de)
{
	const char   *p = buf;

	if (sz < DI_DE_PACK_HDR_SZ)
		return DI_DE_PACK_HDR_SZ;

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
	return di_fn[DIRINODE_FORMAT].create(oi, parent, xerrz(e));
}

static int
di_create_v1(struct oinode *oi, ino_t parent, struct xerr *e)
{
	ssize_t             w;
	struct dir_hdr      hdr = { 1 };
	struct dir_entry_v1 default_dir[2] = {
		{ ".", inode_ino(oi), sizeof(struct dir_entry_v1) },
		{ "..", parent, 0 }
	};

	w = inode_write(oi, 0, &hdr, sizeof(hdr), xerrz(e));
	if (w == -1)
		return XERR_PREPENDFN(e);
	if (w < sizeof(hdr))
		return XERRF(e, XLOG_APP, XLOG_IO,
		    "partial dir_hdr write, this directory might "
		    "be corrupted");

	w = inode_write(oi, w, default_dir, sizeof(default_dir), xerrz(e));
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
	ssize_t             w;
	struct dir_hdr_v2   hdr;
	struct dir_block_v2 b;

	bzero(&hdr, sizeof(hdr));
	hdr.v.h.hdr.dirinode_format = 2;
	hdr.v.h.inode = inode_ino(oi);
	hdr.v.h.parent = parent;

	bzero(&b, sizeof(b));
	b.v.leaf.flags = DI_BLOCK_ALLOCATED|DI_BLOCK_LEAF;

	if (di_write_dir_block_v2(oi, sizeof(hdr), &b, xerrz(e)) == -1)
		return XERR_PREPENDFN(e);

	if ((w = inode_write(oi, 0, &hdr, sizeof(hdr), xerrz(e))) == -1)
		return XERR_PREPENDFN(e);
	else if (w < sizeof(hdr))
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

	if (!(dfmt = di_check_format(oi, xerrz(e))))
		return XERR_PREPENDFN(e);

	return di_fn[dfmt].readdir(oi, dirs, offset, count, xerrz(e));
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

/*
 * Since d_off is the sequential position within a leaf, stored in the
 * rightmost 32 bits, we trim the first 32 bits, which is the hash
 * of the entry. That hash is only needed to locate the right leaf.
 * We return how many entries were read in that particular block
 * so that the caller can keep track of the sequential position of
 * the next leaf.
 */
int
di_readdir_buf_v2(const char *buf, size_t sz, struct dir_entry *dirs,
    size_t count, off_t d_off, off_t virt_d_off, struct xerr *e)
{
	ssize_t              r;
	struct dir_entry_v2  de_v2;
	const char          *p;
	size_t               i;

	for (p = buf, i = 0; i < count && p - buf < sz; p += r, virt_d_off++) {
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

		if (d_off > virt_d_off)
			continue;

		strlcpy(dirs[i].name, de_v2.name, de_v2.length + 1);
		dirs[i].inode = de_v2.inode;

		/*
		 * Add +1 because we d_off must indicate the
		 * next entry to read on readdir() completion.
		 */
		dirs[i].d_off = ((uint64_t)de_v2.hash << 32) |
		    (virt_d_off + 1);
		i++;
	}

	return i;
}

static ssize_t
di_readdir_deep_v2(struct oinode *oi, off_t b_off, int depth,
    struct dir_entry *dirs, size_t count, off_t d_off, struct xerr *e)
{
	struct dir_block_v2 b;
	ssize_t             r;
	int                 bucket, i = 0;

	if (di_read_dir_block_v2(oi, b_off, &b, xerrz(e)) == -1) {
		if (xerr_is(e, XLOG_APP, XLOG_EOF)) {
			xerrz(e);
			return 0;
		}
		return XERR_PREPENDFN(e);
	}

	if (!(b.v.flags & DI_BLOCK_ALLOCATED))
		return 0;

	if (b.v.flags & DI_BLOCK_LEAF) {
		/*
		 * virt_d_off is always 2 in a given leaf. 0 and 1 are used
		 * for "." and "..".
		 */
		i += di_readdir_buf_v2(b.v.leaf.data,
		    b.v.leaf.length, dirs + i, count - i,
		    ((uint64_t)d_off) & 0x00000000FFFFFFFF, 2, xerrz(e));
		while (b.v.leaf.next > 0) {
			if (di_read_dir_block_v2(oi, b.v.leaf.next, &b,
			    xerrz(e)) == -1) {
				if (xerr_is(e, XLOG_APP, XLOG_EOF)) {
					xerrz(e);
					return 0;
				}
				return XERR_PREPENDFN(e);
			}
			i += di_readdir_buf_v2(b.v.leaf.data,
			    b.v.leaf.length, dirs + i, count - i,
			    ((uint64_t)d_off) & 0x00000000FFFFFFFF,
			    2 + i, xerrz(e));
		}
		return i;
	}

	/*
	 * The rightmost 32 bits of d_off is used for the entry number inside
	 * a leaf. The leftmost 32 bits is the hash.
	 */
	for (bucket = ((((uint64_t)d_off) >> 32) >>
	    (depth * 5)) & 0x000000000000001F;
	    bucket < 32 && i < count; bucket++) {
		if (b.v.idx.buckets[bucket] == 0)
			continue;
		r = di_readdir_deep_v2(oi, b.v.idx.buckets[bucket], depth + 1,
		    dirs + i, count - i, d_off, xerrz(e));

		/*
		 * d_off should only be set to the one we're seeking on the
		 * first iteration. Once we've found the point where we left
		 * off, we reset it to ensure we read everything after.
		 */
		d_off = 0;

		if (r == -1)
			return XERR_PREPENDFN(e);
		i += r;
	}

	return i;
}

static ssize_t
di_readdir_v2(struct oinode *oi, struct dir_entry *dirs,
    off_t d_off, size_t count, struct xerr *e)
{
	ssize_t              r;
	struct dir_hdr_v2    hdr;
	int                  i = 0;

	if (di_read_dir_hdr_v2(oi, &hdr, xerrz(e)) == -1)
		return XERR_PREPENDFN(e);

	if (d_off == 0 && i < count) {
		dirs[i].inode = hdr.v.h.inode;
		strlcpy(dirs[i].name, ".", sizeof(dirs[i].name));
		dirs[i].d_off = 1;
		d_off = 1;
		i++;
	}

	if (d_off == 1 && i < count) {
		dirs[i].inode = hdr.v.h.parent;
		strlcpy(dirs[i].name, "..", sizeof(dirs[i].name));
		dirs[i].d_off = 2;
		d_off = 2;
		i++;
	}

	r = di_readdir_deep_v2(oi, sizeof(hdr), 0, dirs + i, count - i,
	    d_off, xerrz(e));
	if (r == -1)
		return XERR_PREPENDFN(e);

	return i + r;
}

int
di_lookup(struct oinode *oi, struct dir_entry *de,
    const char *name, struct xerr *e)
{
	uint32_t dfmt;
	if (!(dfmt = di_check_format(oi, xerrz(e))))
		return XERR_PREPENDFN(e);
	return di_fn[dfmt].lookup(oi, de, name, xerrz(e));
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
			if (de != NULL) {
				strlcpy(de->name, de_v2.name, de_v2.length + 1);
				de->inode = de_v2.inode;
				de->d_off = 0;
			}
			return 0;
		}
	}

	return XERRF(e, XLOG_FS, ENOENT, "no such directory entry: %s", name);
}

static int
di_lookup_deep_v2(struct oinode *oi, off_t b_off, int depth,
    struct dir_entry *de, uint32_t hash, const char *name, struct xerr *e)
{
	ssize_t             r;
	struct dir_block_v2 b;
	int                 i;

	if (di_read_dir_block_v2(oi, b_off, &b, xerrz(e)) == -1) {
		if (xerr_is(e, XLOG_APP, XLOG_EOF))
			return XERRF(e, XLOG_FS, ENOENT,
			    "no such directory entry: %s", name);
		return XERR_PREPENDFN(e);
	}

	if (b.v.flags & DI_BLOCK_LEAF) {
		r = di_lookup_buf_v2(b.v.leaf.data,
		    b.v.leaf.length, de, hash, name, xerrz(e));
		if (r == 0)
			return 0;

		if (!xerr_is(e, XLOG_FS, ENOENT))
			return XERR_PREPENDFN(e);

		while (b.v.leaf.next > 0) {
			if (di_read_dir_block_v2(oi, b.v.leaf.next, &b,
			    xerrz(e)) == -1) {
				if (xerr_is(e, XLOG_APP, XLOG_EOF)) {
					xerrz(e);
					return 0;
				}
				return XERR_PREPENDFN(e);
			}

			r = di_lookup_buf_v2(b.v.leaf.data,
			    b.v.leaf.length, de, hash, name, xerrz(e));
			if (r == 0)
				return r;
			if (!xerr_is(e, XLOG_FS, ENOENT))
				return XERR_PREPENDFN(e);
		}
		return XERRF(e, XLOG_FS, ENOENT,
		    "no such directory entry: %s", name);
	}

	i = (hash >> (depth * 5)) & 0x0000001F;

	if (b.v.idx.buckets[i] == 0)
		return XERRF(e, XLOG_FS, ENOENT,
		    "no such directory entry: %s", name);

	/* Keep this last for tail recursion */
	return di_lookup_deep_v2(oi, b.v.idx.buckets[i], depth + 1,
	    de, hash, name, xerrz(e));
}

static int
di_lookup_v2(struct oinode *oi, struct dir_entry *de, const char *name,
    struct xerr *e)
{
	struct dir_hdr_v2     hdr;
	uint32_t              hash = di_fnv1a32(name, strlen(name));

	if (di_read_dir_hdr_v2(oi, &hdr, xerrz(e)) == -1)
		return XERR_PREPENDFN(e);

	if (strcmp(name, ".") == 0) {
		strlcpy(de->name, name, sizeof(de->name));
		de->inode = hdr.v.h.inode;
		de->d_off = 0;
		return 0;
	} else if (strcmp(name, "..") == 0) {
		strlcpy(de->name, name, sizeof(de->name));
		de->inode = hdr.v.h.parent;
		de->d_off = 0;
		return 0;
	}

	if (di_lookup_deep_v2(oi, sizeof(hdr), 0, de, hash, name, xerrz(e)) == -1)
		return XERR_PREPENDFN(e);

	return 0;
}

int
di_mkdirent(struct oinode *parent, const struct dir_entry *de,
    int replace, struct xerr *e)
{
	uint32_t dfmt;
	if (!(dfmt = di_check_format(parent, xerrz(e))))
		return XERR_PREPENDFN(e);
	return di_fn[dfmt].mkdirent(parent, de, replace, xerrz(e));
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
	    &prev_used, sizeof(prev_used), xerrz(e));
	if (r < sizeof(prev_used)) {
		return XERRF(e, XLOG_APP, XLOG_IO,
		    "partial dirent write, this directory "
		    "might be corrupted");
	}

	return 0;
}

static int
di_unlink_freelist_add_v2(struct oinode *parent, struct dir_hdr_v2 *hdr,
    off_t b_off, struct dir_block_v2 *b, struct xerr *e)
{
	off_t   end = inode_getsize(parent);

	if (b_off == end - sizeof(struct dir_block_v2)) {
		if (inode_truncate(parent, b_off, xerrz(e)) == -1)
			return XERR_PREPENDFN(e);
		return 0;
	}

	bzero(b, sizeof(struct dir_block_v2));
	b->v.leaf.flags = DI_BLOCK_LEAF;

	if (hdr->v.h.free_list_start > 0)
		b->v.leaf.next = hdr->v.h.free_list_start;
	else
		b->v.leaf.next = 0;

	hdr->v.h.free_list_start = b_off;

	if (di_write_dir_block_v2(parent, b_off, b, xerrz(e)) == -1)
		return XERR_PREPENDFN(e);
	return 0;
}

static off_t
di_mkdirent_getblock_v2(struct oinode *parent, struct dir_hdr_v2 *hdr,
    struct xerr *e)
{
	struct dir_block_v2 b;
	off_t               offset;

	if (hdr->v.h.free_list_start == 0) {
		offset = inode_getsize(parent);

		/* Sanity check. */
		if (offset % sizeof(b) != 0)
			return XERRF(e, XLOG_APP, XLOG_IO,
			    "directory offsets are not aligned");
	} else {
		/*
		 * We loop and check for DI_BLOCK_ALLOCATED just
		 * in case things got messy during a crash.
		 * But normally, there shoudn't be a need to loop.
		 */
		do {
			offset = hdr->v.h.free_list_start;
			if (di_read_dir_block_v2(parent, offset, &b,
			    xerrz(e)) == -1)
				return XERR_PREPENDFN(e);
			hdr->v.h.free_list_start = b.v.leaf.next;
		} while (b.v.flags & DI_BLOCK_ALLOCATED);
	}
	return offset;
}

static int
di_to_hash_v2(struct oinode *oi, struct dir_hdr_v2 *hdr, struct dir_block_v2 *b,
    off_t b_off, int depth, struct xerr *e)
{
	struct dir_block_v2  root, child_blks[32];
	char                *p;
	ssize_t              r;
	struct dir_entry_v2  de_v2;
	int                  i;
	char                *buf = b->v.leaf.data;
	size_t               buf_sz = b->v.leaf.length;

	if (depth >= DI_BLOCK_V2_MAX_DEPTH)
		return XERRF(e, XLOG_APP, XLOG_INVAL,
		    "dirinode tree too max depth reached");

	bzero(&root, sizeof(root));
	root.v.idx.flags = DI_BLOCK_ALLOCATED;

	bzero(child_blks, sizeof(child_blks));
	for (i = 0; i < 32; i++)
		child_blks[i].v.leaf.flags = DI_BLOCK_ALLOCATED|DI_BLOCK_LEAF;

	for (p = buf; p - buf < buf_sz; p += r) {
		/*
		 * Dir entries in the inode are always contiguous.
		 * If we see one that's not allocated, it means there
		 * are no more after.
		 */
		if ((r = di_unpack_v2(p, buf_sz - (p - buf), &de_v2)) >
		    buf_sz - (p - buf))
			break;

		if (!(de_v2.flags & DI_ALLOCATED))
			break;

		i = (de_v2.hash >> (depth * 5)) & 0x0000001F;

		child_blks[i].v.leaf.length +=
		    di_pack_v2(child_blks[i].v.leaf.data +
			child_blks[i].v.leaf.length,
			DI_DIR_BLOCK_HDR_V2_BYTES - child_blks[i].v.leaf.length,
			&de_v2);
		child_blks[i].v.leaf.entries++;
	}

	for (i = 0; i < 32; i++) {
		if (child_blks[i].v.leaf.entries == 0)
			continue;

		root.v.idx.buckets[i] = di_mkdirent_getblock_v2(oi, hdr,
		    xerrz(e));
		if (root.v.idx.buckets[i] == -1)
			return XERR_PREPENDFN(e);

		if (di_write_dir_block_v2(oi, root.v.idx.buckets[i],
		    &child_blks[i], xerrz(e)) == -1)
			return XERR_PREPENDFN(e);
	}

	if (di_write_dir_block_v2(oi, b_off, &root, xerrz(e)) == -1)
		return XERR_PREPENDFN(e);

	memcpy(b, &root, sizeof(root));

	return 0;
}

static int
di_mkdirent_deep_v2(struct oinode *parent, struct dir_hdr_v2 *hdr, off_t b_off,
    int depth, struct dir_entry_v2 *de, int replace, struct xerr *e)
{
	int                  i;
	ssize_t              r;
	struct dir_block_v2  b, b_head, b_next;
	char                *p;
	off_t                valid_off = -1;

	if (di_read_dir_block_v2(parent, b_off, &b_head, xerrz(e)) == -1)
		return XERR_PREPENDFN(e);

	if (!(b_head.v.flags & DI_BLOCK_ALLOCATED))
		return XERRF(e, XLOG_APP, XLOG_IO,
		    "unallocated dir_block_v2, this directory "
		    "might be corrupted");

	if (b_head.v.flags & DI_BLOCK_LEAF) {
		/*
		 * We need to scan all the leaf chain and see
		 * if our entry already exists. While we're at
		 * it, save the offset of a leaf that has
		 * enough space for the new entry. We may need
		 * it later.
		 */
		memcpy(&b, &b_head, sizeof(b));
		while (di_lookup_buf_v2(b.v.leaf.data,
		    b.v.leaf.length, NULL, de->hash,
		    de->name, xerrz(e)) == -1) {
			if (!xerr_is(e, XLOG_FS, ENOENT))
				return XERR_PREPENDFN(e);

			if (DI_DIR_BLOCK_HDR_V2_BYTES - b.v.leaf.length >=
			    DI_DE_PACK_HDR_SZ + de->length)
				valid_off = b_off;

			if (b.v.leaf.next == 0)
				break;

			b_off = b.v.leaf.next;
			if (di_read_dir_block_v2(parent, b.v.leaf.next,
			    &b, xerrz(e)) == -1)
				return XERR_PREPENDFN(e);

			if (!(b.v.flags & DI_BLOCK_ALLOCATED))
				return XERRF(e, XLOG_APP, XLOG_IO,
				    "unallocated dir_block_v2, this directory "
				    "might be corrupted");
		}

		if (!xerr_fail(e)) {
			/*
			 * de->name already exists.
			 */
			if (!replace)
				return XERRF(e, XLOG_FS, EEXIST,
				    "file %s already exists", de->name);

			/*
			 * If we wish to replace, remove the old entry
			 * and rewrite the new one. It should fit since
			 * it's the same size, so no need to check
			 * for overflow.
			 */
			if ((r = di_unlink_buf_v2(b.v.leaf.data,
			    b.v.leaf.length, de->hash,
			    de->name, xerrz(e))) == -1)
				return XERR_PREPENDFN(e);

			b.v.leaf.length -= r;
			p = b.v.leaf.data + b.v.leaf.length;
			p += di_pack_v2(p,
			    DI_DIR_BLOCK_HDR_V2_BYTES - b.v.leaf.length, de);
			b.v.leaf.length = p - b.v.leaf.data;

			if (di_write_dir_block_v2(parent, b_off,
			    &b, xerrz(e)) == -1)
				return XERR_PREPENDFN(e);
			return 0;
		}

		/*
		 * If de->name was not found, we want to rewind back to a
		 * block that had enough space for the new entry, if
		 * there was one. Otherwise, the last block should already
		 * be loaded in 'b'.
		 */
		if (valid_off > -1 && valid_off != b_off) {
			if (di_read_dir_block_v2(parent, valid_off,
			    &b, xerrz(e)) == -1)
				return XERR_PREPENDFN(e);
			b_off = valid_off;
		}

		p = b.v.leaf.data + b.v.leaf.length;
		p += di_pack_v2(p,
		    DI_DIR_BLOCK_HDR_V2_BYTES - b.v.leaf.length, de);

		if (p <= b.v.leaf.data + DI_DIR_BLOCK_HDR_V2_BYTES) {
			/*
			 * The new entry fit, just write and we're done.
			 */
			b.v.leaf.length = p - b.v.leaf.data;
			b.v.leaf.entries++;

			if (di_write_dir_block_v2(parent, b_off,
			    &b, xerrz(e)) == -1)
				return XERR_PREPENDFN(e);
			return 0;
		}

		/*
		 * If the new entry won't fit in this leaf, we either
		 * need to add depth to our hash tree, or if we're at
		 * maximum depth, make our leaf longer.
		 */

		if (depth >= DI_BLOCK_V2_MAX_DEPTH) {
			/*
			 * At max depth and this is the last leaf in the chain,
			 * so add a new block to our leaf chain.
			 *
			 * b.v.leaf.next should always be zero here, since we
			 * already followed the chain to the last leaf.
			 */
			b.v.leaf.next = di_mkdirent_getblock_v2(parent,
			    hdr, xerrz(e));
			if (b.v.leaf.next == -1)
				return XERR_PREPENDFN(e);

			bzero(&b_next, sizeof(b_next));
			b_next.v.leaf.flags = DI_BLOCK_ALLOCATED|DI_BLOCK_LEAF;

			p = b_next.v.leaf.data;
			p += di_pack_v2(p,
			    DI_DIR_BLOCK_HDR_V2_BYTES - b_next.v.leaf.length,
			    de);

			b_next.v.leaf.length = p - b_next.v.leaf.data;
			b_next.v.leaf.entries++;

			if (di_write_dir_block_v2(parent, b.v.leaf.next,
			    &b_next, xerrz(e)) == -1)
				return XERR_PREPENDFN(e);

			if (di_write_dir_block_v2(parent, b_off,
			    &b, xerrz(e)) == -1)
				return XERR_PREPENDFN(e);
			return 0;
		}

		/*
		 * We didn't have space to fit the new entry in the leaf and
		 * we're not at max depth. Convert the current block to an
		 * index block, then go on and recurse deeper.
		 */
		if (di_to_hash_v2(parent, hdr, &b_head, b_off, depth, xerrz(e)) == -1)
			return XERR_PREPENDFN(e);
	}

	/*
	 * Shift by depth * 5 bits, since a dir block has 32 buckets.
	 */
	i = (de->hash >> (depth * 5)) & 0x0000001F;

	if (b_head.v.idx.buckets[i] == 0) {
		b_head.v.idx.buckets[i] = di_mkdirent_getblock_v2(parent,
		    hdr, xerrz(e));
		if (b_head.v.idx.buckets[i] == -1)
			return XERR_PREPENDFN(e);

		bzero(&b, sizeof(b));
		b.v.leaf.flags = DI_BLOCK_ALLOCATED|DI_BLOCK_LEAF;

		if (di_write_dir_block_v2(parent, b_head.v.idx.buckets[i],
		    &b, xerrz(e)) == -1)
			return XERR_PREPENDFN(e);

		if (di_mkdirent_deep_v2(parent, hdr, b_head.v.idx.buckets[i],
		    depth + 1, de, replace, xerrz(e)) == -1)
			return XERR_PREPENDFN(e);

		if (di_write_dir_block_v2(parent, b_off,
		    &b_head, xerrz(e)) == -1)
			return XERR_PREPENDFN(e);
		return 0;
	}

	if (di_mkdirent_deep_v2(parent, hdr, b_head.v.idx.buckets[i], depth + 1,
	    de, replace, xerrz(e)) == -1)
		return XERR_PREPENDFN(e);

	return 0;
}

static int
di_mkdirent_v2(struct oinode *parent, const struct dir_entry *de,
    int replace, struct xerr *e)
{
	ssize_t              r;
	struct dir_entry_v2  de_v2;
	struct dir_hdr_v2    hdr, hdr_orig;

	if (di_read_dir_hdr_v2(parent, &hdr_orig, xerrz(e)) == -1)
		return XERR_PREPENDFN(e);

	if (strcmp(de->name, ".") == 0 || strcmp(de->name, "..") == 0)
		return XERRF(e, XLOG_FS, (replace) ? EBUSY : EEXIST,
		    "file %s already exists", de->name);

	de_v2.flags = DI_ALLOCATED;
	de_v2.length = strlen(de->name);
	de_v2.name = de->name;
	de_v2.inode = de->inode;
	de_v2.hash = di_fnv1a32(de_v2.name, de_v2.length);

	memcpy(&hdr, &hdr_orig, sizeof(hdr));
	if (di_mkdirent_deep_v2(parent, &hdr, sizeof(hdr), 0,
	    &de_v2, replace, xerrz(e)) == -1)
		return XERR_PREPENDFN(e);

	if (memcmp(&hdr, &hdr_orig, sizeof(hdr)) != 0) {
		r = inode_write(parent, 0, &hdr, sizeof(hdr), xerrz(e));
		if (r == -1) {
			return XERR_PREPENDFN(e);
		} else if (r  < sizeof(hdr)) {
			return XERRF(e, XLOG_APP, XLOG_IO,
			    "partial dir_hdr_v2 write, this directory "
			    "might be corrupted");
		}
	}

	return 0;
}

int
di_isempty(struct oinode *oi, struct xerr *e)
{
	uint32_t dfmt;
	if (!(dfmt = di_check_format(oi, xerrz(e))))
		return XERR_PREPENDFN(e);
	return di_fn[dfmt].isempty(oi, xerrz(e));
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
	struct dir_block_v2 b;
	struct dir_hdr_v2   hdr;
	int                 i;

	if (di_read_dir_hdr_v2(oi, &hdr, xerrz(e)) == -1)
		return XERR_PREPENDFN(e);

	if (di_read_dir_block_v2(oi, sizeof(hdr), &b, xerrz(e)) == -1) {
		if (xerr_is(e, XLOG_APP, XLOG_EOF)) {
			xerrz(e);
			return 1;
		}
		return XERR_PREPENDFN(e);
	}

	if (!(b.v.flags & DI_BLOCK_ALLOCATED))
		return 1;

	if (b.v.flags & DI_BLOCK_LEAF)
		return (b.v.leaf.entries == 0) ? 1 : 0;

	for (i = 0; i < 32; i++)
		if (b.v.idx.buckets[i] > 0)
			return 0;

	return 1;
}

int
di_unlink(struct oinode *parent, const struct dir_entry *de,
    struct xerr *e)
{
	uint32_t dfmt;
	if (!(dfmt = di_check_format(parent, xerrz(e))))
		return XERR_PREPENDFN(e);
	return di_fn[dfmt].unlink(parent, de, xerrz(e));
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
 * Returns how many bytes were removed from the buffer, or -1 on error.
 */
static ssize_t
di_unlink_buf_v2(char *buf, size_t sz, uint32_t hash, const char *name,
    struct xerr *e)
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
			return r;
		}
	}

	return XERRF(e, XLOG_FS, ENOENT, "no such directory entry: %s", name);
}

static int
di_unlink_deep_v2(struct oinode *parent, struct dir_hdr_v2 *hdr,
    off_t head_b_off, struct dir_block_v2 *parent_b, off_t parent_b_off,
    int depth, const struct dir_entry *de, uint32_t hash, const char *name,
    struct xerr *e)
{
	ssize_t             r;
	struct dir_block_v2 b, b_prev;
	int                 i;
	off_t               b_off, b_off_prev;

	if (di_read_dir_block_v2(parent, head_b_off, &b, xerrz(e)) == -1) {
		if (xerr_is(e, XLOG_APP, XLOG_EOF))
			return XERRF(e, XLOG_FS, ENOENT,
			    "no such directory entry: %s", name);
		return XERR_PREPENDFN(e);
	}

	if (!(b.v.flags & DI_BLOCK_ALLOCATED))
		return XERRF(e, XLOG_FS, ENOENT,
		    "no such directory entry: %s", name);

	if (!(b.v.flags & DI_BLOCK_LEAF)) {
		i = (hash >> (depth * 5)) & 0x0000001F;

		if (b.v.idx.buckets[i] == 0)
			return XERRF(e, XLOG_FS, ENOENT,
			    "no such directory entry: %s", name);

		if (di_unlink_deep_v2(parent, hdr, b.v.idx.buckets[i],
		    &b, head_b_off, depth + 1, de, hash, name, xerrz(e)) == -1)
			return XERR_PREPENDFN(e);

		/*
		 * We never de-allocate the root block.
		 */
		if (depth == 0)
			return 0;

		for (i = 0; i < 32; i++)
			if (b.v.idx.buckets[i] > 0)
				return 0;

		i = (hash >> ((depth - 1) * 5)) & 0x0000001F;
		parent_b->v.idx.buckets[i] = 0;

		if (di_write_dir_block_v2(parent, parent_b_off,
		    parent_b, xerrz(e)) == -1)
			return XERR_PREPENDFN(e);

		if (di_unlink_freelist_add_v2(parent, hdr, head_b_off, &b,
		    xerrz(e)) == -1)
			xlog(LOG_ERR, e, __func__);
		return 0;
	}

	b_off_prev = head_b_off;
	b_off = head_b_off;
	for (;;) {
		r = di_unlink_buf_v2(b.v.leaf.data,
		    b.v.leaf.length, hash, name, xerrz(e));
		if (r == -1) {
			if (!xerr_is(e, XLOG_FS, ENOENT))
				return XERR_PREPENDFN(e);

			if (b.v.leaf.next == 0)
				break;

			b_off_prev = b_off;
			memcpy(&b_prev, &b, sizeof(b_prev));
			b_off = b.v.leaf.next;

			if (di_read_dir_block_v2(parent, b_off,
			    &b, xerrz(e)) == -1) {
				if (xerr_is(e, XLOG_APP, XLOG_EOF))
					return XERRF(e, XLOG_FS, ENOENT,
					    "no such directory entry: %s",
					    name);
				return XERR_PREPENDFN(e);
			}
			continue;
		}

		b.v.leaf.length -= r;
		b.v.leaf.entries--;

		/*
		 * We never de-allocate the root block.
		 */
		if (depth == 0 || b.v.leaf.entries > 0) {
			if (di_write_dir_block_v2(parent, b_off,
			    &b, xerrz(e)) == -1)
				return XERR_PREPENDFN(e);
			return 0;
		}

		if (b_off == head_b_off) {
			i = (hash >> ((depth - 1) * 5)) & 0x0000001F;
			parent_b->v.idx.buckets[i] = b.v.leaf.next;

			if (di_write_dir_block_v2(parent, parent_b_off,
			    parent_b, xerrz(e)) == -1)
				return XERR_PREPENDFN(e);
		} else {
			b_prev.v.leaf.next = b.v.leaf.next;
			if (di_write_dir_block_v2(parent, b_off_prev,
			    &b_prev, xerrz(e)) == -1)
				return XERR_PREPENDFN(e);
		}

		/*
		 * De-allocate, set to leaf so that it can
		 * become part of the freelist.
		 */
		if (di_unlink_freelist_add_v2(parent, hdr,
		    b_off, &b, xerrz(e)) == -1)
			xlog(LOG_ERR, e, __func__);

		return 0;

	}

	return XERRF(e, XLOG_FS, ENOENT,
	    "no such directory entry: %s", name);
}

static int
di_unlink_v2(struct oinode *parent, const struct dir_entry *de,
    struct xerr *e)
{
	ssize_t              r;
	struct dir_hdr_v2    hdr, hdr_orig;
	uint32_t             hash = di_fnv1a32(de->name, strlen(de->name));

	if (di_read_dir_hdr_v2(parent, &hdr_orig, xerrz(e)) == -1)
		return XERR_PREPENDFN(e);

	if (strcmp(de->name, ".") == 0 || strcmp(de->name, "..") == 0)
		return XERRF(e, XLOG_FS, EBUSY,
		    "file %s cannot be removed", de->name);

	memcpy(&hdr, &hdr_orig, sizeof(hdr));
	if (di_unlink_deep_v2(parent, &hdr, sizeof(hdr), NULL, 0, 0, de, hash,
	    de->name, xerrz(e)) == -1)
		return XERR_PREPENDFN(e);

	if (memcmp(&hdr, &hdr_orig, sizeof(hdr)) != 0) {
		r = inode_write(parent, 0, &hdr, sizeof(hdr), xerrz(e));
		if (r == -1) {
			return XERR_PREPENDFN(e);
		} else if (r < sizeof(hdr)) {
			return XERRF(e, XLOG_APP, XLOG_IO,
			    "partial dir_hdr_v2 write, this directory "
			    "might be corrupted");
		}
	}

	return 0;
}

ino_t
di_parent(struct oinode *oi, struct xerr *e)
{
	uint32_t dfmt;
	if (!(dfmt = di_check_format(oi, xerrz(e))))
		return XERR_PREPENDFN(e);
	return di_fn[dfmt].parent(oi, xerrz(e));
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
	if (di_read_dir_hdr_v2(oi, &hdr, xerrz(e)) == -1)
		return XERR_PREPENDFN(e);
	return hdr.v.h.parent;
}

int
di_setparent(struct oinode *oi, ino_t parent, struct xerr *e)
{
	uint32_t dfmt;
	if (!(dfmt = di_check_format(oi, xerrz(e))))
		return XERR_PREPENDFN(e);
	return di_fn[dfmt].setparent(oi, parent, xerrz(e));
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

	if (di_read_dir_hdr_v2(oi, &hdr, xerrz(e)) == -1)
		return XERR_PREPENDFN(e);

	hdr.v.h.parent = parent;
	if (inode_write(oi, 0, &hdr, sizeof(hdr), xerrz(e)) < sizeof(hdr)) {
		return XERRF(e, XLOG_APP, XLOG_IO,
		    "partial dir_hdr_v2 write, this directory "
		    "might be corrupted");
	}
	return 0;
}
