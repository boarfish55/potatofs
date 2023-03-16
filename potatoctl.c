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

#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <locale.h>
#include <ncurses.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <zlib.h>
#include "counter_names.h"
#include "slabdb.h"
#include "slabs.h"
#include "fs_info.h"
#include "inodes.h"
#include "dirinodes.h"
#include "xlog.h"
#include "mgr.h"
#include "potatomgr.h"

static int  slabdb(int, char **);
static int  claim(int, char **);
static int  show_slab(int, char **);
static int  show_dir(int, char **);
static int  show_inode(int, char **);
static int  inode_tables(int, char **);
static int  fsck(int, char **);
static int  top(int, char **);
static int  ctop(int, char **);
static int  dump_counters(int, char **);
static int  dump_config(int, char **);
static int  fs_status(int, char **);
static int  do_shutdown(int, char **);
static int  set_clean(int, char **);
static int  do_scrub(int, char **);
static int  do_flush(int, char **);
static int  do_offline(int, char **);
static int  do_online(int, char **);
static void usage();
static int  load_dir(int, char **, struct inode *, int *);
static int  write_dir(int, char *, struct inode *);
static void print_inode(struct inode *, int);
static void print_slab_hdr(struct slab_hdr *, const uint32_t *);

struct subc {
	char *name;
	int  (*fn)(int argc, char **argv);
	int   clean_warning;
} subcommands[] = {
	{ "slabdb", &slabdb, 0 },
	{ "claim", &claim, 0 },
	{ "slab", &show_slab, 1 },
	{ "dir", &show_dir, 0 },
	{ "inode", &show_inode, 0 },
	{ "top", &top, 0 },
	{ "ctop", &ctop, 0 },
	{ "counters", &dump_counters, 0 },
	{ "config", &dump_config, 0 },
	{ "status", &fs_status, 0 },
	{ "shutdown", &do_shutdown, 0 },
	{ "set_clean", &set_clean, 0 },
	{ "scrub", &do_scrub, 0 },
	{ "flush", &do_flush, 0 },
	{ "offline", &do_offline, 0 },
	{ "online", &do_online, 0 },
	{ "inode_tables", &inode_tables, 0 },
	{ "fsck", &fsck, 0 },
	{ "", NULL }
};

int fsck_verbose = 1;
int fsck_fix = 0;

const char *clean_warning = (
    "WARNING: filesystem not marked clean!!!\n"
    "         Either it is currently mounted or errors are present.\n"
    "         Run fsck.\n");

struct fsck_stats {
	uint64_t n_inodes;
	uint64_t n_dirs;
	uint64_t n_dirents;
	uint64_t errors;
};

struct found_inode {
	ino_t                 ino;
	RB_ENTRY(found_inode) entry;
};

static struct {
	RB_HEAD(scanned_inode_tree, found_inode) head;
	int                                      count;
} scanned_inodes = {
	RB_INITIALIZER(&scanned_inodes.head),
	0
};

static struct {
	RB_HEAD(scanned_dirent_inode_tree, found_inode) head;
	int                                             count;
} scanned_dirent_inodes = {
	RB_INITIALIZER(&scanned_dirent_inode_tree.head),
	0
};

static int
found_inode_cmp(struct found_inode *f1, struct found_inode *f2)
{
	if (f1->ino < f2->ino)
		return -1;
	if (f1->ino > f2->ino)
		return 1;
	return 0;
}

RB_PROTOTYPE(scanned_inode_tree, found_inode, entry, found_inode_cmp);
RB_GENERATE(scanned_inode_tree, found_inode, entry, found_inode_cmp);
RB_PROTOTYPE(scanned_dirent_inode_tree, found_inode, entry, found_inode_cmp);
RB_GENERATE(scanned_dirent_inode_tree, found_inode, entry, found_inode_cmp);

struct slabdb_entry {
	struct slab_key      sk;
	struct slabdb_val    sv;
	struct slabdb_entry *next;
};

void
usage()
{
	fprintf(stderr,
	    "Usage: potatoctl [options] <subcommand> <args...>\n"
	    "           slab  <slab file>\n"
	    "           dir   <dir inode#>\n"
	    "           top   [delay]\n"
	    "           counters\n"
	    "           status\n"
	    "           shutdown [grace period seconds]\n"
	    "           set_clean\n"
	    "           scrub\n"
	    "           flush\n"
	    "           online\n"
	    "           offline\n"
	    "           fsck  [verbose]\n"
	    "           claim <inode> <offset> [create]\n"
	    "           slabdb\n"
	    "\n"
	    "\t-h\t\t\tPrints this help\n"
	    "\t-c <config path>\tPath to the configuration file\n"
	    "\t-D <data dir>\t\tThe base data directory used by PotatoFS\n");
}

extern struct counter counters[];
extern locale_t       log_locale;

static void
fsck_printf(const char *fmt, ...)
{
	va_list ap;
	char    fsck_fmt[LINE_MAX];

	if (!fsck_verbose)
		return;

	snprintf(fsck_fmt, sizeof(fsck_fmt), "fsck: %s\n", fmt);
	va_start(ap, fmt);
	vprintf(fsck_fmt, ap);
	va_end(ap);
}

void
read_metrics(uint64_t *counters_now, uint64_t *mgr_counters_now)
{
	int            c, mgr;
	struct xerr    e;
	struct mgr_msg m;

	if ((mgr = mgr_connect(0, xerrz(&e))) == -1) {
		xerr_print(&e);
		exit(1);
	}

	m.m = MGR_MSG_RCV_COUNTERS;
	if (mgr_send(mgr, -1, &m, xerrz(&e)) == -1) {
		xerr_print(&e);
		exit(1);
	}

	if (mgr_recv(mgr, NULL, &m, xerrz(&e)) == -1) {
		xerr_print(&e);
		exit(1);
	}

	if (m.m == MGR_MSG_RCV_COUNTERS_ERR) {
		xerr_print(&m.v.err);
		exit(1);
	} else if (m.m != MGR_MSG_RCV_COUNTERS_OK)
		errx(1, "%s: mgr_recv: unexpected response: %d",
		    __func__, m.m);

	for (c = 0; c < COUNTER_LAST; c++)
		counters_now[c] = m.v.rcv_counters.c[c];

	for (c = 0; c < MGR_COUNTER_LAST; c++)
		mgr_counters_now[c] = m.v.rcv_counters.mgr_c[c];

	close(mgr);
}

int
valid_inode(int mgr, ino_t ino)
{
	struct inode inode;
	struct xerr  e;

	if (inode_inspect(mgr, ino, &inode, 0, xerrz(&e)) == -1) {
		xerr_print(&e);
		return 0;
	}
	if (inode.v.f.nlink == 0) {
		warnx("unlinked inode %lu; bitmap says it's "
		    "allocated, but nlink is 0", ino);
		return 0;
	}
	return 1;
}

int
clear_dir_entry(struct dir_entry_v1 *start, struct dir_entry_v1 *de,
    size_t *sz, struct xerr *e)
{
	off_t               offset = sizeof(struct dir_hdr), prev_off = 0;
	struct dir_entry_v1 r_de, prev_used;
	ino_t               ino = de->inode;

	bzero(&prev_used, sizeof(prev_used));

	for (;;) {
		memcpy(&r_de, ((char *)start) + offset,
		    sizeof(struct dir_entry_v1));

		if (strcmp(r_de.name, de->name) == 0)
			break;

		if (r_de.next == 0)
			goto noent;

		memcpy(&prev_used, &r_de, sizeof(prev_used));
		prev_off = offset;
		offset = r_de.next;
	}

	prev_used.next = r_de.next;

	memcpy(((char *)start) + prev_off, &prev_used, sizeof(prev_used));

	if (prev_used.next == 0) {
		*sz = prev_off + sizeof(prev_used);
	} else {
		bzero(((char *)start) + offset, sizeof(struct dir_entry));
	}

	fsck_printf("    FIX: cleared dir entry: %lu", ino);
	return 0;
noent:
	return XERRF(e, XLOG_APP, XLOG_IO, "no such dirent");
}

int
add_found_inode(ino_t ino, struct xerr *e)
{
	struct found_inode *fino;

	if ((fino = malloc(sizeof(struct found_inode))) == NULL)
		return XERRF(e, XLOG_ERRNO, errno, "malloc");
	bzero(fino, sizeof(struct found_inode));
	fino->ino = ino;
	if (RB_FIND(scanned_dirent_inode_tree,
	    &scanned_dirent_inodes.head, fino)) {
		free(fino);
		return 0;
	}

	if (RB_INSERT(scanned_dirent_inode_tree,
	    &scanned_dirent_inodes.head, fino) != NULL) {
		free(fino);
		return XERRF(e, XLOG_ERRNO, errno,
		    "RB_INSERT");
	}
	scanned_dirent_inodes.count++;
	return 0;
}

int
validate_dir_v1(int mgr, ino_t ino, char *dir, size_t *dir_sz,
    struct fsck_stats *stats, struct xerr *e)
{
	struct dir_entry_v1 *de;
	int                  dirty = 0;

	for (de = (struct dir_entry_v1 *)(dir + sizeof(struct dir_hdr));
	    (char *)de < (dir + *dir_sz); de++) {
		if (de->inode > 0) {
			fsck_printf("    dirent: %lu (%s)",
			    de->inode, de->name);
			stats->n_dirents++;

			if (!valid_inode(mgr, de->inode)) {
				stats->errors++;

				if (fsck_fix) {
					if (clear_dir_entry(
					    (struct dir_entry_v1 *)dir, de,
					    dir_sz, xerrz(e)) == -1)
						xerr_print(e);
					else
						dirty = 1;
				}
				continue;
			}

			/*
			 * Keep track of all linked inodes to later verify
			 * if any of them are not.
			 */
			if (add_found_inode(de->inode, e) == -1)
				return XERR_PREPENDFN(e);
		}
		if (de->next > 0 && de->next <= ((char *)de - dir)) {
			/*
			 * We link to a next entry, but the offset is
			 * the current offset or before, which is
			 * invalid.
			 */
			stats->errors++;
			warnx("invalid chaining in directory "
			    "inode %lu; entry %s at offset %lu",
			    ino, de->name, (char *)de - dir);
		}
	}
	return dirty;
}

int
validate_dir_block_v2(int mgr, ino_t ino, char *dir, size_t dir_sz,
    off_t b_off, int depth, uint8_t *dir_blocks,
    struct fsck_stats *stats, struct xerr *e)
{
	struct dir_block_v2 *b = (struct dir_block_v2 *)(dir + b_off);
	struct dir_entry_v2  de_v2;
	const char          *p;
	ssize_t              r;
	size_t               i;
	int                  bucket;

	if ((char *)b > dir + dir_sz) {
		warnx("dir inode %lu: trying to read a block at offset %ld, "
		    "which is past the end of the dir inode", ino, b_off);
		stats->errors++;
		return 0;
	}

	if (!(b->v.flags & DI_BLOCK_ALLOCATED)) {
		warnx("unallocated block in dir inode %lu at offset %ld",
		    ino, b_off);
		stats->errors++;
		return 0;
	}

	dir_blocks[(b_off - sizeof(struct dir_hdr_v2)) /
	    sizeof(struct dir_block_v2)] = 1;

	if (b->v.flags & DI_BLOCK_LEAF) {
		for (;;) {
			for (p = b->v.leaf.data, i = 0;
			    p - b->v.leaf.data < b->v.leaf.length; p += r) {
				dir_blocks[((p - sizeof(struct dir_hdr_v2)) -
				    dir) / sizeof(struct dir_block_v2)] = 1;
				/*
				 * Dir entries in the inode are always
				 * contiguous. If we see one that's not
				 * allocated, it means there are no more after.
				 */
				if ((r = di_unpack_v2(p,
				    b->v.leaf.length - (p - b->v.leaf.data),
				    &de_v2)) >
				    b->v.leaf.length - (p - b->v.leaf.data))
					break;

				if (!(de_v2.flags & DI_ALLOCATED)) {
					warnx("dir inode %lu: unallocated dir "
					    "entry at offset %lu in dir "
					    "block offset %ld", ino,
					    p - b->v.leaf.data, b_off);
					stats->errors++;
					break;
				}

				i++;
				stats->n_dirents++;

				if (!valid_inode(mgr, de_v2.inode)) {
					stats->errors++;
					continue;
				}
				if (add_found_inode(de_v2.inode, e) == -1)
					return XERR_PREPENDFN(e);

				if (di_fnv1a32(de_v2.name, de_v2.length) !=
				    de_v2.hash) {
					warnx("dir inode %lu: mismatching hash "
					    "for entry at offset %lu in dir "
					    "block offset %ld", ino,
					    p - b->v.leaf.data, b_off);
					stats->errors++;
				}
			}

			if (i != b->v.leaf.entries) {
				warnx("dir inode %lu / block %ld: mismatching"
				    "number of entries in dir block header and "
				    "leaf data: header=%lu, data=%lu",
				    ino, b_off, b->v.leaf.entries, i);
				stats->errors++;
			}

			if (b->v.leaf.next == 0)
				break;

			b = (struct dir_block_v2 *)(dir + b->v.leaf.next);
			if ((char *)b > dir + dir_sz) {
				warnx("dir inode %lu / block %ld: "
				    "next is point past the end of the"
				    " inode: next=%ld, size=%lu",
				    ino, b_off, b->v.leaf.next, dir_sz);
				stats->errors++;
			}
		}
		return 0;
	}

	if (depth >= DI_BLOCK_V2_MAX_DEPTH) {
		warnx("dir inode %lu / block %ld: max depth reached",
		    ino, b_off);
		stats->errors++;
		return 0;
	}

	for (bucket = 0; bucket < 32; bucket++) {
		if (b->v.idx.buckets[bucket] == 0)
			continue;

		if (validate_dir_block_v2(mgr, ino, dir, dir_sz,
		    b->v.idx.buckets[bucket], depth + 1,
		    dir_blocks, stats, e) == -1)
			return XERR_PREPENDFN(e);
	}
	return 0;
}

int
validate_dir_v2(int mgr, ino_t ino, char *dir, size_t *dir_sz,
    struct fsck_stats *stats, struct xerr *e)
{
	int                  dirty = 0;
	struct dir_hdr_v2   *hdr = (struct dir_hdr_v2 *)dir;
	uint8_t             *dir_blocks;
	size_t               dir_blocks_sz;
	struct dir_block_v2 *b;

	if (!valid_inode(mgr, hdr->v.h.inode))
		stats->errors++;
	if (add_found_inode(hdr->v.h.inode, e) == -1)
		return XERR_PREPENDFN(e);
	stats->n_dirents++;

	if (!valid_inode(mgr, hdr->v.h.parent))
		stats->errors++;
	if (add_found_inode(hdr->v.h.parent, e) == -1)
		return XERR_PREPENDFN(e);
	stats->n_dirents++;

	if (*dir_sz % DEV_BSIZE != 0) {
		warnx("dir inode size is node a multiple of %d: "
		    "inode=%lu", DEV_BSIZE, hdr->v.h.inode);
		stats->errors++;
	}
	/*
	 * Every element in the array is either 0 or 1, where
	 * 1 means this block offset is used.
	 */
	dir_blocks_sz = sizeof(uint8_t) *
	    ((*dir_sz - sizeof(struct dir_hdr_v2)) /
	     sizeof(struct dir_block_v2));
	dir_blocks = malloc(dir_blocks_sz);
	if (dir_blocks == NULL)
		return XERRF(e, XLOG_ERRNO, errno, "malloc");
	bzero(dir_blocks, dir_blocks_sz);

	if (validate_dir_block_v2(mgr, hdr->v.h.inode, dir, *dir_sz,
	    sizeof(struct dir_hdr_v2), 0, dir_blocks, stats, e) == -1) {
		free(dir_blocks);
		return XERR_PREPENDFN(e);
	}

	for (b = (struct dir_block_v2 *)(dir + hdr->v.h.free_list_start);
	    (char *)b - dir > 0;
	    b = (struct dir_block_v2 *)(dir + b->v.leaf.next)) {
		if (b->v.flags & DI_BLOCK_ALLOCATED) {
			stats->errors++;
			warnx("dir inode %lu has a block part of its freelist "
			    "that's allocated at offset %ld",
			    hdr->v.h.inode, (char *)b - dir);
			free(dir_blocks);
			return 0;
		}
		dir_blocks[(((char *)b - sizeof(struct dir_hdr_v2)) - dir) /
		    sizeof(struct dir_block_v2)] = 1;
	}

	for (b = (struct dir_block_v2 *)(dir + sizeof(struct dir_hdr_v2));
	    (char *)b - dir < *dir_sz; b++) {
		/*
		 * See if this block offset is either part of the freelist
		 * or referenced in the dir hash tree. Skip if it lies
		 * at the boundary of inline inode data, which we don't
		 * use in dirinodes.
		 */
		if (dir_blocks[(((char *)b - sizeof(struct dir_hdr_v2)) - dir) /
		    sizeof(struct dir_block_v2)] == 0) {
			stats->errors++;
			warnx("dir inode %lu has a block that is neither "
			    "allocated or part of the freelist, at offset %ld",
			    hdr->v.h.inode, (char *)b - dir);
		}
	}
	free(dir_blocks);

	return dirty;
}

int
fsck_inode(int mgr, ino_t ino, int unallocated, struct inode *inode,
    struct fsck_stats *stats, struct xerr *e)
{
	char               *dir;
	size_t              dir_sz;
	int                 dirty = 0;
	struct found_inode *fino;

	fsck_printf("  inode: %lu", ino);
	if (unallocated) {
		if (inode == NULL) {
			return 0;
		} else if (inode->v.f.nlink > 0) {
			warnx("leaked inode %lu; bitmap says it's free, "
			    "but nlink is %lu", ino, inode->v.f.nlink);
			stats->errors++;
			return -1;
		}
		return 0;
	} else {
		if (inode == NULL) {
			warnx("missing inode %lu; bitmap says it's allocated, "
			    "but inode table ends at a lower offset", ino);
			stats->errors++;
			return -1;
		} else if (inode->v.f.nlink == 0) {
			warnx("unlinked inode %lu; bitmap says it's allocated, "
			    "but nlink is 0", ino);
			stats->errors++;
			return -1;
		}

		/*
		 * Keep track of all allocated inodes to later verify
		 * if they are properly linked in a directory somewhere.
		 */
		if ((fino = malloc(sizeof(struct found_inode))) == NULL)
			return XERRF(e, XLOG_ERRNO, errno, "malloc");
		bzero(fino, sizeof(struct found_inode));
		fino->ino = inode->v.f.inode;
		if (RB_INSERT(scanned_inode_tree, &scanned_inodes.head,
		    fino) != NULL) {
			free(fino);
			return XERRF(e, XLOG_ERRNO, errno, "RB_INSERT");
		}
		scanned_inodes.count++;
	}

	stats->n_inodes++;

	if (!(inode->v.f.mode & S_IFDIR))
		return 0;

	fsck_printf("  inode:   => dir");
	stats->n_dirs++;

	if (load_dir(mgr, &dir, inode, &dirty) == -1) {
		stats->errors++;
		return -1;
	}
	dir_sz = inode->v.f.size;

	if (((struct dir_hdr *)dir)->dirinode_format == 1) {
		dirty = validate_dir_v1(mgr, ino, dir, &dir_sz, stats, e);
		if (dirty == -1) {
			free(dir);
			return XERR_PREPENDFN(e);
		}
	} else if (((struct dir_hdr *)dir)->dirinode_format == 2) {
		dirty = validate_dir_v2(mgr, ino, dir, &dir_sz, stats, e);
		if (dirty == -1) {
			free(dir);
			return XERR_PREPENDFN(e);
		}
	}

	if (dirty) {
		inode->v.f.size = dir_sz;
		inode->v.f.blocks = inode->v.f.size / 512 + 1;
		if (write_dir(mgr, dir, inode) == -1) {
			free(dir);
			stats->errors++;
			return -1;
		}
	}

	free(dir);
	return 0;
}

int
compute_checksum(int fd, uint32_t *crc, struct xerr *e)
{
	char     buf[BUFSIZ];
	ssize_t  r;

	if (lseek(fd, sizeof(struct slab_hdr), SEEK_SET) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "lseek");

	*crc = crc32_z(0L, Z_NULL, 0);
	while ((r = read(fd, buf, sizeof(buf)))) {
		if (r == -1) {
			if (errno == EINTR)
				continue;
			return XERRF(e, XLOG_ERRNO, errno, "read");
		}
		*crc = crc32_z(*crc, (unsigned char *)buf, r);
	}
	return 0;
}

int
verify_checksum(int fd, struct slab_hdr *hdr, struct xerr *e)
{
	uint32_t crc;

	if (compute_checksum(fd, &crc, e) == -1)
		return XERR_PREPENDFN(e);

	if (hdr->v.f.checksum != crc)
		return XERRF(e, XLOG_APP, XLOG_MISMATCH,
		    "mismatching content CRC for ino=%lu / base=%lu: "
		    "expected=%lu, actual=%u", hdr->v.f.key.ino,
		    hdr->v.f.key.base, hdr->v.f.checksum, crc);

	return 0;
}

static int
start_scrub(int mgr, struct xerr *e)
{
	struct mgr_msg  m;

	bzero(&m, sizeof(m));
	m.m = MGR_MSG_SCRUB;
	if (mgr_send(mgr, -1, &m, e) == -1)
		return XERR_PREPENDFN(e);

	if (mgr_recv(mgr, NULL, &m, e) == -1)
		return XERR_PREPENDFN(e);

	return 0;
}

int
do_scrub(int argc, char **argv)
{
	struct xerr    e;
	struct fs_info fs_info;
	int            mgr;

	if (fs_info_read(&fs_info, xerrz(&e)) == -1) {
		xerr_print(&e);
		exit(1);
	}

	if ((mgr = mgr_connect(1, xerrz(&e))) == -1) {
		xerr_print(&e);
		exit(1);
	}

	if (start_scrub(mgr, xerrz(&e)) == -1) {
		xerr_print(&e);
		exit(1);
	}

	close(mgr);

	return 0;
}

static int
start_flush(int mgr, struct xerr *e)
{
	struct mgr_msg  m;

	bzero(&m, sizeof(m));
	m.m = MGR_MSG_FLUSH;
	if (mgr_send(mgr, -1, &m, e) == -1)
		return XERR_PREPENDFN(e);

	if (mgr_recv(mgr, NULL, &m, e) == -1)
		return XERR_PREPENDFN(e);

	return 0;
}

int
do_flush(int argc, char **argv)
{
	int         mgr;
	struct xerr e;
	int         status = 0;

	if (mgr_start(1, 1) == -1)
		err(1, "mgr_start");

	if ((mgr = mgr_connect(1, xerrz(&e))) == -1) {
		xerr_print(&e);
		status = 1;
		goto end;
	}

	if (start_flush(mgr, xerrz(&e)) == -1) {
		xerr_print(&e);
		status = 1;
		close(mgr);
		goto end;
	}

	close(mgr);
end:
	if (mgr_send_shutdown(0, xerrz(&e)) == -1) {
		xerr_print(&e);
		return 1;
	}
	return status;
}

int
do_offline(int argc, char **argv)
{
	struct xerr    e;
	struct fs_info fs_info;
	int            mgr;
	struct mgr_msg m;

	if (fs_info_read(&fs_info, xerrz(&e)) == -1) {
		xerr_print(&e);
		exit(1);
	}

	if ((mgr = mgr_connect(1, xerrz(&e))) == -1) {
		xerr_print(&e);
		exit(1);
	}

	bzero(&m, sizeof(m));
	m.m = MGR_MSG_OFFLINE;

	if (mgr_send(mgr, -1, &m, &e) == -1) {
		xerr_print(&e);
		exit(1);
	}

	if (mgr_recv(mgr, NULL, &m, &e) == -1) {
		xerr_print(&e);
		exit(1);
	}

	if (m.m == MGR_MSG_OFFLINE_ERR) {
		xerr_print(&m.v.err);
		exit(1);
	}

	close(mgr);

	warnx("offline mode on");

	return 0;
}

int
do_online(int argc, char **argv)
{
	struct xerr    e;
	struct fs_info fs_info;
	int            mgr;
	struct mgr_msg m;

	if (fs_info_read(&fs_info, xerrz(&e)) == -1) {
		xerr_print(&e);
		exit(1);
	}

	if ((mgr = mgr_connect(1, xerrz(&e))) == -1) {
		xerr_print(&e);
		exit(1);
	}

	bzero(&m, sizeof(m));
	m.m = MGR_MSG_ONLINE;

	if (mgr_send(mgr, -1, &m, &e) == -1) {
		xerr_print(&e);
		exit(1);
	}

	if (mgr_recv(mgr, NULL, &m, &e) == -1) {
		xerr_print(&e);
		exit(1);
	}

	if (m.m == MGR_MSG_ONLINE_ERR) {
		xerr_print(&m.v.err);
		exit(1);
	}

	close(mgr);

	warnx("offline mode off");

	return 0;
}

/*
 * The error will be set if we ecountered an error that could
 * prevent us from checking other inode tables. If no error
 * is set but itbl is NULL on return, we tell the caller
 * to keep looping, though that current inode table had an issue.
 */
static struct inode *
fsck_load_next_itbl(int mgr, struct oslab *b,
    off_t *itbl_sz, struct xerr *e)
{
	struct mgr_msg  m;
	ssize_t         r;
	struct inode   *itbl = NULL;
	int             fd;

	bzero(&m, sizeof(m));
	m.m = MGR_MSG_CLAIM_NEXT_ITBL;
	m.v.claim_next_itbl.base = b->hdr.v.f.key.base;
	m.v.claim_next_itbl.oflags = OSLAB_NOCREATE|OSLAB_SYNC|OSLAB_EPHEMERAL|OSLAB_NOHINT;
	if (mgr_send(mgr, -1, &m, e) == -1)
		return NULL;

	if (mgr_recv(mgr, &fd, &m, e) == -1)
		return NULL;

	if (m.m == MGR_MSG_CLAIM_NEXT_ITBL_END) {
		XERRF(e, XLOG_APP, XLOG_NOSLAB,
		    "no more inode tables after %lu", b->hdr.v.f.key.base);
		return NULL;
	} else if (m.m == MGR_MSG_CLAIM_ERR) {
		memcpy(e, &m.v.err, sizeof(struct xerr));
		xerr_prepend(e, __func__);
		return NULL;
	} else if (m.m != MGR_MSG_CLAIM_OK) {
		XERRF(e, XLOG_APP, XLOG_MGRERROR,
		    "mgr_recv: unexpected response: %d", m.m);
		return NULL;
	}

	fsck_printf("itbl: %lu/%lu", m.v.claim.key.ino, m.v.claim.key.base);

	b->fd = fd;

	if (slab_read_hdr(b, e) == -1)
		goto end;

	if (b->hdr.v.f.key.ino != m.v.claim.key.ino ||
	    b->hdr.v.f.key.base != m.v.claim.key.base) {
		XERRF(e, XLOG_APP, XLOG_IO,
		    "slab header's ino/base (%lu / %lu) does not match "
		    "what the slabdb contains (%lu / %lu)",
		    b->hdr.v.f.key.ino, b->hdr.v.f.key.base,
		    m.v.claim.key.ino, m.v.claim.key.base);
		goto end;
	}

	if (b->hdr.v.f.slab_version != SLAB_VERSION) {
		XERRF(e, XLOG_APP, XLOG_IO,
		    "unrecognized data format version: base=%lu, "
		    "version=%u", b->hdr.v.f.key.base, b->hdr.v.f.slab_version);
		goto end;
	}

	if (verify_checksum(b->fd, &b->hdr, e) == -1)
		goto end;

	/*
	 * Load entire itbl in memory so we can close it.
	 * Otherwise we'll have flock() deadlock.
	 */
	if ((*itbl_sz = slab_size(b, e)) == ULONG_MAX)
		goto end;

	if ((itbl = malloc(*itbl_sz)) == NULL) {
		XERRF(e, XLOG_ERRNO, errno, "malloc");
		goto end;
	}

	if ((r = slab_read(b, itbl, 0, *itbl_sz, e)) < *itbl_sz) {
		free(itbl);
		itbl = NULL;
		if (r == -1)
			goto end;
		XERRF(e, XLOG_APP, XLOG_IO, "slab shrunk after fstat()");
	}
end:
	m.m = MGR_MSG_UNCLAIM;
	memcpy(&m.v.unclaim.key, &b->hdr.v.f.key, sizeof(struct slab_key));
	if (mgr_send(mgr, b->fd, &m, e) != -1 &&
	    mgr_recv(mgr, NULL, &m, e) != -1 &&
	    m.m != MGR_MSG_UNCLAIM_OK) {
		if (m.m == MGR_MSG_UNCLAIM_ERR) {
			memcpy(e, &m.v.err, sizeof(struct xerr));
			XERR_PREPENDFN(e);
		} else
			XERRF(e, XLOG_APP, XLOG_MGRERROR,
			    "mgr_recv: unexpected response: %d", m.m);
	}
	close(b->fd);
	return itbl;
}

int
fsck(int argc, char **argv)
{
	ino_t                  ino;
	int                    slab_end = 0, is_free;
	struct inode          *inode, *itbl;
	struct oslab           b;
	struct slab_itbl_hdr  *ihdr = (struct slab_itbl_hdr *)slab_hdr_data(&b);
	off_t                  itbl_sz;
	struct xerr            e;
	struct fsck_stats      stats = {0, 0, 0, 0};
	size_t                 n_free;
	int                    mgr;
	char                 **arg;
	struct found_inode    *fino, *nfino, *dfino;

	fsck_verbose = 0;

	for (arg = argv; *arg != NULL; arg++) {
		if (strcmp(*arg, "verbose") == 0)
			fsck_verbose = 1;
		else if (strcmp(*arg, "fix") == 0)
			fsck_fix = 1;
	}

	if (mgr_start(1, 1) == -1)
		err(1, "mgr_start");

	if ((mgr = mgr_connect(1, xerrz(&e))) == -1) {
		xerr_print(&e);
		stats.errors++;
		goto end;
	}

	bzero(&b, sizeof(b));
	for (;;) {
		if ((itbl = fsck_load_next_itbl(mgr, &b,
		    &itbl_sz, xerrz(&e))) == NULL) {
			if (xerr_fail(&e)) {
				if (!xerr_is(&e, XLOG_APP, XLOG_NOSLAB)) {
					stats.errors++;
					xerr_print(&e);
				}
				break;
			}
			continue;
		}

		for (ino = b.hdr.v.f.key.base, slab_end = 0, n_free = 0;
		    ino < b.hdr.v.f.key.base + slab_inode_max(); ino++) {
			if (!slab_end) {
				inode = itbl + (ino - b.hdr.v.f.key.base);
				if ((inode - itbl) *
				    sizeof(struct inode) >= itbl_sz) {
					/*
					 * Once we reach the end of the inode
					 * table, it's implied that the next
					 * inodes are unallocated.
					 */
					slab_end = 1;
				} else if ((inode - itbl) + 1 >= itbl_sz) {
					warnx("%s: inode %lu truncated",
					    __func__, ino);
					stats.errors++;
					slab_end = 1;
				}
			}

			is_free = slab_itbl_is_free(&b, ino);
			fsck_inode(mgr, ino, is_free,
			    ((slab_end) ? NULL : inode), &stats, xerrz(&e));
			if (is_free)
				n_free++;
		}
		if (ihdr->n_free != n_free) {
			warnx("%s: incorrect free inode count in "
			    "inode table base %lu (n_free=%u, actual=%lu)",
			    __func__, b.hdr.v.f.key.base,
			    ihdr->n_free, n_free);
			stats.errors++;
		}
		free(itbl);
	}

	if (fsck_fix && start_scrub(mgr, xerrz(&e)) == -1) {
		xerr_print(&e);
		stats.errors++;
	}

	close(mgr);

	if (fsck_verbose)
		printf("Checking for missing inodes; tables=%d, dirents=%d\n",
		    scanned_inodes.count, scanned_dirent_inodes.count);

	for (fino = RB_MIN(scanned_inode_tree, &scanned_inodes.head);
	    fino != NULL;
	    fino = nfino) {
		nfino = RB_NEXT(scanned_inode_tree, &scanned_inodes.head, fino);
		RB_REMOVE(scanned_inode_tree, &scanned_inodes.head, fino);
		if ((dfino = RB_FIND(scanned_dirent_inode_tree,
		    &scanned_dirent_inodes.head, fino))) {
			RB_REMOVE(scanned_dirent_inode_tree,
			    &scanned_dirent_inodes.head, dfino);
			free(dfino);
		} else {
			warnx("%s: inode %lu is not referenced in any "
			    "directory", __func__, fino->ino);
			stats.errors++;
		}
		free(fino);
	}
end:
	printf("Filesystem statistics:\n");
	printf("    inodes:      %lu\n", stats.n_inodes);
	printf("    directories: %lu\n", stats.n_dirs);
	printf("    dirents:     %lu\n", stats.n_dirents);
	printf("    errors:      %lu\n", stats.errors);
	printf("Scan result: %s\n",
	    (stats.errors) ? "errors" : "clean");

	if (mgr_send_shutdown(0, xerrz(&e)) == -1)
		xerr_print(&e);
	return (stats.errors) ? 1 : 0;
}

int
inode_tables(int argc, char **argv)
{
	struct xerr     e;
	int             mgr;
	struct mgr_msg  m;
	off_t           base = 0;
	struct slab_key sk;
	int             fd;
	uuid_t          u;

	uuid_clear(u);
	if (slabdb_init(u, xerrz(&e)) == -1) {
		xerr_print(&e);
		exit(1);
	}

	while (slabdb_get_next_itbl(&base, xerrz(&e)) != -1) {
		printf("slabdb_get_next_itbl: found base %lu\n", base);
	}

	slabdb_shutdown();

	if ((mgr = mgr_connect(0, xerrz(&e))) == -1) {
		xerr_print(&e);
		exit(1);
	}

	base = 0;
	for (;;) {
		m.m = MGR_MSG_CLAIM_NEXT_ITBL;
		m.v.claim_next_itbl.base = base;
		m.v.claim_next_itbl.oflags = OSLAB_NOCREATE|OSLAB_SYNC|OSLAB_EPHEMERAL|OSLAB_NOHINT;
		if (mgr_send(mgr, -1, &m, xerrz(&e)) == -1) {
			xerr_print(&e);
			exit(1);
		}

		if (mgr_recv(mgr, &fd, &m, xerrz(&e)) == -1) {
			xerr_print(&e);
			exit(1);
		}

		if (m.m == MGR_MSG_CLAIM_NEXT_ITBL_END) {
			break;
		} else if (m.m != MGR_MSG_CLAIM_ERR) {
			memcpy(&e, &m.v.err, sizeof(struct xerr));
			xerr_prepend(&e, __func__);
			xerr_print(&e);
			exit(1);
		} else if (m.m != MGR_MSG_CLAIM_OK) {
			errx(1, "%s: mgr_recv: unexpected response: %d",
			    __func__, m.m);
		}
		memcpy(&sk, &m.v.claim.key, sizeof(sk));
		base = sk.base;

		fsck_printf("itbl: %lu/%lu", sk.ino, sk.base);

		m.m = MGR_MSG_UNCLAIM;
		memcpy(&m.v.unclaim.key, &sk, sizeof(struct slab_key));
		if (mgr_send(mgr, fd, &m, xerrz(&e)) != -1 &&
		    mgr_recv(mgr, NULL, &m, xerrz(&e)) != -1 &&
		    m.m != MGR_MSG_UNCLAIM_OK) {
			if (m.m == MGR_MSG_UNCLAIM_ERR) {
				memcpy(&e, &m.v.err, sizeof(struct xerr));
				xerr_prepend(&e, __func__);
				xerr_print(&e);
				exit(1);
			} else
				errx(1, "%s: mgr_recv: unexpected response: %d",
				    __func__, m.m);
		}
		close(fd);
	}
	close(mgr);
	return 0;
}

void
print_metric_header()
{
	printf("%10s %10s %10s %10s %10s %10s %10s\n",
	    "read/s", "read MB/s", "write/s", "write MB/s",
	    "be-r MB/s", "be-w MB/s", "errors");
}

int
do_shutdown(int argc, char **argv)
{
	struct xerr e;
	time_t      grace_seconds = 10;

	if (argc >= 1)
		grace_seconds = strtoul(argv[0], NULL, 10);
	if (mgr_send_shutdown(grace_seconds, xerrz(&e)) == -1) {
		xerr_print(&e);
		return 1;
	}

	printf("%s: shutdown signal sent\n", __func__);
	return 0;
}

int
fs_status(int argc, char **argv)
{
	int            mgr;
	char           u[37];
	struct mgr_msg m;
	struct xerr    e = XLOG_ERR_INITIALIZER;
	double         used, total;
	struct fs_info fs_info;
	struct statvfs stv;
	char           mgr_line[80], pid_version[50];
	int            exit_code = 0;

	mgr = mgr_connect(0, xerrz(&e));

	if (mgr == -1) {
		if (errno == ECONNREFUSED) {
			printf("WARNING: connection to mgr was refused; "
			    "reading fs_info offline instead\n");
			if (fs_info_read(&fs_info, xerrz(&e)) == -1) {
				xerr_print(&e);
				return 1;
			}
			exit_code = 2;
		} else {
			xerr_print(&e);
			return 1;
		}
		snprintf(mgr_line, sizeof(mgr_line), "not running");
	} else {
		bzero(&m, sizeof(m));
		m.m = MGR_MSG_INFO;
		if (mgr_send(mgr, -1, &m, xerrz(&e)) == -1) {
			close(mgr);
			xerr_print(&e);
			return 1;
		}
		if (mgr_recv(mgr, NULL, &m, xerrz(&e)) == -1) {
			close(mgr);
			xerr_print(&e);
			return 1;
		}
		if (m.m == MGR_MSG_INFO_ERR) {
			close(mgr);
			memcpy(&e, &m.v.err, sizeof(struct xerr));
			xerr_print(&e);
			return 1;
		} else if (m.m != MGR_MSG_INFO_OK) {
			close(mgr);
			warnx("%s: mgr_recv: unexpected response: %d",
			    __func__, m.m);
			return 1;
		}
		snprintf(pid_version, sizeof(pid_version),
		    "running with PID %d, version %s",
		    m.v.info.mgr_pid, m.v.info.version_string);
		memcpy(&fs_info, &m.v.info.fs_info, sizeof(fs_info));

		bzero(&m, sizeof(m));
		m.m = MGR_MSG_GET_OFFLINE;
		if (mgr_send(mgr, -1, &m, xerrz(&e)) == -1) {
			close(mgr);
			xerr_print(&e);
			return 1;
		}
		if (mgr_recv(mgr, NULL, &m, xerrz(&e)) == -1) {
			close(mgr);
			xerr_print(&e);
			return 1;
		}
		close(mgr);
		if (m.m == MGR_MSG_GET_OFFLINE_ERR) {
			memcpy(&e, &m.v.err, sizeof(e));
			xerr_print(&e);
			return 1;
		} else if (m.m != MGR_MSG_GET_OFFLINE_OK) {
			warnx("%s: mgr_recv: unexpected response: %d",
			    __func__, m.m);
			return 1;
		}

		snprintf(mgr_line, sizeof(mgr_line),
		    "%s, offline mode %s", pid_version,
		    (m.v.get_offline.offline) ? "on" : "off");
	}

	printf("%s: %s\n", MGR_PROGNAME, mgr_line);

	uuid_unparse(fs_info.instance_id, u);
	printf("\nfs_info (%lu bytes):\n", sizeof(fs_info));

	printf("  version:     %u\n", fs_info.fs_info_version);
	printf("  instance_id: %s\n", u);
	printf("  slab_size:   %lu\n", fs_info.slab_size);
	printf("  clean:       %u\n", fs_info.clean);
	printf("  error:       %u\n", fs_info.error);
	printf("  last_update: %lu.%lu\n",
	    fs_info.stats_last_update.tv_sec,
	    fs_info.stats_last_update.tv_nsec);
	printf("  statvfs:\n");
	printf("    f_bsize:   %lu\n", fs_info.stats.f_bsize);
	printf("    f_frsize:  %lu\n", fs_info.stats.f_frsize);

	printf("    f_blocks:  %lu\n", fs_info.stats.f_blocks);
	printf("    f_bfree:   %lu\n", fs_info.stats.f_bfree);
	printf("    f_bavail:  %lu\n", fs_info.stats.f_bavail);

	printf("    f_files:   %lu\n", fs_info.stats.f_files);
	printf("    f_ffree:   %lu\n", fs_info.stats.f_ffree);
	printf("    f_favail:  %lu\n", fs_info.stats.f_favail);
	/*
	 * Also, fsid is currently irrelevant.
	 */
	printf("    f_namemax: %lu\n", fs_info.stats.f_namemax);
	printf("\n");

	/*
	 * Convert values to GiB
	 */
	used = (double) (fs_info.stats.f_blocks -
	    fs_info.stats.f_bfree) *
	    fs_info.stats.f_bsize / (2UL << 29UL);
	total = (double) fs_info.stats.f_blocks *
	    fs_info.stats.f_bsize / (2UL << 29UL);

	printf("Backend usage: %.1f / %.1f GiB (%.1f%%)\n", used, total,
	    used * 100.0 / total);

	if (statvfs(fs_config.data_dir, &stv) == -1)
		err(1, "statvfs");
	used = (double) (stv.f_blocks - stv.f_bfree) *
	    stv.f_bsize / (2UL << 29UL);
	total = (double) stv.f_blocks * stv.f_bsize / (2UL << 29UL);

	printf("  Cache usage: %.1f / %.1f GiB (%.1f%%)\n", used, total,
	    used * 100.0 / total);

	return exit_code;
}

int
set_clean(int argc, char **argv)
{
	char           u[37];
	struct xerr    e;
	struct fs_info fs_info;

	if (fs_info_read(&fs_info, xerrz(&e)) == -1) {
		xerr_print(&e);
		exit(1);
	}

	uuid_unparse(fs_info.instance_id, u);

	printf("fs_info:\n");
	printf("  version:     %u\n", fs_info.fs_info_version);
	printf("  instance_id: %s\n", u);
	printf("  slab_size:   %lu\n", fs_info.slab_size);
	printf("  clean:       %u => 1\n", fs_info.clean);
	printf("  error:       %u => 0\n", fs_info.error);
	printf("  last_update: %lu.%lu\n",
	    fs_info.stats_last_update.tv_sec,
	    fs_info.stats_last_update.tv_nsec);

	fs_info.error = 0;
	fs_info.clean = 1;

	if (fs_info_write(&fs_info, xerrz(&e)) == -1) {
		xerr_print(&e);
		exit(1);
	}

	return 0;
}

int
dump_config(int argc, char **argv)
{
	// TODO: this should be pulled from the running filesystem
	// eventually.
	printf("uid:                         %u\n", fs_config.uid);
	printf("gid:                         %u\n", fs_config.gid);
	printf("dbg:                         %s\n",
	    (fs_config.dbg[0] != '\0') ? fs_config.dbg : "off");
	printf("max_open_slabs:              %lu\n", fs_config.max_open_slabs);
	printf("entry_timeouts:              %u\n", fs_config.entry_timeouts);
	printf("slab_max_age:                %lu\n", fs_config.slab_max_age);
	printf("slab_size:                   %lu\n", fs_config.slab_size);
	printf("noatime:                     %s\n",
	    (fs_config.noatime) ? "true" : "false");
	printf("data_dir:                    %s\n", fs_config.data_dir);
	printf("mgr_sock_path:               %s\n", fs_config.mgr_sock_path);
	printf("mgr_exec:                    %s\n", fs_config.mgr_exec);
	printf("cfg_path:                    %s\n", fs_config.cfg_path);
	printf("unclaim_purge_threshold_pct: %lu\n",
	    fs_config.unclaim_purge_threshold_pct);
	printf("purge_threshold_pct:         %lu\n",
	    fs_config.purge_threshold_pct);
	return 0;
}

int
dump_counters(int argc, char **argv)
{
	int      c;
	uint64_t counters[COUNTER_LAST];
	uint64_t mgr_counters[MGR_COUNTER_LAST];

	read_metrics(counters, mgr_counters);
	printf("{\n");
	for (c = 0; c < COUNTER_LAST; c++)
		printf("    \"%s\": %lu,\n",
		    counter_names[c], counters[c]);
	for (c = 0; c < MGR_COUNTER_LAST; c++)
		printf("    \"%s\": %lu%s\n",
		    mgr_counter_names[c], mgr_counters[c],
		    (c == (MGR_COUNTER_LAST - 1)) ? "" : ",");
	printf("}\n");
	return 0;
}

int
top(int argc, char **argv)
{
	unsigned int    seconds = 2;
	uint64_t        counters_now[COUNTER_LAST];
	uint64_t        counters_prev[COUNTER_LAST];
	double          counters_delta[COUNTER_LAST];
	uint64_t        mgr_counters_now[MGR_COUNTER_LAST];
	uint64_t        mgr_counters_prev[MGR_COUNTER_LAST];
	double          mgr_counters_delta[MGR_COUNTER_LAST];
	int             c, i;
	struct timespec ts, te;

	if (argc > 0)
		seconds = strtol(argv[0], NULL, 10);

	read_metrics(counters_prev, mgr_counters_prev);
	for (i = 0;; i++) {
		clock_gettime_x(CLOCK_MONOTONIC, &ts);
		sleep(seconds);

		read_metrics(counters_now, mgr_counters_now);
		clock_gettime_x(CLOCK_MONOTONIC, &te);
		for (c = 0; c < COUNTER_LAST; c++) {
			counters_delta[c] = counters_now[c] - counters_prev[c];
			counters_prev[c] = counters_now[c];
		}
		for (c = 0; c < MGR_COUNTER_LAST; c++) {
			mgr_counters_delta[c] = mgr_counters_now[c] -
			    mgr_counters_prev[c];
			mgr_counters_prev[c] = mgr_counters_now[c];
		}

		if (i % 23 == 0)
			print_metric_header();
		printf("%10.1f %10.2f %10.1f %10.2f %10.2f %10.2f %10lu\n",
		    counters_delta[COUNTER_FS_READ] /
		    (te.tv_sec - ts.tv_sec),

		    counters_delta[COUNTER_READ_BYTES] /
		    1024.0 / 1024.0 / (te.tv_sec - ts.tv_sec),

		    counters_delta[COUNTER_FS_WRITE] /
		    (te.tv_sec - ts.tv_sec),

		    counters_delta[COUNTER_WRITE_BYTES] /
		    1024.0 / 1024.0 / (te.tv_sec - ts.tv_sec),

		    mgr_counters_delta[MGR_COUNTER_BACKEND_IN_BYTES] /
		    1024.0 / 1024.0 / (te.tv_sec - ts.tv_sec),

		    mgr_counters_delta[MGR_COUNTER_BACKEND_OUT_BYTES] /
		    1024.0 / 1024.0 / (te.tv_sec - ts.tv_sec),

		    counters_now[COUNTER_FS_ERROR]);
	}
	return 0;
}

int
read_info(struct fs_info *info, pid_t *mgr_pid,
    char *version, size_t version_len, struct xerr *e)
{
	int            mgr;
	struct mgr_msg m;

	mgr = mgr_connect(0, xerrz(e));
	if (mgr == -1)
		return XERR_PREPENDFN(e);
	m.m = MGR_MSG_INFO;
	if (mgr_send(mgr, -1, &m, xerrz(e)) == -1) {
		close(mgr);
		return XERR_PREPENDFN(e);
	}
	if (mgr_recv(mgr, NULL, &m, xerrz(e)) == -1) {
		close(mgr);
		return XERR_PREPENDFN(e);
	}
	close(mgr);

	if (m.m == MGR_MSG_INFO_ERR) {
		memcpy(e, &m.v.err, sizeof(struct xerr));
		return XERR_PREPENDFN(e);
	} else if (m.m != MGR_MSG_INFO_OK) {
		return XERRF(e, XLOG_APP, XLOG_MGRERROR,
		    "mgr_recv: unexpected response: %d", m.m);
	}
	memcpy(info, &m.v.info.fs_info, sizeof(struct fs_info));
	*mgr_pid = m.v.info.mgr_pid;
	strlcpy(version, m.v.info.version_string, version_len);
	return 0;
}

int
ctop(int argc, char **argv)
{
	uint64_t         counters_now[COUNTER_LAST];
	uint64_t         counters_prev[COUNTER_LAST];
	double           counters_delta[COUNTER_LAST];
	uint64_t         mgr_counters_now[MGR_COUNTER_LAST];
	uint64_t         mgr_counters_prev[MGR_COUNTER_LAST];
	double           mgr_counters_delta[MGR_COUNTER_LAST];
	double           hit_ratio;
	int              c;
	struct timespec  ts, te, slp = {0, 100000000}; /* 100ms */
	struct fs_info   fs_info;
	char             u[37], tstr[32];
	double           used, total;
	int              row, col1, col2, stats_row, dim_x;
	char             pid_version_str[80];
	char             version_string[16];
	struct tm       *tm;
	time_t           t;
	struct statvfs   stv;
	double           delta_s;
	int              interval = 1;
	struct xerr      e;
	pid_t            mgr_pid;

	bzero(&fs_info, sizeof(fs_info));
	if (read_info(&fs_info, &mgr_pid, version_string,
	    sizeof(version_string), &e) == -1) {
		xerr_print(&e);
		return 1;
	}
	uuid_unparse(fs_info.instance_id, u);

	initscr();
	cbreak();
	noecho();
	timeout(0);
	dim_x = getmaxx(stdscr);

	t = time(NULL);
	tm = localtime(&t);
	strftime(tstr, sizeof(tstr), "%c", tm);
	mvprintw(0, 0, "PotatoFS ctop - %s", tstr);
	snprintf(pid_version_str, sizeof(pid_version_str),
	    "potatomgr PID %d, version %s", mgr_pid, version_string);
	mvprintw(0, dim_x - strlen(pid_version_str), pid_version_str);

	row = 2;
	col1 = 2;
	mvprintw(row++, col1, "fs instance  : %s", u);
	mvprintw(row++, col1, "Cache usage  :");
	mvprintw(row++, col1, "Backend usage:");

	col2 = 32;
	stats_row = ++row;
	mvprintw(row++, col1, "reads       :");
	mvprintw(row++, col1, "read MB     :");
	mvprintw(row++, col1, "writes      :");
	mvprintw(row++, col1, "write MB    :");
	mvprintw(row++, col1, "be read MB  :");
	mvprintw(row++, col1, "be write MB :");
	row++;
	mvprintw(row++, col1, "getattr     :");
	mvprintw(row++, col1, "setattr     :");
	mvprintw(row++, col1, "opendir     :");
	mvprintw(row++, col1, "readdir     :");
	mvprintw(row++, col1, "releasedir  :");
	mvprintw(row++, col1, "open        :");
	mvprintw(row++, col1, "flush       :");
	mvprintw(row++, col1, "forget      :");
	mvprintw(row++, col1, "forget_multi:");
	mvprintw(row++, col1, "lookup      :");
	mvprintw(row++, col1, "mkdir       :");

	row = stats_row;
	mvprintw(row++, col2, "rmdir       :");
	mvprintw(row++, col2, "unlink      :");
	mvprintw(row++, col2, "mknod       :");
	mvprintw(row++, col2, "fallocate   :");
	mvprintw(row++, col2, "fsync       :");
	mvprintw(row++, col2, "fsyncdir    :");
	mvprintw(row++, col2, "link        :");
	mvprintw(row++, col2, "symlink     :");
	mvprintw(row++, col2, "readlink    :");
	mvprintw(row++, col2, "rename      :");
	mvprintw(row++, col2, "statfs      :");
	row++;
	mvprintw(row++, col2, "delay truncs:");
	mvprintw(row++, col2, "open slabs  :");
	mvprintw(row++, col2, "open inodes :");
	mvprintw(row++, col2, "fs purges   :");
	mvprintw(row++, col2, "mgr purges  :");
	mvprintw(row++, col2, "errors      :");
	mvprintw(row++, col2, "claim cttn  :");

	/* length of longest string above. */
	col1 += 15;
	col2 += 15;

	read_metrics(counters_prev, mgr_counters_prev);
	for (;;) {
		clock_gettime_x(CLOCK_MONOTONIC, &ts);
again:
		if (nanosleep(&slp, NULL) == -1)
			goto end;
		switch (getch()) {
		case 'q':
			goto end;
		case '+':
			if (interval < 300)
				interval++;
			break;
		case '-':
			if (interval > 1)
				interval--;
			break;
		default:
			clock_gettime_x(CLOCK_MONOTONIC, &te);
			if (te.tv_sec - ts.tv_sec < interval)
				goto again;
		}

		read_metrics(counters_now, mgr_counters_now);
		clock_gettime_x(CLOCK_MONOTONIC, &te);
		if (read_info(&fs_info, &mgr_pid, version_string,
		    sizeof(version_string), &e) == -1) {
			xerr_print(&e);
			return 1;
		}

		for (c = 0; c < COUNTER_LAST; c++) {
			counters_delta[c] = counters_now[c] - counters_prev[c];
			counters_prev[c] = counters_now[c];
		}
		for (c = 0; c < MGR_COUNTER_LAST; c++) {
			mgr_counters_delta[c] = mgr_counters_now[c] -
			    mgr_counters_prev[c];
			mgr_counters_prev[c] = mgr_counters_now[c];
		}

		delta_s = (((te.tv_sec * 1000000000) + te.tv_nsec) -
		    ((ts.tv_sec * 1000000000) + ts.tv_nsec)) / 1000000000.0;

		t = time(NULL);
		tm = localtime(&t);
		strftime(tstr, sizeof(tstr), "%c", tm);
		mvprintw(0, 16, "%s", tstr);

		snprintf(tstr, sizeof(tstr), "[refresh: %3ds]", interval);
		mvprintw(1, dim_x - strlen(tstr), tstr);

		if (statvfs(fs_config.data_dir, &stv) == -1)
			err(1, "statvfs");
		used = (double) (stv.f_blocks - stv.f_bfree) *
		    stv.f_bsize / (2UL << 29UL);
		total = (double) stv.f_blocks * stv.f_bsize / (2UL << 29UL);

		if (mgr_counters_now[MGR_COUNTER_BACKEND_HINTS] +
		    mgr_counters_now[MGR_COUNTER_BACKEND_GETS] == 0) {
			mvprintw(3, 17, "%.1f / %.1f GiB (%.1f%%)",
			    used, total, used * 100.0 / total);
		} else {
			hit_ratio =
			    100.0 *
			    mgr_counters_now[MGR_COUNTER_BACKEND_HINTS] /
			    (mgr_counters_now[MGR_COUNTER_BACKEND_HINTS] +
			     mgr_counters_now[MGR_COUNTER_BACKEND_GETS]);
			mvprintw(3, 17, "%.1f / %.1f GiB (%.1f%%),"
			    " %.1f%% slab hit ratio\n",
			    used, total, used * 100.0 / total, hit_ratio);
		}
		/*
		 * Convert values to GiB
		 */
		used = (double) (fs_info.stats.f_blocks -
		    fs_info.stats.f_bfree) *
		    fs_info.stats.f_bsize / (2UL << 29UL);
		total = (double) fs_info.stats.f_blocks *
		    fs_info.stats.f_bsize / (2UL << 29UL);
		mvprintw(4, 17, "%.1f / %.1f GiB (%.1f%%)\n",
		    used, total, used * 100.0 / total);

		row = stats_row;
		mvprintw(row++, col1, "%8.1f/s",
		    ((double)counters_delta[COUNTER_FS_READ]) / delta_s);
		mvprintw(row++, col1, "%8.1f/s",
		    counters_delta[COUNTER_READ_BYTES] /
		    1024.0 / 1024.0 / delta_s);
		mvprintw(row++, col1, "%8.1f/s",
		    counters_delta[COUNTER_FS_WRITE] / delta_s);
		mvprintw(row++, col1, "%8.1f/s",
		    counters_delta[COUNTER_WRITE_BYTES] /
		    1024.0 / 1024.0 / delta_s);
		mvprintw(row++, col1, "%8.1f/s",
		    mgr_counters_delta[MGR_COUNTER_BACKEND_IN_BYTES] /
		    1024.0 / 1024.0 / delta_s);
		mvprintw(row++, col1, "%8.1f/s",
		    mgr_counters_delta[MGR_COUNTER_BACKEND_OUT_BYTES] /
		    1024.0 / 1024.0 / delta_s);

		row++;
		mvprintw(row++, col1, "%8.1f/s",
		    counters_delta[COUNTER_FS_GETATTR] / delta_s);
		mvprintw(row++, col1, "%8.1f/s",
		    counters_delta[COUNTER_FS_SETATTR] / delta_s);
		mvprintw(row++, col1, "%8.1f/s",
		    counters_delta[COUNTER_FS_OPENDIR] / delta_s);
		mvprintw(row++, col1, "%8.1f/s",
		    counters_delta[COUNTER_FS_READDIR] / delta_s);
		mvprintw(row++, col1, "%8.1f/s",
		    counters_delta[COUNTER_FS_RELEASEDIR] / delta_s);
		mvprintw(row++, col1, "%8.1f/s",
		    counters_delta[COUNTER_FS_OPEN] / delta_s);
		mvprintw(row++, col1, "%8.1f/s",
		    counters_delta[COUNTER_FS_FLUSH] / delta_s);
		mvprintw(row++, col1, "%8.1f/s",
		    counters_delta[COUNTER_FS_FORGET] / delta_s);
		mvprintw(row++, col1, "%8.1f/s",
		    counters_delta[COUNTER_FS_FORGET_MULTI] / delta_s);
		mvprintw(row++, col1, "%8.1f/s",
		    counters_delta[COUNTER_FS_LOOKUP] / delta_s);
		mvprintw(row++, col1, "%8.1f/s",
		    counters_delta[COUNTER_FS_MKDIR] / delta_s);

		row = stats_row;
		mvprintw(row++, col2, "%8.1f/s",
		    counters_delta[COUNTER_FS_RMDIR] / delta_s);
		mvprintw(row++, col2, "%8.1f/s",
		    counters_delta[COUNTER_FS_UNLINK] / delta_s);
		mvprintw(row++, col2, "%8.1f/s",
		    counters_delta[COUNTER_FS_MKNOD] / delta_s);
		mvprintw(row++, col2, "%8.1f/s",
		    counters_delta[COUNTER_FS_FALLOCATE] / delta_s);
		mvprintw(row++, col2, "%8.1f/s",
		    counters_delta[COUNTER_FS_FSYNC] / delta_s);
		mvprintw(row++, col2, "%8.1f/s",
		    counters_delta[COUNTER_FS_FSYNCDIR] / delta_s);
		mvprintw(row++, col2, "%8.1f/s",
		    counters_delta[COUNTER_FS_LINK] / delta_s);
		mvprintw(row++, col2, "%8.1f/s",
		    counters_delta[COUNTER_FS_SYMLINK] / delta_s);
		mvprintw(row++, col2, "%8.1f/s",
		    counters_delta[COUNTER_FS_READLINK] / delta_s);
		mvprintw(row++, col2, "%8.1f/s",
		    counters_delta[COUNTER_FS_RENAME] / delta_s);
		mvprintw(row++, col2, "%8.1f/s",
		    counters_delta[COUNTER_FS_STATFS] / delta_s);

		row++;
		mvprintw(row++, col2, "%6lu",
		    counters_now[COUNTER_FS_DELAYED_TRUNCATE]);
		mvprintw(row++, col2, "%6lu",
		    counters_now[COUNTER_N_OPEN_SLABS]);
		mvprintw(row++, col2, "%6lu",
		    counters_now[COUNTER_N_OPEN_INODES]);
		mvprintw(row++, col2, "%8.1f/s",
		    counters_now[COUNTER_SLABS_PURGED] / delta_s);
		mvprintw(row++, col2, "%6lu",
		    mgr_counters_now[MGR_COUNTER_SLABS_PURGED]);
		mvprintw(row++, col2, "%6lu", counters_now[COUNTER_FS_ERROR]);
		mvprintw(row++, col2, "%6lu",
		    mgr_counters_now[MGR_COUNTER_CLAIM_CONTENTION]);

		refresh();
	}
end:
	endwin();
	return 0;
}

int
slabdb_print(const struct slab_key *sk, const struct slabdb_val *v, void *data)
{
	struct slabdb_entry **e = (struct slabdb_entry **)data;
	struct slabdb_entry  *e_new;

	if ((e_new = malloc(sizeof(struct slabdb_entry))) == NULL) {
		warn("malloc");
		slabdb_shutdown();
		exit(1);
	}

	memcpy(&e_new->sk, sk, sizeof(struct slab_key));
	memcpy(&e_new->sv, v, sizeof(struct slabdb_val));
	e_new->next = *e;
	*e = e_new;

	return 0;
}

int
slabdb(int argc, char **argv)
{
	struct xerr          e;
	struct fs_info       fs_info;
	int                  r;
	struct slabdb_entry *head, *entry;
	char                 u[37];

	if (fs_info_inspect(&fs_info, xerrz(&e)) == -1) {
		xerr_print(&e);
		exit(1);
	}

	if (slabdb_init(fs_info.instance_id, xerrz(&e)) == -1) {
		xerr_print(&e);
		exit(1);
	}

	r = slabdb_loop(&slabdb_print, &head, xerrz(&e));
	if (r == -1) {
		slabdb_shutdown();
		xerr_print(&e);
		exit(1);
	}

	for (entry = head; entry != NULL; entry = entry->next) {
		uuid_unparse(entry->sv.owner, u);
		printf("%s: sk=%lu/%lu, rev=%lu, header_crc=%u, uuid=%s,"
		    " last_claimed=%lu.%lu, flags=%u, truncate_offset=%lu\n",
		    __func__,
		    entry->sk.ino, entry->sk.base,
		    entry->sv.revision, entry->sv.header_crc, u,
		    entry->sv.last_claimed.tv_sec,
		    entry->sv.last_claimed.tv_nsec,
		    entry->sv.flags,
		    entry->sv.truncate_offset);
	}

	slabdb_shutdown();

	return 0;
}

/*
 * Claim and unclaim a slab; useful to attempt to get it locally.
 * Exit status is 2 if the error was that the slab is locked.
 */
int
claim(int argc, char **argv)
{
	ino_t          ino;
	off_t          base;
	int            mgr, fd;
	struct mgr_msg m;
	struct oslab   b;
	struct xerr    e;
	uint32_t       oflags = OSLAB_NOCREATE|OSLAB_NONBLOCK|OSLAB_NOHINT;

	if (argc < 2) {
		usage();
		exit(1);
	}

	if ((ino = strtoull(argv[0], NULL, 10)) == ULLONG_MAX)
		errx(1, "inode provided is invalid");
	if ((base = strtoull(argv[1], NULL, 10)) == ULLONG_MAX)
		errx(1, "base provided is invalid");

	if (argc > 2) {
		if (strcmp(argv[2], "create") == 0)
			oflags &= ~OSLAB_NOCREATE;
	}

	if ((mgr = mgr_connect(1, xerrz(&e))) == -1)
		goto fail;

	m.m = MGR_MSG_CLAIM;
	m.v.claim.key.ino = ino;
	m.v.claim.key.base = base;
	m.v.claim.oflags = oflags;

	if (mgr_send(mgr, -1, &m, xerrz(&e)) == -1)
		goto fail;

	if (mgr_recv(mgr, &fd, &m, xerrz(&e)) == -1)
		goto fail;

	if (m.m == MGR_MSG_CLAIM_NOENT)
		errx(1, "failed to claim slab for inode %lu "
		    "at base %lu: no such slab", ino, base);
	else if (m.m == MGR_MSG_CLAIM_ERR) {
		if (xerr_is(&m.v.err, XLOG_APP, XLOG_BUSY)) {
			errx(2, "%s: could not claim slab; already locked",
			    __func__);
		}
		xerr_print(&m.v.err);
		exit(1);
	} else if (m.m != MGR_MSG_CLAIM_OK)
		errx(1, "failed to claim slab for inode %lu "
		    "at base %lu: resp=%d", ino, base, m.m);

	b.fd = fd;

	if (slab_read_hdr(&b, xerrz(&e)) == -1)
		goto fail;

	if (b.hdr.v.f.slab_version != SLAB_VERSION)
		errx(1, "unrecognized data format version: %u",
		    b.hdr.v.f.slab_version);

	if (verify_checksum(b.fd, &b.hdr, xerrz(&e)) == -1)
		goto fail;

	print_slab_hdr(&b.hdr, NULL);

	m.m = MGR_MSG_UNCLAIM;
	memcpy(&m.v.unclaim.key, &b.hdr.v.f.key, sizeof(struct slab_key));
	if (mgr_send(mgr, b.fd, &m, xerrz(&e)) == -1)
		goto fail;

	if (mgr_recv(mgr, NULL, &m, xerrz(&e)) == -1)
		goto fail;

	if (m.m == MGR_MSG_UNCLAIM_ERR) {
		xerr_print(&m.v.err);
		exit(1);
	} else if (m.m != MGR_MSG_UNCLAIM_OK)
		errx(1, "%s: mgr_recv: unexpected response: %d",
		    __func__, m.m);

	close(b.fd);
	close(mgr);
	return 0;
fail:
	xerr_print(&e);
	exit(1);
}

int
write_dir(int mgr, char *data, struct inode *inode)
{
	ssize_t        r, wsize;
	int            fd;
	struct mgr_msg m;
	struct oslab   b;
	struct xerr    e = XLOG_ERR_INITIALIZER;
	off_t          offset;

	if (inode->v.f.size < INODE_INLINE_BYTES) {
		memcpy(inode_data(inode), data, inode->v.f.size);
		bzero(inode_data(inode) + inode->v.f.size,
		    INODE_INLINE_BYTES - inode->v.f.size);
		offset = inode->v.f.size;
	} else {
		memcpy(inode_data(inode), data, INODE_INLINE_BYTES);
		offset = INODE_INLINE_BYTES;
	}

	while (offset <= inode->v.f.size &&
	    inode->v.f.size > INODE_INLINE_BYTES) {
		bzero(&m, sizeof(m));
		m.m = MGR_MSG_CLAIM;
		slab_key(&m.v.claim.key, inode->v.f.inode, offset);
		m.v.claim.oflags = OSLAB_NOCREATE|OSLAB_EPHEMERAL|OSLAB_NOHINT;

		if (mgr_send(mgr, -1, &m, xerrz(&e)) == -1) {
			xerr_print(&e);
			goto fail;
		}

		if (mgr_recv(mgr, &fd, &m, xerrz(&e)) == -1) {
			xerr_print(&e);
			goto fail;
		}

		if (m.m == MGR_MSG_CLAIM_NOENT) {
			continue;
		} else if (m.m == MGR_MSG_CLAIM_ERR) {
			xerr_print(&m.v.err);
			goto fail;
		} else if (m.m != MGR_MSG_CLAIM_OK) {
			warnx("mgr_recv: unexpected response: %d", m.m);
			goto fail;
		}

		bzero(&b, sizeof(b));
		b.fd = fd;
		b.dirty = 1;
		b.oflags = OSLAB_NOCREATE|OSLAB_EPHEMERAL|OSLAB_NOHINT;

		if (slab_read_hdr(&b, xerrz(&e)) == -1) {
			xerr_print(&e);
			goto fail;
		}

		if (b.hdr.v.f.slab_version != SLAB_VERSION) {
			warnx("unrecognized data format version: %u",
			    b.hdr.v.f.slab_version);
			goto fail;
		}

		if (verify_checksum(b.fd, &b.hdr, xerrz(&e)) == -1) {
			xerr_print(&e);
			goto fail;
		}

		if (offset < inode->v.f.size) {
			if (inode->v.f.size - offset > slab_get_max_size() -
			    (offset % slab_get_max_size()))
				wsize = slab_get_max_size() -
				    (offset % slab_get_max_size());
			else
				wsize = inode->v.f.size - offset;
			if ((r = slab_write(&b, data + offset,
			    offset % slab_get_max_size(),
			    wsize, xerrz(&e))) == -1) {
				xerr_print(&e);
				goto fail;
			}
			offset += r;
			if (slab_truncate(&b,
			    offset % slab_get_max_size(), xerrz(&e)) == -1) {
				xerr_print(&e);
				goto fail;
			}
		} else {
			if (slab_unlink(&b, xerrz(&e)) == -1) {
				xerr_print(&e);
				goto fail;
			}
		}
		offset += slab_get_max_size() -
		    (offset % slab_get_max_size());

		m.m = MGR_MSG_UNCLAIM;
		memcpy(&m.v.unclaim.key, &b.hdr.v.f.key,
		    sizeof(struct slab_key));
		if (mgr_send(mgr, b.fd, &m, xerrz(&e)) == -1) {
			xerr_print(&e);
			goto fail;
		}

		if (mgr_recv(mgr, NULL, &m, xerrz(&e)) == -1) {
			xerr_print(&e);
			goto fail;
		}

		if (m.m == MGR_MSG_UNCLAIM_ERR) {
			xerr_print(&m.v.err);
			goto fail;
		} else if (m.m != MGR_MSG_UNCLAIM_OK) {
			warnx("%s: mgr_recv: unexpected response: %d",
			    __func__, m.m);
			goto fail;
		}

		close(b.fd);
	}

	bzero(&m, sizeof(m));
	m.m = MGR_MSG_CLAIM;
	slab_key(&m.v.claim.key, 0, inode->v.f.inode);
	m.v.claim.oflags = OSLAB_NOCREATE|OSLAB_EPHEMERAL|OSLAB_NOHINT;

	if (mgr_send(mgr, -1, &m, xerrz(&e)) == -1) {
		xerr_print(&e);
		return -1;
	}

	if (mgr_recv(mgr, &fd, &m, xerrz(&e)) == -1) {
		xerr_print(&e);
		return -1;
	}

	if (m.m == MGR_MSG_CLAIM_ERR) {
		xerr_print(&m.v.err);
		return -1;
	} else if (m.m != MGR_MSG_CLAIM_OK) {
		warnx("mgr_recv: unexpected response: %d", m.m);
		return -1;
	}

	bzero(&b, sizeof(b));
	b.fd = fd;
	b.dirty = 1;
	b.oflags = OSLAB_NOCREATE|OSLAB_EPHEMERAL|OSLAB_NOHINT;

	if (slab_read_hdr(&b, xerrz(&e)) == -1) {
		xerr_print(&e);
		goto fail;
	}

	if (b.hdr.v.f.slab_version != SLAB_VERSION) {
		warnx("unrecognized data format version: %u",
		    b.hdr.v.f.slab_version);
		goto fail;
	}

	if (verify_checksum(b.fd, &b.hdr, xerrz(&e)) == -1) {
		xerr_print(&e);
		goto fail;
	}

	if ((r = slab_write(&b, inode,
	    (inode->v.f.inode - b.hdr.v.f.key.base) * sizeof(struct inode),
	    sizeof(struct inode), xerrz(&e))) == -1) {
		xerr_print(&e);
		goto fail;
	}
	if (r < sizeof(struct inode))
		xlog(LOG_ERR, NULL, "%s: short write on inode table",
		    __func__);

	m.m = MGR_MSG_UNCLAIM;
	memcpy(&m.v.unclaim.key, &b.hdr.v.f.key,
	    sizeof(struct slab_key));
	if (mgr_send(mgr, b.fd, &m, xerrz(&e)) == -1) {
		xerr_print(&e);
		goto fail;
	}

	if (mgr_recv(mgr, NULL, &m, xerrz(&e)) == -1) {
		xerr_print(&e);
		goto fail;
	}

	if (m.m == MGR_MSG_UNCLAIM_ERR) {
		xerr_print(&m.v.err);
		goto fail;
	} else if (m.m != MGR_MSG_UNCLAIM_OK) {
		warnx("%s: mgr_recv: unexpected response: %d",
		    __func__, m.m);
		goto fail;
	}

	close(b.fd);
	return 0;
fail:
	close(b.fd);
	return -1;
}

/*
 * Load all of a directory inode's data from
 * all slabs tied to that inode.
 */
int
load_dir(int mgr, char **data, struct inode *inode, int *dirty)
{
	off_t           r_offset, w_offset, slab_sz, dir_sz;
	ssize_t         r;
	ino_t           ino = inode->v.f.inode;
	int             fd;
	struct mgr_msg  m;
	struct oslab   *b;
	char            path[PATH_MAX];
	char           *d;
	struct xerr     e = XLOG_ERR_INITIALIZER;

	// TODO: properly return an error, don't err()

	if ((d = malloc(inode->v.f.size)) == NULL)
		err(1, "malloc");

	r_offset = (inode->v.f.size < INODE_INLINE_BYTES)
	    ? inode->v.f.size
	    : INODE_INLINE_BYTES;
	w_offset = r_offset;
	dir_sz = inode->v.f.size;

	memcpy(d, inode_data(inode), r_offset);

	if (((struct dir_hdr *)d)->dirinode_format > DIRINODE_FORMAT ||
	    ((struct dir_hdr *)d)->dirinode_format == 0) {
		warnx("%s: unsupposed dirinode format %u",
		    __func__, ((struct dir_hdr *)d)->dirinode_format);
		free(d);
		return -1;
	}

	if (w_offset >= inode->v.f.size) {
		*data = d;
		return 0;
	}

	for (; r_offset < dir_sz; r_offset += r) {
		bzero(&m, sizeof(m));
		m.m = MGR_MSG_CLAIM;
		slab_key(&m.v.claim.key, ino, r_offset);
		m.v.claim.oflags = OSLAB_NOCREATE|OSLAB_EPHEMERAL|OSLAB_NOHINT;

		if (mgr_send(mgr, -1, &m, &e) == -1) {
			xerr_print(&e);
			goto fail;
		}

		if (mgr_recv(mgr, &fd, &m, &e) == -1) {
			xerr_prepend(&e, __func__);
			xerr_print(&e);
			goto fail;
		}

		if (m.m == MGR_MSG_CLAIM_ERR) {
			memcpy(&e, &m.v.err, sizeof(struct xerr));
			xerr_prepend(&e, __func__);
			xerr_print(&e);
			goto fail;
		} else if (m.m != MGR_MSG_CLAIM_OK) {
			warnx("%s: mgr_recv: unexpected response: %d",
			    __func__, m.m);
			goto fail;
		}

		if ((b = malloc(sizeof(struct oslab))) == NULL)
			err(1, "malloc");
		bzero(b, sizeof(struct oslab));

		b->fd = fd;
		if (slab_read_hdr(b, &e) == -1) {
			xerr_print(&e);
			goto fail_free_slab;
		}

		if (b->hdr.v.f.slab_version != SLAB_VERSION) {
			warnx("unrecognized data format version: %u",
			    b->hdr.v.f.slab_version);
			goto fail_free_slab;
		}

		if (verify_checksum(b->fd, &b->hdr, &e) == -1) {
			xerr_print(&e);
			goto fail_free_slab;
		}

		if ((slab_sz = slab_size(b, &e)) == ULONG_MAX) {
			xerr_print(&e);
			goto fail_free_slab;
		}

		if ((b->hdr.v.f.flags & SLAB_REMOVED) && slab_sz > 0) {
			warnx("slab %s is removed, but size is larger than %lu",
			    path, sizeof(struct slab_hdr));
			goto fail_free_slab;
		}

		if ((r = slab_read(b, d + w_offset,
		    r_offset % slab_get_max_size(),
		    ((dir_sz - w_offset < slab_get_max_size())
		    ? dir_sz - w_offset
		    : slab_get_max_size()), &e)) == -1) {
			xerr_print(&e);
			goto fail_free_slab;
		}
		w_offset += r;

		bzero(&m, sizeof(m));
		m.m = MGR_MSG_UNCLAIM;
		memcpy(&m.v.unclaim.key, &b->hdr.v.f.key,
		    sizeof(struct slab_key));
		if (mgr_send(mgr, b->fd, &m, &e) == -1) {
			xerr_print(&e);
			goto fail_free_slab;
		}

		if (mgr_recv(mgr, NULL, &m, &e) == -1) {
			xerr_prepend(&e, __func__);
			xerr_print(&e);
			goto fail_free_slab;
		}

		if (m.m == MGR_MSG_UNCLAIM_ERR) {
			memcpy(&e, &m.v.err, sizeof(struct xerr));
			xerr_prepend(&e, __func__);
			xerr_print(&e);
			goto fail_free_slab;
		} else if (m.m != MGR_MSG_UNCLAIM_OK) {
			warnx("%s: mgr_recv: unexpected response: %d",
			    __func__, m.m);
			goto fail_free_slab;
		}

		close(b->fd);
		free(b);
		if (r == 0)
			break;
	}

	if (r_offset < dir_sz) {
		warnx("inode %lu is truncated; data might be incomplete", ino);
		return -1;
	}
	*data = d;
	return 0;
fail_free_slab:
	close(b->fd);
	free(b);
fail:
	free(d);
	*data = NULL;
	return -1;
}

int
show_inode(int argc, char **argv)
{
	ino_t            ino;
	struct inode     inode;
	off_t            i;
	struct xerr      e = XLOG_ERR_INITIALIZER;
	struct slab_hdr  hdr;
	void            *data;
	size_t           slab_sz;
	char             path[PATH_MAX];
	struct slab_key  sk;
	int              mgr;

	if (argc < 1) {
		usage();
		exit(1);
	}

	if ((ino = strtoull(argv[0], NULL, 10)) == ULLONG_MAX)
		errx(1, "inode provided is invalid");

	if ((mgr = mgr_connect(1, &e)) == -1) {
		xerr_print(&e);
		exit(1);
	}

	if (inode_inspect(mgr, ino, &inode, 1, &e) == -1) {
		if (xerr_is(&e, XLOG_FS, ENOENT))
			errx(1, "inode is not allocated");
		xerr_print(&e);
		exit(1);
	}

	printf("inode: %lu\n", ino);
	print_inode(&inode, 0);

	for (i = INODE_INLINE_BYTES; i < inode.v.f.size;
	    i += slab_get_max_size()) {
		if (slab_path(path, sizeof(path),
		    slab_key(&sk, ino, i), 1, &e) == -1) {
			xerr_print(&e);
			exit(1);
		}

		if ((data = slab_inspect(mgr, slab_key(&sk, ino, i),
		    OSLAB_NOCREATE|OSLAB_EPHEMERAL|OSLAB_NOHINT,
		    &hdr, &slab_sz, &e)) == NULL) {
			xerr_print(&e);
			exit(1);
		}
		free(data);

		printf("  slab: %s\n", path);
		printf("    hdr:\n");
		printf("      slab_version: %u\n",
		    hdr.v.f.slab_version);
		printf("      checksum:     %u\n", hdr.v.f.checksum);
		printf("      revision:     %lu\n", hdr.v.f.revision);
		printf("      flags:       ");
		if (hdr.v.f.flags & SLAB_DIRTY)
			printf(" dirty");
		if (hdr.v.f.flags & SLAB_REMOVED)
			printf(" removed");
		printf("\n");
		printf("      data size:    %lu\n", slab_sz);
		printf("      sparse:       %s\n",
		    (slab_sz < (inode.v.f.size % slab_get_max_size()))
		    ? "yes" : "no");
		printf("\n");
	}

	close(mgr);

	if (i < inode.v.f.size)
		warnx("  ** inode is truncated; data might be incomplete");
	return 0;
}

int
show_dir(int argc, char **argv)
{
	struct slab_hdr      hdr;
	int                  n, mgr;
	off_t                i;
	ino_t                ino;
	struct inode         inode;
	char                *data;
	void                *slab_data;
	size_t               slab_sz;
	struct slab_key      sk;
	struct dir_entry_v1 *de;
	struct xerr          e;

	if (argc < 1) {
		usage();
		exit(1);
	}

	if ((ino = strtoull(argv[0], NULL, 10)) == ULLONG_MAX)
		errx(1, "inode provided is invalid");

	if (ino < 1)
		errx(1, "inode must be greater than zero");

	if ((mgr = mgr_connect(1, xerrz(&e))) == -1) {
		xerr_print(&e);
		exit(1);
	}

	if (inode_inspect(mgr, ino, &inode, 1, xerrz(&e)) == -1) {
		if (xerr_is(&e, XLOG_FS, ENOENT))
			errx(1, "inode is not allocated");
		xerr_print(&e);
		exit(1);
	}

	if ((inode.v.f.mode & S_IFMT) != S_IFDIR) {
		printf("inode %lu is not a directory; use 'slab' to see "
		    "inode details\n", ino);
		return 0;
	}

	if ((data = calloc(inode.v.f.size, 1)) == NULL)
		err(1, "calloc");

	i = (inode.v.f.size < INODE_INLINE_BYTES)
	    ?  inode.v.f.size
	    : INODE_INLINE_BYTES;

	memcpy(data, inode_data(&inode), i);

	printf("inode: %lu\n", ino);

	for (; i < inode.v.f.size; i += slab_sz) {
		if ((slab_data = slab_inspect(mgr, slab_key(&sk, ino, i),
		    OSLAB_NOCREATE|OSLAB_EPHEMERAL|OSLAB_NOHINT|OSLAB_NONBLOCK,
		    &hdr, &slab_sz, &e)) == NULL) {
			if (xerr_is(&e, XLOG_APP, XLOG_NOSLAB)) {
				xerrz(&e);
				break;
			}
			xerr_print(&e);
			exit(1);
		}

		if (slab_sz == 0)
			break;

		printf("  slab:\n");
		printf("    hdr:\n");
		printf("      version:    %u\n", hdr.v.f.slab_version);
		printf("      checksum:   %u\n", hdr.v.f.checksum);
		printf("      revision:   %lu\n", hdr.v.f.revision);
		printf("      flags:     ");
		if (hdr.v.f.flags & SLAB_DIRTY)
			printf(" dirty");
		if (hdr.v.f.flags & SLAB_REMOVED)
			printf(" removed");
		printf("\n\n");

		memcpy(data + i, slab_data + i, slab_sz - i);
		free(slab_data);
	}

	close(mgr);

	if (i < inode.v.f.size)
		warnx("  ** inode is truncated; data might be incomplete");
	printf("  dirents:\n\n");

	de = (struct dir_entry_v1 *)(data + sizeof(struct dir_hdr));

	for (n = 0; i > 0; i -= sizeof(struct dir_entry_v1), de++, n++) {
		printf("    name:        %s\n", de->name);
		printf("    offset:      %lu\n", (char *)de - data);
		printf("    inode:       %lu\n", de->inode);
		printf("    next offset: %lu\n\n", de->next);
	}

	printf("  Total dirents: %d\n", n);
	free(data);

	return 0;
}

static void
print_slab_hdr(struct slab_hdr *hdr, const uint32_t *crc)
{
	char     crc_str[32] = "";
	uint32_t header_crc = crc32_z(0L, (Bytef *)hdr,
	    sizeof(struct slab_hdr));

	if (crc != NULL)
		snprintf(crc_str, sizeof(crc_str), " (actual: %u)", *crc);

	printf("  hdr (CRC %u):\n", header_crc);
	printf("    slab_version:    %u\n", hdr->v.f.slab_version);
	printf("    checksum:        %u%s\n", hdr->v.f.checksum, crc_str);
	printf("    revision:        %lu\n", hdr->v.f.revision);
	printf("    inode / base:    %lu / %lu%s\n", hdr->v.f.key.ino,
	    hdr->v.f.key.base, (hdr->v.f.key.ino) ? "" : " (itbl)");
	printf("    flags:          ");
	if (hdr->v.f.flags & SLAB_DIRTY)
		printf(" dirty");
	if (hdr->v.f.flags & SLAB_REMOVED)
		printf(" removed");
	printf("\n\n");
}

static void
print_inode(struct inode *inode, int is_free)
{
	printf("    inode:  %lu %s\n", inode->v.f.inode,
	    (is_free) ?  "(free)" : "(allocated)");
	printf("    dev:    %lu\n", inode->v.f.dev);

	printf("    mode:   %04o ", (inode->v.f.mode & ~S_IFMT));
	switch (inode->v.f.mode & S_IFMT) {
	case S_IFBLK: printf("(block device)\n"); break;
	case S_IFCHR: printf("(character device)\n"); break;
	case S_IFDIR: printf("(directory)\n"); break;
	case S_IFIFO: printf("(FIFO/pipe)\n"); break;
	case S_IFLNK: printf("(symlink)\n"); break;
	case S_IFREG: printf("(regular file)\n"); break;
	case S_IFSOCK: printf("(socket)\n"); break;
	default: printf("(unknown type?)\n"); break;
	}

	printf("    nlink:  %lu\n", inode->v.f.nlink);
	printf("    uid:    %u\n", inode->v.f.uid);
	printf("    gid:    %u\n", inode->v.f.gid);
	printf("    rdev:   %lu\n", inode->v.f.rdev);
	printf("    size:   %lu\n", inode->v.f.size);
	printf("    blocks: %lu\n", inode->v.f.blocks);
	printf("    atime:  %lu.%.9lu\n",
	    inode->v.f.atime.tv_sec,
	    inode->v.f.atime.tv_nsec);
	printf("    mtime:  %lu.%.9lu\n",
	    inode->v.f.mtime.tv_sec,
	    inode->v.f.mtime.tv_nsec);
	printf("    ctime:  %lu.%.9lu\n",
	    inode->v.f.ctime.tv_sec,
	    inode->v.f.ctime.tv_nsec);
	printf("    gen:    %lu\n", inode->v.f.generation);
	printf("\n");
}

int
show_slab(int argc, char **argv)
{
	struct oslab          b;
	struct slab_itbl_hdr *itbl_hdr;
	int                   fd, i;
	ssize_t               r;
	ino_t                 ino;
	struct inode          inode;
	uint32_t              crc;
	struct xerr           e;

	if (argc < 1) {
		usage();
		exit(1);
	}

	if ((fd = open(argv[0], O_RDONLY)) == -1)
		err(1, "open");

	if ((r = read(fd, &b.hdr, sizeof(b.hdr))) == -1)
		err(1, "read");
	if (r < sizeof(b.hdr))
		errx(1, "%s: short read on itbl header", __func__);
	if (compute_checksum(fd, &crc, xerrz(&e)) == -1) {
		xerr_print(&e);
		exit(1);
	}

	printf("slab: %s\n", argv[0]);
	print_slab_hdr(&b.hdr, &crc);

	if (!b.hdr.v.f.key.ino) {
		itbl_hdr = (struct slab_itbl_hdr *)b.hdr.v.padding.data;

		printf("  itbl hdr:\n");
		printf("       base:    %lu\n", b.hdr.v.f.key.base);
		printf("       n_free:  %u\n", itbl_hdr->n_free);
		printf("       bitmap:  (0000)");
		for (i = 0; i < slab_inode_max() / 32; i++) {
			printf(" %08x", itbl_hdr->bitmap[i]);
			if (i > 0 && (i + 1) % 4 == 0 &&
			    i < slab_inode_max() / 32 - 1)
				printf("\n                (%04d)", i + 1);
		}
		printf("\n\n");

		printf("  inodes:\n");
		if (lseek(fd, 0, SEEK_SET) == -1)
			err(1, "lseek");
		for (ino = b.hdr.v.f.key.base;
		    ino < b.hdr.v.f.key.base + slab_inode_max(); ino++) {
			if ((r = read(fd, &inode, sizeof(inode))) == -1)
				err(1, "read");
			else if (r == 0)
				break;
			else if (r < sizeof(inode))
				errx(1, "%s: short read on inode", __func__);
			print_inode(&inode, slab_itbl_is_free(&b, ino));
		}
	}

	close(fd);
	return 0;
}

int
main(int argc, char **argv)
{
	struct subc    *c;
	struct xerr     e;
	char            opt;
	struct fs_info  fs_info;
	char            cfg[PATH_MAX];

	if (getenv("POTATOFS_CONFIG"))
		fs_config.cfg_path = getenv("POTATOFS_CONFIG");

	while ((opt = getopt(argc, argv, "hvd:D:w:W:e:fc:p:s:T:")) != -1) {
		switch (opt) {
			case 'h':
				usage();
				exit(0);
			case 'c':
				strlcpy(cfg, optarg, sizeof(cfg));
				fs_config.cfg_path = cfg;
				break;
			default:
				usage();
				exit(1);
		}
	}

	if (optind >= argc) {
		usage();
		return 1;
	}

	config_read();

	if ((log_locale = newlocale(LC_CTYPE_MASK, "C", 0)) == 0)
		err(1, "newlocale");

	for (c = subcommands; c->fn; c++) {
		if (strcmp(c->name, argv[optind]) == 0) {
			optind++;
			if (c->clean_warning) {
				if (fs_info_inspect(&fs_info, xerrz(&e)) == -1) {
					xerr_print(&e);
					exit(1);
				}
				if (!fs_info.clean)
					fprintf(stderr, "%s", clean_warning);
			}
			return c->fn(argc - optind, argv + optind);
		}
	}

	usage();
	return 1;
}
