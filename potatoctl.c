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
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <jansson.h>
#include "counters.h"
#include "slabs.h"
#include "fs_info.h"
#include "inodes.h"
#include "dirinodes.h"
#include "exlog.h"

static int  show_slab(int, char **);
static int  show_dir(int, char **);
static int  show_inode(int, char **);
static int  fsck(int, char **);
static int  top(int, char **);
static void usage();
static int  load_dir(char **, struct inode *);
static void print_inode(struct inode *, int);

struct subc {
	char *name;
	int  (*fn)(int argc, char **argv);
} subcommands[] = {
	{ "slab", &show_slab },
	{ "dir", &show_dir },
	{ "inode", &show_inode },
	{ "top", &top },
	{ "fsck", &fsck },
	{ "", NULL }
};

struct fsck_stats {
	uint64_t n_inodes;
	uint64_t n_dirs;
	uint64_t n_dirents;
	uint64_t errors;
};

void
usage()
{
	fprintf(stderr, "Usage: potatoctl <potatofs data path> <subcommand> <args...>\n");
	fprintf(stderr, "           slab  <slab file>\n");
	fprintf(stderr, "           dir   <dir inode#>\n");
	fprintf(stderr, "           top   <delay>\n");
	fprintf(stderr, "           fsck\n");
}

extern struct counter counters[];
extern size_t         slab_max_size;
extern char           datadir[];
extern locale_t       log_locale;

struct fs_info        fs_info;

void
read_metrics(const char *counters_file, uint64_t *counters_now)
{
	FILE         *f;
	json_error_t  error;
	json_t       *stats, *s;
	int           c, fd;

	if ((fd = open(counters_file, O_RDONLY)) == -1)
		err(1, "open");
	if (flock(fd, LOCK_SH) == -1)
		err(1, "flock");
	if ((f = fdopen(fd, "r")) == NULL)
		err(1, "fopen");
	stats = json_loadf(f, JSON_REJECT_DUPLICATES, &error);
	if (stats == NULL)
		errx(1, "JSON error: %s, line %d", error.text, error.line);

	for (c = 0; c < COUNTER_LAST; c++) {
		if ((s = json_object_get(stats, counters[c].desc)))
			counters_now[c] = json_integer_value(s);
		else
			counters_now[c] = 0;
	}
	if (json_object_clear(stats) == -1)
		errx(1, "failed to clear JSON");
	fclose(f);
}

int
valid_inode(ino_t ino)
{
	struct inode     inode;
	struct exlog_err e = EXLOG_ERR_INITIALIZER;

	if (inode_inspect(ino, &inode, &e) == -1) {
		exlog_prt(&e);
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
fsck_inode(ino_t ino, int unallocated, struct inode *inode,
    struct fsck_stats *stats)
{
	struct dir_entry *de;
	char             *dir;

	if (unallocated) {
		if (inode == NULL) {
			return 0;
		} else if (inode->v.f.nlink > 0) {
			warnx("leaked inode %lu; bitmap says it's free, "
			    "but nlink is %lu", ino, inode->v.f.nlink);
			stats->errors++;
			return -1;
		}
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
	}

	stats->n_inodes++;

	if (!(inode->v.f.mode & S_IFDIR))
		return 0;

	stats->n_dirs++;

	if (load_dir(&dir, inode) == -1) {
		stats->errors++;
		return -1;
	}

	for (de = (struct dir_entry *)((char *)dir);
	    (char *)de < (dir + inode->v.f.size); de++) {
		if (de->inode > 0) {
			stats->n_dirents++;
			if (!valid_inode(ino))
				stats->errors++;
		}
		if (de->next > 0 && de->next <= ((char *)de - dir)) {
			stats->errors++;
			warnx("invalid chaining in directory "
			    "inode %lu; entry %s at offset %lu",
			    ino, de->name, (char *)de - dir);
		}
	}
	free(dir);
	return 0;
}

int
fsck(int argc, char **argv)
{
	ino_t                 ino;
	char                  itbl_path[PATH_MAX], itbl[PATH_MAX];
	DIR                  *itbl_dir;
	struct dirent        *d;
	int                   slab_end = 0, is_free;
	ssize_t               r;
	struct oslab         *b;
	struct inode          inode;
	struct slab_itbl_hdr *itbl_hdr;
	char                 *end;
	struct exlog_err      e = EXLOG_ERR_INITIALIZER;
	struct fsck_stats     stats = {0, 0, 0, 0};
	size_t                n_free;

	if (snprintf(itbl_path, sizeof(itbl_path), "%s/%s", datadir,
	    ITBL_DIR) >= sizeof(itbl_path)) {
		stats.errors++;
		warnx("%s: potatofs base path too long", __func__);
		goto end;
	}

	if ((itbl_dir = opendir(itbl_path)) == NULL) {
		warn("opendir");
		goto end;
	}

	for (d = readdir(itbl_dir); d != NULL; d = readdir(itbl_dir)) {
		if (strcmp(d->d_name, ".") == 0 ||
		    strcmp(d->d_name, "..") == 0)
			continue;
		if (d->d_name[0] != 'i')
			continue;

		ino = strtoull(d->d_name + 1, &end, 10);
		if (*end != '\0') {
			stats.errors++;
			warnx("%s: bad inode table name: %s",
			    __func__, d->d_name);
			continue;
		}
		if (ino == ULLONG_MAX) {
			stats.errors++;
			warn("%s: bad inode table name: %s",
			    __func__, d->d_name);
			continue;
		}

		if ((b = slab_inspect(ino, 0, SLAB_ITBL, &e)) == NULL) {
			exlog_prt(&e);
			stats.errors++;
			continue;
		}
		if (!(b->hdr.v.f.flags & SLAB_ITBL)) {
			warnx("file is not an ITBL: %s", itbl);
			stats.errors++;
			close(b->fd);
			free(b);
			continue;
		}
		if (b->hdr.v.f.data_format_version != SLAB_VERSION) {
			warnx("unrecognized data format version: %s: %u",
			    itbl, b->hdr.v.f.data_format_version);
			stats.errors++;
			close(b->fd);
			free(b);
			continue;
		}

		// TODO: verify checksum
		//if (hdr.v.f.checksum ...)

		itbl_hdr = (struct slab_itbl_hdr *)b->hdr.v.f.data;

		for (ino = itbl_hdr->base, slab_end = 0, n_free = 0;
		    ino < itbl_hdr->base + slab_inode_max(); ino++) {
			if (!slab_end) {
				r = slab_read(b, &inode,
				    (ino - itbl_hdr->base) * sizeof(inode),
				    sizeof(inode), &e);
				if (r == -1) {
					warn("read");
					stats.errors++;
					slab_end = 1;
				} else if (r == 0) {
					slab_end = 1;
				} else if (r < sizeof(inode)) {
					warnx("%s: short read on inode",
					    __func__);
					stats.errors++;
					slab_end = 1;
				}
			}

			is_free = slab_inode_free(itbl_hdr, ino);
			fsck_inode(ino, is_free,
			    ((slab_end) ? NULL : &inode), &stats);
			if (is_free)
				n_free++;
		}
		if (itbl_hdr->n_free != n_free) {
			warnx("%s: incorrect free inode count in "
			    "inode table base %lu (n_free=%u, actual=%lu)",
			    __func__, itbl_hdr->base, itbl_hdr->n_free,
			    n_free);
			stats.errors++;
		}
		close(b->fd);
		free(b);
	}
end:
	printf("Filesystem statistics:\n");
	printf("    inodes:      %lu\n", stats.n_inodes);
	printf("    directories: %lu\n", stats.n_dirs);
	printf("    dirents:     %lu\n", stats.n_dirents);
	printf("    errors:      %lu\n", stats.errors);
	printf("Scan result: %s\n", (stats.errors) ? "errors" : "clean");
	return (stats.errors) ? 1 : 0;
}

void
print_metric_header()
{
	printf("%10s %10s %10s %10s %10s %10s %10s\n",
	    "read/s", "read MB/s", "write/s", "write MB/s",
	    "fsync/s", "fsyncdir/s", "errors");
}

int
top(int argc, char **argv)
{
	unsigned int    seconds;
	uint64_t        counters_now[COUNTER_LAST];
	uint64_t        counters_prev[COUNTER_LAST];
	double          counters_delta[COUNTER_LAST];
	int             c, i;
	struct timespec ts, te;
	char            path[PATH_MAX];

	if (argc < 1) {
		usage();
		exit(1);
	}

	if (snprintf(path, sizeof(path), "%s/counters", datadir)
	    >= sizeof(path))
		errx(1, "%s: counters path too long", __func__);

	seconds = strtol(argv[0], NULL, 10);
	read_metrics(path, counters_prev);
	for (i = 0;; i++) {
		clock_gettime(CLOCK_MONOTONIC, &ts);
		sleep(seconds);

		read_metrics(path, counters_now);
		clock_gettime(CLOCK_MONOTONIC, &te);
		for (c = 0; c < COUNTER_LAST; c++) {
			counters_delta[c] = counters_now[c] - counters_prev[c];
			counters_prev[c] = counters_now[c];
		}

		if (i % 23 == 0)
			print_metric_header();
		printf("%10.1f %10.2f %10.1f %10.2f %10.1f %10.1f %10lu\n",
		    counters_delta[COUNTER_FS_READ] /
		    (te.tv_sec - ts.tv_sec),
		    counters_delta[COUNTER_READ_BYTES] /
		    1024.0 / 1024.0 / (te.tv_sec - ts.tv_sec),
		    counters_delta[COUNTER_FS_WRITE] /
		    (te.tv_sec - ts.tv_sec),
		    counters_delta[COUNTER_WRITE_BYTES] /
		    1024.0 / 1024.0 / (te.tv_sec - ts.tv_sec),
		    counters_delta[COUNTER_FS_FSYNC] /
		    (te.tv_sec - ts.tv_sec),
		    counters_delta[COUNTER_FS_FSYNCDIR] /
		    (te.tv_sec - ts.tv_sec),
		    counters_now[COUNTER_FS_ERROR]);
	}
}

int
load_dir(char **data, struct inode *inode)
{
	off_t             i;
	ssize_t           r;
	ino_t             ino = inode->v.f.inode;
	int               fd = -1;
	char              path[PATH_MAX];
	struct slab_hdr   hdr;
	struct stat       st;
	char             *d;
	struct exlog_err  e = EXLOG_ERR_INITIALIZER;

	if ((d = calloc(inode->v.f.size, 1)) == NULL)
		err(1, "calloc");

	i = (inode->v.f.size <
	    (sizeof(struct inode) - sizeof(struct inode_fields)))
	    ? inode->v.f.size
	    : sizeof(struct inode) - sizeof(struct inode_fields);

	memcpy(d, inode->v.data + sizeof(struct inode_fields), i);

	for (; i < inode->v.f.size; i += r) {
		if (slab_path(path, sizeof(path), ino, i, 0, &e) == -1) {
			exlog_prt(&e);
			goto fail;
		}

		if ((fd = open(path, O_RDONLY)) == -1) {
			if (errno == ENOENT)
				errx(1, "%s: missing slabs for an inode this "
				    "size: %s", __func__, path);
			warn("open");
			goto fail;
		}

		if (flock(fd, LOCK_SH) == -1) {
			warn("flock");
			goto fail;
		}

		if (fstat(fd, &st) == -1) {
			warn("fstat");
			goto fail;
		}

		if ((r = read(fd, &hdr, sizeof(hdr))) == -1) {
			warn("failed to read slab header: %s", path);
			goto fail;
		}
		if (r < sizeof(hdr)) {
			warnx("%s: short read on slab header: %s",
			    __func__, path);
			goto fail;
		}

		if (hdr.v.f.data_format_version != SLAB_VERSION) {
			warnx("unrecognized data format version: %s: %u",
			    path, hdr.v.f.data_format_version);
			goto fail;
		}

		// TODO: verify checksum
		//if (hdr.v.f.checksum ...)

		if ((hdr.v.f.flags & SLAB_REMOVED) &&
		    st.st_size > sizeof(struct slab_hdr)) {
			warn("slab %s is removed, but size is larger than %lu",
			    path, sizeof(struct slab_hdr));
		}

		if (i / slab_get_max_size() == 0)
			if (lseek(fd, i, SEEK_CUR) == -1)
				err(1, "lseek");
		if ((r = read(fd, d + i, slab_get_max_size())) == -1) {
			warn("read");
			goto fail;
		}
		close(fd);
		fd = -1;
		if (r == 0)
			break;
	}

	if (i < inode->v.f.size) {
		warnx("inode %lu is truncated; data might be incomplete", ino);
		return -1;
	}
	*data = d;
	return 0;
fail:
	free(d);
	*data = NULL;
	if (fd != -1)
		close(fd);
	return -1;
}

int
show_inode(int argc, char **argv)
{
	ino_t            ino;
	struct inode     inode;
	char             path[PATH_MAX];
	off_t            i;
	ssize_t          r;
	struct exlog_err e = EXLOG_ERR_INITIALIZER;
	int              fd;
	struct slab_hdr  hdr;
	struct stat      st;

	if (argc < 1) {
		usage();
		exit(1);
	}

	if ((ino = strtoull(argv[0], NULL, 10)) == ULLONG_MAX)
		errx(1, "inode provided is invalid");

	if (inode_inspect(ino, &inode, &e) == -1) {
		if (exlog_err_is(&e, EXLOG_APP, EXLOG_ENOENT))
			errx(1, "inode is not allocated");
		exlog_prt(&e);
		exit(1);
	}

	printf("inode: %lu\n", ino);
	print_inode(&inode, 0);

	for (i = inode_max_inline_b(); i < inode.v.f.size;
	    i += slab_get_max_size()) {
		if (slab_path(path, sizeof(path), ino, i, 0, &e) == -1) {
			exlog_prt(&e);
			exit(1);
		}

		if ((fd = open(path, O_RDONLY)) == -1) {
			if (errno == ENOENT)
				errx(1, "%s: missing slabs for an inode this "
				    "size: %s", __func__, path);
			err(1, "open");
		}

		if ((r = read(fd, &hdr, sizeof(hdr))) == -1)
			err(1, "read");
		if (r < sizeof(hdr))
			errx(1, "%s: short read on slab header",
			    __func__);
		if ((r = fstat(fd, &st)) == -1)
			err(1, "fstat");
		close(fd);

		printf("  slab: %s\n", path);
		printf("    hdr:\n");
		printf("      version:    %u\n",
		    hdr.v.f.data_format_version);
		printf("      checksum:   %u\n", hdr.v.f.checksum);
		printf("      revision:   %lu\n", hdr.v.f.revision);
		printf("      flags:     ");
		if (hdr.v.f.flags & SLAB_ITBL)
			printf(" itbl");
		if (hdr.v.f.flags & SLAB_DIRTY)
			printf(" dirty");
		if (hdr.v.f.flags & SLAB_REMOVED)
			printf(" removed");
		printf("\n");
		printf("      data size:  %lu\n",
		    st.st_size - sizeof(struct slab_hdr));
		printf("      sparse:     %s\n",
		    (st.st_size < (inode.v.f.size % slab_get_max_size()))
		    ? "yes" : "no");
		printf("\n");
	}

	if (i < inode.v.f.size)
		warnx("  ** inode is truncated; data might be incomplete");
	return 0;
}

int
show_dir(int argc, char **argv)
{
	struct slab_hdr   hdr;
	int               fd, n;
	off_t             i;
	ssize_t           r;
	ino_t             ino;
	struct inode      inode;
	char              path[PATH_MAX];
	char             *data;
	struct dir_entry *de;
	struct exlog_err  e = EXLOG_ERR_INITIALIZER;

	if (argc < 1) {
		usage();
		exit(1);
	}

	if ((ino = strtoull(argv[0], NULL, 10)) == ULLONG_MAX)
		errx(1, "inode provided is invalid");

	if (inode_inspect(ino, &inode, &e) == -1) {
		if (exlog_err_is(&e, EXLOG_APP, EXLOG_ENOENT))
			errx(1, "inode is not allocated");
		exlog_prt(&e);
		exit(1);
	}

	if ((inode.v.f.mode & S_IFMT) != S_IFDIR) {
		printf("inode %lu is not a directory; use 'slab' to see "
		    "inode details\n", ino);
		return 0;
	}

	if ((data = calloc(inode.v.f.size, 1)) == NULL)
		err(1, "calloc");

	i = (inode.v.f.size < sizeof(inode)
	    - sizeof(struct inode_fields)) ?
	    inode.v.f.size : sizeof(inode) - sizeof(struct inode_fields);

	memcpy(data, inode.v.data + sizeof(struct inode_fields), i);

	printf("inode: %lu\n", ino);

	for (; i < inode.v.f.size; i += r) {
		if (slab_path(path, sizeof(path), ino, i, 0, &e) == -1) {
			exlog_prt(&e);
			exit(1);
		}

		if ((fd = open(path, O_RDONLY)) == -1) {
			if (errno == ENOENT)
				errx(1, "%s: missing slabs for an inode this "
				    "size: %s", __func__, path);
			err(1, "open");
		}

		if ((r = read(fd, &hdr, sizeof(hdr))) == -1)
			err(1, "read");
		if (r < sizeof(hdr))
			errx(1, "%s: short read on slab header",
			    __func__);
		printf("  slab: %s\n", path);
		printf("    hdr:\n");
		printf("      version:    %u\n",
		    hdr.v.f.data_format_version);
		printf("      checksum:   %u\n", hdr.v.f.checksum);
		printf("      revision:   %lu\n", hdr.v.f.revision);
		printf("      flags:     ");
		if (hdr.v.f.flags & SLAB_ITBL)
			printf(" itbl");
		if (hdr.v.f.flags & SLAB_DIRTY)
			printf(" dirty");
		if (hdr.v.f.flags & SLAB_REMOVED)
			printf(" removed");
		printf("\n\n");

		if (i / slab_get_max_size() == 0)
			if (lseek(fd, i, SEEK_CUR) == -1)
				err(1, "lseek");
		if ((r = read(fd, data + i, slab_get_max_size())) == -1)
			err(1, "read");
		close(fd);
		if (r == 0)
			break;
	}

	if (i < inode.v.f.size)
		warnx("  ** inode is truncated; data might be incomplete");
	printf("  dirents:\n\n");

	de = (struct dir_entry *)data;

	for (n = 0; i > 0; i -= sizeof(struct dir_entry), de++, n++) {
		printf("    name:        %s\n", de->name);
		printf("    offset:      %lu\n", (char *)de - data);
		printf("    inode:       %lu\n", de->inode);
		printf("    next offset: %lu\n\n", de->next);
	}

	printf("  Total dirents: %d\n", n);

	return 0;
}

void
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
	struct slab_hdr       hdr;
	struct slab_itbl_hdr *itbl_hdr;
	int                   fd, i;
	ssize_t               r;
	ino_t                 ino;
	struct inode          inode;

	if (argc < 1) {
		usage();
		exit(1);
	}

	if ((fd = open(argv[0], O_RDONLY)) == -1)
		err(1, "open");

	if ((r = read(fd, &hdr, sizeof(hdr))) == -1)
		err(1, "read");
	if (r < sizeof(hdr))
		errx(1, "%s: short read on itbl header", __func__);

	printf("slab: %s\n", argv[0]);
	printf("  hdr:\n");
	printf("    version:    %u\n", hdr.v.f.data_format_version);
	printf("    checksum:   %u\n", hdr.v.f.checksum);
	printf("    revision:   %lu\n", hdr.v.f.revision);
	printf("    flags:     ");
	if (hdr.v.f.flags & SLAB_ITBL)
		printf(" itbl");
	if (hdr.v.f.flags & SLAB_DIRTY)
		printf(" dirty");
	if (hdr.v.f.flags & SLAB_REMOVED)
		printf(" removed");
	printf("\n\n");

	if (hdr.v.f.flags & SLAB_ITBL) {
		itbl_hdr = (struct slab_itbl_hdr *)hdr.v.f.data;

		printf("  itbl hdr:\n");
		printf("       base:    %lu\n", itbl_hdr->base);
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
		for (ino = itbl_hdr->base;
		    ino < itbl_hdr->base + slab_inode_max(); ino++) {
			if ((r = read(fd, &inode, sizeof(inode))) == -1)
				err(1, "read");
			else if (r == 0)
				break;
			else if (r < sizeof(inode))
				errx(1, "%s: short read on inode", __func__);
			print_inode(&inode,
			    slab_inode_free(itbl_hdr, ino));
		}
	}

	return 0;
}

int
main(int argc, char **argv)
{
	struct subc      *c;
	struct exlog_err  e = EXLOG_ERR_INITIALIZER;

	if (argc < 3) {
		usage();
		exit(1);
	}

	if ((log_locale = newlocale(LC_CTYPE_MASK, "C", 0)) == 0)
		err(1, "newlocale");

	strncpy(datadir, argv[1], PATH_MAX - 1);
	if (strcmp(argv[2], "top") != 0) {
		if (fs_info_inspect(&fs_info, &e) == -1) {
			exlog_prt(&e);
			exit(1);
		}
		if (!fs_info.clean) {
			warnx("WARNING: filesystem not marked clean!!!");
			warnx("         Run fsck.");
		}
		slab_max_size = fs_info.slab_size;
	}

	for (c = subcommands; c->fn; c++) {
		if (strcmp(c->name, argv[2]) == 0)
			return c->fn(argc - 3, argv + 3);
	}

	usage();
	return 1;
}
