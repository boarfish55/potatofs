#define _GNU_SOURCE
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <locale.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <utime.h>
#include "config.h"
#include "fs_info.h"
#include "inodes.h"
#include "slabdb.h"
#include "mgr.h"

char mnt[PATH_MAX] = "";
char path[PATH_MAX] = "";

/*
 * The following file names have matching hashes (fnv1a32) for their
 * rightmost 30 bits.
 */
const char *same_hash_30b_suffix[] = {
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",

	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac9qqjF",

	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaadcKcN1",

	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaadKAotI",

	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaadMEfm9",

	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad9UAjk",

	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaexAzeK",

	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaagtR9CU",

	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaagTL3v2",

	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaag6OlTP",

	NULL
};

/*
 * This name's fnv1a32 has matches the rightmost 16bits of the names
 * in the above array.
 */
const char *same_hash_16b_suffix =
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabjCA";

const char *shorter_same_hash_30b_suffix[] = {
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa30DR7a",

	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaadftA0Na",

	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaeaMjUua",

	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaagPeQcwa",

	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaahd5ufqa",

	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaah3hdQQa",

	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaajrRdsva",

	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaajRl84Ea",

	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaakTSdGXa",

	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaalJMfBla",

	NULL
};

extern locale_t log_locale;

static struct path
{
	char         p[PATH_MAX];
	struct path *next;
} *all_paths = NULL;

char *
fail(const char *msg, int e, const char *fn, int line)
{
	char *m;

	if (asprintf(&m, "%s%s (errno=%d; %s:%d)", msg,
	    (e) ? strerror_l(e, log_locale) : "", e, fn, line) == -1)
		err(1, "asprintf");
        return m;
}
#define ERR(msg, e) fail(msg, e, __func__, __LINE__)

char *
makepath(const char *p)
{
	struct path *path, *prev;

	if ((path = malloc(sizeof(struct path))) == NULL)
		err(1, "malloc");
	path->next = NULL;

	if (snprintf(path->p, sizeof(path->p), "%s/%s", mnt, p)
	    >= sizeof(path->p))
		errx(1, "error: resulting path too long: %s", p);

	if (all_paths == NULL) {
		all_paths = path;
	} else {
		for (prev = all_paths; prev->next != NULL; prev = prev->next)
			;
		prev->next = path;
	}

	return path->p;
}

void
free_all_paths()
{
	struct path *p = all_paths, *next;

	while (p != NULL) {
		next = p->next;
		free(p);
		p = next;
	}
	all_paths = NULL;
}

void
xnanosleep()
{
	struct timespec req = {0, 100000000};

	while (nanosleep(&req, NULL) == -1) {
		if (errno != EINTR)
			err(1, "nanosleep");
	}
}

#define ST_INODE  0x0001
#define ST_MODE   0x0002
#define ST_NLINK  0x0004
#define ST_UID    0x0008
#define ST_GID    0x0010
#define ST_SIZE   0x0020
#define ST_BLOCKS 0x0040
#define ST_ATIME  0x0080
#define ST_CTIME  0x0100
#define ST_MTIME  0x0200

int
get_disk_inode(ino_t ino, struct stat *st, struct xerr *e)
{
	struct inode inode;

	if (inode_disk_inspect(ino, &inode, e) == -1)
		return -1;
	if (st != NULL)
		inode_cp_stat(st, &inode);
	return 0;
}

char *
check_stat(const char *p, struct stat *st_want, uint16_t what)
{
	char         msg[LINE_MAX];
	struct stat  st;
	struct inode inode;
	struct xerr  e = XLOG_ERR_INITIALIZER;

	if (lstat(p, &st) == -1)
		return ERR("", errno);

	/* Check the data structure on disk */
	if (inode_disk_inspect(st.st_ino, &inode, &e) == -1) {
		xerr_print(&e);
		return ERR("reading inode failed", 0);
	}

	if ((what & ST_INODE) &&
	    (st_want->st_ino != st.st_ino ||
	     st_want->st_ino != inode.v.f.inode)) {
		snprintf(msg, sizeof(msg),
		    "st_ino doesn't match: current=%lu, want=%lu",
		    st.st_ino, st_want->st_ino);
		return ERR(msg, 0);
	}

	if (what & ST_MODE) {
		if (st_want->st_mode != st.st_mode) {
			snprintf(msg, sizeof(msg),
			    "st_mode doesn't match: current=%o, want=%o",
			    st.st_mode, st_want->st_mode);
			return ERR(msg, 0);
		}
		if (st_want->st_mode != inode.v.f.mode) {
			snprintf(msg, sizeof(msg),
			    "st_mode matches in-memory, but not on-disk: "
			    "current=%o, want=%o",
			    inode.v.f.mode, st_want->st_mode);
			return ERR(msg, 0);
		}
	}

	if (what & ST_NLINK) {
		if (st_want->st_nlink != st.st_nlink) {
			snprintf(msg, sizeof(msg),
			    "st_nlink doesn't match: current=%lu, want=%lu",
			    st.st_nlink, st_want->st_nlink);
			return ERR(msg, 0);
		}
		if (st_want->st_nlink != inode.v.f.nlink) {
			snprintf(msg, sizeof(msg),
			    "st_nlink matches in-memory, but not on-disk: "
			    "current=%lu, want=%lu",
			    inode.v.f.nlink, st_want->st_nlink);
			return ERR(msg, 0);
		}
	}

	if (what & ST_UID) {
		if (st_want->st_uid != st.st_uid) {
			snprintf(msg, sizeof(msg),
			    "st_uid doesn't match: current=%u, want=%u",
			    st.st_uid, st_want->st_uid);
			return ERR(msg, 0);
		}
		if (st_want->st_uid != inode.v.f.uid) {
			snprintf(msg, sizeof(msg),
			    "st_uid matches in-memory, but not on-disk: "
			    "current=%u, want=%u",
			    inode.v.f.uid, st_want->st_uid);
			return ERR(msg, 0);
		}
	}

	if (what & ST_GID) {
		if (st_want->st_gid != st.st_gid) {
			snprintf(msg, sizeof(msg),
			    "st_gid doesn't match: current=%u, want=%u",
			    st.st_gid, st_want->st_gid);
			return ERR(msg, 0);
		}
		if (st_want->st_gid != inode.v.f.gid) {
			snprintf(msg, sizeof(msg),
			    "st_gid matches in-memory, but not on-disk: "
			    "current=%u, want=%u",
			    inode.v.f.gid, st_want->st_gid);
			return ERR(msg, 0);
		}
	}

	if (what & ST_SIZE) {
		if (st_want->st_size != st.st_size) {
			snprintf(msg, sizeof(msg),
			    "st_size doesn't match: current=%lu, want=%lu",
			    st.st_size, st_want->st_size);
			return ERR(msg, 0);
		}
		if (st_want->st_size != inode.v.f.size) {
			snprintf(msg, sizeof(msg),
			    "st_size matches in-memory, but not on-disk: "
			    "current=%lu, want=%lu",
			    inode.v.f.size, st_want->st_size);
			return ERR(msg, 0);
		}
	}

	if (what & ST_BLOCKS) {
		if (st_want->st_blocks != st.st_blocks) {
			snprintf(msg, sizeof(msg),
			    "st_blocks doesn't match: current=%lu, want=%lu",
			    st.st_blocks, st_want->st_blocks);
			return ERR(msg, 0);
		}
		if (st_want->st_blocks != inode.v.f.blocks) {
			snprintf(msg, sizeof(msg),
			    "st_blocks matches in-memory, but not on-disk: "
			    "current=%lu, want=%lu",
			    inode.v.f.blocks, st_want->st_blocks);
			return ERR(msg, 0);
		}
	}

	if (what & ST_ATIME) {
		if (st_want->st_atim.tv_sec != st.st_atim.tv_sec ||
		    st_want->st_atim.tv_nsec != st.st_atim.tv_nsec) {
			snprintf(msg, sizeof(msg),
			    "st_atim doesn't match: "
			    "current=%lu.%lu, want=%lu.%lu",
			    st.st_atim.tv_sec, st.st_atim.tv_nsec,
			    st_want->st_atim.tv_sec, st_want->st_atim.tv_nsec);
			return ERR(msg, 0);
		}
		if (st_want->st_atim.tv_sec != inode.v.f.atime.tv_sec ||
		    st_want->st_atim.tv_nsec != inode.v.f.atime.tv_nsec) {
			snprintf(msg, sizeof(msg),
			    "st_atim matches in-memory, but not on-disk: "
			    "current=%lu.%lu, want=%lu.%lu",
			    st.st_atim.tv_sec, st.st_atim.tv_nsec,
			    st_want->st_atim.tv_sec, st_want->st_atim.tv_nsec);
			return ERR(msg, 0);
		}
	}

	if (what & ST_CTIME) {
		if (st_want->st_ctim.tv_sec != st.st_ctim.tv_sec ||
		    st_want->st_ctim.tv_nsec != st.st_ctim.tv_nsec) {
			snprintf(msg, sizeof(msg),
			    "st_ctim doesn't match: "
			    "current=%lu.%lu, want=%lu.%lu",
			    st.st_ctim.tv_sec, st.st_ctim.tv_nsec,
			    st_want->st_ctim.tv_sec, st_want->st_ctim.tv_nsec);
			return ERR(msg, 0);
		}
		if (st_want->st_ctim.tv_sec != inode.v.f.ctime.tv_sec ||
		    st_want->st_ctim.tv_nsec != inode.v.f.ctime.tv_nsec) {
			snprintf(msg, sizeof(msg),
			    "st_ctim matches in-memory, but not on-disk: "
			    "current=%lu.%lu, want=%lu.%lu",
			    st.st_ctim.tv_sec, st.st_ctim.tv_nsec,
			    st_want->st_ctim.tv_sec, st_want->st_ctim.tv_nsec);
			return ERR(msg, 0);
		}
	}

	if (what & ST_MTIME) {
		if (st_want->st_mtim.tv_sec != st.st_mtim.tv_sec ||
		    st_want->st_mtim.tv_nsec != st.st_mtim.tv_nsec) {
			snprintf(msg, sizeof(msg),
			    "st_mtim doesn't match: "
			    "current=%lu.%lu, want=%lu.%lu",
			    st.st_mtim.tv_sec, st.st_mtim.tv_nsec,
			    st_want->st_mtim.tv_sec, st_want->st_mtim.tv_nsec);
			return ERR(msg, 0);
		}
		if (st_want->st_mtim.tv_sec != inode.v.f.mtime.tv_sec ||
		    st_want->st_mtim.tv_nsec != inode.v.f.mtime.tv_nsec) {
			snprintf(msg, sizeof(msg),
			    "st_mtim matches in-memory, but not on-disk: "
			    "current=%lu.%lu, want=%lu.%lu",
			    st.st_mtim.tv_sec, st.st_mtim.tv_nsec,
			    st_want->st_mtim.tv_sec, st_want->st_mtim.tv_nsec);
			return ERR(msg, 0);
		}
	}

	return NULL;
}

char *
check_utime_gte(const char *p, struct timespec *mintime, uint16_t what)
{
	struct stat     st;
	char            msg[1024];
	struct timespec tp;
	char            t[] = "mtime";

	if (lstat(p, &st) == -1)
		return ERR("", errno);

	if (what & ST_MTIME) {
		memcpy(&tp, &st.st_mtim, sizeof(tp));
	} else if (what & ST_CTIME) {
		memcpy(&tp, &st.st_ctim, sizeof(tp));
		t[0] = 'c';
	} else if (what & ST_ATIME) {
		memcpy(&tp, &st.st_atim, sizeof(tp));
		t[0] = 'a';
	} else {
		return ERR("invalid time mask", 0);
	}

	if (tp.tv_sec < mintime->tv_sec ||
	    (tp.tv_sec == mintime->tv_sec && tp.tv_nsec < mintime->tv_nsec)) {
		snprintf(msg, sizeof(msg),
		    "file %s not updated: "
		    "current=%lu.%lu, mintime=%lu.%lu",
		    t, tp.tv_sec, tp.tv_nsec,
		    mintime->tv_sec, mintime->tv_nsec);
		return ERR(msg, 0);
	}
	return NULL;
}

char *
test_slab_size()
{
	char            msg[LINE_MAX];
	struct slab_hdr hdr;
	size_t          hdr_data_sz;

	if (sizeof(struct slab_hdr) != FS_BLOCK_SIZE) {
		snprintf(msg, sizeof(msg),
		    "struct slab_hdr size (%lu) is not equal to the "
		    "filesystem block size (%d)", sizeof(struct slab_hdr),
		    FS_BLOCK_SIZE);
		return ERR(msg, 0);
	}

	hdr_data_sz = sizeof(hdr) - (hdr.v.padding.data - (char *)&hdr);
	if (sizeof(struct slab_itbl_hdr) > hdr_data_sz) {
		snprintf(msg, sizeof(msg),
		    "struct slab_itbl_hdr's size (%lu) does not fit in "
		    "the struct slab_hdr's additional data area (%lu)",
		    sizeof(struct slab_itbl_hdr), hdr_data_sz);
		return ERR(msg, 0);
	}
	return NULL;
}

char *
test_mounted()
{
	struct stat st_want;

	st_want.st_ino = FS_ROOT_INODE;
	return check_stat(mnt, &st_want, ST_INODE);
}

char *
test_mkdir()
{
	struct stat  st_want;
	char        *p = makepath("A");

	st_want.st_mode = (S_IFDIR | 0755);
	st_want.st_nlink = 2;
	st_want.st_uid = getuid();
	st_want.st_gid = getgid();

	if (mkdir(p, 0755) == -1)
		return ERR("", errno);
	return check_stat(p, &st_want, ST_MODE|ST_NLINK|ST_UID|ST_GID);
}

char *
test_mknod()
{
	struct stat  st_want;
	char        *p = makepath("a");

	st_want.st_mode = (S_IFREG | 0640);
	st_want.st_nlink = 1;
	st_want.st_uid = getuid();
	st_want.st_gid = getgid();
	st_want.st_size = 0;

	if (mknod(p, 0640, 0) == -1)
		return ERR("", errno);
	return check_stat(p, &st_want, ST_MODE|ST_NLINK|ST_UID|ST_GID|ST_SIZE);
}

char *
test_mknod_exists()
{
	char *p = makepath("a");

	if (mknod(p, 0640, 0) == -1 && errno == EEXIST)
		return NULL;

	return ERR("file creation should have failed with EEXIST", 0);
}

char *
test_utimes_file()
{
	char            *p = makepath("times");
	struct stat      st_want, st;
	char             msg[1024];
	struct timespec  tp;
	struct timeval   times[2] = {
		{ 1595334000, 1 },
		{ 1595334001, 2 }
	};

	st_want.st_mode = (S_IFREG | 0640);
	st_want.st_nlink = 1;

	st_want.st_atim.tv_sec = 1595334000;
	st_want.st_atim.tv_nsec = 1000;

	st_want.st_mtim.tv_sec = 1595334001;
	st_want.st_mtim.tv_nsec = 2000;

	if (mknod(p, 0640, 0) == -1)
		return ERR("", errno);

	if (clock_gettime(CLOCK_REALTIME, &tp) == -1)
		return ERR("", errno);

	if (utimes(p, times) == -1)
		return ERR("", errno);

	if (stat(p, &st) == -1)
		return ERR("", errno);

	if (st.st_ctim.tv_sec < tp.tv_sec) {
		snprintf(msg, sizeof(msg),
		    "file ctime not updated after utimes(): "
		    "current=%lu.%lu, want=%lu.%lu",
		    st.st_ctim.tv_sec, st.st_ctim.tv_nsec,
		    tp.tv_sec, tp.tv_nsec);
		return ERR(msg, 0);
	}

	return check_stat(p, &st_want, ST_MODE|ST_NLINK|ST_ATIME|ST_MTIME);
}

char *
test_chmod()
{
	char            *p = makepath("perms");
	struct stat      st_want, st;
	char            *r;
	struct timespec  tp;

	st_want.st_mode = (S_IFREG | 0466);
	st_want.st_nlink = 1;

	if (mknod(p, 0640, 0) == -1)
		return ERR("", errno);
	xnanosleep();
	if (clock_gettime(CLOCK_REALTIME, &tp) == -1)
		return ERR("", errno);
	if (chmod(p, 0466) == -1)
		return ERR("", errno);

	if (stat(p, &st) == -1)
		return ERR("", errno);

	if ((r = check_utime_gte(p, &tp, ST_CTIME)) != NULL)
		return r;

	return check_stat(p, &st_want, ST_MODE|ST_NLINK);
}

char *
test_parent_mtime_after_mknod()
{
	char            *d1 = makepath("parent_mtime_after_mknod");
	char            *p1 = makepath("parent_mtime_after_mknod/x");
	struct timespec  tp;


	if (mkdir(d1, 0755) == -1)
		return ERR("", errno);
	xnanosleep();
	if (clock_gettime(CLOCK_REALTIME, &tp) == -1)
		return ERR("", errno);
	if (mknod(p1, 0640, 0) == -1)
		return ERR("", errno);

	return check_utime_gte(d1, &tp, ST_MTIME);
}

char *
test_atime()
{
	char        *p = makepath("atime");
	struct stat  st;
	int          fd;
	char         buf[1];

	if (mknod(p, 0640, 0) == -1)
		return ERR("", errno);
	if (stat(p, &st) == -1)
		return ERR("", errno);

	xnanosleep();

	if ((fd = open(p, O_RDONLY)) == -1)
		return ERR("", errno);
	if (read(fd, buf, sizeof(buf)) == -1)
		return ERR("", errno);
	close(fd);

	return check_utime_gte(p, &st.st_atim, ST_ATIME);
}

char *
test_unlink()
{
	struct stat  st;
	ino_t        ino;
	char        *p = makepath("unlink-me");
	struct xerr  e = XLOG_ERR_INITIALIZER;

	if (mknod(p, 0640, 0) == -1)
		return ERR("", errno);
	if (stat(p, &st) == -1)
		return ERR("", errno);
	ino = st.st_ino;
	if (unlink(p) == -1)
		return ERR("", errno);

	if (access(p, R_OK|F_OK) == -1 && errno == ENOENT) {
		if (get_disk_inode(ino, &st, &e) == -1) {
			if (!xerr_is(&e, XLOG_FS, ENOENT)) {
				xerr_print(&e);
				return ERR("error querying inode", 0);
			}
		} else {
			return ERR("file still exists on-disk "
			    "after unlink", 0);
		}
		return NULL;
	}
	return ERR("file still exists after unlink", 0);
}

char *
test_parent_mtime_after_rmnod()
{
	char            *d1 = makepath("parent_mtime_after_rmnod");
	char            *p1 = makepath("parent_mtime_after_rmnod/x");
	struct timespec  tp;


	if (mkdir(d1, 0755) == -1)
		return ERR("", errno);
	if (mknod(p1, 0640, 0) == -1)
		return ERR("", errno);
	xnanosleep();
	if (clock_gettime(CLOCK_REALTIME, &tp) == -1)
		return ERR("", errno);
	if (unlink(p1) == -1)
		return ERR("", errno);

	return check_utime_gte(d1, &tp, ST_MTIME);
}

char *
test_rmdir()
{
	struct stat  st;
	ino_t        ino;
	char        *p = makepath("rmdir-me");
	struct xerr  e = XLOG_ERR_INITIALIZER;

	if (mkdir(p, 0755) == -1)
		return ERR("", errno);
	if (stat(p, &st) == -1)
		return ERR("", errno);
	ino = st.st_ino;
	if (rmdir(p) == -1)
		return ERR("", errno);

	if (access(p, R_OK|X_OK) == -1 && errno == ENOENT) {
		if (get_disk_inode(ino, &st, &e) == -1) {
			if (!xerr_is(&e, XLOG_FS, ENOENT)) {
				xerr_print(&e);
				return ERR("error querying inode", 0);
			}
		} else {
			return ERR("directory still exists on-disk "
			    "after rmdir", 0);
		}
		return NULL;
	}
	return ERR("directory still exists after unlink", 0);
}

char *
test_rmdir_notempty_notdir()
{
	struct stat  st;
	char        *p = makepath("rmdir-me2");
	char        *p2 = makepath("rmdir-me2/notempty");
	struct stat  st_want;

	st_want.st_mode = (S_IFDIR | 0711);
	st_want.st_nlink = 2;
	st_want.st_uid = getuid();
	st_want.st_gid = getgid();

	if (mkdir(p, 0711) == -1)
		return ERR("", errno);
	if (stat(p, &st) == -1)
		return ERR("", errno);
	if (mknod(p2, 0600, 0) == -1)
		return ERR("", errno);

	if (rmdir(p2) != -1 || errno != ENOTDIR)
		return ERR("rmdir() on non-directory failed to return "
		    "ENOTDIR", 0);
	errno = 0;

	if (rmdir(p) != -1 || errno != ENOTEMPTY)
		return ERR("rmdir() on non-empty directory failed to return "
		    "ENOTEMPTY", 0);

	if (access(p, R_OK|X_OK) == -1)
		return ERR("directory should still exist after rmdir", 0);

	return check_stat(p, &st_want, ST_MODE|ST_NLINK|ST_UID|ST_GID);
}

char *
test_readdir_max_v2_dir_depth()
{
	char          *p = makepath("readdir_v2_max_depth");
	char           file[PATH_MAX];
	DIR           *dir;
	struct dirent *de;
	int           *found;
	int            found_count, i;

	if (mkdir(p, 0755) == -1)
		return ERR("", errno);

	for (i = 0; same_hash_30b_suffix[i] != NULL; i++) {
		snprintf(file, sizeof(file), "%s/%s", p,
		    same_hash_30b_suffix[i]);
		if (mknod(file, 0600, 0) == -1)
			return ERR("", errno);
	}

	snprintf(file, sizeof(file), "%s/%s", p, same_hash_16b_suffix);
	if (mknod(file, 0600, 0) == -1)
		return ERR("", errno);

	found_count = i + 1;
	found = malloc(sizeof(int) * found_count);
	if (found == NULL)
		err(1, "malloc");
	bzero(found, sizeof(int) * found_count);

	if ((dir = opendir(p)) == NULL)
		return ERR("", errno);
	while ((de = readdir(dir))) {
		for (i = 0; same_hash_30b_suffix[i] != NULL; i++) {
			if (strcmp(de->d_name, same_hash_30b_suffix[i]) == 0)
				found[i] = 1;
		}
		if (strcmp(de->d_name, same_hash_16b_suffix) == 0)
			found[found_count - 1] = 1;
	}
	closedir(dir);

	for (i = 0; i < found_count; i++) {
		if (found[i] == 0) {
			free(found);
			return ERR("not all created entries were found "
			    "by readdir()", 0);
		}
	}

	free(found);
	return NULL;
}

char *
test_mkdirent_fill_first_chained_leaf_max_v2_dir_depth()
{
	char          *p = makepath("mkdirent_fill_first_chained_leaf_v2_dir");
	char           file[PATH_MAX];
	struct stat    st, st_want;
	int            i;

	if (mkdir(p, 0755) == -1)
		return ERR("", errno);

	for (i = 0; same_hash_30b_suffix[i] != NULL; i++) {
		snprintf(file, sizeof(file), "%s/%s", p,
		    same_hash_30b_suffix[i]);
		if (mknod(file, 0600, 0) == -1)
			return ERR("", errno);
	}
	if (stat(p, &st) == -1)
		return ERR("", errno);

	st_want.st_size = st.st_size;

	for (i = 0; shorter_same_hash_30b_suffix[i] != NULL; i++) {
		snprintf(file, sizeof(file), "%s/%s", p,
		    shorter_same_hash_30b_suffix[i]);
		if (mknod(file, 0600, 0) == -1)
			return ERR("", errno);
	}

	/*
	 * See if we can re-insert in a leaf chain that's not at the
	 * end.
	 */
	snprintf(file, sizeof(file), "%s/%s", p,
	    shorter_same_hash_30b_suffix[1]);
	if (unlink(file) == -1)
		return ERR("", errno);
	if (mknod(file, 0600, 0) == -1)
		return ERR("", errno);

	return check_stat(p, &st_want, ST_SIZE);
}

char *
test_lookup_dot_dotdot()
{
	char        *p_root = makepath("");
	char        *p = makepath("lookup_dot_dotdot");
	char        *p2 = makepath("lookup_dot_dotdot/.");
	char        *p3 = makepath("lookup_dot_dotdot/..");
	struct stat  st, st_want_p2, st_want_p3;
	char        *r;

	if (stat(p_root, &st) == -1)
		return ERR("", errno);
	if (mkdir(p, 0755) == -1)
		return ERR("", errno);

	st_want_p3.st_mode = st.st_mode;
	st_want_p3.st_nlink = st.st_nlink + 1;
	st_want_p3.st_ino = st.st_ino;

	if (stat(p, &st) == -1)
		return ERR("", errno);

	st_want_p2.st_mode = (S_IFDIR | 0755);
	st_want_p2.st_nlink = 2;
	st_want_p2.st_ino = st.st_ino;
	if ((r = check_stat(p2, &st_want_p2,
	    ST_MODE|ST_NLINK|ST_INODE)) != NULL)
		return r;

	return check_stat(p3, &st_want_p3, ST_MODE|ST_NLINK|ST_INODE);
}

char *
test_lookup_max_v2_dir_depth()
{
	char        *p = makepath("lookup_v2_max_depth");
	char         file[PATH_MAX];
	int          i;
	struct stat  st_want;

	st_want.st_mode = (S_IFREG | 0600);
	st_want.st_nlink = 1;

	if (mkdir(p, 0755) == -1)
		return ERR("", errno);

	for (i = 0; same_hash_30b_suffix[i] != NULL; i++) {
		snprintf(file, sizeof(file), "%s/%s", p,
		    same_hash_30b_suffix[i]);
		if (mknod(file, 0600, 0) == -1)
			return ERR("", errno);
	}

	return check_stat(file, &st_want, ST_MODE|ST_NLINK);
}

char *
test_unlink_max_v2_dir_depth()
{
	char          *p = makepath("unlink_v2_max_depth");
	char           file[PATH_MAX];
	int           *found;
	int            found_count, i;
	char           msg[1024];

	if (mkdir(p, 0755) == -1)
		return ERR("", errno);

	for (i = 0; same_hash_30b_suffix[i] != NULL; i++) {
		snprintf(file, sizeof(file), "%s/%s", p,
		    same_hash_30b_suffix[i]);
		if (mknod(file, 0600, 0) == -1)
			return ERR("", errno);
	}
	found_count = i;
	found = malloc(sizeof(int) * found_count);
	if (found == NULL)
		err(1, "malloc");
	for (i = 0; i < found_count; i++)
		found[i] = 1;

	/*
	 * Remove an entry at the end, in the middle, and at the start
	 * of our list of files.
	 */
	snprintf(file, sizeof(file), "%s/%s", p, same_hash_30b_suffix[i - 1]);
	if (unlink(file) == -1)
		return ERR("", errno);
	found[i - 1] = 0;
	i--;

	snprintf(file, sizeof(file), "%s/%s", p, same_hash_30b_suffix[i / 2]);
	if (unlink(file) == -1)
		return ERR("", errno);
	found[i / 2] = 0;
	i--;

	snprintf(file, sizeof(file), "%s/%s", p, same_hash_30b_suffix[0]);
	if (unlink(file) == -1)
		return ERR("", errno);
	found[0] = 0;
	i--;

	for (i = 0; same_hash_30b_suffix[i] != NULL; i++) {
		snprintf(file, sizeof(file), "%s/%s", p,
		    same_hash_30b_suffix[i]);
		if (found[i] == 1 && access(file, F_OK) == -1) {
			free(found);
			snprintf(msg, sizeof(msg),
			    "failed to lookup entry #%d that should "
			    "exist after unlinking another file: ", i);
			return ERR(msg, errno);
		}
		if (found[i] == 0 && access(file, F_OK) == 0) {
			free(found);
			snprintf(msg, sizeof(msg),
			    "successful lookup for entry #%d that "
			    "was just unlinked", i);
			return ERR(msg, 0);
		}
	}

	if (rmdir(p) == 0)
		return ERR("successfully removed directory that "
		    "is not empty", 0);
	else if (errno != ENOTEMPTY)
		return ERR("", errno);

	/*
	 * And now delete them all.
	 */
	for (i = 0; i < found_count; i++) {
		if (found[i] == 1) {
			snprintf(file, sizeof(file), "%s/%s", p,
			    same_hash_30b_suffix[i]);
			if (unlink(file) == -1)
				return ERR("", errno);
		}
	}

	if (rmdir(p) == -1)
		return ERR("", errno);

	free(found);
	return NULL;
}

char *
test_dir_freelist()
{
	char        *p = makepath("dir_freelist");
	char         file[PATH_MAX];
	struct stat  st, st_want;
	int          i;

	if (mkdir(p, 0755) == -1)
		return ERR("", errno);

	for (i = 0; same_hash_30b_suffix[i] != NULL; i++) {
		snprintf(file, sizeof(file), "%s/%s", p,
		    same_hash_30b_suffix[i]);
		if (mknod(file, 0600, 0) == -1)
			return ERR("", errno);
	}

	if (stat(p, &st) == -1)
		return ERR("", errno);
	st_want.st_size = st.st_size;
	st_want.st_nlink = st.st_nlink;

	snprintf(file, sizeof(file), "%s/%s", p, same_hash_30b_suffix[0]);
	if (unlink(file) == -1)
		return ERR("", errno);

	if (stat(p, &st) == -1)
		return ERR("", errno);
	if (st.st_size != st_want.st_size)
		return ERR("dir was truncated even though we did not"
		    "remove entries at the end", 0);

	snprintf(file, sizeof(file), "%s/%s", p, same_hash_30b_suffix[0]);
	if (mknod(file, 0600, 0) == -1)
		return ERR("", errno);

	return check_stat(p, &st_want, ST_SIZE|ST_NLINK);
}

char *
test_rmdir_contains_dir()
{
	struct stat  st;
	char        *p = makepath("rmdir-me3");
	char        *p2 = makepath("rmdir-me3/notempty");
	struct stat  st_want;

	st_want.st_mode = (S_IFDIR | 0711);
	st_want.st_nlink = 3;
	st_want.st_uid = getuid();
	st_want.st_gid = getgid();

	if (mkdir(p, 0711) == -1)
		return ERR("", errno);
	if (stat(p, &st) == -1)
		return ERR("", errno);
	if (mkdir(p2, 0700) == -1)
		return ERR("", errno);

	if (rmdir(p) != -1 || errno != ENOTEMPTY)
		return ERR("rmdir() on non-empty directory failed to return "
		    "ENOTEMPTY", 0);

	if (access(p, R_OK|X_OK) == -1)
		return ERR("directory should still exist after rmdir", 0);

	return check_stat(p, &st_want, ST_MODE|ST_NLINK|ST_UID|ST_GID);
}

char *
test_file_size_and_mtime()
{
	struct stat      st_want, st;
	int              fd;
	ssize_t          w;
	char             buf[4096];
	char            *p = makepath("file_size");
	struct timespec  tp;
	char             msg[LINE_MAX];
	off_t            sz;
	struct xerr      e = XLOG_ERR_INITIALIZER;
	struct slab_hdr  hdr;
	void            *slab_data;
	size_t           slab_sz;
	struct slab_key  sk;

	st_want.st_mode = (S_IFREG | 0600);
	st_want.st_nlink = 1;
	st_want.st_size = sizeof(buf) * 2;

	if ((fd = open(p, O_CREAT|O_RDWR|O_SYNC, 0600)) == -1)
		return ERR("", errno);

	bzero(buf, sizeof(buf));

	if ((w = write(fd, buf, sizeof(buf))) < sizeof(buf)) {
		if (w == -1)
			return ERR("", errno);
		return ERR("short write on file", 0);
	}
	sleep(1);

	if (clock_gettime(CLOCK_REALTIME, &tp) == -1)
		return ERR("", errno);

	if ((w = write(fd, buf, sizeof(buf))) < sizeof(buf)) {
		if (w == -1)
			return ERR("", errno);
		return ERR("short write on file", 0);
	}

	if (fstat(fd, &st) == -1)
		return ERR("", errno);
	if (st.st_mtim.tv_sec < tp.tv_sec) {
		snprintf(msg, sizeof(msg),
		    "file mtime not updated after write/sync: "
		    "current=%lu.%lu, want=%lu.%lu",
		    st.st_mtim.tv_sec, st.st_mtim.tv_nsec,
		    tp.tv_sec, tp.tv_nsec);
		return ERR(msg, 0);
	}

	/* The change time should not be updated after a simeple write() */
	if (st.st_ctim.tv_sec < tp.tv_sec) {
		snprintf(msg, sizeof(msg),
		    "file ctime not updated after write: "
		    "current=%lu.%lu, want=%lu.%lu",
		    st.st_ctim.tv_sec, st.st_ctim.tv_nsec,
		    tp.tv_sec, tp.tv_nsec);
		return ERR(msg, 0);
	}

	if ((sz = lseek(fd, 0, SEEK_CUR)) == -1)
		return ERR("", 0);

	if (close(fd) == -1)
		return ERR("", errno);

	if ((slab_data = slab_disk_inspect(slab_key(&sk, st.st_ino, sz),
	    &hdr, &slab_sz, &e)) == NULL) {
		xerr_print(&e);
		return ERR("failed to inspect slab", 0);
	}
	free(slab_data);

	/*
	 * Once we start spilling bytes into slabs, the total slab
	 * sizes should match the file size, even if we use inline data.
	 * This is so that we preserve block alignment.
	 */
	if (slab_sz != sz) {
		snprintf(msg, sizeof(msg),
		    "slab size doesn't match "
		    "total size minus max inline for the inode: "
		    "current=%lu, want=%lu",
		    slab_sz, sz - INODE_INLINE_BYTES);
		return ERR(msg, 0);
	}

	return check_stat(p, &st_want, ST_MODE|ST_NLINK|ST_SIZE);
}

char *
test_symlink()
{
	struct stat  st_want;
	char        *p = makepath("symlink");
	const char  *target = "xyz";

	st_want.st_mode = (S_IFLNK | 0777);
	st_want.st_nlink = 1;
	st_want.st_uid = getuid();
	st_want.st_gid = getgid();
	st_want.st_size = strlen(target);

	if (symlink(target, p) == -1)
		return ERR("", errno);
	return check_stat(p, &st_want, ST_MODE|ST_NLINK|ST_UID|ST_GID|ST_SIZE);
}

char *
test_readlink_path_max()
{
	char            *p = makepath("readlink_path_max");
	char             target[FS_PATH_MAX + 1];
	char             buf[FS_PATH_MAX + 1];
	ssize_t          r;

	memset(target, 'a', FS_PATH_MAX - 1);
	target[FS_PATH_MAX - 1] = '\0';

	if (symlink(target, p) == -1)
		return ERR("", errno);
	if ((r = readlink(p, buf, sizeof(buf))) == -1)
		return ERR("", errno);
	buf[r] = '\0';

	if (strcmp(buf, target) != 0)
		return ERR("readlink doesn't match created symlink", 0);

	if (unlink(p) == -1)
		return ERR("", errno);

	strlcat(target, "a", sizeof(target));
	if (symlink(target, p) == -1 && errno == ENAMETOOLONG)
		return NULL;

	return ERR("symlink created with name in excess of FS_PATH_MAX", 0);
}

char *
test_hardlink()
{
	struct stat  st_want, st;
	char        *p = makepath("hardlink1");
	char        *p2 = makepath("hardlink2");

	st_want.st_mode = (S_IFREG | 0666);
	st_want.st_nlink = 2;
	st_want.st_uid = getuid();
	st_want.st_gid = getgid();
	st_want.st_size = 0;

	if (mknod(p, 0666, 0) == -1)
		return ERR("", errno);
	if (stat(p, &st) == -1)
		return ERR("", errno);

	st_want.st_ino = st.st_ino;

	if (link(p, p2) == -1)
		return ERR("", errno);

	if (link(p, p2) != -1 || errno != EEXIST)
		return ERR("link to an existing target is supposed "
		    "to fail", 0);

	return check_stat(p2, &st_want,
	    ST_INODE|ST_MODE|ST_NLINK|ST_UID|ST_GID|ST_SIZE);
}

char *
test_link_max()
{
	int   i;
	char *d = makepath("link_max");
	char  src[PATH_MAX];
	char  dst[PATH_MAX];
	char  msg[PATH_MAX * 2 + 64];

	if (mkdir(d, 0700) == -1)
		return ERR("", errno);

	snprintf(src, sizeof(src), "%s/hardlink", d);
	if (mknod(src, 0666, 0) == -1)
		return ERR("", errno);

	for (i = 2; i <= FS_LINK_MAX; i++) {
		snprintf(dst, sizeof(dst), "%s/hardlink%d", d, i);
		if (link(src, dst) == -1) {
			snprintf(msg, sizeof(msg),
			    "link: %s -> %s", src, dst);
			return ERR(msg, errno);
		}
	}

	snprintf(dst, sizeof(dst), "%s/hardlink%d", d, i);
	if (link(src, dst) == -1 && errno == EMLINK)
		return NULL;

	return ERR("link succeeded beyond FS_LINK_MAX", 0);
}

char *
test_ctime_after_link()
{
	struct timespec  tp;
	char            *p = makepath("hardlink1_ctime");
	char            *p2 = makepath("hardlink2_ctime");

	if (mknod(p, 0666, 0) == -1)
		return ERR("", errno);
	xnanosleep();
	if (clock_gettime(CLOCK_REALTIME, &tp) == -1)
		return ERR("", errno);
	if (link(p, p2) == -1)
		return ERR("", errno);

	return check_utime_gte(p, &tp, ST_CTIME);
}

char *
test_parent_mtime_after_link()
{
	char            *d1 = makepath("parent_mtime_after_link");
	char            *p1 = makepath("parent_mtime_after_link/x");
	char            *p2 = makepath("parent_mtime_after_link/y");
	struct timespec  tp;

	if (mkdir(d1, 0755) == -1)
		return ERR("", errno);
	if (mknod(p1, 0640, 0) == -1)
		return ERR("", errno);
	xnanosleep();
	if (clock_gettime(CLOCK_REALTIME, &tp) == -1)
		return ERR("", errno);
	if (link(p1, p2) == -1)
		return ERR("", errno);

	return check_utime_gte(d1, &tp, ST_MTIME);
}

char *
test_hardlink_dir()
{
	char *p = makepath("hardlink_dir");
	char *p2 = makepath("hardlink_dir2");

	if (mkdir(p, 0755) == -1)
		return ERR("", errno);

	if (link(p, p2) == -1 && errno == EPERM)
		return NULL;

	return ERR("hardlink to a directory is supposed to fail; "
	    "errno: ", errno);
}

char *
test_rename()
{
	struct stat  st_want, st_root;
	char        *root = makepath("");
	char        *p = makepath("before_move");
	char        *p2 = makepath("after_move");
	char        *r;

	if (stat(root, &st_root) == -1)
		return ERR("", errno);

	if (mknod(p, 0444, 0) == -1)
		return ERR("", errno);

	if (stat(p, &st_want) == -1)
		return ERR("", errno);

	if (rename(p, p2) == -1)
		return ERR("", errno);

	if ((r = check_stat(p2, &st_want,
	    ST_MODE|ST_NLINK|ST_UID|ST_GID|ST_SIZE)) != NULL)
		return r;
	return check_stat(root, &st_root, ST_MODE|ST_NLINK|ST_UID|ST_GID);
}

char *
test_rename_to_self()
{
	struct stat  st_want, st_root;
	char        *p = makepath("move_self");
	char        *root = makepath("");
	char        *r;

	if (mknod(p, 0444, 0) == -1)
		return ERR("", errno);

	if (stat(p, &st_want) == -1)
		return ERR("", errno);
	if (stat(root, &st_root) == -1)
		return ERR("", errno);

	if (rename(p, p) == -1)
		return ERR("", errno);

	if ((r = check_stat(p, &st_want,
	    ST_MODE|ST_NLINK|ST_UID|ST_GID|ST_SIZE)) != NULL)
		return r;
	return check_stat(root, &st_root,
	    ST_MODE|ST_NLINK|ST_UID|ST_GID|ST_SIZE);
}

char *
test_rename_replace()
{
	struct stat  st_want, st_unlink, st_root;
	char        *root = makepath("");
	char        *p1 = makepath("before_move_replace");
	char        *p2 = makepath("after_move_replace");
	ino_t        gone;
	struct xerr  e = XLOG_ERR_INITIALIZER;
	int          i = 0;
	char        *r;

	if (stat(root, &st_root) == -1)
		return ERR("", errno);

	if (mknod(p1, 0444, 0) == -1)
		return ERR("", errno);
	if (mknod(p2, 0666, 0) == -1)
		return ERR("", errno);

	if (stat(p1, &st_want) == -1)
		return ERR("", errno);
	if (stat(p2, &st_unlink) == -1)
		return ERR("", errno);
	gone = st_unlink.st_ino;

	if (rename(p1, p2) == -1)
		return ERR("", errno);

	if (access(p1, F_OK) != -1)
		return ERR("old file was not removed", 0);

	/*
	 * We have to sleep until FUSE calls FORGET on the inode, which
	 * when nlookup is 0, the inode will be deallocated.
	 */
	for (i = 5; i > 0; i--) {
		if (get_disk_inode(gone, NULL, &e) == -1) {
			if (!xerr_is(&e, XLOG_FS, ENOENT)) {
				xerr_print(&e);
				return ERR("error querying inode", 0);
			}
			break;
		}
		xnanosleep();
	}
	if (i == 0)
		return ERR("file still exists on-disk after unlink", 0);

	if ((r = check_stat(p2, &st_want,
	    ST_MODE|ST_NLINK|ST_UID|ST_GID|ST_SIZE)) != NULL)
		return r;
	return check_stat(root, &st_root, ST_MODE|ST_NLINK|ST_UID|ST_GID);
}

char *
test_rename_crossdir()
{
	struct stat      st_want, st_want_d1, st_want_d2;
	char            *d1 = makepath("crossdir1");
	char            *d2 = makepath("crossdir2");
	char            *p1 = makepath("crossdir1/moved");
	char            *p2 = makepath("crossdir2/moved");
	char            *r;
	struct timespec  tp;

	if (mkdir(d1, 0700) == -1)
		return ERR("", errno);
	if (mkdir(d2, 0700) == -1)
		return ERR("", errno);

	if (mknod(p1, 0444, 0) == -1)
		return ERR("", errno);
	if (stat(p1, &st_want) == -1)
		return ERR("", errno);

	if (stat(d1, &st_want_d1) == -1)
		return ERR("", errno);
	if (stat(d2, &st_want_d2) == -1)
		return ERR("", errno);

	xnanosleep();
	if (clock_gettime(CLOCK_REALTIME, &tp) == -1)
		return ERR("", errno);
	if (rename(p1, p2) == -1)
		return ERR("", errno);

	if ((r = check_stat(d1, &st_want_d1,
	    ST_MODE|ST_NLINK|ST_UID|ST_GID)) != NULL)
		return r;
	if ((r = check_stat(d2, &st_want_d2,
	    ST_MODE|ST_NLINK|ST_UID|ST_GID)) != NULL)
		return r;

	if ((r = check_utime_gte(p2, &tp, ST_CTIME)) != NULL)
		return r;

	return check_stat(p2, &st_want,
	    ST_MODE|ST_NLINK|ST_UID|ST_GID|ST_SIZE);
}

char *
test_rename_dir_crossdir()
{
	struct stat      st_want, st_want_d1, st_want_d2;
	char            *d1 = makepath("dir_crossdir1");
	char            *d2 = makepath("dir_crossdir2");
	char            *p1 = makepath("dir_crossdir1/moved");
	char            *p2 = makepath("dir_crossdir2/moved");
	char            *r;
	struct timespec  tp;

	if (mkdir(d1, 0700) == -1)
		return ERR("", errno);
	if (mkdir(d2, 0700) == -1)
		return ERR("", errno);

	if (mkdir(p1, 0700) == -1)
		return ERR("", errno);
	if (stat(p1, &st_want) == -1)
		return ERR("", errno);

	if (stat(d1, &st_want_d1) == -1)
		return ERR("", errno);
	if (stat(d2, &st_want_d2) == -1)
		return ERR("", errno);

	xnanosleep();
	if (clock_gettime(CLOCK_REALTIME, &tp) == -1)
		return ERR("", errno);
	if (rename(p1, p2) == -1)
		return ERR("", errno);

	st_want_d1.st_nlink--;
	if ((r = check_stat(d1, &st_want_d1,
	    ST_MODE|ST_NLINK|ST_UID|ST_GID)) != NULL)
		return r;
	st_want_d2.st_nlink++;
	if ((r = check_stat(d2, &st_want_d2,
	    ST_MODE|ST_NLINK|ST_UID|ST_GID)) != NULL)
		return r;

	if ((r = check_utime_gte(p2, &tp, ST_CTIME)) != NULL)
		return r;

	return check_stat(p2, &st_want,
	    ST_MODE|ST_NLINK|ST_UID|ST_GID|ST_SIZE);
}

char *
test_rename_replace_crossdir()
{
	struct stat       st_want, st_unlink;
	char             *d1 = makepath("crossdir_replace1");
	char             *d2 = makepath("crossdir_replace2");
	char             *p1 = makepath("crossdir_replace1/x");
	char             *p2 = makepath("crossdir_replace2/y");
	ino_t             gone;
	struct xerr       e = XLOG_ERR_INITIALIZER;
	int               i = 0;

	if (mkdir(d1, 0700) == -1)
		return ERR("", errno);
	if (mkdir(d2, 0700) == -1)
		return ERR("", errno);

	if (mknod(p1, 0444, 0) == -1)
		return ERR("", errno);
	if (mknod(p2, 0666, 0) == -1)
		return ERR("", errno);

	if (stat(p1, &st_want) == -1)
		return ERR("", errno);
	if (stat(p2, &st_unlink) == -1)
		return ERR("", errno);
	gone = st_unlink.st_ino;

	if (rename(p1, p2) == -1)
		return ERR("", errno);

	/*
	 * We have to sleep until FUSE calls FORGET on the inode, which
	 * when nlookup is 0, the inode will be deallocated.
	 */
	for (i = 5; i > 0; i--) {
		if (get_disk_inode(gone, NULL, &e) == -1) {
			if (!xerr_is(&e, XLOG_FS, ENOENT)) {
				xerr_print(&e);
				return ERR("error querying inode", 0);
			}
			break;
		}
		xnanosleep();
	}
	if (i == 0)
		return ERR("file still exists on-disk after unlink", 0);

	return check_stat(p2, &st_want,
	    ST_MODE|ST_NLINK|ST_UID|ST_GID|ST_SIZE);
}

char *
test_rename_to_descendant()
{
	char *d1 = makepath("rename_descendant");
	char *d2 = makepath("rename_descendant/x");
	char *d3 = makepath("rename_descendant/x/y");
	char *d4 = makepath("rename_descendant/x/y/z");

	if (mkdir(d1, 0700) == -1)
		return ERR("", errno);
	if (mkdir(d2, 0700) == -1)
		return ERR("", errno);
	if (mkdir(d3, 0700) == -1)
		return ERR("", errno);
	if (mkdir(d4, 0700) == -1)
		return ERR("", errno);

	if (rename(d2, d3) == -1) {
		if (errno != EINVAL)
			return ERR("", errno);
		return NULL;
	}
	if (rename(d2, d4) == -1) {
		if (errno != EINVAL)
			return ERR("", errno);
		return NULL;
	}
	return ERR("rename to descendant should return EINVAL", 0);
}

char *
test_rename_to_ancestor()
{
	char *d1 = makepath("rename_ancestor");
	char *d2 = makepath("rename_ancestor/x");
	char *d3 = makepath("rename_ancestor/x/y");
	char *d4 = makepath("rename_ancestor/x/y/z");

	if (mkdir(d1, 0700) == -1)
		return ERR("", errno);
	if (mkdir(d2, 0700) == -1)
		return ERR("", errno);
	if (mkdir(d3, 0700) == -1)
		return ERR("", errno);
	if (mkdir(d4, 0700) == -1)
		return ERR("", errno);

	if (rename(d3, d2) == -1) {
		if (errno != ENOTEMPTY)
			return ERR("", errno);
		return NULL;
	}
	if (rename(d4, d2) == -1) {
		if (errno != ENOTEMPTY)
			return ERR("", errno);
		return NULL;
	}
	return ERR("rename to ancestor should return EINVAL", 0);
}

char *
test_rename_nondir_to_dir()
{
	char *d = makepath("rename_nondir_to_dir");
	char *p1 = makepath("rename_nondir_to_dir/x");
	char *p2 = makepath("rename_nondir_to_dir/d");

	if (mkdir(d, 0700) == -1)
		return ERR("", errno);
	if (mknod(p1, 0400, 0) == -1)
		return ERR("", errno);
	if (mkdir(p2, 0700) == -1)
		return ERR("", errno);

	if (rename(p1, p2) == -1) {
		if (errno != EISDIR)
			return ERR("", errno);
		return NULL;
	}
	return ERR("rename from non-dir to dir should fail with EISDIR", 0);
}

char *
test_rename_dir_to_nondir()
{
	char *d = makepath("rename_dir_to_nondir");
	char *p1 = makepath("rename_dir_to_nondir/x");
	char *p2 = makepath("rename_dir_to_nondir/d");

	if (mkdir(d, 0700) == -1)
		return ERR("", errno);
	if (mknod(p1, 0400, 0) == -1)
		return ERR("", errno);
	if (mkdir(p2, 0700) == -1)
		return ERR("", errno);

	if (rename(p1, p2) == -1) {
		if (errno != EISDIR)
			return ERR("", errno);
		return NULL;
	}
	return ERR("rename from dir to non-dir should fail with "
	    "ENOTDIR (or EISDIR if FUSE handles it)", 0);
}

char *
test_rename_crossdir_nondir_to_dir()
{
	char *d1 = makepath("rename_crossdir_nondir_to_dir1");
	char *d2 = makepath("rename_crossdir_nondir_to_dir2");
	char *p1 = makepath("rename_crossdir_nondir_to_dir1/x");
	char *p2 = makepath("rename_crossdir_nondir_to_dir2/d");

	if (mkdir(d1, 0700) == -1)
		return ERR("", errno);
	if (mkdir(d2, 0700) == -1)
		return ERR("", errno);
	if (mknod(p1, 0400, 0) == -1)
		return ERR("", errno);
	if (mkdir(p2, 0700) == -1)
		return ERR("", errno);

	if (rename(p1, p2) == -1) {
		if (errno != EISDIR)
			return ERR("", errno);
		return NULL;
	}
	return ERR("rename from non-dir to dir should fail with EISDIR", 0);
}

char *
test_rename_crossdir_dir_to_nondir()
{
	char *d1 = makepath("rename_crossdir_dir_to_nondir1");
	char *d2 = makepath("rename_crossdir_dir_to_nondir2");
	char *p1 = makepath("rename_crossdir_dir_to_nondir1/d");
	char *p2 = makepath("rename_crossdir_dir_to_nondir2/x");

	if (mkdir(d1, 0700) == -1)
		return ERR("", errno);
	if (mkdir(d2, 0700) == -1)
		return ERR("", errno);
	if (mkdir(p1, 0700) == -1)
		return ERR("", errno);
	if (mknod(p2, 0400, 0) == -1)
		return ERR("", errno);

	if (rename(p1, p2) == -1) {
		if (errno != ENOTDIR)
			return ERR("", errno);
		return NULL;
	}
	return ERR("rename from non-dir to dir should fail with ENOTDIR", 0);
}

char *
test_rename_dir_to_existing_emtpy_dir()
{
	char        *d = makepath("rename_dir_to_dir");
	char        *p1 = makepath("rename_dir_to_dir/x");
	char        *p2 = makepath("rename_dir_to_dir/d");
	struct stat  st_want;

	if (mkdir(d, 0700) == -1)
		return ERR("", errno);
	if (mkdir(p1, 0700) == -1)
		return ERR("", errno);
	if (mkdir(p2, 0700) == -1)
		return ERR("", errno);

	if (stat(d, &st_want) == -1)
		return ERR("", errno);

	if (rename(p1, p2) == -1)
		return ERR("", errno);
	st_want.st_nlink--;

	return check_stat(d, &st_want, ST_MODE|ST_NLINK|ST_UID|ST_GID);
}

char *
test_rename_dir_to_existing_nonemtpy_dir()
{
	char        *d = makepath("rename_dir_to_nonempty_dir");
	char        *p1 = makepath("rename_dir_to_nonempty_dir/x");
	char        *p2 = makepath("rename_dir_to_nonempty_dir/d");
	char        *p3 = makepath("rename_dir_to_nonempty_dir/d/x");

	if (mkdir(d, 0700) == -1)
		return ERR("", errno);
	if (mkdir(p1, 0700) == -1)
		return ERR("", errno);
	if (mkdir(p2, 0700) == -1)
		return ERR("", errno);
	if (mknod(p3, 0400, 0) == -1)
		return ERR("", errno);

	if (rename(p1, p2) == -1) {
		if (errno == ENOTEMPTY)
			return NULL;
		return ERR("", errno);
	}

	return ERR("replacing non-empty dir should fail", 0);
}

char *
test_rename_root_inode()
{
	char *d = makepath("fail_with_root_inode");
	char *p1 = makepath("fail_with_root_inode/x");
	char *p2 = makepath("");

	if (mkdir(d, 0700) == -1)
		return ERR("", errno);
	if (mknod(p1, 0600, 0) == -1)
		return ERR("", errno);

	if (rename(p1, p2) == -1) {
		/*
		 * We can't easily test EBUSY, because FUSE catches
		 * most errors. Still, just in case ...
		 */
		if (errno != EBUSY && errno != EXDEV)
			return ERR("", errno);
	} else
		return ERR("renaming or replacing root inode should fail", 0);

	if (rename(p2, p1) == -1) {
		/*
		 * We can't easily test EBUSY, because FUSE catches
		 * most errors. Still, just in case ...
		 */
		if (errno != EBUSY && errno != EXDEV)
			return ERR("", errno);
		return NULL;
	}
	return ERR("renaming or replacing root inode should fail", 0);
}

char *
test_parents_mtime_after_rename()
{
	char            *d1 = makepath("parent_mtime_after_rename1");
	char            *d2 = makepath("parent_mtime_after_rename2");
	char            *p1 = makepath("parent_mtime_after_rename1/x");
	char            *p2 = makepath("parent_mtime_after_rename2/y");
	char            *r;
	struct timespec  tp;

	if (mkdir(d1, 0755) == -1)
		return ERR("", errno);
	if (mkdir(d2, 0755) == -1)
		return ERR("", errno);
	if (mknod(p1, 0640, 0) == -1)
		return ERR("", errno);
	xnanosleep();
	if (clock_gettime(CLOCK_REALTIME, &tp) == -1)
		return ERR("", errno);
	if (rename(p1, p2) == -1)
		return ERR("", errno);

	if ((r = check_utime_gte(d1, &tp, ST_MTIME)) != NULL)
		return r;
	return check_utime_gte(d2, &tp, ST_MTIME);
}

char *
test_file_content()
{
	struct stat      st_want, st;
	int              fd, i;
	ssize_t          r, w;
	char             buf[4096];
	char             path[4096];
	char            *p = makepath("create_file");
	struct xerr      e = XLOG_ERR_INITIALIZER;
	char             msg[PATH_MAX + 1024];
	ino_t            ino;
	struct slab_key  sk;

	st_want.st_mode = (S_IFREG | 0600);
	st_want.st_nlink = 1;
	st_want.st_size = SLAB_SIZE_DEFAULT * 2;

	if ((fd = open(p, O_CREAT|O_RDWR, 0600)) == -1)
		return ERR("", errno);

	/* Fill the inline bytes with 'a', the rest with 'b' */
	for (i = 0; i < sizeof(buf); i++)
		buf[i] = (i < INODE_INLINE_BYTES) ? 'a': 'b';
	if ((w = write(fd, buf, sizeof(buf))) < sizeof(buf)) {
		if (w == -1)
			return ERR("", errno);
		return ERR("short write on file", 0);
	}

	/* The second block in the file has no inline bytes, so all 'b' */
	for (i = 0; i < sizeof(buf); i++)
		buf[i] = 'c';
	for (i = sizeof(buf); i < SLAB_SIZE_DEFAULT; i += w) {
		if ((w = write(fd, buf, sizeof(buf))) < sizeof(buf)) {
			if (w == -1)
				return ERR("", errno);
			return ERR("short write on file", 0);
		}
	}

	for (i = 0; i < sizeof(buf); i++)
		buf[i] = 'd';
	for (i = 0; i < SLAB_SIZE_DEFAULT; i += w) {
		if ((w = write(fd, buf, sizeof(buf))) < sizeof(buf)) {
			if (w == -1)
				return ERR("", errno);
			return ERR("short write on file", 0);
		}
	}

	if (fsync(fd) == -1)
		return ERR("", errno);
	if (fstat(fd, &st) == -1)
		return ERR("", errno);
	ino = st.st_ino;
	if (close(fd) == -1)
		return ERR("", errno);

	/*
	 * The first slab should start having 'b' after inline bytes
	 * are exhausted in the inode. For the inline bytes, they should
	 * be \0, since they're actually stored in the inode.
	 */
	if (slab_path(path, sizeof(path), slab_key(&sk, ino, 0), 0, &e) == -1) {
		xerr_print(&e);
		return ERR("failed to get slab path", 0);
	}
	if ((fd = open(path, O_RDONLY)) == -1)
		return ERR("", errno);
	if (lseek(fd, sizeof(struct slab_hdr), SEEK_SET) == -1)
		return ERR("", errno);

	if ((r = read(fd, buf, sizeof(buf))) == -1)
		return ERR("", errno);
	if (r < sizeof(buf))
		return ERR("short read on first slab", 0);
	for (i = 0; i < sizeof(buf); i++) {
		if (buf[i] != ((i < INODE_INLINE_BYTES) ? '\0': 'b')) {
			snprintf(msg, sizeof(msg),
			    "unexpected byte in slab %s; "
			    "current=0x%x, want=%s", path, buf[i],
			    (i < INODE_INLINE_BYTES) ? "\\0": "b");
			return ERR(msg, 0);
		}
	}

	for (; i < SLAB_SIZE_DEFAULT; i += r) {
		if ((r = read(fd, buf, sizeof(buf))) == -1)
			return ERR("", errno);
		if (r < sizeof(buf))
			return ERR("short read on first slab", 0);
		for (; i < sizeof(buf); i++) {
			if (buf[i] != 'c') {
				snprintf(msg, sizeof(msg),
				    "unexpected byte in slab %s; "
				    "current=0x%x, want='b'",
				    path, buf[i]);
				return ERR(msg, 0);
			}
		}
	}
	if (fstat(fd, &st) == -1)
		return ERR("", errno);
	close(fd);
	if (st.st_size < sizeof(struct slab_hdr) + SLAB_SIZE_DEFAULT) {
		snprintf(msg, sizeof(msg),
		    "slab (%s) size is smaller than what it should be: "
		    "current=%lu, want=%lu",
		    path, st.st_size,
		    sizeof(struct slab_hdr) + SLAB_SIZE_DEFAULT);
		return ERR(msg, 0);
	}

	/*
	 * The second slab should be all 'd'.
	 */
	if (slab_path(path, sizeof(path),
	    slab_key(&sk, ino, SLAB_SIZE_DEFAULT), 0, &e) == -1) {
		xerr_print(&e);
		return ERR("failed to get slab path", 0);
	}
	if ((fd = open(path, O_RDONLY)) == -1)
		return ERR("", errno);
	if (lseek(fd, sizeof(struct slab_hdr), SEEK_SET) == -1)
		return ERR("", errno);
	for (i = 0; i < SLAB_SIZE_DEFAULT; i += r) {
		if ((r = read(fd, buf, sizeof(buf))) == -1)
			return ERR("", errno);
		if (r < sizeof(buf))
			return ERR("short read on first slab", 0);
		for (; i < sizeof(buf); i++) {
			if (buf[i] != 'd') {
				snprintf(msg, sizeof(msg),
				    "unexpected byte in slab %s; "
				    "current=0x%x, want='c'",
				    path, buf[i]);
				return ERR(msg, 0);
			}
		}
	}
	if (fstat(fd, &st) == -1)
		return ERR("", errno);
	close(fd);
	if (st.st_size < sizeof(struct slab_hdr) + SLAB_SIZE_DEFAULT) {
		snprintf(msg, sizeof(msg),
		    "slab (%s) size is smaller than what it should be: "
		    "current=%lu, want=%lu",
		    path, st.st_size,
		    sizeof(struct slab_hdr) + SLAB_SIZE_DEFAULT);
		return ERR(msg, 0);
	}

	return check_stat(p, &st_want, ST_MODE|ST_NLINK|ST_SIZE);
}

char *
test_fallocate()
{
	int          fd, i;
	char        *p = makepath("fallocated");
	struct stat  st, st_want;
	char         buf[6001];
	char         bytes[4096];
	ssize_t      r;

	st_want.st_mode = (S_IFREG | 0600);
	st_want.st_nlink = 1;
	st_want.st_size = sizeof(buf) - 1;

	for (i = 0; i < sizeof(bytes); i++)
		bytes[i] = 'a';

	if ((fd = open(p, O_CREAT|O_RDWR|O_SYNC, 0600)) == -1)
		return ERR("", errno);

	if ((r = write(fd, bytes, sizeof(bytes))) == -1)
		return ERR("", errno);
	if (r < sizeof(bytes))
		return ERR("short write on file", 0);

	if (fallocate(fd, 0, 1000, st_want.st_size - 1000) == -1)
		return ERR("", errno);

	if (fstat(fd, &st) == -1)
		return ERR("", errno);

	if ((r = pread(fd, buf, sizeof(buf), 0)) == -1)
		return ERR("", errno);
	if (r != st_want.st_size)
		return ERR("size after fallocate() is not what we expect", 0);
	for (i = 0; i < sizeof(bytes); i++) {
		if (buf[i] != 'a')
			return ERR("first 4K bytes should be 'a'", 0);
	}
	for (; i < st_want.st_size; i++) {
		if (buf[i] != '\0')
			return ERR("all bytes in fallocate()'dd area should "
			    "be \\0", 0);
	}
	close(fd);

	return check_stat(p, &st_want, ST_MODE|ST_NLINK|ST_SIZE);
}

char *
test_fallocate_large()
{
	int              fd;
	char            *p = makepath("fallocated_large");
	struct stat      st, st_want;
	char             path[PATH_MAX];
	char             msg[PATH_MAX + 1024];
	struct xerr      e = XLOG_ERR_INITIALIZER;
	struct slab_key  sk;

	st_want.st_mode = (S_IFREG | 0600);
	st_want.st_nlink = 1;
	st_want.st_size = slab_get_max_size() * 2;

	if ((fd = open(p, O_CREAT|O_RDWR|O_SYNC, 0600)) == -1)
		return ERR("", errno);

	if (fallocate(fd, 0, 5000, st_want.st_size - 5000) == -1)
		return ERR("", errno);

	if (fstat(fd, &st) == -1)
		return ERR("", errno);

	close(fd);

	if (slab_path(path, sizeof(path),
	    slab_key(&sk, st.st_ino, slab_get_max_size()), 0, &e) == -1) {
		xerr_print(&e);
		return ERR("failed to get slab path", 0);
	}

	if (stat(path, &st) == -1) {
		snprintf(msg, sizeof(msg),
		    "failed to stat slab %s at offset %lu: ",
		    path, slab_get_max_size());
		return ERR(msg, errno);
	}

	if ((st.st_size - sizeof(struct slab_hdr)) > 0)
		return ERR("empty slab following fallocate() is missing "
		    "at the end of the file", 0);

	return check_stat(p, &st_want, ST_MODE|ST_NLINK|ST_SIZE);
}

char *
test_truncate()
{
	int              fd, i;
	char            *p = makepath("truncate");
	struct stat      st, st_want;
	char             path[PATH_MAX];
	char             msg[PATH_MAX + 1024];
	char             buf[BUFSIZ];
	struct xerr      e = XLOG_ERR_INITIALIZER;
	struct slab_key  sk;
	ssize_t          r;
	off_t            sz, off;
	size_t           slab_sz;
	void            *data;
	struct slab_hdr  hdr;
	ino_t            ino;

	sz = slab_get_max_size() * 3;
	st_want.st_nlink = 1;
	st_want.st_size = slab_get_max_size() + (slab_get_max_size() / 2);

	for (i = 0; i < sizeof(buf); i++)
		buf[i] = 'a';
	if ((fd = open(p, O_CREAT|O_RDWR|O_SYNC, 0600)) == -1)
		return ERR("", errno);

	while (i < sz) {
		if ((r = write(fd, buf, sizeof(buf))) == -1)
			return ERR("", errno);
		i += r;
	}

	/*
	 * Truncate halfway through the second slab.
	 */
	if (ftruncate(fd, st_want.st_size) == -1)
		return ERR("", errno);

	if (fstat(fd, &st) == -1)
		return ERR("", errno);

	close(fd);

	ino = st.st_ino;

	for (off = 0; off < sz; off += slab_get_max_size()) {
		if (slab_path(path, sizeof(path),
		    slab_key(&sk, ino, off), 0, &e) == -1) {
			xerr_print(&e);
			return ERR("failed to get slab path", 0);
		}

		if ((data = slab_disk_inspect(slab_key(&sk, ino,
		    off), &hdr, &slab_sz, &e)) == NULL) {
			xerr_print(&e);
			return ERR("failed to inspect slab", 0);
		}
		free(data);

		if (stat(path, &st) == -1) {
			snprintf(msg, sizeof(msg),
			    "failed to stat slab %s at offset %lu: ",
			    path, off);
			return ERR(msg, errno);
		}

		if (off == 0) {
			if (st.st_size <
			    (sizeof(struct slab_hdr) + slab_get_max_size()))
				return ERR("first slab is less than its "
				    "full size; we truncated the "
				    "wrong slab!", 0);
			if (hdr.v.f.flags & SLAB_REMOVED)
				return ERR("slab marked as removed, "
				    "but should not", 0);
		} else if (off > st_want.st_size) {
			if (st.st_size > sizeof(struct slab_hdr))
				return ERR("truncated slab is larger "
				    "than the slab header", 0);
			if (!(hdr.v.f.flags & SLAB_REMOVED))
				return ERR("slab should be marked as removed, "
				    "but isn't", 0);
		} else {
			if (st.st_size !=
			    (sizeof(struct slab_hdr) +
			     (st_want.st_size % slab_get_max_size())))
				return ERR("truncated slab is the "
				    "wrong size", 0);
			if (hdr.v.f.flags & SLAB_REMOVED)
				return ERR("slab marked as removed, "
				    "but should not", 0);
		}
	}

	return check_stat(p, &st_want, ST_NLINK|ST_SIZE);
}

char *
test_truncate_less_than_inline()
{
	int              fd, i;
	char            *p = makepath("truncate_less_than_inline");
	struct stat      st, st_want;
	char             path[PATH_MAX];
	char             msg[PATH_MAX + 1024];
	char             buf[BUFSIZ];
	struct xerr      e = XLOG_ERR_INITIALIZER;
	struct slab_key  sk;
	ssize_t          r;
	off_t            sz, off;
	size_t           slab_sz;
	void            *data;
	struct slab_hdr  hdr;
	ino_t            ino;

	sz = (slab_get_max_size() * 2) + (slab_get_max_size() / 2);
	st_want.st_nlink = 1;
	st_want.st_size = 5;

	for (i = 0; i < sizeof(buf); i++)
		buf[i] = 'a';
	if ((fd = open(p, O_CREAT|O_RDWR|O_SYNC, 0600)) == -1)
		return ERR("", errno);

	/* 2.5x slab size, so we truncate from different offsets */
	while (i < sz) {
		if ((r = write(fd, buf, sizeof(buf))) == -1)
			return ERR("", errno);
		i += r;
	}

	/*
	 * Truncate to 5. We explicitly don't pick zero, because
	 * we want to confirm that the slab is truncated to zero
	 * anyway. This is because all 5 bytes now fit within the inode's
	 * inline bytes and therefore the underlying slab isn't useful,
	 * and should essentially be marked for removal.
	 */
	if (ftruncate(fd, st_want.st_size) == -1)
		return ERR("", errno);

	if (fstat(fd, &st) == -1)
		return ERR("", errno);

	close(fd);

	ino = st.st_ino;

	for (off = 0; off < sz; off += slab_get_max_size()) {
		if (slab_path(path, sizeof(path),
		    slab_key(&sk, ino, off), 0, &e) == -1) {
			xerr_print(&e);
			return ERR("failed to get slab path", 0);
		}

		if ((data = slab_disk_inspect(slab_key(&sk, ino,
		    off), &hdr, &slab_sz, &e)) == NULL) {
			xerr_print(&e);
			return ERR("failed to inspect slab", 0);
		}
		free(data);
		if (!(hdr.v.f.flags & SLAB_REMOVED))
			return ERR("slab should be marked as removed, "
			    "but isn't", 0);
		if (stat(path, &st) == -1) {
			snprintf(msg, sizeof(msg),
			    "failed to stat slab %s at offset %lu: ",
			    path, off);
			return ERR(msg, errno);
		}

		if (st.st_size > sizeof(struct slab_hdr))
			return ERR("truncated slab is larger "
			    "than the slab header", 0);
	}

	return check_stat(p, &st_want, ST_NLINK|ST_SIZE);
}

char *
test_delayed_truncate_large()
{
	int                fd, slab_fd, i, mgr;
	char              *p = makepath("delayed_truncate_large");
	struct stat        st;
	char               path[PATH_MAX];
	char               buf[BUFSIZ];
	char               msg[PATH_MAX + 1024];
	struct xerr        e = XLOG_ERR_INITIALIZER;
	struct slab_key    sk;
	ssize_t            r;
	off_t              sz, off;
	size_t             slab_sz;
	ino_t              ino;
	struct slabdb_val  v;
	struct mgr_msg     m;
	void              *data;
	struct slab_hdr    hdr;

	sz = (slab_get_max_size() * 2) + (slab_get_max_size() / 2);

	for (i = 0; i < sizeof(buf); i++)
		buf[i] = 'a';
	if ((fd = open(p, O_CREAT|O_RDWR|O_SYNC, 0600)) == -1)
		return ERR("", errno);

	while (i < sz) {
		if ((r = write(fd, buf, sizeof(buf))) == -1)
			return ERR("", errno);
		i += r;
	}

	if (fstat(fd, &st) == -1)
		return ERR("", errno);

	/*
	 * Wait for each slab involved in our large file to be
	 * released by the fs, then truncate. This should be
	 * sufficient to trigger a delayed truncation.
	 */
	for (i = 0; i < sz; i += slab_get_max_size()) {
		if (slab_path(path, sizeof(path),
		    slab_key(&sk, st.st_ino, i), 0, &e) == -1) {
			xerr_print(&e);
			return ERR("failed to get slab path", 0);
		}
		if ((slab_fd = open(path, O_RDONLY)) == -1)
			return ERR("", errno);

		/* Wait for the fs/mgr to release the claim on the slab. */
		if (flock(slab_fd, LOCK_EX) == -1)
			return ERR("", errno);

		close(slab_fd);
	}

	if (ftruncate(fd, 0) == -1)
		return ERR("", errno);

	close(fd);

	ino = st.st_ino;

	for (off = 0; off < sz; off += slab_get_max_size()) {
		if (slab_path(path, sizeof(path),
		    slab_key(&sk, ino, off), 0, &e) == -1) {
			xerr_print(&e);
			return ERR("failed to get slab path", 0);
		}

		if (slabdb_get(&sk, &v, OSLAB_NOCREATE, &e) == -1) {
			xerr_print(&e);
			return ERR("failed to get slab from slabdb", 0);
		}

		if (!(v.flags & SLABDB_FLAG_TRUNCATE) ||
		    v.truncate_offset != 0) {
			return ERR("slab not marked for truncation at "
			    "0 offset", 0);
		}
	}

	/*
	 * Call for an explicit scrub pass to ensure delayed
	 * truncations are processed.
	 */
	if ((mgr = mgr_connect(1, xerrz(&e))) == -1) {
		xerr_print(&e);
		return ERR("failed to connect to mgr", 0);
	}
	m.m = MGR_MSG_SCRUB;
	if (mgr_send(mgr, -1, &m, xerrz(&e)) == -1) {
		xerr_print(&e);
		return ERR("failed to send to mgr", 0);
	}
	if (mgr_recv(mgr, NULL, &m, xerrz(&e)) == -1) {
		xerr_print(&e);
		return ERR("failed to recv from mgr", 0);
	}
	close(mgr);

	/*
	 * Check that slabs are actually truncated.
	 */
	for (off = 0; off < sz; off += slab_get_max_size()) {
		if (slab_path(path, sizeof(path),
		    slab_key(&sk, ino, off), 0, &e) == -1) {
			xerr_print(&e);
			return ERR("failed to get slab path", 0);
		}

		if ((data = slab_disk_inspect(slab_key(&sk, ino,
		    sz), &hdr, &slab_sz, &e)) == NULL) {
			xerr_print(&e);
			return ERR("failed to inspect slab", 0);
		}
		free(data);
		if (!(hdr.v.f.flags & SLAB_REMOVED))
			return ERR("slab should be marked as removed, "
			    "but isn't", 0);
		if (stat(path, &st) == -1) {
			snprintf(msg, sizeof(msg),
			    "failed to stat slab %s at offset %lu: ",
			    path, off);
			return ERR(msg, errno);
		}

		if (st.st_size > sizeof(struct slab_hdr))
			return ERR("truncated slab is larger "
			    "than the slab header", 0);
	}

	return NULL;
}

char *
test_many_inodes()
{
	char           path[PATH_MAX];
	char          *d = makepath("many_inodes");
	int            i, n_inodes = slab_inode_max() + 1;
	struct inode   inode;
	struct xerr    e;
	DIR           *dir;
	struct dirent *de;
	char           msg[LINE_MAX];

	if (mkdir(d, 0700) == -1)
		return ERR("", errno);

	for (i = 0; i < n_inodes; i++) {
		snprintf(path, sizeof(path), "%s/%d", d, i);
		if (mknod(path, 0644, 0) == -1)
			return ERR("", errno);
	}

	if ((dir = opendir(d)) == NULL)
		return ERR("", errno);
	errno = 0;
	i = 0;
	while ((de = readdir(dir))) {
		if (inode_disk_inspect(de->d_ino, &inode, xerrz(&e)) == -1) {
			xerr_print(&e);
			return ERR("reading inode failed", 0);
		}
		i++;
	}
	closedir(dir);

	if ((i - 2) != n_inodes) {
		snprintf(msg, sizeof(msg),
		    "inode count is not what it should be; want=%d, actual=%d",
		    n_inodes, i);
		return ERR(msg, 0);
	}
	return NULL;
}

char *
inode_reuse()
{
	struct stat    st;
	struct inode   inode;
	unsigned long  gen;
	char          *p = makepath("reuse_me");
	struct xerr    e = XLOG_ERR_INITIALIZER;
	char           msg[1024];

	if (mknod(p, 0640, 0) == -1)
		return ERR("", errno);
	if (stat(p, &st) == -1)
		return ERR("", errno);
	if (inode_disk_inspect(st.st_ino, &inode, &e) == -1) {
		xerr_print(&e);
		return ERR("reading inode failed", 0);
	}
	gen = inode.v.f.generation;
	if (unlink(p) == -1)
		return ERR("", errno);

	if (mknod(p, 0640, 0) == -1)
		return ERR("", errno);

	if (inode_disk_inspect(st.st_ino, &inode, &e) == -1) {
		xerr_print(&e);
		return ERR("reading inode failed", 0);
	}

	if (inode.v.f.generation != gen + 1) {
		snprintf(msg, sizeof(msg),
		    "generation was not incremented by inode %lu reuse: "
		    "current=%lu, want=%lu",
		    st.st_ino, inode.v.f.generation, gen + 1);
		return ERR(msg, 0);
	}
	return NULL;
}

char *
test_clock_gettime()
{
	struct timespec tp;
	if (clock_gettime(CLOCK_REALTIME, &tp) == -1)
		return ERR("CLOCK_REALTIME", errno);
	if (clock_gettime(CLOCK_MONOTONIC, &tp) == -1)
		return ERR("CLOCK_MONOTONIC", errno);
	return NULL;
}

char *
test_xlog_over_line_max()
{
	int         i;
	char        msg[LINE_MAX * 2];
	struct xerr e = XLOG_ERR_INITIALIZER;

	for (i = 0; i < sizeof(msg) - 1; i++)
		msg[i] = 'a';
	msg[i] = '\0';
	xerrf(&e, XLOG_APP, XLOG_INVAL, msg);
	if (e.msg[LINE_MAX - 2] != '*')
		return ERR("truncated message formatting incorrect", 0);
	XERRF(&e, XLOG_APP, XLOG_INVAL, msg);
	if (e.msg[LINE_MAX - 2] != '*')
		return ERR("truncated message formatting incorrect", 0);
	return NULL;
}

char *
test_name_max()
{
	char *p = makepath("name_max");
	char  path[FS_PATH_MAX];
	char  n1[FS_NAME_MAX + 1];
	char  n2[FS_NAME_MAX + 2];

	if (mkdir(p, 0700) == -1)
		return ERR("", errno);

	strlcpy(path, p, sizeof(path));

	memset(n1, 'm', sizeof(n1) - 1);
	n1[sizeof(n1) - 1] = '\0';

	memset(n2, 'e', sizeof(n2) - 1);
	n2[sizeof(n2) - 1] = '\0';

	snprintf(path, sizeof(path), "%s/%s", p, n1);
	if (mknod(path, 0640, 0) == -1)
		return ERR("", errno);

	snprintf(path, sizeof(path), "%s/%s", p, n2);
	if (mknod(path, 0640, 0) == -1 && errno == ENAMETOOLONG)
		return NULL;

	return ERR("file creation with name longer than FS_NAME_MAX should "
	    "have failed", 0);
}

char *
test_path_max()
{
	char       *p = makepath("path_max");
	const char *pcomp = "/a";
	char        name[FS_NAME_MAX + 1];
	int         i;
	/* POSIX PATH_MAX includes the nul byte. */
	char        path[FS_PATH_MAX + 1];

	if (mkdir(p, 0700) == -1)
		return ERR("", errno);

	strlcpy(path, p, sizeof(path));

	/* We'll fill the last 10 bytes with our file name */
	for (i = strlen(path); sizeof(path) - i > 10; i += strlen(pcomp)) {
		strlcat(path, pcomp, sizeof(path));
		if (mkdir(path, 0700) == -1)
			return ERR("", errno);
	}

	strlcat(path, "/", sizeof(path));
	i++;

	memset(name, 'a', sizeof(path) - i - 2);
	name[sizeof(path) - i - 2] = '\0';
	strlcat(path, name, sizeof(path));

	/* This should succeed, since we're at PATH_MAX - 2. */
	if (mknod(path, 0640, 0) == -1)
		return ERR("", errno);

	/*
	 * This should fail, since we're at PATH_MAX -1, and we need
	 * room for our nul byte.
	 */
	strlcat(path, "a", sizeof(path));
	if (mknod(path, 0640, 0) == -1 && errno == ENAMETOOLONG)
		return NULL;

	return ERR("path creation with name longer than FS_PATH_MAX should "
	    "have failed", 0);
}

char *
test_claim_from_backend()
{
	char            *p = makepath("claim_me");
	struct stat      st;
	int              i, fd;
	char             path[PATH_MAX];
	char             out_name[NAME_MAX];
	char             out_path[PATH_MAX];
	char             buf[BUFSIZ];
	struct xerr      e = XLOG_ERR_INITIALIZER;
	struct slab_key  sk;
	ssize_t          r;

	for (i = 0; i < sizeof(buf); i++)
		buf[i] = 'a';
	if ((fd = open(p, O_CREAT|O_RDWR|O_SYNC, 0600)) == -1)
		return ERR("", errno);

	while (i < slab_get_max_size()) {
		if ((r = write(fd, buf, sizeof(buf))) == -1)
			return ERR("", errno);
		i += r;
	}

	if (fstat(fd, &st) == -1)
		return ERR("", errno);

	close(fd);

	if (slab_path(path, sizeof(path),
	    slab_key(&sk, st.st_ino, 0), 0, &e) == -1) {
		xerr_print(&e);
		return ERR("failed to get slab path", 0);
	}
	if (slab_path(out_name, sizeof(out_name),
	    slab_key(&sk, st.st_ino, 0), 1, &e) == -1) {
		xerr_print(&e);
		return ERR("failed to get slab name", 0);
	}
	if (snprintf(out_path, sizeof(out_path), "%s/%s/%s",
	    fs_config.data_dir, OUTGOING_DIR, out_name) >= sizeof(out_path))
		return ERR("outgoing slab name too long", errno);

	if ((fd = open(path, O_RDONLY)) == -1)
		return ERR("", errno);

	/* Wait for the fs/mgr to release the claim on the slab. */
	if (flock(fd, LOCK_EX) == -1)
		return ERR("", errno);

	if (unlink(path) == -1)
		return ERR("", errno);

	close(fd);

	if (access(path, F_OK) != -1)
		return ERR("slab is present, but should have been unlinked", 0);
	if (errno != ENOENT)
		return ERR("failed to access() slab for "
		    "reason other than ENOENT", errno);

	/* Then reclaim; this is probably coming from the outoing dir. */
	if ((fd = open(p, O_RDONLY)) == -1)
		return ERR("", errno);
	/* Reading the inode size is enough to trigger a slab download */
	if (read(fd, buf, sizeof(struct inode)) == -1)
		return ERR("", errno);
	close(fd);

	if (access(path, F_OK) == -1)
		return ERR("", errno);

	/*
	 * This time make sure the slab in outgoing is actually flushed
	 * to the backend.
	 */
	/* At this point, both our slab and outgoing slab should be gone. */
	for (i = 0; access(out_path, F_OK) == 0; i++) {
		if (i > 10)
			return ERR("outgoing slab still present; "
			    "is bg_flush running?", 0);
		sleep(1);
	}
	if (errno != ENOENT)
		return ERR("access() failed for outgoing slab with reason "
		    "other than ENOENT", errno);

	/*
	 * Next let's try to get it from the actual backend. Because we
	 * did not write to it, the slab is not dirty so this time will not
	 * end up in outgoing. If we erase it, well have to get it from
	 * the backend.
	 */
	if ((fd = open(path, O_RDONLY)) == -1)
		return ERR("", errno);

	/* Wait for the fs/mgr to release the claim on the slab. */
	if (flock(fd, LOCK_EX) == -1)
		return ERR("", errno);

	if (unlink(path) == -1)
		return ERR("", errno);

	close(fd);

	if (access(path, F_OK) != -1)
		return ERR("slab is present, but should have been unlinked", 0);
	if (errno != ENOENT)
		return ERR("failed to access() slab for "
		    "reason other than ENOENT", errno);

	/* Then reclaim, hopefully from the actual backend this time. */
	if ((fd = open(p, O_RDONLY)) == -1)
		return ERR("", errno);
	/* Reading the inode size is enough to trigger a slab download */
	if (read(fd, buf, sizeof(struct inode)) == -1)
		return ERR("", errno);
	close(fd);

	if (access(path, F_OK) == -1)
		return ERR("", errno);

	return NULL;
}

struct potatofs_test {
	char  description[256];
	char *(*fn)();
} tests[] = {
	{
		"slab size",
		&test_slab_size
	},
	{
		"clock_gettime",
		&test_clock_gettime
	},
	{
		"long (truncated) error message",
		&test_xlog_over_line_max
	},
	{
		"mounted",
		&test_mounted
	},
	{
		"mkdir and stat",
		&test_mkdir
	},
	{
		"mknod and stat",
		&test_mknod
	},
	{
		"file name > FS_NAME_MAX",
		&test_name_max
	},
	{
		"path >= FS_PATH_MAX",
		&test_path_max
	},
	{
		"mknod fails with EEXIST",
		&test_mknod_exists
	},
	{
		"utimes file",
		&test_utimes_file
	},
	{
		"atime",
		&test_atime
	},
	{
		"chmod",
		&test_chmod
	},
	{
		"mtime on parent after make_inode",
		&test_parent_mtime_after_mknod
	},
	{
		"unlink and stat",
		&test_unlink
	},
	{
		"mtime on parent after rmnod",
		&test_parent_mtime_after_rmnod
	},
	{
		"file size and mtime",
		&test_file_size_and_mtime
	},
	{
		"rmdir",
		&test_rmdir
	},
	{
		"rmdir on non-empty dir, or non-directory",
		&test_rmdir_notempty_notdir
	},
	{
		"rmdir on non-empty dir that contains another dir",
		&test_rmdir_contains_dir
	},
	{
		"symlink",
		&test_symlink
	},
	{
		"symlink target >= FSPATH_MAX",
		&test_readlink_path_max
	},
	{
		"hard link",
		&test_hardlink
	},
	{
		"link max > FS_LINK_MAX",
		&test_link_max
	},
	{
		"ctime on hard link",
		&test_ctime_after_link
	},
	{
		"mtime on parent after link",
		&test_parent_mtime_after_link
	},
	{
		"hard link dir",
		&test_hardlink_dir
	},
	{
		"rename, same parent",
		&test_rename
	},
	{
		"rename to self fails",
		&test_rename_to_self
	},
	{
		"rename w/replace, same parent",
		&test_rename_replace
	},
	{
		"rename, cross dir",
		&test_rename_crossdir
	},
	{
		"rename dir, cross dir",
		&test_rename_dir_crossdir
	},
	{
		"rename w/replace, cross dir",
		&test_rename_replace_crossdir
	},
	{
		"rename to descendant",
		&test_rename_to_descendant
	},
	{
		"rename to ancestor",
		&test_rename_to_ancestor
	},
	{
		"rename, fails on non-dir to dir with EISDIR",
		&test_rename_nondir_to_dir
	},
	{
		"rename, fails on dir to non-dir with ENOTDIR",
		&test_rename_dir_to_nondir
	},
	{
		"rename, fails on non-dir to dir with EISDIR, cross directory",
		&test_rename_crossdir_nondir_to_dir
	},
	{
		"rename, fails on dir to non-dir with ENOTDIR, cross directory",
		&test_rename_crossdir_dir_to_nondir
	},
	{
		"rename dir over another empty dir",
		&test_rename_dir_to_existing_emtpy_dir
	},
	{
		"rename dir over another non-empty dir",
		&test_rename_dir_to_existing_nonemtpy_dir
	},
	{
		"rename, to/from root inode fails with EBUSY / EXDEV",
		&test_rename_root_inode
	},
	{
		"mtime on parents after rename",
		&test_parents_mtime_after_rename
	},
	{
		"create file with 2 full slabs, check slab contents",
		&test_file_content
	},
	{
		"fallocate",
		&test_fallocate
	},
	{
		"fallocate file spanning multiple slabs",
		&test_fallocate_large
	},
	{
		"truncate file spanning multiple slabs",
		&test_truncate
	},
	{
		"truncate file spanning multiple slabs, "
		    "to a size less than an inode's inline bytes",
		&test_truncate_less_than_inline
	},
	{
		"delayed truncation spanning multiple slabs",
		&test_delayed_truncate_large
	},
	{
		"inode reuse increases generation",
		&inode_reuse
	},
	{
		"many inodes (beyond a single inode table)",
		&test_many_inodes
	},
	{
		"claim from backend",
		&test_claim_from_backend
	},
	{
		"test readdir on v2 dirs at maximum hash tree depth",
		&test_readdir_max_v2_dir_depth
	},
	{
		"test lookup on v2 dirs at maximum hash tree depth",
		&test_lookup_max_v2_dir_depth
	},
	{
		"test lookup for . and ..",
		&test_lookup_dot_dotdot
	},
	{
		"test unlink on v2 dirs at maximum hash tree depth",
		&test_unlink_max_v2_dir_depth
	},
	{
		"test dir freelist",
		&test_dir_freelist
	},
	{
		"test v2 dir mkdirent filling first chained leaf",
		&test_mkdirent_fill_first_chained_leaf_max_v2_dir_depth
	},

	/* End */
	{ "", NULL }
};

void
usage()
{
	fprintf(stderr,
	    "Usage: potatofs_tests [options] <mount point> [test substring]\n"
	    "\t-h\t\t\tPrints this help\n"
	    "\t-c <config path>\tPath to the configuration file\n");
}

int
main(int argc, char **argv)
{
	struct potatofs_test *t;
	char                 *msg;
	struct xerr           e = XLOG_ERR_INITIALIZER;
	struct fs_info        fs_info;
	int                   status = 0;
	char                  opt;
	char                  cfg[PATH_MAX];

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

	config_read();

	if (optind >= argc) {
		usage();
		exit(1);
	}

	if (fs_info_inspect(&fs_info, &e) == -1) {
		xerr_print(&e);
		exit(1);
	}

	if (slabdb_init(fs_info.instance_id, xerrz(&e)) == -1) {
		xerr_print(&e);
		exit(1);
	}

	if (snprintf(mnt, sizeof(mnt), "%s", argv[optind++]) >= sizeof(mnt))
		errx(1, "error: mount point path too long");

	if (access(mnt, R_OK|W_OK|X_OK) == -1)
		errx(1, "access");

	if (optind > argc) {
		usage();
		exit(1);
	}

	if ((log_locale = newlocale(LC_CTYPE_MASK, "C", 0)) == 0)
		err(1, "newlocale");

	umask(0);
	for (t = tests; t->fn != NULL; t++) {
		if (argc > optind &&
		    strstr(t->description, argv[optind]) == NULL)
			continue;

		msg = t->fn();
		free_all_paths();
		printf("[%s] %s\n", (msg) ? "ERROR" : "OK", t->description);
		if (msg) {
			status = 1;
			printf("\n%s\n\n", msg);
			free(msg);

			/*
			 * Our first test is "mounted". If that fails,
			 * we stop here.
			 */
			if (t == tests)
				break;
		}
	}
	return status;
}
