#define _GNU_SOURCE
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
#include "fs_info.h"
#include "inodes.h"

char mnt[PATH_MAX] = "";
char path[PATH_MAX] = "";

extern locale_t log_locale;
extern char     datadir[];
extern size_t   slab_max_size;

static struct path
{
	char         p[PATH_MAX];
	struct path *next;
} *all_paths = NULL;

char *
fail(const char *msg, int e, const char *fn, int line)
{
	char *m;

	if (asprintf(&m, "%s%s (%s:%d)", msg,
	    (e) ? strerror_l(e, log_locale) : "", fn, line) == -1)
		err(1, "asprintf");
        return m;
}
#define ERR(msg, e) fail(msg, e, __func__, __LINE__)

char *
makepath(const char *p)
{
	struct path *path, *prev;

	if ((path = calloc(1, sizeof(struct path))) == NULL)
		err(1, "calloc");

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
get_disk_inode(ino_t ino, struct stat *st, struct exlog_err *e)
{
	struct inode inode;

	if (inode_inspect(ino, &inode, e) == -1)
		return -1;
	if (st != NULL)
		inode_cp_stat(st, &inode);
	return 0;
}

char *
check_stat(const char *p, struct stat *st_want, uint16_t what)
{
	char             msg[LINE_MAX];
	struct stat      st;
	struct inode     inode;
	struct exlog_err e = EXLOG_ERR_INITIALIZER;

	if (lstat(p, &st) == -1)
		return ERR("", errno);

	/* Check the data structure on disk */
	if (inode_inspect(st.st_ino, &inode, &e) == -1) {
		exlog_prt(&e);
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
test_unlink()
{
	struct stat       st;
	ino_t             ino;
	char             *p = makepath("unlink-me");
	struct exlog_err  e = EXLOG_ERR_INITIALIZER;

	if (mknod(p, 0640, 0) == -1)
		return ERR("", errno);
	if (stat(p, &st) == -1)
		return ERR("", errno);
	ino = st.st_ino;
	if (unlink(p) == -1)
		return ERR("", errno);

	if (access(p, R_OK|F_OK) == -1 && errno == ENOENT) {
		if (get_disk_inode(ino, &st, &e) == -1) {
			if (!exlog_err_is(&e, EXLOG_APP, EXLOG_ENOENT)) {
				exlog_prt(&e);
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
	struct stat       st;
	ino_t             ino;
	char             *p = makepath("rmdir-me");
	struct exlog_err  e = EXLOG_ERR_INITIALIZER;

	if (mkdir(p, 0755) == -1)
		return ERR("", errno);
	if (stat(p, &st) == -1)
		return ERR("", errno);
	ino = st.st_ino;
	if (rmdir(p) == -1)
		return ERR("", errno);

	if (access(p, R_OK|X_OK) == -1 && errno == ENOENT) {
		if (get_disk_inode(ino, &st, &e) == -1) {
			if (!exlog_err_is(&e, EXLOG_APP, EXLOG_ENOENT)) {
				exlog_prt(&e);
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
	struct stat     st;
	char           *p = makepath("rmdir-me");
	char           *p2 = makepath("rmdir-me/notempty");
	struct stat     st_want;

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
test_file_size_and_mtime()
{
	struct stat       st_want, st;
	int               fd;
	ssize_t           w;
	char              buf[4096];
	char             *p = makepath("file_size");
	struct timespec   tp;
	char              msg[LINE_MAX];
	off_t             sz, bsize;
	struct exlog_err  e = EXLOG_ERR_INITIALIZER;
	struct oslab     *b;

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
		return ERR(msg, 0);

	if (close(fd) == -1)
		return ERR("", errno);

	if ((b = slab_inspect(st.st_ino, sz, 0, &e)) == NULL) {
		exlog_prt(&e);
		return ERR("failed to inspect slab", 0);
	}

	if ((bsize = slab_size(b, &e)) == -1) {
		exlog_prt(&e);
		return ERR("failed to get slab size", 0);
	}

	close(b->fd);
	free(b);

	/*
	 * Once we start spilling bytes into slabs, the total slab
	 * sizes should match the file size, even if we use inline data.
	 * This is so that we preserve block alignment.
	 */
	if (bsize != sz) {
		snprintf(msg, sizeof(msg),
		    "slab size doesn't match "
		    "total size minus max inline for the inode: "
		    "current=%lu, want=%lu",
		    bsize, sz - inode_max_inline_b());
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

	strncat(target, "a", sizeof(target) - 1);
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

	if (mkdir(d, 0700) == -1)
		return ERR("", errno);

	snprintf(src, sizeof(src), "%s/hardlink", d);
	if (mknod(src, 0666, 0) == -1)
		return ERR("", errno);

	for (i = 2; i <= FS_LINK_MAX; i++) {
		snprintf(dst, sizeof(dst), "%s/hardlink%d", d, i);
		if (link(src, dst) == -1)
			return ERR("", errno);
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
	struct stat  st_want;
	char        *p = makepath("before_move");
	char        *p2 = makepath("after_move");

	if (mknod(p, 0444, 0) == -1)
		return ERR("", errno);

	if (stat(p, &st_want) == -1)
		return ERR("", errno);

	if (rename(p, p2) == -1)
		return ERR("", errno);
	return check_stat(p2, &st_want,
	    ST_MODE|ST_NLINK|ST_UID|ST_GID|ST_SIZE);
}

char *
test_rename_to_self()
{
	struct stat  st_want, st_parent;
	char        *p = makepath("move_self");
	char        *root = makepath("");
	char        *r;

	if (mknod(p, 0444, 0) == -1)
		return ERR("", errno);

	if (stat(p, &st_want) == -1)
		return ERR("", errno);
	if (stat(root, &st_parent) == -1)
		return ERR("", errno);

	if (rename(p, p) == -1)
		return ERR("", errno);
	r = check_stat(p, &st_want,
	    ST_MODE|ST_NLINK|ST_UID|ST_GID|ST_SIZE);
	if (r != NULL)
		return r;

	return check_stat(root, &st_parent,
	    ST_MODE|ST_NLINK|ST_UID|ST_GID|ST_SIZE);
}

char *
test_rename_replace()
{
	struct stat       st_want, st_unlink;
	char             *p1 = makepath("before_move_replace");
	char             *p2 = makepath("after_move_replace");
	ino_t             gone;
	struct exlog_err  e = EXLOG_ERR_INITIALIZER;
	int               i = 0;

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
			if (!exlog_err_is(&e, EXLOG_APP, EXLOG_ENOENT)) {
				exlog_prt(&e);
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
test_rename_crossdir()
{
	struct stat      st_want;
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

	xnanosleep();
	if (clock_gettime(CLOCK_REALTIME, &tp) == -1)
		return ERR("", errno);
	if (rename(p1, p2) == -1)
		return ERR("", errno);

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
	struct exlog_err  e = EXLOG_ERR_INITIALIZER;
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
			if (!exlog_err_is(&e, EXLOG_APP, EXLOG_ENOENT)) {
				exlog_prt(&e);
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
	struct stat       st_want, st;
	int               fd, i;
	ssize_t           r, w;
	char              buf[4096];
	char              path[4096];
	char             *p = makepath("create_file");
	struct exlog_err  e = EXLOG_ERR_INITIALIZER;
	char              msg[PATH_MAX + 1024];
	ino_t             ino;

	st_want.st_mode = (S_IFREG | 0600);
	st_want.st_nlink = 1;
	st_want.st_size = SLAB_SIZE_DEFAULT * 2;

	if ((fd = open(p, O_CREAT|O_RDWR, 0600)) == -1)
		return ERR("", errno);

	/* Fill the inline bytes with 'a', the rest with 'b' */
	for (i = 0; i < sizeof(buf); i++)
		buf[i] = (i < inode_max_inline_b()) ? 'a': 'b';
	if ((w = write(fd, buf, sizeof(buf))) < sizeof(buf)) {
		if (w == -1)
			return ERR("", errno);
		return ERR("short write on file", 0);
	}

	/* The second block in the file has no inline bytes, so all 'b' */
	for (i = 0; i < sizeof(buf); i++)
		buf[i] = 'b';
	for (i = sizeof(buf); i < SLAB_SIZE_DEFAULT; i += w) {
		if ((w = write(fd, buf, sizeof(buf))) < sizeof(buf)) {
			if (w == -1)
				return ERR("", errno);
			return ERR("short write on file", 0);
		}
	}

	for (i = 0; i < sizeof(buf); i++)
		buf[i] = 'c';
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
	if (slab_path(path, sizeof(path), ino, 0, 0, &e) == -1) {
		exlog_prt(&e);
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
		if (buf[i] != ((i < inode_max_inline_b()) ? '\0': 'b')) {
			snprintf(msg, sizeof(msg),
			    "unexpected byte in slab %s; "
			    "current=0x%x, want=%s", path, buf[i],
			    (i < inode_max_inline_b()) ? "\\0": "b");
			return ERR(msg, 0);
		}
	}

	for (; i < SLAB_SIZE_DEFAULT; i += r) {
		if ((r = read(fd, buf, sizeof(buf))) == -1)
			return ERR("", errno);
		if (r < sizeof(buf))
			return ERR("short read on first slab", 0);
		for (; i < sizeof(buf); i++) {
			if (buf[i] != 'b') {
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
	 * The second slab should be all 'c'.
	 */
	if (slab_path(path, sizeof(path), ino,
	    SLAB_SIZE_DEFAULT, 0, &e) == -1) {
		exlog_prt(&e);
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
			if (buf[i] != 'c') {
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
	int               fd;
	char             *p = makepath("fallocated_large");
	struct stat       st, st_want;
	char              path[PATH_MAX];
	char              msg[PATH_MAX + 1024];
	struct exlog_err  e = EXLOG_ERR_INITIALIZER;

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

	if (slab_path(path, sizeof(path), st.st_ino,
	    slab_get_max_size(), 0, &e) == -1) {
		exlog_prt(&e);
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
test_many_inodes()
{
	char              path[PATH_MAX];
	char             *d = makepath("many_inodes");
	int               i, n_inodes = slab_inode_max() + 1;
	struct inode      inode;
	struct exlog_err  e = EXLOG_ERR_INITIALIZER;
	DIR              *dir;
	struct dirent    *de;

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
	while ((de = readdir(dir))) {
		if (inode_inspect(de->d_ino, &inode, &e) == -1) {
			exlog_prt(&e);
			return ERR("reading inode failed", 0);
		}
		n_inodes--;
	}
	closedir(dir);

	if (n_inodes > 0)
		return ERR("inode count is not what it should be", 0);
	return NULL;
}

char *
inode_reuse()
{
	struct stat       st;
	struct inode      inode;
	unsigned long     gen;
	char             *p = makepath("reuse_me");
	struct exlog_err  e = EXLOG_ERR_INITIALIZER;
	char              msg[1024];

	if (mknod(p, 0640, 0) == -1)
		return ERR("", errno);
	if (stat(p, &st) == -1)
		return ERR("", errno);
	if (inode_inspect(st.st_ino, &inode, &e) == -1) {
		exlog_prt(&e);
		return ERR("reading inode failed", 0);
	}
	gen = inode.v.f.generation;
	if (unlink(p) == -1)
		return ERR("", errno);

	if (mknod(p, 0640, 0) == -1)
		return ERR("", errno);

	if (inode_inspect(st.st_ino, &inode, &e) == -1) {
		exlog_prt(&e);
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
test_exlog_over_line_max()
{
	int              i;
	char             msg[LINE_MAX * 2];
	struct exlog_err e = EXLOG_ERR_INITIALIZER;

	for (i = 0; i < sizeof(msg) - 1; i++)
		msg[i] = 'a';
	msg[i] = '\0';
	exlog_errf(&e, EXLOG_APP, EXLOG_EINVAL, msg);
	if (strcmp(e.msg + LINE_MAX - 5, " ...") != 0)
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

	strncpy(path, p, sizeof(path) - 1);

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
	    "have failed", errno);
}

char *
test_path_max()
{
	char       *p = makepath("path_max");
	const char *pcomp = "/a";
	char        name[FS_NAME_MAX + 1];
	int         i;
	/* POSIX PATH_MAX includes the nul byte. */
	char        path[FS_PATH_MAX];

	if (mkdir(p, 0700) == -1)
		return ERR("", errno);

	strncpy(path, p, sizeof(path) - 1);

	/* We'll fill the last 10 bytes with our file name */
	for (i = strlen(path); sizeof(path) - i > 10; i += strlen(pcomp)) {
		strncat(path, pcomp, sizeof(path) - 1);
		if (mkdir(path, 0700) == -1)
			return ERR("", errno);
	}

	strncat(path, "/", sizeof(path) - 1);
	i++;

	memset(name, 'a', sizeof(path) - i - 1);
	name[sizeof(path) - i - 1] = '\0';

	strncat(path, name, sizeof(path) - 1);
	if (mknod(path, 0640, 0) == -1)
		return ERR("", errno);

	strncat(path, "a", sizeof(path) - 1);
	if (mknod(path, 0640, 0) == -1 && errno == ENAMETOOLONG)
		return NULL;

	return ERR("path creation with name longer than FS_PATH_MAX should "
	    "have failed", errno);
}

struct potatofs_test {
	char  description[256];
	char *(*fn)();
} tests[] = {
	{
		"long (truncated) error message",
		&test_exlog_over_line_max
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
		"mknod fails with EEXIST",
		&test_mknod_exists
	},
	{
		"utimes file",
		&test_utimes_file
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
		"inode reuse increases generation",
		&inode_reuse
	},
	{
		"many inodes (beyond a single inode table)",
		&test_many_inodes
	},
	{
		"file name > FS_NAME_MAX",
		&test_name_max
	},
	{
		"path >= FS_PATH_MAX",
		&test_path_max
	},

	/* End */
	{ "", NULL }
};

int
main(int argc, char **argv)
{
	struct potatofs_test *t;
	char                 *msg;
	struct exlog_err      e = EXLOG_ERR_INITIALIZER;
	struct fs_info        fs_info;
	int                   status = 0;

	if (argc < 3)
		errx(1, "Usage: potatofs_tests <data path> "
		    "<mount point> [test substring]");

	if (snprintf(datadir, PATH_MAX, "%s", argv[1]) >= PATH_MAX - 1)
		errx(1, "error: data path too long");

	if (fs_info_inspect(&fs_info, &e) == -1) {
		exlog_prt(&e);
		exit(1);
	}
	slab_max_size = fs_info.slab_size;

	if (snprintf(mnt, sizeof(mnt), "%s", argv[2]) >= sizeof(mnt))
		errx(1, "error: mount point path too long");

	if ((log_locale = newlocale(LC_CTYPE_MASK, "C", 0)) == 0)
		err(1, "newlocale");

	umask(0);
	for (t = tests; t->fn != NULL; t++) {
		if (argc == 4 &&  strstr(t->description, argv[3]) == NULL)
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
