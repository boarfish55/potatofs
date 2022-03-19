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

#include <err.h>
#include <locale.h>
#include <signal.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <fuse.h>
#include <fuse_lowlevel.h>
#include <limits.h>
#include <stdio.h>
#include "config.h"
#include "counters.h"
#include "dirinodes.h"
#include "xlog.h"
#include "fs_error.h"
#include "fs_info.h"
#include "inodes.h"
#include "mgr.h"
#include "openfiles.h"

enum {
	OPT_HELP,
	OPT_VERSION,
	OPT_FOREGROUND,
	OPT_NOATIME
};

#define FS_OPT(t, p, v) { t, offsetof(struct fs_config, p), v }
static struct fuse_opt fs_opts[] = {
	/* Enable debug mode for specific modules. */
	FS_OPT("dbg=%s", dbg, 0),
	/* Limit on the local storage size for slabs. */
	FS_OPT("max_open_slabs=%llu", max_open_slabs, 0),
	FS_OPT("entry_timeouts=%u", entry_timeouts, 0),
	FS_OPT("slab_max_age=%u", slab_max_age, 0),
	FUSE_OPT_KEY("-h", OPT_HELP),
	FUSE_OPT_KEY("-V", OPT_VERSION),
	FUSE_OPT_KEY("-f", OPT_FOREGROUND),
	FUSE_OPT_KEY("noatime", OPT_NOATIME),
	FS_OPT("cfg_path=%s", cfg_path, 0),
	FUSE_OPT_END
};

static int  fs_opt_proc(void *, const char *, int, struct fuse_args *);
static void check_fuse_reply(int, const char *, const char *);
static void fs_getattr(fuse_req_t, fuse_ino_t, struct fuse_file_info *);
static void fs_setattr(fuse_req_t, fuse_ino_t, struct stat *, int,
                struct fuse_file_info *);
static void fs_destroy(void *);
static void fs_init(void *, struct fuse_conn_info *);
static void fs_opendir(fuse_req_t, fuse_ino_t, struct fuse_file_info *);
static void fs_readdir(fuse_req_t, fuse_ino_t, size_t, off_t,
                struct fuse_file_info *);
static void fs_release(fuse_req_t, fuse_ino_t, struct fuse_file_info *);
static void fs_open(fuse_req_t, fuse_ino_t, struct fuse_file_info *);
static void fs_read(fuse_req_t, fuse_ino_t, size_t, off_t,
                struct fuse_file_info *);
static void fs_write_buf(fuse_req_t, fuse_ino_t, struct fuse_bufvec *,
                off_t, struct fuse_file_info *);
static void fs_flush(fuse_req_t, fuse_ino_t, struct fuse_file_info *);
static void fs_forget(fuse_req_t, fuse_ino_t, unsigned long);
static void fs_forget_multi(fuse_req_t, size_t, struct fuse_forget_data *);
static void fs_lookup(fuse_req_t, fuse_ino_t, const char *);
static void fs_mkdir(fuse_req_t, fuse_ino_t, const char *, mode_t);
static void fs_rmnod(fuse_req_t, fuse_ino_t, const char *, int);
static void fs_rmdir(fuse_req_t, fuse_ino_t, const char *);
static void fs_unlink(fuse_req_t, fuse_ino_t, const char *);
static void fs_statfs(fuse_req_t, fuse_ino_t);
static void fs_mknod(fuse_req_t, fuse_ino_t, const char *, mode_t, dev_t);
static void fs_create(fuse_req_t, fuse_ino_t, const char *, mode_t,
                struct fuse_file_info *);
static void fs_fallocate(fuse_req_t, fuse_ino_t, int, off_t, off_t,
                struct fuse_file_info *);
static void fs_fsync(fuse_req_t, fuse_ino_t, int, struct fuse_file_info *);
static void fs_fsyncdir(fuse_req_t, fuse_ino_t, int, struct fuse_file_info *);
static void fs_rename(fuse_req_t, fuse_ino_t, const char *, fuse_ino_t,
                const char *);
static void fs_link(fuse_req_t, fuse_ino_t, fuse_ino_t, const char *);
static void fs_symlink(fuse_req_t, const char *, fuse_ino_t, const char *);
static void fs_readlink(fuse_req_t, fuse_ino_t);
static int  make_inode(ino_t, const char *, uid_t, gid_t, mode_t, mode_t,
                dev_t, struct inode *, const char *, size_t,
                struct xerr *);
static void fs_err(int *, fuse_req_t, const struct xerr *, const char *);

static struct fuse_lowlevel_ops fs_ops = {
	.init         = fs_init,
	.destroy      = fs_destroy,

	.lookup       = fs_lookup,
	.forget       = fs_forget,
	.forget_multi = fs_forget_multi,

	.getattr      = fs_getattr,
	.setattr      = fs_setattr,
	.fallocate    = fs_fallocate,

	.mknod        = fs_mknod,
	.mkdir        = fs_mkdir,
	.create       = fs_create,

	.unlink       = fs_unlink,
	.rmdir        = fs_rmdir,

	.readlink     = fs_readlink,
	.symlink      = fs_symlink,
	.link         = fs_link,
	.rename       = fs_rename,

	.open         = fs_open,
	.read         = fs_read,
	.write_buf    = fs_write_buf,
	.flush        = fs_flush,
	.release      = fs_release,
	.fsync        = fs_fsync,

	.opendir      = fs_opendir,
	.readdir      = fs_readdir,
	.releasedir   = fs_release,
	.fsyncdir     = fs_fsyncdir,

	.statfs       = fs_statfs,

	//.setxattr     = fs_setxattr,
	//.getxattr     = fs_getxattr,
	//.listxattr    = fs_listxattr,
	//.removexattr  = fs_removexattr,

	//.poll         = fs_poll,

	// TODO: probably needed only if we decide to support device files
	//.ioctl        = fs_ioctl,

	// TODO: the locking methods are only relevant once we start
	//       dealing with multiple instances of potatofs on the same
	//       backend.
	//.flock        = fs_flock,
	//.getlk        = fs_getlk,
	//.setlk        = fs_setlk,
};

/*
 * Global directory tree lock; use RDLOCK in all functions that may need
 * a lock on a directory. Use RWLOCK in fs_rename.
 */
static rwlk fs_tree_lock = RWLK_INITIALIZER;

static int
fs_opt_proc(void *data, const char *arg, int key, struct fuse_args *outargs)
{
	const struct module_dbg_map_entry *dbge;

	switch (key) {
	case OPT_HELP:
		fuse_opt_add_arg(outargs, "-h");
		fuse_main(outargs->argc, outargs->argv, NULL, NULL);
		fprintf(stderr, "\n"
		    "[PotatoFS]\n"
		    "    -o entry_timeouts=<seconds>\n"
		    "        How long to cache inode attributes and name\n"
		    "        entries (default: %d)\n"
		    "\n"
		    "    -o max_open_slabs=<int>\n"
		    "        Maximum slabs open simultaneously. Slabs will\n"
		    "        be closed early if we reach this amount.\n"
		    "        (default: %d)\n"
		    "\n"
		    "    -o slab_max_age=<seconds>\n"
		    "        How long to keep a slab open even when no longer\n"
		    "        referenced. (default: %u)\n"
		    "\n"
		    "    -o cfg_path=<path>\n"
		    "        PotatoFS configuration file path (default: %s)\n"
		    "\n"
		    "    -o dbg=<module1,module2,...>\n"
		    "        Enable debug logging for selected modules:\n",
		    FS_DEFAULT_ENTRY_TIMEOUTS, SLAB_MAX_OPEN_DEFAULT,
		    SLAB_MAX_AGE_DEFAULT, DEFAULT_CONFIG_PATH);
		for (dbge = module_dbg_map; *dbge->name; dbge++)
			fprintf(stderr, "          - %s\n", dbge->name);
		exit(1);
	case OPT_VERSION:
		fuse_opt_add_arg(outargs, "-V");
		fuse_main(outargs->argc, outargs->argv, NULL, NULL);
		fprintf(stderr, "%s version %s\n", PROGNAME, VERSION);
		exit(0);
	case OPT_FOREGROUND:
		fuse_opt_add_arg(outargs, "-f");
	case OPT_NOATIME:
		fs_config.noatime = 1;
	}
	return 1;
}

/*
 * FUSE_REPLY logs errors from fuse replies. It won't send a reply if
 * reply_sent is non-zero, and sets the value after sending it. This makes it
 * easier to ensure only a single fuse reply is sent per fuse operation.
 */
#define FUSE_REPLY(reply_sent, f) do {              \
	if (!*reply_sent) {                         \
		check_fuse_reply(f, __func__, #f);  \
		*reply_sent = 1;                    \
	}                                           \
} while(0)
static void
check_fuse_reply(int err, const char *fn, const char *invocation)
{
	locale_t lc;

	if (err != 0) {
		if ((lc = newlocale(LC_CTYPE_MASK, "C", 0)) == 0)
			xlog(LOG_ERR, NULL, "%s: fuse reply failed: %s (%d)",
			    fn, invocation, err);
		else
			xlog(LOG_ERR, NULL,
			    "%s: fuse reply failed: %s: %s (%d)",
			    fn, invocation, strerror_l(-err, lc), err);
	}
}

#define FS_RO_ON_ERR(req) fs_ro_on_errors(req, __func__)
static int
fs_ro_on_errors(fuse_req_t req, const char *fn)
{
	if (fs_error_is_set()) {
		check_fuse_reply(fuse_reply_err(req, EROFS), fn, __func__);
		return -1;
	}
	return 0;
}

#define FS_ERR(r_sent, req, e) fs_err(r_sent, req, e, __func__)
static void
fs_err(int *reply_sent, fuse_req_t req, const struct xerr *e, const char *fn)
{
	fs_error_set();
	xlog(LOG_ERR, e, fn);
	if (!*reply_sent) {
		check_fuse_reply(fuse_reply_err(req, EIO), fn, __func__);
		*reply_sent = 1;
	}
}

// TODO: implement interrupt (INTERRUPT)

static void
fs_set_time(struct oinode *oi, uint32_t what)
{
	struct timespec tp;
	struct xerr     e = XLOG_ERR_INITIALIZER;
	struct stat     st;

	if (fs_error_is_set())
		return;

	if (what == INODE_ATTR_ATIME && fs_config.noatime)
		return;

	what &= (INODE_ATTR_ATIME|INODE_ATTR_CTIME|INODE_ATTR_MTIME);

	if (clock_gettime(CLOCK_REALTIME, &tp) == -1) {
		xlog_strerror(LOG_ERR, errno, "clock_gettime");
		return;
	}

	if (what & INODE_ATTR_ATIME && !fs_config.noatime)
		memcpy(&st.st_atim, &tp, sizeof(tp));
	if (what & INODE_ATTR_MTIME)
		memcpy(&st.st_mtim, &tp, sizeof(tp));
	if (what & INODE_ATTR_CTIME)
		memcpy(&st.st_ctim, &tp, sizeof(tp));
	inode_setattr(oi, &st, what, &e);
}

static void
fs_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct stat  st;
	struct xerr  e = XLOG_ERR_INITIALIZER;
	struct inode inode;
	int          r_sent = 0;

	counter_incr(COUNTER_FS_GETATTR);
	LK_RDLOCK(&fs_tree_lock);

	bzero(&st, sizeof(st));

	if (inode_cp_ino(ino, &inode, &e) == -1) {
		if (e.sp == XLOG_FS) {
			FUSE_REPLY(&r_sent, fuse_reply_err(req, e.code));
		} else {
			FS_ERR(&r_sent, req, &e);
		}
		goto unlock;
	}

	inode_cp_stat(&st, &inode);

	FUSE_REPLY(&r_sent, fuse_reply_attr(req, &st,
	    fs_config.entry_timeouts));
unlock:
	LK_UNLOCK(&fs_tree_lock);
}

static void
fs_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr,
    int to_set, struct fuse_file_info *fi)
{
	struct xerr      e = XLOG_ERR_INITIALIZER;
	struct stat      st;
	struct timespec  tp;
	uint32_t         mask = INODE_ATTR_CTIME;
	struct oinode   *oi = NULL;
	int              r_sent = 0;

	counter_incr(COUNTER_FS_SETATTR);
	if (FS_RO_ON_ERR(req)) return;
	LK_RDLOCK(&fs_tree_lock);

	memcpy(&st, attr, sizeof(st));

	if (to_set & FUSE_SET_ATTR_MODE)
		mask |= INODE_ATTR_MODE;
	if (to_set & FUSE_SET_ATTR_UID)
		mask |= INODE_ATTR_UID;
	if (to_set & FUSE_SET_ATTR_GID)
		mask |= INODE_ATTR_GID;
	if (to_set & FUSE_SET_ATTR_SIZE)
		mask |= (INODE_ATTR_SIZE|INODE_ATTR_MTIME);

	if (to_set & (FUSE_SET_ATTR_ATIME|FUSE_SET_ATTR_ATIME_NOW))
		mask |= INODE_ATTR_ATIME;
	if (to_set & (FUSE_SET_ATTR_MTIME|FUSE_SET_ATTR_MTIME_NOW))
		mask |= INODE_ATTR_MTIME;

	if (clock_gettime(CLOCK_REALTIME, &tp) == -1) {
		xlog_strerror(LOG_ERR, errno,
		    "failed to get time for inode creation");
		return;
	}
	memcpy(&st.st_ctim, &tp, sizeof(st.st_ctim));

	if (to_set & (FUSE_SET_ATTR_ATIME_NOW))
		memcpy(&st.st_atim, &tp, sizeof(st.st_atim));
	if (to_set & (FUSE_SET_ATTR_MTIME_NOW))
		memcpy(&st.st_mtim, &tp, sizeof(st.st_mtim));

	/* Because looking up by open file is faster */
	if (fi == NULL) {
		if ((oi = inode_load(ino, 0, &e)) == NULL) {
			if (e.sp == XLOG_FS) {
				FUSE_REPLY(&r_sent,
				    fuse_reply_err(req, e.code));
			} else {
				FS_ERR(&r_sent, req, &e);
			}
			goto unlock;
		}
	} else {
		oi = ((struct open_file *)fi->fh)->oi;
	}

	inode_lock(oi, LK_LOCK_RW);
	if (inode_setattr(oi, &st, mask, &e) == -1) {
		if (e.sp == XLOG_FS)
			FUSE_REPLY(&r_sent, fuse_reply_err(req, e.code));
		else
			FS_ERR(&r_sent, req, &e);
	} else {
		FUSE_REPLY(&r_sent, fuse_reply_attr(req, &st,
		    fs_config.entry_timeouts));
	}
	if (inode_flush(oi, 0, &e) == -1)
		FS_ERR(&r_sent, req, &e);
	inode_unlock(oi);

	xerrz(&e);

	if (fi == NULL)
		inode_unload(oi, &e);

	if (xerr_fail(&e))
		FS_ERR(&r_sent, req, &e);
unlock:
	LK_UNLOCK(&fs_tree_lock);
}

static void
fs_destroy(void *unused)
{
	struct xerr e;

	xlog(LOG_NOTICE, NULL, "cleaning up and exiting");

	LK_WRLOCK(&fs_tree_lock);

	inode_shutdown();

	if (slab_shutdown(xerrz(&e)) == -1) {
		xlog(LOG_CRIT, &e, __func__);
		fs_error_set();
	}

	if (counter_shutdown(xerrz(&e)) == -1) {
		xlog(LOG_CRIT, &e, __func__);
		fs_error_set();
	}

	LK_UNLOCK(&fs_tree_lock);

	if (mgr_send_shutdown(xerrz(&e)) == -1)
		xlog(LOG_ERR, &e, __func__);
}

static void
fs_init(void *userdata, struct fuse_conn_info *conn)
{
	struct xerr       e = XLOG_ERR_INITIALIZER;
	struct fs_config *c = (struct fs_config *)userdata;
	struct oinode    *oi;
	struct dir_entry  default_dir[2] = {
		{ ".", FS_ROOT_INODE, sizeof(struct dir_entry) },
		{ "..", FS_ROOT_INODE, 0 }
	};

	xlog(LOG_NOTICE, NULL, "entry timeouts: %u", c->entry_timeouts);

	if (counter_init(&e) == -1)
		goto fail;

	if (slab_configure(c->max_open_slabs, c->slab_max_age, &e) == -1)
		goto fail;

	if (inode_startup(&e) == -1)
		goto fail;

	xlog(LOG_NOTICE, NULL, "noatime is %s",
	    (c->noatime) ? "set" : "unset");

	if ((oi = inode_load(FS_ROOT_INODE, 0, &e)) == NULL) {
		if (!xerr_is(&e, XLOG_FS, ENOENT))
			goto fail;

		xerrz(&e);
		if (inode_make(FS_ROOT_INODE, c->uid, c->gid,
		    S_IFDIR|0755, NULL, &e) == -1)
			goto fail;
		if ((oi = inode_load(FS_ROOT_INODE, 0, &e)) == NULL)
			goto fail;
		inode_nlink(oi, 2);

		if (inode_write(oi, 0, default_dir,
		    sizeof(default_dir), &e) != sizeof(default_dir))
			goto fail;
	}
	if (inode_flush(oi, 0, &e) == -1)
		goto fail;
	if (inode_unload(oi, &e) == -1)
		goto fail;
	return;
fail:
	xlog(LOG_CRIT, &e, __func__);
	exit(1);
}

static void
fs_opendir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct xerr       e = XLOG_ERR_INITIALIZER;
	struct open_file *of;
	int               r_sent = 0, is_dir;

	counter_incr(COUNTER_FS_OPENDIR);
	LK_RDLOCK(&fs_tree_lock);

	if ((of = openfile_alloc(ino, 0, &e)) == NULL) {
		if (e.sp == XLOG_FS)
			FUSE_REPLY(&r_sent, fuse_reply_err(req, e.code));
		else
			FS_ERR(&r_sent, req, &e);
		goto unlock;
	}

	fi->fh = (uint64_t)of;

	inode_lock(of->oi, LK_LOCK_RD);
	is_dir = inode_isdir(of->oi);
	inode_unlock(of->oi);

	if (!is_dir) {
		FUSE_REPLY(&r_sent, fuse_reply_err(req, ENOTDIR));
		if (openfile_free(of, &e) == -1) {
			xlog(LOG_ERR, &e, __func__);
			fs_error_set();
		}
	}

	FUSE_REPLY(&r_sent, fuse_reply_open(req, fi));
unlock:
	LK_UNLOCK(&fs_tree_lock);
}

static void
fs_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
    struct fuse_file_info *fi)
{
	struct xerr       e = XLOG_ERR_INITIALIZER;
	struct oinode    *oi;
	struct inode      inode;
	struct dir_entry  dirs[64];
	ssize_t           r;
	int               i;
	struct stat       st;
	char              buf[size];
	size_t            buf_used = 0;
	size_t            need;
	int               r_sent = 0;
	off_t             de_off;

	counter_incr(COUNTER_FS_READDIR);
	LK_RDLOCK(&fs_tree_lock);

	oi = ((struct open_file *)fi->fh)->oi;

	inode_lock(oi, LK_LOCK_RD);

	for (;;) {
		r = di_readdir(oi, dirs, &off,
		    sizeof(dirs) / sizeof(struct dir_entry), &e);
		if (r == -1) {
			if (e.sp == XLOG_FS)
				FUSE_REPLY(&r_sent,
				    fuse_reply_err(req, e.code));
			else
				FS_ERR(&r_sent, req, &e);
			goto fail;
		} else if (r == 0)
			break;

		for (i = 0, de_off = off - ((r - 1) * sizeof(struct dir_entry));
		    i < r; i++, de_off += sizeof(struct dir_entry)) {
			bzero(&st, sizeof(st));

			if (dirs[i].inode != inode_ino(oi)) {
				if (inode_cp_ino(dirs[i].inode, &inode,
				    &e) == -1) {
					if (!xerr_is(&e, XLOG_FS, ENOENT)) {
						FS_ERR(&r_sent, req, &e);
						goto fail;
					}
					continue;
				}
				inode_cp_stat(&st, &inode);
			} else
				inode_cp_stat(&st, &oi->ino);

			need = fuse_add_direntry(req, NULL, 0,
			    dirs[i].name, NULL, 0);
			if (buf_used + need > size)
				goto end;

			buf_used += fuse_add_direntry(req, buf + buf_used,
			    size - buf_used, dirs[i].name, &st, de_off);
		}
	}
end:
	fs_set_time(oi, INODE_ATTR_ATIME);

	if (buf_used == 0)
		FUSE_REPLY(&r_sent, fuse_reply_buf(req, NULL, buf_used));
	else
		FUSE_REPLY(&r_sent, fuse_reply_buf(req, buf, buf_used));
fail:
	inode_unlock(oi);
	LK_UNLOCK(&fs_tree_lock);
}

static void
fs_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	int               r_sent = 0, is_dir;
	struct xerr       e = XLOG_ERR_INITIALIZER;
	struct open_file *of = (struct open_file *)fi->fh;

	LK_RDLOCK(&fs_tree_lock);
	inode_lock(of->oi, LK_LOCK_RD);
	is_dir = inode_isdir(of->oi);
	inode_unlock(of->oi);

	counter_incr(is_dir
	    ? COUNTER_FS_RELEASEDIR
	    : COUNTER_FS_RELEASE);

	if (openfile_free(of, &e) == -1)
		FS_ERR(&r_sent, req, &e);
	else
		FUSE_REPLY(&r_sent, fuse_reply_err(req, 0));
	LK_UNLOCK(&fs_tree_lock);
}

static void
fs_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct xerr       e = XLOG_ERR_INITIALIZER;
	struct open_file *of;
	int               r_sent = 0;

	counter_incr(COUNTER_FS_OPEN);

	if ((of = openfile_alloc(ino, fi->flags, &e)) == NULL) {
		if (e.sp == XLOG_FS)
			FUSE_REPLY(&r_sent, fuse_reply_err(req, e.code));
		else
			FS_ERR(&r_sent, req, &e);
		return;
	}

	fi->fh = (uint64_t)of;

	FUSE_REPLY(&r_sent, fuse_reply_open(req, fi));
}

static void
fs_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
    struct fuse_file_info *fi)
{
	struct xerr                 e = XLOG_ERR_INITIALIZER;
	struct open_file           *of;
	struct fuse_bufvec         *bv;
	int                         r_sent = 0, i;
	struct inode_splice_bufvec  si;

	counter_incr(COUNTER_FS_READ);

	of = (struct open_file *)fi->fh;

	bv = malloc(sizeof(struct fuse_bufvec) +
	    (sizeof(struct fuse_buf) * (size / slab_get_max_size() + 2)));
	if (bv == NULL) {
		XERRF(&e, XLOG_ERRNO, errno, "malloc");
		FS_ERR(&r_sent, req, &e);
		return;
	}

	if (inode_splice_begin_read(&si, of->oi, off, size, &e) == -1) {
		FS_ERR(&r_sent, req, &e);
		free(bv);
		return;
	}

	bv->count = si.nv;
	bv->idx = 0;
	bv->off = 0;
	if (si.nv == 0) {
		FUSE_REPLY(&r_sent, fuse_reply_buf(req, "", 0));
	} else {
		for (i = 0; i < si.nv; i++) {
			bv->buf[i].size = si.v[i].count;
			if (si.v[i].buf != NULL) {
				bv->buf[i].mem = si.v[i].buf;
				bv->buf[i].flags = 0;
			} else {
				bv->buf[i].pos = si.v[i].rel_offset;
				bv->buf[i].fd = si.v[i].fd;
				bv->buf[i].flags =
				    FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
			}
		}
		counter_add(COUNTER_READ_BYTES, fuse_buf_size(bv));
		inode_lock(of->oi, LK_LOCK_RW);
		fs_set_time(of->oi, INODE_ATTR_ATIME);
		inode_unlock(of->oi);
		FUSE_REPLY(&r_sent, fuse_reply_data(req, bv,
		    FUSE_BUF_FORCE_SPLICE));
	}

	if (inode_splice_end_read(&si, &e) == -1)
		xlog(LOG_ERR, &e, "%s: inode_splice_end_read", __func__);
	free(bv);
}

static void
fs_write_buf(fuse_req_t req, fuse_ino_t ino, struct fuse_bufvec *bufv,
    off_t off, struct fuse_file_info *fi)
{
	struct xerr                 e = XLOG_ERR_INITIALIZER;
	struct open_file           *of;
	ssize_t                     w;
	size_t                      sz = fuse_buf_size(bufv);
	struct fuse_bufvec         *bv;
	int                         i, r_sent = 0;
	struct inode_splice_bufvec  si;

	counter_incr(COUNTER_FS_WRITE);
	if (FS_RO_ON_ERR(req)) return;

	of = (struct open_file *)fi->fh;

	bv = malloc(sizeof(struct fuse_bufvec) +
	    (sizeof(struct fuse_buf) * (sz / slab_get_max_size() + 2)));
	if (bv == NULL) {
		XERRF(&e, XLOG_ERRNO, errno, "malloc");
		FS_ERR(&r_sent, req, &e);
		return;
	}

	if (inode_splice_begin_write(&si, of->oi, off,
	    fuse_buf_size(bufv), &e) == -1) {
		if (e.sp == XLOG_FS)
			FUSE_REPLY(&r_sent, fuse_reply_err(req, e.code));
		else
			FS_ERR(&r_sent, req, &e);
		free(bv);
		return;
	}

	bv->count = si.nv;
	bv->idx = 0;
	bv->off = 0;
	for (i = 0; i < si.nv; i++) {
		bv->buf[i].size = si.v[i].count;
		if (si.v[i].buf != NULL) {
			bv->buf[i].mem = si.v[i].buf;
			bv->buf[i].flags = 0;
		} else {
			bv->buf[i].pos = si.v[i].rel_offset;
			bv->buf[i].fd = si.v[i].fd;
			bv->buf[i].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
		}
	}

	if ((w = fuse_buf_copy(bv, bufv, FUSE_BUF_FORCE_SPLICE)) < 0) {
		FUSE_REPLY(&r_sent, fuse_reply_err(req, -w));
		return;
	}
	xerrz(&e);

	/*
	 * We still need to do cleanup on error. Let's report zero bytes
	 * written.
	 */
	if (w < 0)
		w = 0;

	bufv->off += w;

	if (inode_splice_end_write(&si, w, &e) == -1)
		FS_ERR(&r_sent, req, &e);
	free(bv);

	inode_lock(of->oi, LK_LOCK_RW);
	fs_set_time(of->oi, INODE_ATTR_MTIME|INODE_ATTR_CTIME);
	inode_unlock(of->oi);

	counter_add(COUNTER_WRITE_BYTES, w);
	FUSE_REPLY(&r_sent, fuse_reply_write(req, w));
}

static void
fs_flush(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct xerr       e = XLOG_ERR_INITIALIZER;
	struct open_file *of;
	int               r_sent = 0;

	LK_RDLOCK(&fs_tree_lock);
	counter_incr(COUNTER_FS_FLUSH);

	of = (struct open_file *)fi->fh;

	inode_lock(of->oi, LK_LOCK_RW);
	if (inode_flush(of->oi, 0, &e) == -1)
		FS_ERR(&r_sent, req, &e);
	inode_unlock(of->oi);

	FUSE_REPLY(&r_sent, fuse_reply_err(req, 0));
	LK_UNLOCK(&fs_tree_lock);
}

static void
fs_forget(fuse_req_t req, fuse_ino_t ino, unsigned long nlookup)
{
	struct xerr e = XLOG_ERR_INITIALIZER;

	xlog_dbg(XLOG_OP, "%s: req=%p, ino=%lu, nlookup=%ld",
	    __func__, req, ino, -nlookup);

	LK_RDLOCK(&fs_tree_lock);
	counter_incr(COUNTER_FS_FORGET);
	if (inode_nlookup_ino(ino, -nlookup, &e) == -1)
		xlog(LOG_ERR, &e, __func__);
	fuse_reply_none(req);
	LK_UNLOCK(&fs_tree_lock);
}

static void
fs_forget_multi(fuse_req_t req, size_t count,
    struct fuse_forget_data *forgets)
{
	struct xerr e = XLOG_ERR_INITIALIZER;
	int         i;

	LK_RDLOCK(&fs_tree_lock);
	counter_incr(COUNTER_FS_FORGET_MULTI);

	for (i = 0; i < count; i++) {
		xlog_dbg(XLOG_OP, "%s: req=%p, ino=%lu, nlookup=%ld",
		    __func__, req, forgets[i].ino, -forgets[i].nlookup);
		if (inode_nlookup_ino(forgets[i].ino,
		    -forgets[i].nlookup, &e) == -1)
			xlog(LOG_ERR, &e, __func__);
	}
	fuse_reply_none(req);
	LK_UNLOCK(&fs_tree_lock);
}

static void
fs_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	struct xerr              e = XLOG_ERR_INITIALIZER;
	struct fuse_entry_param  entry;
	struct dir_entry         de;
	int                      status;
	struct oinode           *oi = NULL, *parent_oi;
	int                      r_sent = 0;

	xlog_dbg(XLOG_OP, "%s: req=%p, parent_ino=%lu, name=%s",
	    __func__, req, parent, name);
	counter_incr(COUNTER_FS_LOOKUP);
	LK_RDLOCK(&fs_tree_lock);

	if ((parent_oi = inode_load(parent, 0, &e)) == NULL) {
		if (e.sp == XLOG_FS)
			FUSE_REPLY(&r_sent, fuse_reply_err(req, e.code));
		else
			FS_ERR(&r_sent, req, &e);
		goto unlock;
	}
	inode_lock(parent_oi, LK_LOCK_RD);

	if ((status = di_lookup(parent_oi, &de, name, &e)) == -1) {
		if (e.sp == XLOG_FS)
			FUSE_REPLY(&r_sent, fuse_reply_err(req, e.code));
		else
			FS_ERR(&r_sent, req, &e);
	}

	xerrz(&e);
	if (r_sent)
		goto end;

	if ((oi = inode_load(de.inode, 0, &e)) == NULL) {
		if (e.sp == XLOG_FS)
			FUSE_REPLY(&r_sent, fuse_reply_err(req, e.code));
		else
			FS_ERR(&r_sent, req, &e);
		goto end;
	}
	inode_lock(oi, LK_LOCK_RW);

	bzero(&entry, sizeof(entry));
	entry.ino = de.inode;
	entry.generation = oi->ino.v.f.generation;
	entry.attr_timeout = fs_config.entry_timeouts;
	entry.entry_timeout = fs_config.entry_timeouts;
	inode_cp_stat(&entry.attr, &oi->ino);
	inode_nlookup(oi, 1);

end:
	if (oi) {
		inode_unlock(oi);
		if (inode_unload(oi, &e) == -1)
			FS_ERR(&r_sent, req, &e);
		else
			FUSE_REPLY(&r_sent, fuse_reply_entry(req, &entry));
	}

	xerrz(&e);

	/* We don't update atime on the parent for lookups. */

	inode_unlock(parent_oi);
	if (inode_unload(parent_oi, &e) == -1)
		FS_ERR(&r_sent, req, &e);
unlock:
	LK_UNLOCK(&fs_tree_lock);
}

static void
fs_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode)
{
	counter_incr(COUNTER_FS_MKDIR);
	if (FS_RO_ON_ERR(req)) return;
	LK_RDLOCK(&fs_tree_lock);
	fs_mknod(req, parent, name, mode | S_IFDIR, 0);
	LK_UNLOCK(&fs_tree_lock);
}

static void
fs_rmnod(fuse_req_t req, fuse_ino_t parent, const char *name, int is_rmdir)
{
	struct xerr       e = XLOG_ERR_INITIALIZER;
	struct oinode    *parent_oi, *oi = NULL;
	struct dir_entry  de;
	int               r_sent = 0;

	if (strlen(name) > FS_NAME_MAX) {
		FUSE_REPLY(&r_sent, fuse_reply_err(req, ENAMETOOLONG));
		return;
	}

	LK_RDLOCK(&fs_tree_lock);

	if ((parent_oi = inode_load(parent, 0, &e)) == NULL) {
		if (e.sp == XLOG_FS)
			FUSE_REPLY(&r_sent, fuse_reply_err(req, e.code));
		else
			FS_ERR(&r_sent, req, &e);
		goto unlock;
	}
	inode_lock(parent_oi, LK_LOCK_RW);

	if (di_lookup(parent_oi, &de, name, &e) == -1) {
		if (e.sp == XLOG_FS)
			FUSE_REPLY(&r_sent, fuse_reply_err(req, e.code));
		else
			FS_ERR(&r_sent, req, &e);
		xerrz(&e);
		goto end;
	}

	if ((oi = inode_load(de.inode, 0, &e)) == NULL) {
		FS_ERR(&r_sent, req, &e);
		xerrz(&e);
		goto end;
	}
	inode_lock(oi, LK_LOCK_RW);

	if (!inode_isdir(oi)) {
		if (is_rmdir) {
			FUSE_REPLY(&r_sent, fuse_reply_err(req, ENOTDIR));
			goto end;
		}
	} else if (oi->ino.v.f.nlink <= 2) {
		switch (di_isempty(oi, &e)) {
		case 0:
			FUSE_REPLY(&r_sent,
			    fuse_reply_err(req, ENOTEMPTY));
			goto end;
		case 1:
			break;
		default:
			FS_ERR(&r_sent, req, &e);
			xerrz(&e);
			goto end;
		}
	}

	if ((di_unlink(parent_oi, &de, &e)) == -1) {
		if (e.sp == XLOG_FS)
			FUSE_REPLY(&r_sent, fuse_reply_err(req, e.code));
		else
			FS_ERR(&r_sent, req, &e);
		xerrz(&e);
		goto end;
	}

	if (inode_isdir(oi)) {
		/*
		 * Directories always have at least 2 links,
		 * with one for "." and itself. The parent must also
		 * be reduced by one link, since ".." is going away in the
		 * removed dir.
		 */
		inode_nlink(parent_oi, -1);
		inode_nlink(oi, -2);
	} else {
		inode_nlink(oi, -1);
	}
	if (inode_flush(parent_oi, 0, &e) == -1)
		FS_ERR(&r_sent, req, &e);
	if (inode_flush(oi, 0, &e) == -1)
		FS_ERR(&r_sent, req, &e);
end:
	if (oi) {
		inode_unlock(oi);
		if (inode_unload(oi, &e) == -1) {
			FS_ERR(&r_sent, req, &e);
			xerrz(&e);
		}
	}

	fs_set_time(parent_oi, INODE_ATTR_MTIME);

	inode_unlock(parent_oi);

	if (inode_unload(parent_oi, &e) == -1)
		FS_ERR(&r_sent, req, &e);
	else
		FUSE_REPLY(&r_sent, fuse_reply_err(req, 0));
unlock:
	LK_UNLOCK(&fs_tree_lock);
}

static void
fs_rmdir(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	counter_incr(COUNTER_FS_RMDIR);
	if (FS_RO_ON_ERR(req)) return;
	fs_rmnod(req, parent, name, 1);
}

static void
fs_unlink(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	counter_incr(COUNTER_FS_UNLINK);
	if (FS_RO_ON_ERR(req)) return;
	fs_rmnod(req, parent, name, 0);
}

static void
fs_statfs(fuse_req_t req, fuse_ino_t ino)
{
	struct xerr    e = XLOG_ERR_INITIALIZER;
	int            r_sent = 0;
	struct fs_info fs_info;

	counter_incr(COUNTER_FS_STATFS);

	if (mgr_fs_info(&fs_info, &e) == -1) {
		xlog(LOG_ERR, &e, __func__);
		fs_error_set();
		FS_ERR(&r_sent, req, &e);
		return;
	}

	FUSE_REPLY(&r_sent, fuse_reply_statfs(req, &fs_info.stats));
	return;
}

static int
make_inode(ino_t parent, const char *name, uid_t uid, gid_t gid,
    mode_t mode, mode_t mask, dev_t rdev, struct inode *inode,
    const char *data, size_t data_len, struct xerr *e)
{
	struct xerr       e_dealloc = XLOG_ERR_INITIALIZER;
	struct xerr       e_unload = XLOG_ERR_INITIALIZER;
	struct dir_entry  de;
	struct oinode    *parent_oi, *oi;
	int               status = 0;
	ssize_t           w = 0;
	int               flushed = 0;
	int               is_dir = 0;
	struct dir_entry  default_dir[2] = {
		{ ".", 0, sizeof(struct dir_entry) },
		{ "..", parent, 0 }
	};

	if (strlen(name) > FS_NAME_MAX)
		return XERRF(e, XLOG_FS, ENAMETOOLONG,
		    "file name too long");

	if ((inode_make(0, uid, gid, (mode & ~(mode & mask)), inode, e)) == -1)
		return -1;

	if ((oi = inode_load(inode->v.f.inode, 0, e)) == NULL) {
		if (inode_dealloc(inode->v.f.inode, &e_dealloc) == -1) {
			fs_error_set();
			xlog(LOG_ERR, &e_dealloc, __func__);
		}
		return -1;
	}

	inode_lock(oi, LK_LOCK_RW);
	inode_nlink(oi, 1);
	inode_nlookup(oi, 1);
	if (inode_isdir(oi)) {
		default_dir[0].inode = inode_ino(oi);
		is_dir = 1;
		inode_nlink(oi, 1);
		w = inode_write(oi, 0, default_dir, sizeof(default_dir), e);
	} else if (data) {
		/* So far this is strictly used for symlinks */
		w = inode_write(oi, 0, data, data_len, e);
	}
	if ((flushed = inode_flush(oi, 0, e)) == -1) {
		xlog(LOG_ERR, e, __func__);
		xerrz(e);
	}
	memcpy(inode, &oi->ino, sizeof(struct inode));
	inode_unlock(oi);

	if (w == -1) {
		xlog(LOG_ERR, e, __func__);
		xerrz(e);
	}

	if (inode_unload(oi, e) == -1 || flushed == -1 ||
	    (data && (w < data_len)) || (is_dir && (w < sizeof(default_dir)))) {
		if (!xerr_fail(e))
			XERRF(e, XLOG_APP, XLOG_IO,
			    "short write on inline inode data or directory");
		goto unlink;
	}
	oi = NULL;

	de.inode = inode->v.f.inode;
	strlcpy(de.name, name, sizeof(de.name));
	de.name[sizeof(de.name) - 1] = '\0';

	if ((parent_oi = inode_load(parent, 0, e)) == NULL)
		goto unlink;

	inode_lock(parent_oi, LK_LOCK_RW);
	/* Because of the new inode's ".." link */
	if (is_dir)
		inode_nlink(parent_oi, 1);
	status = di_mkdirent(parent_oi, &de, NULL, e);
	if ((flushed = inode_flush(parent_oi, 0, e)) == -1) {
		xlog(LOG_ERR, e, __func__);
		xerrz(e);
	}
	fs_set_time(parent_oi, INODE_ATTR_MTIME);
	inode_unlock(parent_oi);

	if (inode_unload(parent_oi, &e_unload) == -1) {
		fs_error_set();
		xlog(LOG_ERR, &e_unload, __func__);
		goto unlink;
	}

	if (status == -1 || flushed == -1) {
		fs_error_set();
		goto unlink;
	}

	return 0;
unlink:
	if (inode_nlink_ino(inode->v.f.inode,
	    (is_dir) ? -2 : -1, &e_dealloc) == -1) {
		fs_error_set();
		xlog(LOG_ERR, &e_dealloc, __func__);
	}
	xerrz(&e_dealloc);
	if (is_dir && inode_nlink_ino(parent, -1, &e_dealloc) == -1) {
		fs_error_set();
		xlog(LOG_ERR, &e_dealloc, __func__);
	}
	return -1;
}

static void
fs_mknod(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode,
    dev_t rdev)
{
	int                     status;
	struct xerr             e = XLOG_ERR_INITIALIZER;
	struct inode            inode;
	struct fuse_entry_param entry;
	int                     r_sent = 0;

	if (!(mode & S_IFDIR))
		counter_incr(COUNTER_FS_MKNOD);
	if (FS_RO_ON_ERR(req)) return;
	LK_RDLOCK(&fs_tree_lock);

	status = make_inode(parent, name, fuse_req_ctx(req)->uid,
	    fuse_req_ctx(req)->gid, mode, fuse_req_ctx(req)->umask,
	    rdev, &inode, NULL, 0, &e);
	if (status == -1) {
		if (e.sp == XLOG_FS)
			FUSE_REPLY(&r_sent, fuse_reply_err(req, e.code));
		else
			FS_ERR(&r_sent, req, &e);
		goto unlock;
	}

	bzero(&entry, sizeof(entry));
	entry.ino = inode.v.f.inode;
	entry.generation = inode.v.f.generation;
	entry.attr_timeout = fs_config.entry_timeouts;
	entry.entry_timeout = fs_config.entry_timeouts;
	inode_cp_stat(&entry.attr, &inode);

	FUSE_REPLY(&r_sent, fuse_reply_entry(req, &entry));
unlock:
	LK_UNLOCK(&fs_tree_lock);
}

static void
fs_create(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode,
    struct fuse_file_info *fi)
{
	int                      status;
	struct xerr              e = XLOG_ERR_INITIALIZER;
	struct inode             inode;
	struct fuse_entry_param  entry;
	struct open_file        *of;
	int                      r_sent = 0;

	counter_incr(COUNTER_FS_CREATE);
	if (FS_RO_ON_ERR(req)) return;
	LK_RDLOCK(&fs_tree_lock);

	status = make_inode(parent, name, fuse_req_ctx(req)->uid,
	    fuse_req_ctx(req)->gid, mode, fuse_req_ctx(req)->umask,
	    0, &inode, NULL, 0, &e);
	if (status == -1) {
		if (e.sp == XLOG_FS)
			FUSE_REPLY(&r_sent, fuse_reply_err(req, e.code));
		else
			FS_ERR(&r_sent, req, &e);
		goto unlock;
	}

	bzero(&entry, sizeof(entry));
	entry.ino = inode.v.f.inode;
	entry.generation = inode.v.f.generation;
	entry.attr_timeout = fs_config.entry_timeouts;
	entry.entry_timeout = fs_config.entry_timeouts;
	inode_cp_stat(&entry.attr, &inode);

	if ((of = openfile_alloc(inode.v.f.inode,
	    fi->flags, &e)) == NULL) {
		if (e.sp == XLOG_FS)
			FUSE_REPLY(&r_sent, fuse_reply_err(req, e.code));
		else
			FS_ERR(&r_sent, req, &e);
		if (inode_nlink_ino(inode.v.f.inode, -1, &e) == -1)
			FS_ERR(&r_sent, req, &e);
		goto unlock;
	}

	fi->fh = (uint64_t)of;

	FUSE_REPLY(&r_sent, fuse_reply_create(req, &entry, fi));
unlock:
	LK_UNLOCK(&fs_tree_lock);
}

static void
fs_fallocate(fuse_req_t req, fuse_ino_t ino, int mode,
    off_t offset, off_t length, struct fuse_file_info *fi)
{
	struct xerr    e = XLOG_ERR_INITIALIZER;
	struct oinode *oi;
	int            r_sent = 0;

	counter_incr(COUNTER_FS_FALLOCATE);
	if (FS_RO_ON_ERR(req)) return;

	if ((oi = inode_load(ino, 0, &e)) == NULL) {
		if (e.sp == XLOG_FS)
			FUSE_REPLY(&r_sent, fuse_reply_err(req, e.code));
		else
			FS_ERR(&r_sent, req, &e);
		return;
	}

	if (inode_fallocate(oi, offset, length, mode, &e) == -1)
		FS_ERR(&r_sent, req, &e);
	else
		FUSE_REPLY(&r_sent, fuse_reply_err(req, 0));

	xerrz(&e);

	if (inode_unload(oi, &e) == -1)
		FS_ERR(&r_sent, req, &e);
}

/*
 * 'datasync' isn't used. The metadata is always synced, since part of the
 * data is stored in the inode itself. There's no way to not sync the
 * metadata.
 */
static void
fs_fsync(fuse_req_t req, fuse_ino_t ino, int datasync,
    struct fuse_file_info *fi)
{
	struct xerr    e = XLOG_ERR_INITIALIZER;
	int            r_sent = 0;
	struct oinode *oi;

	oi = ((struct open_file *)fi->fh)->oi;

	counter_incr(COUNTER_FS_FSYNC);

	inode_lock(oi, LK_LOCK_RW);
	if (inode_sync(oi, &e) == -1)
		FS_ERR(&r_sent, req, &e);
	else
		FUSE_REPLY(&r_sent, fuse_reply_err(req, 0));
	inode_unlock(oi);
}

/*
 * 'datasync' isn't used. The metadata is always synced, since part of the
 * data is stored in the inode itself. There's no way to not sync the
 * metadata.
 */
static void
fs_fsyncdir(fuse_req_t req, fuse_ino_t ino, int datasync,
    struct fuse_file_info *fi)
{
	struct xerr    e = XLOG_ERR_INITIALIZER;
	int            r_sent = 0;
	struct oinode *oi;

	counter_incr(COUNTER_FS_FSYNCDIR);
	LK_RDLOCK(&fs_tree_lock);

	oi = ((struct open_file *)fi->fh)->oi;

	inode_lock(oi, LK_LOCK_RW);
	if (inode_sync(((struct open_file *)fi->fh)->oi, &e) == -1)
		FS_ERR(&r_sent, req, &e);
	else
		FUSE_REPLY(&r_sent, fuse_reply_err(req, 0));
	inode_unlock(oi);
	LK_UNLOCK(&fs_tree_lock);
}

static void
fs_link(fuse_req_t req, fuse_ino_t ino, fuse_ino_t newparent,
    const char *newname)
{
	struct xerr              e = XLOG_ERR_INITIALIZER;
	struct dir_entry         new_de;
	struct oinode           *oi = NULL, *parent_oi;
	struct fuse_entry_param  entry;
	int                      r_sent = 0;

	counter_incr(COUNTER_FS_LINK);
	if (FS_RO_ON_ERR(req)) return;

	if (strlen(newname) > FS_NAME_MAX) {
		FUSE_REPLY(&r_sent, fuse_reply_err(req, ENAMETOOLONG));
		return;
	}

	LK_RDLOCK(&fs_tree_lock);

	new_de.inode = ino;
	strlcpy(new_de.name, newname, sizeof(new_de.name));
	new_de.name[sizeof(new_de.name) - 1] = '\0';

	if ((parent_oi = inode_load(newparent, 0, &e)) == NULL) {
		if (e.sp == XLOG_FS)
			FUSE_REPLY(&r_sent, fuse_reply_err(req, e.code));
		else
			FS_ERR(&r_sent, req, &e);
		goto unlock;
	}
	inode_lock(parent_oi, LK_LOCK_RW);

	if ((oi = inode_load(ino, 0, &e)) == NULL) {
		if (e.sp == XLOG_FS)
			FUSE_REPLY(&r_sent, fuse_reply_err(req, e.code));
		else
			FS_ERR(&r_sent, req, &e);
		xerrz(&e);
		goto end;
	}
	inode_lock(oi, LK_LOCK_RW);

	if (inode_isdir(oi)) {
		FUSE_REPLY(&r_sent, fuse_reply_err(req, EPERM));
		xerrz(&e);
		goto end;
	}
	if (oi->ino.v.f.nlink >= FS_LINK_MAX) {
		FUSE_REPLY(&r_sent, fuse_reply_err(req, EMLINK));
		xerrz(&e);
		goto end;
	}

	bzero(&entry, sizeof(entry));
	entry.ino = ino;
	entry.generation = oi->ino.v.f.generation;
	entry.attr_timeout = fs_config.entry_timeouts;
	entry.entry_timeout = fs_config.entry_timeouts;
	inode_cp_stat(&entry.attr, &oi->ino);
	inode_nlookup(oi, 1);
	inode_nlink(oi, 1);
	fs_set_time(oi, INODE_ATTR_CTIME);

	if (di_mkdirent(parent_oi, &new_de, NULL, &e) == -1) {
		FS_ERR(&r_sent, req, &e);
		xerrz(&e);
		inode_nlink(oi, -1);
		inode_nlookup(oi, -1);
	}
	if (inode_flush(oi, 0, &e) == -1)
		FS_ERR(&r_sent, req, &e);
end:
	if (oi) {
		inode_unlock(oi);
		if (inode_unload(oi, &e) == -1) {
			FS_ERR(&r_sent, req, &e);
			xerrz(&e);
		}
	}

	fs_set_time(parent_oi, INODE_ATTR_MTIME|INODE_ATTR_CTIME);
	inode_unlock(parent_oi);
	if (inode_unload(parent_oi, &e) == -1)
		FS_ERR(&r_sent, req, &e);

	FUSE_REPLY(&r_sent, fuse_reply_entry(req, &entry));
unlock:
	LK_UNLOCK(&fs_tree_lock);
}

static void
fs_symlink(fuse_req_t req, const char *link, fuse_ino_t parent,
    const char *name)
{
	int                     status;
	struct xerr             e = XLOG_ERR_INITIALIZER;
	struct inode            inode;
	struct fuse_entry_param entry;
	int                     r_sent = 0;

	counter_incr(COUNTER_FS_SYMLINK);
	if (FS_RO_ON_ERR(req)) return;

	if (strlen(link) >= FS_PATH_MAX) {
		FUSE_REPLY(&r_sent, fuse_reply_err(req, ENAMETOOLONG));
		return;
	}

	LK_RDLOCK(&fs_tree_lock);

	status = make_inode(parent, name, fuse_req_ctx(req)->uid,
	    fuse_req_ctx(req)->gid, 0777 | S_IFLNK, fuse_req_ctx(req)->umask,
	    0, &inode, link, strlen(link), &e);
	if (status == -1) {
		if (e.sp == XLOG_FS)
			FUSE_REPLY(&r_sent, fuse_reply_err(req, e.code));
		else
			FS_ERR(&r_sent, req, &e);
		goto unlock;
	}

	bzero(&entry, sizeof(entry));
	entry.ino = inode.v.f.inode;
	entry.generation = inode.v.f.generation;
	entry.attr_timeout = fs_config.entry_timeouts;
	entry.entry_timeout = fs_config.entry_timeouts;
	inode_cp_stat(&entry.attr, &inode);

	FUSE_REPLY(&r_sent, fuse_reply_entry(req, &entry));
unlock:
	LK_UNLOCK(&fs_tree_lock);
}

static void
fs_readlink(fuse_req_t req, fuse_ino_t ino)
{
	struct xerr    e = XLOG_ERR_INITIALIZER;
	ssize_t        r, offset;
	char           link[FS_PATH_MAX];
	int            r_sent = 0;
	struct oinode *oi;

	counter_incr(COUNTER_FS_READLINK);
	LK_RDLOCK(&fs_tree_lock);

	if ((oi = inode_load(ino, 0, &e)) == NULL) {
		if (e.sp == XLOG_FS)
			FUSE_REPLY(&r_sent, fuse_reply_err(req, e.code));
		else
			FS_ERR(&r_sent, req, &e);
		goto unlock;
	}
	inode_lock(oi, LK_LOCK_RD);

	for (offset = 0; offset < (FS_PATH_MAX - 1); offset += r) {
		r = inode_read(oi, offset, link + offset,
		    FS_PATH_MAX - offset - 1, &e);
		if (r == 0) {
			break;
		} else if (r == -1) {
			FS_ERR(&r_sent, req, &e);
			xerrz(&e);
			break;
		} else if (offset >= FS_PATH_MAX) {
			FUSE_REPLY(&r_sent, fuse_reply_err(req, ENAMETOOLONG));
			break;
		}
	}
	link[offset] = '\0';

	fs_set_time(oi, INODE_ATTR_ATIME);
	inode_unlock(oi);

	if (inode_unload(oi, &e) == -1)
		FS_ERR(&r_sent, req, &e);

	FUSE_REPLY(&r_sent, fuse_reply_readlink(req, link));
unlock:
	LK_UNLOCK(&fs_tree_lock);
}

static void
fs_rename(fuse_req_t req, fuse_ino_t oldparent, const char *oldname,
    fuse_ino_t newparent, const char *newname)
{
	struct xerr       e = XLOG_ERR_INITIALIZER;
	struct dir_entry  de, new_de, replaced;
	struct oinode    *old_doi = NULL, *new_doi = NULL;
	struct oinode    *oi = NULL, *new_oi = NULL, *p_oi;
	int               r_sent = 0;
	int               oldparent_depth = 0, newparent_depth = 0;
	ino_t             p;

	counter_incr(COUNTER_FS_RENAME);
	if (FS_RO_ON_ERR(req)) return;

	if (strlen(newname) > FS_NAME_MAX) {
		FUSE_REPLY(&r_sent, fuse_reply_err(req, ENAMETOOLONG));
		return;
	}

	LK_WRLOCK(&fs_tree_lock);

	if ((old_doi = inode_load(oldparent, 0, &e)) == NULL) {
		if (e.sp == XLOG_FS)
			FUSE_REPLY(&r_sent, fuse_reply_err(req, e.code));
		else
			FS_ERR(&r_sent, req, &e);
		goto unlock;
	}

	if (oldparent == newparent) {
		new_doi = old_doi;
	} else if ((new_doi = inode_load(newparent, 0, &e)) == NULL) {
		if (e.sp == XLOG_FS)
			FUSE_REPLY(&r_sent, fuse_reply_err(req, e.code));
		else
			FS_ERR(&r_sent, req, &e);
		xerrz(&e);
		goto end;
	}

	if (di_lookup(old_doi, &de, oldname, &e) == -1) {
		if (e.sp == XLOG_FS)
			FUSE_REPLY(&r_sent, fuse_reply_err(req, e.code));
		else
			FS_ERR(&r_sent, req, &e);
		xerrz(&e);
		goto end;
	} else if ((oi = inode_load(de.inode, 0, &e)) == NULL) {
		if (e.sp == XLOG_FS)
			FUSE_REPLY(&r_sent, fuse_reply_err(req, e.code));
		else
			FS_ERR(&r_sent, req, &e);
		xerrz(&e);
		goto end;
	}

	if (di_lookup(new_doi, &new_de, newname, &e) == -1) {
		if (!xerr_is(&e, XLOG_FS, ENOENT)) {
			FS_ERR(&r_sent, req, &e);
			xerrz(&e);
			goto end;
		}
		xerrz(&e);
	} else if ((new_oi = inode_load(new_de.inode, 0, &e)) == NULL) {
		FS_ERR(&r_sent, req, &e);
		xerrz(&e);
		goto end;
	}

	if (new_oi == oi) {
		/*
		 * We do this out of completeness, but FUSE already
		 * catches this for us.
		 */
		goto end;
	}

	if (new_oi != NULL &&
	    !inode_isdir(oi) && inode_isdir(new_oi)) {
		/*
		 * We do this out of completeness, but FUSE already
		 * catches this for us.
		 */
		FUSE_REPLY(&r_sent, fuse_reply_err(req, EISDIR));
		goto end;
	}

	if (inode_ino(oi) == FS_ROOT_INODE ||
	    (new_oi != NULL && inode_ino(new_oi) == FS_ROOT_INODE)) {
		FUSE_REPLY(&r_sent, fuse_reply_err(req, EBUSY));
		goto end;
	}

	if (oldparent == newparent) {
		inode_lock(old_doi, LK_LOCK_RW);
	} else {
		/*
		 * We can't move in one of our descendants. Walk back from
		 * the new parent to the root, and if we see the moved inode
		 * in the chain, return EINVAL.
		 */
		for (p = newparent; p != FS_ROOT_INODE; newparent_depth++) {
			if ((p_oi = inode_load(p, 0, &e)) == NULL) {
				FS_ERR(&r_sent, req, &e);
				xerrz(&e);
				goto end;
			}
			if ((p = di_parent(p_oi, &e)) == -1) {
				FS_ERR(&r_sent, req, &e);
				xerrz(&e);
			}
			if (inode_unload(p_oi, &e) == -1) {
				FS_ERR(&r_sent, req, &e);
				xerrz(&e);
				goto end;
			}

			if (p == -1)
				goto end;

			if (p == inode_ino(oi)) {
				FUSE_REPLY(&r_sent,
				    fuse_reply_err(req, EINVAL));
				goto end;
			}
		}

		/*
		 * We can't replace one of our ancestors. Walk back
		 * from the old parent to the root, and if we see the
		 * moved inode int he chain, return ENOTEMPTY.
		 */
		for (p = oldparent; p != FS_ROOT_INODE; oldparent_depth++) {
			if ((p_oi = inode_load(p, 0, &e)) == NULL) {
				FS_ERR(&r_sent, req, &e);
				xerrz(&e);
				goto end;
			}
			if ((p = di_parent(p_oi, &e)) == -1) {
				FS_ERR(&r_sent, req, &e);
				xerrz(&e);
			}
			if (inode_unload(p_oi, &e) == -1) {
				FS_ERR(&r_sent, req, &e);
				xerrz(&e);
				goto end;
			}

			if (p == -1)
				goto end;

			if (new_oi != NULL && p == inode_ino(new_oi)) {
				FUSE_REPLY(&r_sent,
				    fuse_reply_err(req, ENOTEMPTY));
				goto end;
			}
		}

		if (oldparent_depth == newparent_depth) {
			/* Always lock directories in pointer ascending order */
			if (old_doi < new_doi) {
				inode_lock(old_doi, LK_LOCK_RW);
				inode_lock(new_doi, LK_LOCK_RW);
			} else {
				inode_lock(new_doi, LK_LOCK_RW);
				inode_lock(old_doi, LK_LOCK_RW);
			}
		} else if (oldparent_depth < newparent_depth) {
			inode_lock(old_doi, LK_LOCK_RW);
			inode_lock(new_doi, LK_LOCK_RW);
		} else {
			inode_lock(new_doi, LK_LOCK_RW);
			inode_lock(old_doi, LK_LOCK_RW);
		}
	}

	if (new_oi == NULL) {
		inode_lock(oi, LK_LOCK_RW);
	} else if (oi < new_oi) {
		inode_lock(oi, LK_LOCK_RW);
		inode_lock(new_oi, LK_LOCK_RW);
	} else {
		inode_lock(new_oi, LK_LOCK_RW);
		inode_lock(oi, LK_LOCK_RW);
	}

	inode_nlink(oi, 1);
	if (inode_flush(oi, 0, &e) == -1) {
		FS_ERR(&r_sent, req, &e);
		xerrz(&e);
	}

	new_de.inode = de.inode;
	strlcpy(new_de.name, newname, sizeof(new_de.name));
	new_de.name[sizeof(new_de.name) - 1] = '\0';

	if (di_mkdirent(new_doi, &new_de, &replaced, &e) == -1) {
		inode_nlink(oi, -1);
		FS_ERR(&r_sent, req, &e);
		xerrz(&e);
		goto end;
	}

	/* Adjust the links for directory ".." entries. */
	if (inode_isdir(oi)) {
		if (di_setparent(oi, inode_ino(new_doi), &e) == -1) {
			FS_ERR(&r_sent, req, &e);
			xerrz(&e);
			goto end;
		}
		/*
		 * If we're replacing a file with our directory,
		 * the new parent should have an increased link count.
		 */
		if (new_oi && !inode_isdir(new_oi)) {
			inode_nlink(new_doi, 1);
			if (inode_flush(new_doi, 0, &e) == -1) {
				FS_ERR(&r_sent, req, &e);
				xerrz(&e);
			}
		}

	}

	if (replaced.inode != 0) {
		inode_nlink(new_oi, -1);
		if (inode_flush(new_oi, 0, &e) == -1) {
			FS_ERR(&r_sent, req, &e);
			xerrz(&e);
		}
	}

	if (di_unlink(old_doi, &de, &e) == -1) {
		FS_ERR(&r_sent, req, &e);
		xerrz(&e);
	}
	if (inode_isdir(oi)) {
		inode_nlink(old_doi, -1);
		if (inode_flush(old_doi, 0, &e) == -1) {
			FS_ERR(&r_sent, req, &e);
			xerrz(&e);
		}
	}
	inode_nlink(oi, -1);
	if (inode_flush(oi, 0, &e) == -1) {
		FS_ERR(&r_sent, req, &e);
		xerrz(&e);
	}
end:
	if (old_doi) {
		fs_set_time(old_doi, INODE_ATTR_MTIME);
		inode_unlock(old_doi);
		if (inode_unload(old_doi, &e) == -1) {
			FS_ERR(&r_sent, req, &e);
			xerrz(&e);
		}
	}
	if (oldparent != newparent && new_doi != NULL) {
		fs_set_time(new_doi, INODE_ATTR_MTIME);
		inode_unlock(new_doi);
		if (inode_unload(new_doi, &e) == -1) {
			FS_ERR(&r_sent, req, &e);
			xerrz(&e);
		}
	}
	if (oi) {
		fs_set_time(oi, INODE_ATTR_CTIME);
		inode_unlock(oi);
		if (inode_unload(oi, &e) == -1)
			FS_ERR(&r_sent, req, &e);
	}
	if (new_oi) {
		inode_unlock(new_oi);
		if (inode_unload(new_oi, &e) == -1)
			FS_ERR(&r_sent, req, &e);
	}
	FUSE_REPLY(&r_sent, fuse_reply_err(req, 0));
unlock:
	LK_UNLOCK(&fs_tree_lock);
}

int
main(int argc, char **argv)
{
	struct fuse_args  args = FUSE_ARGS_INIT(argc, argv);
	struct fuse_chan *ch;
	char             *mountpoint;
	int               status = -1;
	struct sigaction  act;
	sigset_t          set;
	int               foreground;
	struct fs_info    fs_info;
	struct xerr       e;

	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);
	if (pthread_sigmask(SIG_BLOCK, &set, NULL) != 0)
		err(1, "pthread_sigmask");

	bzero(&act, sizeof(act));
	act.sa_flags = 0;
	act.sa_handler = SIG_IGN;
	if (sigaction(SIGPIPE, &act, NULL) == -1)
		err(1, "sigaction");

	if (getenv("POTATOFS_CONFIG"))
		fs_config.cfg_path = getenv("POTATOFS_CONFIG");

	fs_config.uid = getuid();
	fs_config.gid = getgid();

	fuse_opt_parse(&args, &fs_config, fs_opts, &fs_opt_proc);
	fuse_opt_add_arg(&args, "-odefault_permissions");
	fuse_opt_add_arg(&args, "-obig_writes");
	fuse_opt_add_arg(&args, "-osplice_write");
	fuse_opt_add_arg(&args, "-osplice_move");
	fuse_opt_add_arg(&args, "-osplice_read");

	config_read();

	if (xlog_init(PROGNAME, fs_config.dbg, 1) == -1)
		err(1, "xlog_init");

	if (fuse_parse_cmdline(&args, &mountpoint, NULL, &foreground) == -1)
		exit(1);

	mgr_init(fs_config.mgr_sock_path);

	if (mgr_fs_info(&fs_info, xerrz(&e)) == -1) {
		xerr_print(&e);
		exit(1);
	}
	if (fs_info.error)
		errx(1, "filesystem has errors; run fsck");

	if ((ch = fuse_mount(mountpoint, &args)) != NULL) {
		struct fuse_session *se;

		se = fuse_lowlevel_new(&args, &fs_ops,
		    sizeof(fs_ops), &fs_config);
		if (se != NULL) {
			if (fuse_set_signal_handlers(se) != -1) {
				fuse_session_add_chan(se, ch);
				if (fuse_daemonize(foreground) == 0)
					status = fuse_session_loop_mt(se);
				fuse_remove_signal_handlers(se);
				fuse_session_remove_chan(ch);
			}
			fuse_session_destroy(se);
		}
		fuse_unmount(mountpoint, ch);
	}
	fuse_opt_free_args(&args);

	return status ? 1 : 0;
}
