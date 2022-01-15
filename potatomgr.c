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

#include <sys/file.h>
#include <sys/statvfs.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <jansson.h>
#include <lmdb.h>
#include <uuid/uuid.h>
#include <zlib.h>
#include "config.h"
#include "fs_info.h"
#include "mgr.h"
#include "slabs.h"

struct slab_key {
	int   itbl;
	ino_t ino;
	off_t offset;
};

struct slab_val {
	uint64_t revision;
	uint32_t header_crc;
	uuid_t   owner;
};

char            *dbg_spec = NULL;
struct timeval   socket_timeout = {60, 0};
extern char    **environ;
MDB_env         *mdb;
uuid_t           instance_id;
char             bglock_path[PATH_MAX];
off_t            cache_size = 0;
uuid_t           uuid_zero;

static void
usage()
{
	fprintf(stderr, "Usage: " MGR_PROGNAME
	    " [-fhv] [-d level] [-c config] [-p pidfile]\n");
	fprintf(stderr,
	    "\t-h\t\tPrints this help\n"
	    "\t-v\t\tPrints version\n"
	    "\t-d <spec>\tDebug specification\n"
	    "\t-w <workers>\tHow many workers to spawn\n"
	    "\t-W <workers>\tHow many background workers to spawn\n"
	    "\t-f\t\tRun in the foreground, do not fork\n"
	    "\t-c <path>\tPath to configuration\n"
	    "\t-p <path>\tPID file path\n"
	    "\t-T <timeout>\tUnix socket timeout\n");
}

static void
handle_sig(int sig)
{
	struct fs_info   fs_info;
	struct exlog_err e = EXLOG_ERR_INITIALIZER;

	if (fs_info_read(&fs_info, &e) == -1) {
		exlog_lerr(LOG_CRIT, &e, "%s", __func__);
		exit(1);
	} else {
		if (!fs_info.error)
			fs_info.clean = 1;

		if (fs_info_write(&fs_info, &e) == -1)
			exlog_lerr(LOG_ERR, &e, "%s", __func__);
	}

	switch (sig) {
	case SIGPIPE:
		syslog(LOG_ERR, "SIGPIPE received, exiting.");
		exit(sig);
	case SIGTERM:
		syslog(LOG_NOTICE, "SIGTERM received, exiting.");
		killpg(0, 15);
		exit(sig);
	case SIGINT:
		syslog(LOG_NOTICE, "SIGINT received, exiting.");
		exit(sig);
	default:
		syslog(LOG_ERR, "Unhandled signal received. Exiting.");
		exit(sig);
	}
}

static int
slabdb_put(uint32_t itbl, ino_t ino, off_t offset, uint64_t revision,
    uint32_t header_crc, uuid_t owner, struct exlog_err *e)
{
	int              r;
	MDB_txn         *txn;
	MDB_dbi          dbi;
	MDB_val          mk, mv;
	struct slab_key  k;
	struct slab_val  v;

	if ((r = mdb_txn_begin(mdb, NULL, 0, &txn)) != 0)
		return exlog_errf(e, EXLOG_MDB, r, "%s: mdb_txn_begin: %s",
		    __func__, mdb_strerror(r));

	if ((r = mdb_dbi_open(txn, NULL, 0, &dbi)) != 0) {
		exlog_errf(e, EXLOG_MDB, r, "%s: mdb_dbi_open: %s",
		    __func__, mdb_strerror(r));
		goto fail;
	}

	/*
	 * Always bzero() the key structure to avoid unspecified bits
	 * in the struct gaps.
	 */
	bzero(&k, sizeof(k));
	k.itbl = itbl;
	k.ino = ino;
	k.offset = offset;

	bzero(&v, sizeof(v));
	v.revision = revision;
	v.header_crc = header_crc;
	uuid_copy(v.owner, owner);

	mk.mv_size = sizeof(k);
	mk.mv_data = &k;
	mv.mv_size = sizeof(v);
	mv.mv_data = &v;

	if ((r = mdb_put(txn, dbi, &mk, &mv, 0)) != 0) {
		exlog_errf(e, EXLOG_MDB, r, "%s: mdb_put: %s",
		    __func__, mdb_strerror(r));
		goto fail;
	}

	exlog(LOG_DEBUG, "%s: k=%u/%lu/%lu, v=%u/%lu", __func__,
	    ((struct slab_key *)mk.mv_data)->itbl,
	    ((struct slab_key *)mk.mv_data)->ino,
	    ((struct slab_key *)mk.mv_data)->offset,
	    ((struct slab_val *)mv.mv_data)->revision,
	    ((struct slab_val *)mv.mv_data)->header_crc);

	if ((r = mdb_txn_commit(txn)) != 0) {
		exlog_errf(e, EXLOG_MDB, r, "%s: mdb_txn_commit: %s",
		    __func__, mdb_strerror(r));
		goto fail;
	}
	return 0;
fail:
	mdb_txn_abort(txn);
	return -1;
}

/*
 * Get the revision, CRC and current owner of a slab; if the slab is not found
 * in the database (that is, it was never allocated), create an entry with
 * revision 0 to claim ownership.
 * TODO: Eventually this will involved consensus resolution as to who gets
 * ownership of the slab.
 */
static int
slabdb_get(uint32_t itbl, ino_t ino, off_t offset, uint64_t *revision,
    uint32_t *header_crc, uuid_t *owner, struct exlog_err *e)
{
	int              r;
	MDB_txn         *txn;
	MDB_dbi          dbi;
	MDB_val          mk, mv;
	struct slab_key  k;
	struct slab_val  v;
	char             u[37];

	if ((r = mdb_txn_begin(mdb, NULL, 0, &txn)) != 0)
		return exlog_errf(e, EXLOG_MDB, r, "%s: mdb_txn_begin: %s",
		    __func__, mdb_strerror(r));

	if ((r = mdb_dbi_open(txn, NULL, 0, &dbi)) != 0) {
		exlog_errf(e, EXLOG_MDB, r, "%s: mdb_dbi_open: %s",
		    __func__, mdb_strerror(r));
		goto fail;
	}

	/*
	 * Always bzero() the key structure to avoid unspecified bits
	 * in the struct gaps.
	 */
	bzero(&k, sizeof(k));
	k.itbl = itbl;
	k.ino = ino;
	k.offset = offset;

	mk.mv_size = sizeof(k);
	mk.mv_data = &k;

	if ((r = mdb_get(txn, dbi, &mk, &mv))) {
		if (r != MDB_NOTFOUND) {
			exlog_errf(e, EXLOG_MDB, r, "%s: mdb_get: %s",
			    __func__, mdb_strerror(r));
			goto fail;
		}

		bzero(&v, sizeof(v));
		v.revision = 0;
		v.header_crc = 0L;
		uuid_copy(v.owner, instance_id);

		mv.mv_size = sizeof(v);
		mv.mv_data = &v;

		// TODO: consensus resolution here; determine owner

		if ((r = mdb_put(txn, dbi, &mk, &mv, 0)) != 0) {
			exlog_errf(e, EXLOG_MDB, r, "%s: mdb_put: %s",
			    __func__, mdb_strerror(r));
			goto fail;
		}

		if ((r = mdb_txn_commit(txn)) != 0) {
			exlog_errf(e, EXLOG_MDB, r, "%s: mdb_txn_commit: %s",
			    __func__, mdb_strerror(r));
			goto fail;
		}
		goto end;
	}
	mdb_txn_abort(txn);
end:
	*revision = ((struct slab_val *)mv.mv_data)->revision;
	*header_crc = ((struct slab_val *)mv.mv_data)->header_crc;
	uuid_copy(*owner, ((struct slab_val *)mv.mv_data)->owner);
	uuid_unparse(*owner, u);

	exlog(LOG_DEBUG, "%s: k=%u/%lu/%lu, v=%u/%lu/%s\n", __func__,
	    itbl, ino, offset, *revision, *header_crc, u);

	return 0;
fail:
	mdb_txn_abort(txn);
	return -1;
}

static int
slabdb_loop(void(*fn)(const struct slab_key *, const struct slab_val *),
    struct exlog_err *e)
{
	int              r;
	MDB_txn         *txn;
	MDB_dbi          dbi;
	MDB_cursor      *cursor;
	MDB_val          mk, mv;

	if ((r = mdb_txn_begin(mdb, NULL, MDB_RDONLY, &txn)) != 0)
		return exlog_errf(e, EXLOG_MDB, r, "%s: mdb_txn_begin: %s",
		    __func__, mdb_strerror(r));

	if ((r = mdb_dbi_open(txn, NULL, 0, &dbi)) != 0) {
		exlog_errf(e, EXLOG_MDB, r, "%s: mdb_dbi_open: %s",
		    __func__, mdb_strerror(r));
		mdb_txn_abort(txn);
		return -1;
	}

	if ((r = mdb_cursor_open(txn, dbi, &cursor)) != 0) {
		exlog_errf(e, EXLOG_MDB, r, "%s: mdb_cursor_open: %s",
		    __func__, mdb_strerror(r));
		mdb_txn_abort(txn);
		return -1;
	}

	for (r = mdb_cursor_get(cursor, &mk, &mv, MDB_FIRST);
	    r != MDB_NOTFOUND;
	    r = mdb_cursor_get(cursor, &mk, &mv, MDB_NEXT)) {
		if (r != 0) {
			exlog_errf(e, EXLOG_MDB, r, "%s: mdb_cursor_get: %s",
			    __func__, mdb_strerror(r));
			mdb_cursor_close(cursor);
			mdb_txn_abort(txn);
			return -1;
		}
		fn((struct slab_key *)mk.mv_data,
		    (struct slab_val *)mv.mv_data);
	}

	mdb_cursor_close(cursor);
	mdb_txn_abort(txn);
	return 0;
}

static int
mgr_spawn(char *const argv[], int *wstatus, char *stdout, size_t stdout_len,
    char *stderr, size_t stderr_len, struct exlog_err *e)
{
	pid_t         pid;
	int           p_out[2];
	int           p_err[2];
	struct pollfd fds[2];
	int           stdout_closed = 0;
	int           stderr_closed = 0;
	int           nfds;
	ssize_t       r;
	int           poll_r;
	size_t        stdout_r, stderr_r;

	if (pipe(p_out) == -1)
		return exlog_errf(e, EXLOG_OS, errno, "%s: pipe", __func__);
	if (pipe(p_err) == -1)
		return exlog_errf(e, EXLOG_OS, errno, "%s: pipe", __func__);

	if ((pid = fork()) == -1) {
		return exlog_errf(e, EXLOG_OS, errno, "%s: fork", __func__);
	} else if (pid == 0) {
		close(p_out[0]);
		close(p_err[0]);
		if (p_out[1] != STDOUT_FILENO) {
			if (dup2(p_out[1], STDOUT_FILENO) == -1)
				return exlog_errf(e, EXLOG_OS, errno,
				    "%s: dup2", __func__);
			close(p_out[1]);
		}
		if (p_err[1] != STDOUT_FILENO) {
			if (dup2(p_err[1], STDERR_FILENO) == -1)
				return exlog_errf(e, EXLOG_OS, errno,
				    "%s: dup2", __func__);
			close(p_err[1]);
		}

		chdir(fs_config.data_dir);

		if (execv(fs_config.mgr_exec, argv) == -1) {
			close(p_out[1]);
			close(p_err[1]);
			return exlog_errf(e, EXLOG_OS, errno, "%s: execv",
			    __func__);
		}
	}

	close(p_out[1]);
	close(p_err[1]);

	/*
	 * Make room for \n.
	 */
	stdout_len--;
	stderr_len--;

	stdout_r = 0;
	stderr_r = 0;
	while (!stdout_closed || !stderr_closed) {
		nfds = 0;
		if (!stdout_closed) {
			fds[nfds].fd = p_out[0];
			fds[nfds++].events = POLLIN;
		}
		if (!stderr_closed) {
			fds[nfds].fd = p_err[0];
			fds[nfds++].events = POLLIN;
		}

		if ((poll_r = poll(fds, nfds,
		    BACKEND_TIMEOUT_SECONDS * 1000)) == -1)
			return exlog_errf(e, EXLOG_OS, errno,
			    "%s: poll", __func__);

		if (poll_r == 0) {
			exlog(LOG_ERR, "%s: command timed out after %d "
			    "seconds; aborting",
			    __func__, BACKEND_TIMEOUT_SECONDS);
			kill(pid, 9);
		}

		while (nfds-- > 0) {
			if (fds[nfds].revents & POLLERR) {
				if (fds[nfds].fd == p_out[1])
					stdout_closed = 1;
				else
					stderr_closed = 1;
				exlog(LOG_ERR, "%s: file descriptor %d "
				    "closed unexpectedly", __func__,
				    fds[nfds].fd);
				continue;
			}

			if (!(fds[nfds].revents & POLLIN))
				continue;

			if (fds[nfds].fd == p_out[1]) {
				r = read(p_out[1], stdout + stdout_r,
				    stdout_len - stdout_r);
				if (r > 0) {
					stdout_r += r;
				} else
					stdout_closed = 1;
			} else {
				r = read(p_err[1], stderr + stderr_r,
				    stderr_len - stderr_r);
				if (r > 0)
					stderr_r += r;
				else
					stderr_closed = 1;
			}
			if (r == -1)
				exlog_lerrno(LOG_ERR, errno,
				    "%s: file descriptor %d error",
				    __func__, fds[nfds].fd);
		}
	}
	stdout[stdout_r] = '\0';
	stderr[stderr_r] = '\0';
	if (waitpid(pid, wstatus, 0) == -1)
		return exlog_errf(e, EXLOG_OS, errno, "%s: waitpid", __func__);

	return 0;
}

static int
outq(int fd, ino_t ino, off_t offset, struct slab_hdr *hdr, struct exlog_err *e)
{
	int             dst_fd;
	char            dst[PATH_MAX], dst_name[NAME_MAX + 1];
	char            buf[8192];
	struct stat     st;
	struct slab_hdr dst_hdr;
	ssize_t         r;

	if (slab_path(dst_name, sizeof(dst_name), ino, offset,
	    hdr->v.f.flags, 1, e) == -1)
		return -1;

	if (snprintf(dst, sizeof(dst), "%s/%s/%s", fs_config.data_dir,
	    OUTGOING_DIR, dst_name) >= sizeof(dst))
		return exlog_errf(e, EXLOG_APP, EXLOG_NAMETOOLONG,
		    "%s: outq slab name too long", __func__);

	if ((dst_fd = open_wflock(dst, O_CREAT|O_WRONLY, 0600, LOCK_EX))
	    == -1) {
		exlog_errf(e, EXLOG_OS, errno, "%s: failed "
		    "to open_wflock() outq slab %s", __func__, dst);
	}

	if (fstat(dst_fd, &st) == -1) {
		exlog_errf(e, EXLOG_OS, errno, "%s: fstat", __func__);
		goto fail;
	}

	if (st.st_size >= sizeof(dst_hdr)) {
		if (read_x(dst_fd, &dst_hdr, sizeof(dst_hdr))
		    < sizeof(dst_hdr)) {
			exlog_errf(e, EXLOG_OS, errno,
			    "%s: short read on slab header", __func__);
			goto fail;
		}
		if (dst_hdr.v.f.revision >= hdr->v.f.revision) {
			exlog(LOG_INFO, "slab in outq has a revision "
			    "greater or equal to this one: %s "
			    "(revision %llu >= %llu", dst_name,
			    dst_hdr.v.f.revision, hdr->v.f.revision);
			goto end;
		}
	} else {
		/* Make room for the header we're about to fill in. */
		if (lseek(dst_fd, sizeof(struct slab_hdr), SEEK_SET) == -1) {
			exlog_errf(e, EXLOG_OS, errno,
			    "%s: lseek", __func__);
			goto fail;
		}
	}

	hdr->v.f.checksum = crc32_z(0L,
	    (unsigned char *)hdr, sizeof(struct slab_hdr));

	while ((r = read(fd, buf, sizeof(buf)))) {
		if (r == -1) {
			if (errno == EINTR)
				continue;
			exlog_errf(e, EXLOG_OS, errno, "%s: read", __func__);
			goto fail_unlink_dst;
		}

		hdr->v.f.checksum = crc32_z(hdr->v.f.checksum,
		    (unsigned char *)buf, r);

		r = write_x(dst_fd, buf, r);
		if (r == -1) {
			exlog_errf(e, EXLOG_OS, errno, "%s: write", __func__);
			goto fail_unlink_dst;
		}
	}

	if (lseek(dst_fd, 0, SEEK_SET) == -1) {
		exlog_errf(e, EXLOG_OS, errno,
		    "%s: seek on dst_fd", __func__);
		goto fail_unlink_dst;
	}

	if (write_x(dst_fd, hdr, sizeof(hdr)) < sizeof(hdr)) {
		exlog_errf(e, EXLOG_OS, errno,
		    "%s: short write on slab header", __func__);
		goto fail_unlink_dst;
	}
end:
	close(dst_fd);
	return 0;
fail_unlink_dst:
	if (unlink(dst) == -1)
		exlog_lerrno(LOG_ERR, errno, "%s: unlink dst", __func__);
fail:
	if (dst_fd > -1)
		close(dst_fd);
	return -1;
}

static int
disown(int c, struct mgr_msg *m, int fd, struct exlog_err *e)
{
	struct         slab_hdr hdr;
	struct         timespec now;
	char           src[PATH_MAX];
	int            purge = 0;
	struct statvfs stv;
	uint32_t       crc;

	if (clock_gettime(CLOCK_REALTIME, &now) == -1) {
		exlog_errf(e, EXLOG_OS, errno,
		    "%s: clock_gettime", __func__);
		goto fail;
	}

	if (lseek(fd, 0, SEEK_SET) == -1) {
		exlog_errf(e, EXLOG_OS, errno,
		    "%s: lseek", __func__);
		goto fail;
	}

	if (read_x(fd, &hdr, sizeof(hdr)) < sizeof(hdr)) {
		exlog_errf(e, EXLOG_OS, errno,
		    "%s: short read on slab header", __func__);
		goto fail;
	}

	if (statvfs(fs_config.data_dir, &stv) == -1) {
		exlog_lerrno(LOG_ERR, errno, "statvfs");
	} else {
		// TODO: don't hardcode 70%
		if (stv.f_bavail * stv.f_frsize < cache_size * 30 / 100) {
			purge = 1;
		}
	}
	// TODO: here ... what's the logic here for purging and
	// doing slabdb_put() ??
	crc = crc32_z(0L, (Bytef *)&hdr, sizeof(hdr));
	if (slabdb_put((hdr.v.f.flags & SLAB_ITBL) ? 1 : 0,
	    m->v.disown.ino, m->v.disown.offset, hdr.v.f.revision,
	    crc, (purge) ? uuid_zero : instance_id, e) == -1) {
		exlog_errf(e, EXLOG_OS, errno,
		    "%s: slabdb_put", __func__);
		goto fail;
	}

	if (hdr.v.f.flags & SLAB_DIRTY &&
	    now.tv_sec >= (hdr.v.f.last_backend_sync.tv_sec +
	    fs_config.slab_max_age)) {
		if (outq(fd, m->v.disown.ino, m->v.disown.offset,
		    &hdr, e) == -1)
			goto fail;

		if (slab_path(src, sizeof(src), m->v.disown.ino,
		    m->v.disown.offset, hdr.v.f.flags, 0, e) == -1)
			goto fail;

		// TODO: Don't always unlink as this is inefficient. Only
		// unlink if we have no more local space.
		if (purge && unlink(src) == -1) {
			exlog_lerrno(LOG_ERR, errno,
			    "%s: unlink src", __func__);
			goto fail;
		}
	}

	close(fd);

	m->m = MGR_MSG_DISOWN_OK;
	return mgr_send(c, -1, m, e);
fail:
	m->m = MGR_MSG_DISOWN_ERR;
	return mgr_send(c, -1, m, e);
}

static int
backend_get(const char *local_path, const char *backend_path,
    size_t *in_bytes, struct exlog_err *e)
{
	char            *args[4];
	int              wstatus;
	char             stdout[1024], stderr[1024];
	json_t          *j = NULL, *o;
	json_error_t     jerr;

	args[0] = "get";
	args[1] = (char *)backend_path;
	args[2] = (char *)local_path;
	args[3] = NULL;

	if (mgr_spawn(args, &wstatus, stdout, sizeof(stdout),
	    stderr, sizeof(stderr), e) == -1)
		goto fail;

	exlog_zerr(e);

	/* Bad invocation error, there is no JSON to read here. */
	if (wstatus == 2) {
		exlog_errf(e, EXLOG_APP, EXLOG_EXEC,
		    "%s: \"get\" reported bad invocation (exit 2)", __func__);
		goto fail;
	}

	if ((j = json_loads(stdout, JSON_REJECT_DUPLICATES, &jerr)) == NULL) {
		exlog_errf(e, EXLOG_APP, EXLOG_EXEC,
		    "%s: %s", __func__, jerr.text);
		goto fail;
	}

	if ((o = json_object_get(j, "status")) == NULL) {
		exlog_errf(e, EXLOG_APP, EXLOG_EXEC,
		    "%s: \"status\" missing from backend JSON output",
		    __func__);
		goto fail;
	}

	if (strcmp(json_string_value(o), "ERR_NOENT") == 0) {
		exlog_errf(e, EXLOG_APP, EXLOG_NOENT,
		    "%s: slab not found on backend", __func__);
		goto fail;
	}

	if (strcmp(json_string_value(o), "OK") != 0) {
		if ((o = json_object_get(j, "msg")) == NULL) {
			exlog_errf(e, EXLOG_APP, EXLOG_EXEC,
			    "%s: \"msg\" missing from JSON", __func__);
			goto fail;
		}

		exlog_errf(e, EXLOG_APP, EXLOG_EXEC,
		    "%s: \"get\" failed: %s", __func__, json_string_value(o));
		goto fail;
	}

	if (wstatus == 1) {
		exlog_errf(e, EXLOG_APP, EXLOG_EXEC,
		    "%s: \"get\" exit 1; backend produced no error message",
		    __func__);
		goto fail;
	}

	if ((o = json_object_get(j, "in_bytes")) == NULL) {
		exlog_errf(e, EXLOG_APP, EXLOG_EXEC,
		    "%s: \"in_bytes\" missing from JSON", __func__);
		goto fail;
	}

	*in_bytes = json_integer_value(o);

	if (json_object_clear(j) == -1) {
		exlog_errf(e, EXLOG_APP, EXLOG_JSON,
		    "%s: failed to clear JSON", __func__);
		goto fail;
	}

	return 0;
fail:
	if (j != NULL && json_object_clear(j) == -1)
		exlog(LOG_ERR, "%s: failed to clear JSON", __func__);
	unlink(local_path);
	return -1;
}

static int
backend_put(const char *local_path, const char *backend_path,
    size_t *out_bytes, struct exlog_err *e)
{
	char         *args[4];
	int           wstatus;
	char          stdout[1024], stderr[1024];
	json_t       *j, *o;
	json_error_t  jerr;

	args[0] = "put";
	args[1] = (char *)local_path;
	args[2] = (char *)backend_path;
	args[3] = NULL;

	if (mgr_spawn(args, &wstatus, stdout, sizeof(stdout),
	    stderr, sizeof(stderr), e) == -1)
		return -1;

	exlog_zerr(e);

	if (wstatus == 2)
		return exlog_errf(e, EXLOG_APP, EXLOG_EXEC,
		    "%s: \"put\" exit 2", __func__);

	if ((j = json_loads(stdout, JSON_REJECT_DUPLICATES, &jerr)) == NULL) {
		return exlog_errf(e, EXLOG_APP, EXLOG_EXEC,
		    "%s: %s", __func__, jerr.text);
	}

	if ((o = json_object_get(j, "status")) == NULL) {
		return exlog_errf(e, EXLOG_APP, EXLOG_EXEC,
		    "%s: \"status\" missing from JSON", __func__);
	}

	if (strcmp(json_string_value(o), "OK") != 0) {
		if ((o = json_object_get(j, "msg")) == NULL) {
			return exlog_errf(e, EXLOG_APP, EXLOG_EXEC,
			    "%s: \"msg\" missing from JSON", __func__);
		}
		return exlog_errf(e, EXLOG_APP, EXLOG_EXEC,
		    "%s: \"put\" failed: %s", __func__, json_string_value(o));
	}

	if (wstatus == 1)
		return exlog_errf(e, EXLOG_APP, EXLOG_EXEC,
		    "%s: \"put\" exit 1; no message available", __func__);

	if ((o = json_object_get(j, "out_bytes")) == NULL) {
		return exlog_errf(e, EXLOG_APP, EXLOG_EXEC,
		    "%s: \"in_bytes\" missing from JSON", __func__);
	}

	*out_bytes = json_integer_value(o);

	if (json_object_clear(j) == -1)
		exlog_errf(e, EXLOG_APP, EXLOG_JSON,
		    "%s: failed to clear JSON", __func__);

	return 0;
}

/*
 * Compare a slab's revision and header CRC against
 * expected values and return an error on mismatch.
 * Expects an open fd to the slab in question.
 * The file offset at the end of the header upon return.
 */
static int
check_slab_header(int fd, uint32_t header_crc, uint64_t rev,
    struct exlog_err *e)
{
	struct slab_hdr hdr;
	uint32_t        crc;

	if (lseek(fd, 0, SEEK_SET) == -1)
		return exlog_errf(e, EXLOG_OS, errno, "%s: lseek", __func__);

	if (read_x(fd, &hdr, sizeof(hdr)) < sizeof(hdr))
		return exlog_errf(e, EXLOG_OS, errno,
		    "%s: short read on slab header", __func__);

	if (hdr.v.f.revision != rev) {
		/*
		 * backend doesn't have correct (latest?) version
		 * of slab. Are we dealing with eventual consistency?
		 */
		exlog_errf(e, EXLOG_APP, EXLOG_INVAL,
		    "%s: mismatching slab revision: "
		    "expected=%lu, slab=%lu", __func__,
		    rev, hdr.v.f.revision);
	}

	if ((crc = crc32_z(0L, (Bytef *)&hdr, sizeof(hdr))) != header_crc) {
		return exlog_errf(e, EXLOG_APP, EXLOG_INVAL,
		    "%s: mismatching header CRC: "
		    "expected=%u, slab=%u", __func__, header_crc, crc);
	}

	return 0;
}

/*
 * Unqueue q_path into dst_fd if the queued slab's header_crc and
 * revision match what's passed in the function args.
 */
static int
copy_slab(int dst_fd, int src_fd, uint32_t header_crc,
    uint64_t revision, struct exlog_err *e)
{
	struct slab_hdr hdr;
	ssize_t         r;
	char            buf[BUFSIZ];
	uint32_t        crc;

	if (lseek(src_fd, 0, SEEK_SET) == -1)
		return exlog_errf(e, EXLOG_OS, errno,
		    "%s: lseek src_fd", __func__);
	if (lseek(dst_fd, 0, SEEK_SET) == -1)
		return exlog_errf(e, EXLOG_OS, errno,
		    "%s: lseek dst_fd", __func__);

	if (read_x(src_fd, &hdr, sizeof(hdr)) < sizeof(hdr))
		return exlog_errf(e, EXLOG_OS, errno,
		    "%s: short read on slab header", __func__);

	if (hdr.v.f.revision != revision) {
		/*
		 * backend doesn't have correct (latest?) version
		 * of slab. Are we dealing with eventual consistency?
		 */
		exlog_errf(e, EXLOG_APP, EXLOG_INVAL,
		    "%s: mismatching slab revision: "
		    "expected=%lu, slab=%lu", __func__,
		    revision, hdr.v.f.revision);
	}

	if ((crc = crc32_z(0L, (Bytef *)&hdr, sizeof(hdr))) != header_crc) {
		return exlog_errf(e, EXLOG_APP, EXLOG_INVAL,
		    "%s: mismatching header CRC: "
		    "expected=%u, slab=%u", __func__, header_crc, crc);
	}

write_hdr_again:
	if (write_x(dst_fd, &hdr, sizeof(hdr)) == -1) {
		if (errno == ENOSPC) {
			exlog(LOG_ERR, "%s: ran out of space during; "
			    "retrying", __func__);
			sleep(5);
			goto write_hdr_again;
		}
		return exlog_errf(e, EXLOG_OS, errno, "%s: write", __func__);
	}

	crc = crc32_z(0L, Z_NULL, 0);

copy_again:
	while ((r = read_x(src_fd, buf, sizeof(buf)))) {
		if (r == -1)
			return exlog_errf(e, EXLOG_OS, errno,
			    "%s: read", __func__);

		crc = crc32_z(crc, (Bytef *)buf, r);

		if (write_x(dst_fd, buf, r) == -1) {
			if (errno == ENOSPC) {
				exlog(LOG_ERR, "%s: ran out of space; "
				    "retrying", __func__);
				sleep(5);
				goto copy_again;
			}
			return exlog_errf(e, EXLOG_OS, errno,
			    "%s: write", __func__);
		}
	}

	return 0;
}

static int
claim(int c, struct mgr_msg *m, struct exlog_err *e)
{
	char            name[NAME_MAX + 1];
	char            in_path[PATH_MAX], out_path[PATH_MAX], dst[PATH_MAX];
	int             fd_flags = O_RDWR|O_CREAT;
	int             dst_fd, incoming_fd, outgoing_fd;
	size_t          in_bytes;
	struct slab_hdr hdr;
	struct timespec tp = {0, 10000000}; /* 10 ms */
	struct stat     st;

	uint64_t        revision;
	uint32_t        header_crc, crc;
	uuid_t          owner;

	/*
	 * Check existence in DB, if owned by another instance, otherwise
	 * a new entry will be allocated and returned.
	 */
	if (slabdb_get((m->v.claim.flags & SLAB_ITBL) ? 1 : 0,
	    m->v.claim.ino, m->v.claim.offset, &revision, &header_crc,
	    &owner, e) == -1) {
		goto fail;
	}

	/*
	 * TODO: compare owners; need to reach consensus about who really
	 * owns this slab. If the owner is another instance, we'll need
	 * to relay bytes instead. For now, we just fail.
	 */
	if (uuid_compare(owner, instance_id) != 0)
		goto fail;

	/*
	 * We compute the absolute path for the destination path. We use
	 * the destination file as a lock with flock() to handle concurrent
	 * claim() or disown() with other potatomgr processes.
	 *
	 * The slab is first downloaded at dst during which the CRC
	 * is validated, then copied to dst_fd. dst is unlinked after
	 * successfully copying.
	 */

	if (slab_path(dst, sizeof(dst), m->v.claim.ino, m->v.claim.offset,
	    m->v.claim.flags, 0, e) == -1 ||
	    slab_path(name, sizeof(name), m->v.claim.ino, m->v.claim.offset,
	    m->v.claim.flags, 1, e) == -1)
		goto fail;

	if (m->v.claim.oflags & OSLAB_SYNC)
		fd_flags |= O_SYNC;

	/*
	 * We loop on open instead of simply doing a blocking flock()
	 * because the lock could be held by a disown which will
	 * unlink() the file at the end. Therefore we would want to
	 * reopen a new filehandle to ensure it is present in the dir
	 * entry.
	 * Note: On disown(), unlink() happens before close()
	 */
	for (;;) {
		if ((dst_fd = open_wflock(dst, fd_flags, 0600,
		    LOCK_EX|LOCK_NB)) == -1) {
			if (errno == EWOULDBLOCK) {
				nanosleep(&tp, NULL);
				continue;
			}
			exlog_errf(e, EXLOG_OS, errno,
			    "%s: open_wflock() for slab %s", __func__, dst);
			goto fail;
		}
	}

	if (fstat(dst_fd, &st) == -1) {
		exlog_errf(e, EXLOG_OS, errno,
		    "%s: fstat", __func__);
		goto fail_close_dst;
	}

	if (st.st_size > 0) {
		/*
		 * Someone downloaded this just before we could acquire
		 * the lock. If header_crc and revision match
		 * what we have in the DB, looks like we're done.
		 */
		if (check_slab_header(dst_fd, header_crc, revision, e) == 0) {
			goto end;
		/*
		 * Wrong rev/header_crc is fine, just proceed
		 * with retrieving.
		 */
		} else if (!exlog_err_is(e, EXLOG_APP, EXLOG_INVAL))
			goto fail_close_dst;
	}

	/*
	 * See if we still have the slab in our outgoing dir to avoid having to
	 * pull it from the backend.
	 */
	if (snprintf(out_path, sizeof(out_path), "%s/%s/%s",
	    fs_config.data_dir, OUTGOING_DIR, name) >= sizeof(out_path)) {
		exlog_errf(e, EXLOG_APP, EXLOG_NAMETOOLONG,
		    "%s: outgoing slab name too long", __func__);
		goto fail_close_dst;
	}
	if ((outgoing_fd = open_wflock(out_path, O_RDONLY, 0, LOCK_SH)) != -1) {
		if (copy_slab(dst_fd, outgoing_fd, header_crc,
		    revision, e) == 0) {
			close(outgoing_fd);
			goto end;
		}
	}

	/*
	 * At this point we need to pull it from the backend.
	 */
	if (snprintf(in_path, sizeof(in_path), "%s/%s/%s",
	    fs_config.data_dir, INCOMING_DIR, name) >= sizeof(in_path)) {
		exlog_errf(e, EXLOG_APP, EXLOG_NAMETOOLONG,
		    "%s: inq slab name too long", __func__);
		goto fail_close_dst;
	}
	if ((incoming_fd = open_wflock(in_path, O_RDWR,
	    O_CREAT, LOCK_EX)) > 0) {
		/*
		 * Normally this shouldn't happen, but if for some reason
		 * we failed to unlink from our incoming queue the open could
		 * succeed. Furthermore, if the rev and CRC match, well,
		 * use it.
		 */
		if (copy_slab(dst_fd, incoming_fd, header_crc,
		    revision, e) == 0) {
			close(incoming_fd);
			goto end;
		}
	} else if (errno != ENOENT) {
		exlog_errf(e, EXLOG_OS, errno,
		    "%s: open_wflock() for incoming slab %s",
		    __func__, in_path);
		goto fail_close_dst;
	}

get_again:
	if (backend_get(in_path, name, &in_bytes, e) == -1) {
		if (m->v.claim.oflags & OSLAB_NOCREATE &&
		    exlog_err_is(e, EXLOG_APP, EXLOG_NOENT)) {
			unlink(dst);
			close(dst_fd);
			close(incoming_fd);
			exlog_zerr(e);
			m->m = MGR_MSG_CLAIM_NOENT;
			if (mgr_send(c, -1, m, e) == -1) {
				exlog_lerr(LOG_ERR, e, "%s", __func__);
				goto fail;
			}
			return 0;
		} else if (exlog_err_is(e, EXLOG_APP, EXLOG_NOENT)) {
			exlog_zerr(e);
			close(incoming_fd);
			bzero(&hdr, sizeof(hdr));
			hdr.v.f.slab_version = SLAB_VERSION;
			hdr.v.f.flags = m->v.claim.flags | SLAB_DIRTY;
			hdr.v.f.revision = 0;
			hdr.v.f.checksum = crc32(0L, Z_NULL, 0);
			if (write_x(dst_fd, &hdr, sizeof(hdr)) < sizeof(hdr)) {
				exlog_errf(e, EXLOG_OS, errno,
				    "%s: short write on slab header", __func__);
				goto fail_close_dst;
			}
			/*
			 * Make sure to fsync() if the file wasn't opened
			 * with O_SYNC initially.
			 */
			if (!(m->v.claim.oflags & OSLAB_SYNC) &&
			    fsync(dst_fd) == -1) {
				exlog_errf(e, EXLOG_OS, errno,
				    "%s: fsync", __func__);
				goto fail_close_dst;
			}
			/*
			 * We initialize the CRC to zero for now, since
			 * this wasn't sent to the backend yet.
			 */
			crc = crc32_z(0L, (Bytef *)&hdr, sizeof(hdr));
			if (slabdb_put((m->v.claim.flags & SLAB_ITBL) ? 1 : 0,
			    m->v.claim.ino, m->v.claim.offset, hdr.v.f.revision,
			    crc, instance_id, e) == -1) {
				exlog_errf(e, EXLOG_OS, errno,
				    "%s: slabdb_put", __func__);
				goto fail_close_dst;
			}
			goto end;
		} else if (exlog_err_is(e, EXLOG_OS, ENOSPC)) {
			exlog_zerr(e);
			exlog(LOG_ERR, "%s: ran out of space during "
			    "backend_get(); retrying", __func__);
			sleep(5);
			goto get_again;
		}
		goto fail_close_dst;
	}

	if (copy_slab(dst_fd, incoming_fd, header_crc, revision, e) == -1) {
		if (exlog_err_is(e, EXLOG_APP, EXLOG_INVAL)) {
			exlog_zerr(e);
			exlog(LOG_ERR, "%s: wrong revision/header_crc "
			    "from backend; retrying", __func__);
			sleep(5);
			goto get_again;
		}
		goto fail_close_dst;
	}

	unlink(in_path);
	close(incoming_fd);

end:
	m->m = MGR_MSG_CLAIM_OK;
	if (mgr_send(c, dst_fd, m, e) == -1) {
		exlog_lerr(LOG_ERR, e, "%s", __func__);
		return -1;
	}
	close(dst_fd);
	return 0;

fail_close_dst:
	close(dst_fd);
fail:
	m->m = MGR_MSG_CLAIM_ERR;
	if (mgr_send(c, -1, m, e) == -1)
		exlog_lerr(LOG_ERR, e, "%s", __func__);
	return -1;
}

static int
set_fs_error(int c, struct mgr_msg *m, struct exlog_err *e)
{
	struct fs_info fs_info;

	if (fs_info_read(&fs_info, e) == -1) {
		exlog_lerr(LOG_ERR, e, "%s", __func__);
		goto fail;
	}

	exlog_zerr(e);
	fs_info.error = 1;

	if (fs_info_write(&fs_info, e) == -1) {
		exlog_lerr(LOG_ERR, e, "%s", __func__);
		goto fail;
	}

	m->m = MGR_MSG_SET_FS_ERROR_OK;
	if (mgr_send(c, -1, m, e) == -1)
		return -1;
	return 0;
fail:
	m->m = MGR_MSG_SET_FS_ERROR_ERR;
	if (mgr_send(c, -1, m, e) == -1)
		exlog_lerr(LOG_ERR, e, "%s", __func__);
	return -1;
}

static int
df(int c, struct mgr_msg *m, struct exlog_err *e)
{
	if (fs_info_read(&m->v.fs_info, e) == -1) {
		exlog_lerr(LOG_ERR, e, "%s", __func__);
		m->m = MGR_MSG_FS_INFO_ERR;
	} else
		m->m = MGR_MSG_FS_INFO_OK;

	exlog_zerr(e);

	if (mgr_send(c, -1, m, e) == -1)
		return -1;

	return 0;
}

static int
bg_df(struct exlog_err *e)
{
	int               wstatus;
	char              stdout[1024], stderr[1024];
	json_t           *j, *o;
	json_error_t      jerr;
	char             *args[] = {"df", NULL};
	off_t             bytes_total, bytes_used;
	struct fs_info    fs_info;
	struct timespec   now;

	if (fs_info_read(&fs_info, e) == -1) {
		exlog_lerr(LOG_ERR, e, "%s", __func__);
		return -1;
	}

	if (clock_gettime(CLOCK_REALTIME, &now) == -1) {
		exlog_lerrno(LOG_ERR, errno, "%s: clock_gettime", __func__);
		return -1;
	}

	/*
	 * Because any worker could update the current fs usage,
	 * avoid poking at the backend too many times by checking if
	 * 60s or more elapsed since our last check.
	 */
	if (now.tv_sec - fs_info.stats_last_update.tv_sec < 60)
		return 0;

	if (mgr_spawn(args, &wstatus, stdout, sizeof(stdout),
	    stderr, sizeof(stderr), e) == -1) {
		exlog(LOG_ERR, "%s", __func__);
		return -1;
	}

	if ((j = json_loads(stdout, JSON_REJECT_DUPLICATES, &jerr)) == NULL) {
		exlog(LOG_ERR, "%s: %s", __func__, jerr.text);
		return -1;
	}

	if ((o = json_object_get(j, "total_bytes")) == NULL) {
		exlog(LOG_ERR, "%s: \"total_bytes\" missing from JSON",
		    __func__);
		return -1;
	}
	bytes_total = json_integer_value(o);

	if ((o = json_object_get(j, "used_bytes")) == NULL) {
		exlog(LOG_ERR, "%s: \"used_bytes\" missing from JSON",
		    __func__);
		return -1;
	}
	bytes_used = json_integer_value(o);

	fs_info.stats.f_blocks = bytes_total / fs_info.stats.f_bsize;
	fs_info.stats.f_bfree = (bytes_total - bytes_used) /
	    fs_info.stats.f_bsize;
	fs_info.stats.f_bavail = fs_info.stats.f_bfree;
	if (clock_gettime(CLOCK_REALTIME, &fs_info.stats_last_update) == -1) {
		exlog_lerrno(LOG_ERR, errno, "%s: clock_gettime", __func__);
		return -1;
	}

	if (fs_info_write(&fs_info, e) == -1)
		return -1;

	return 0;
}

static int
bglock()
{
	int fd;

	if ((fd = open_wflock(bglock_path, O_RDONLY, 0,
	    LOCK_EX|LOCK_NB)) == -1) {
		if (errno != EWOULDBLOCK)
			exlog_lerrno(LOG_ERR, errno, "%s: open_wflock", __func__);
		return -1;
	}

	return fd;
}

static void
bgworker()
{
	char              path[PATH_MAX], outq_path[PATH_MAX];
	DIR              *dir;
	struct dirent    *de;
	size_t            out_bytes;
	struct exlog_err  e = EXLOG_ERR_INITIALIZER;
	int               bglock_fd;

	if (exlog_init(MGR_PROGNAME "-bgworker", dbg_spec, 0) == -1) {
		exlog(LOG_ERR, "failed to initialize logging in bgworker");
		exit(1);
	}

	setproctitle("bgworker");
	exlog(LOG_INFO, "%s: ready", __func__);

	for (;;) {
		if ((bglock_fd = bglock()) != -1) {
			if (bg_df(&e) == -1)
				exlog_lerr(LOG_ERR, &e, "%s", __func__);
			close(bglock_fd);
		}

		if (snprintf(outq_path, sizeof(outq_path), "%s/%s",
		    fs_config.data_dir, OUTGOING_DIR) >= sizeof(path)) {
			exlog(LOG_ERR, "%s: outq name too long", __func__);
			goto fail_outq;
		}

		if ((dir = opendir(outq_path)) == NULL) {
			exlog_lerrno(LOG_ERR, errno, "%s: opendir", __func__);
			goto fail_outq;
		}

		while ((de = readdir(dir))) {
			if (snprintf(path, sizeof(path), "%s/%s",
			    outq_path, de->d_name) >= sizeof(path)) {
				exlog(LOG_ERR, "%s: name too long", __func__);
				goto fail_outq;
			}

			// for each slab in out queue:
				// open, LOCK_EX|LOCK_NB
				// Compute checksum
				// upload, unlink
				// close fd

			if (backend_put(path, path + strlen(fs_config.data_dir),
			    &out_bytes, &e) == -1) {
				exlog_lerr(LOG_ERR, &e, "%s", __func__);
				goto fail;
			}

			exlog(LOG_INFO, "%s: backend_put: %s (%lu bytes)",
			    __func__, path, out_bytes);
		}
fail:
		closedir(dir);

		/*
		// for each slab in main data dir:
		while ((de = readdir(some_dir))) {
			// open, LOCK_EX|LOCK_NB
			open_wflock();
			read hdr;

			// copy to out queue if old enough and dirty
			// check LOCK_EX|LOCK_NB on out queue target

			// unlink if free space is below watermark (need_purge)
			if (statvfs(fs_config.data_dir, &stv) == -1) {
				exlog_lerrno(LOG_ERR, errno, "statvfs");
				goto fail_outq;
			}
			if (stv.f_bavail * stv.f_frsize < cache_size * 30 / 100) {
				purge = 1;
				uuid_clear();
			} else
				purge = 0;
			if (purge)
				unlink();


			// close
		}
		*/
fail_outq:
		sleep(60);
	}
}

static void
worker(int lsock)
{
	int              fd;
	struct mgr_msg   m;
	struct exlog_err e = EXLOG_ERR_INITIALIZER;
	int              c;
	int              r;

	if (exlog_init(MGR_PROGNAME "-worker", dbg_spec, 0) == -1) {
		exlog(LOG_ERR, "failed to initialize logging in worker");
		exit(1);
	}

	setproctitle("worker");
	exlog(LOG_INFO, "%s: ready", __func__);

	for (;;) {
		if ((c = accept(lsock, NULL, 0)) == -1) {
			switch (errno) {
			case EINTR:
				continue;
			case EMFILE:
				exlog_lerrno(LOG_ERR, errno,
				    "%s: accept", __func__);
				sleep(5);
				continue;
			default:
				exlog_lerrno(LOG_ERR, errno,
				    "%s: accept", __func__);
				exit(1);
			}
		}

		if (setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &socket_timeout,
		    sizeof(socket_timeout)) == -1) {
			exlog_lerr(LOG_ERR, &e, "%s", __func__);
			continue;
		}

		for (;;) {
			exlog_zerr(&e);
			if ((r = mgr_recv(c, &fd, &m, &e)) == -1) {
				if (exlog_err_is(&e, EXLOG_OS, EAGAIN))
					exlog(LOG_NOTICE,
					    "read timeout on socket %d", c);
				else if (!exlog_err_is(&e, EXLOG_APP,
				    EXLOG_EOF))
					exlog_lerr(LOG_ERR, &e, "%s", __func__);
				close(c);
				break;
			}

			switch (m.m) {
			case MGR_MSG_CLAIM:
				claim(c, &m, &e);
				break;
			case MGR_MSG_DISOWN:
				disown(c, &m, fd, &e);
				break;
			case MGR_MSG_FS_INFO:
				df(c, &m, &e);
				break;
			case MGR_MSG_SET_FS_ERROR:
				set_fs_error(c, &m, &e);
				break;
			default:
				exlog(LOG_ERR, "%s: wrong message %d",
				    __func__, m.m);
				close(c);
				break;
			}
			if (exlog_fail(&e)) {
				exlog_lerr(LOG_ERR, &e, "%s", __func__);
				if (e.layer == EXLOG_OS) {
					close(c);
					break;
				}
			}
		}
	}
}

void
slabdb_status(const struct slab_key *k, const struct slab_val *v)
{
	char u[37];

	uuid_unparse(v->owner, u);
	exlog(LOG_DEBUG, "%s: found entry k=%u/%lu/%lu, v=%lu/%u/%s", __func__,
	    ((struct slab_key *)k)->itbl,
	    ((struct slab_key *)k)->ino,
	    ((struct slab_key *)k)->offset,
	    ((struct slab_val *)v)->revision,
	    ((struct slab_val *)v)->header_crc, u);
}

int
main(int argc, char **argv)
{
	char                opt;
	struct              sigaction act, oact;
	char               *pidfile_path = MGR_DEFAULT_PIDFILE_PATH;
	int                 foreground = 0;
	FILE               *pid_f;
        struct passwd      *pw;
        struct group       *gr;
	char               *unpriv_user = MGR_DEFAULT_UNPRIV_USER;
	char               *unpriv_group = MGR_DEFAULT_UNPRIV_GROUP;
	int                 lsock;
	struct sockaddr_un  saddr;
	int                 workers = 12, n;
	int                 bgworkers = 4;
	struct statvfs      stv;
	struct exlog_err    e = EXLOG_ERR_INITIALIZER;
	off_t               cache_size_limit;
	char                mdb_path[PATH_MAX];
	int                 r;
	struct fs_info      info;


	while ((opt = getopt(argc, argv, "hvd:D:w:W:e:fc:p:s:T:")) != -1) {
		switch (opt) {
			case 'h':
				usage();
				exit(0);
			case 'v':
				printf(MGR_PROGNAME " version " VERSION "\n");
				exit(0);
			case 'd':
				if ((dbg_spec = strdup(optarg)) == NULL)
					err(1, "strdup");
				break;
			case 'w':
				workers = atoi(optarg);
				break;
			case 'W':
				bgworkers = atoi(optarg);
				break;
			case 'f':
				foreground = 1;
				break;
			case 'c':
				if ((fs_config.cfg_path = strdup(optarg))
				    == NULL)
					err(1, "strdup");
				break;
			case 'p':
				if ((pidfile_path = strdup(optarg)) == NULL)
					err(1, "strdup");
				break;
			case 'T':
				socket_timeout.tv_sec = atoi(optarg);
				break;
			default:
				usage();
				exit(1);
		}
	}

	setproctitle_init(argc, argv, environ);

	act.sa_handler = &handle_sig;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	if (sigaction(SIGINT, &act, &oact) == -1
			|| sigaction(SIGPIPE, &act, &oact) == -1
			|| sigaction(SIGTERM, &act, &oact) == -1) {
		err(1, "sigaction");
	}

	if (exlog_init(MGR_PROGNAME, dbg_spec, foreground) == -1)
		err(1, "exlog_init");

	config_read();

	if (!foreground) {
		if (daemon(0, 0) == -1)
			err(1, "daemon");
		setproctitle(MGR_PROGNAME " (parent)");
	}

        if ((pid_f = fopen(pidfile_path, "w")) == NULL) {
		exlog_lerrno(LOG_ERR, errno, "fopen");
		exit(1);
        }
        if (fprintf(pid_f, "%d\n", getpid()) == -1) {
		exlog_lerrno(LOG_ERR, errno, "fprintf");
                exit(1);
        }
        fclose(pid_f);

	if (geteuid() == 0) {
		if ((gr = getgrnam(unpriv_group)) == NULL) {
			exlog_lerrno(LOG_ERR, errno,
			    "Group %s not found in group database",
			    unpriv_group);
			exit(1);
		}
		if (setgid(gr->gr_gid) == -1) {
			exlog_lerrno(LOG_ERR, errno, "setgid");
			exit(1);
		}
		if (setegid(gr->gr_gid) == -1) {
			exlog_lerrno(LOG_ERR, errno, "setegid");
			exit(1);
		}

		if ((pw = getpwnam(unpriv_user)) == NULL) {
			exlog_lerrno(LOG_ERR, errno,
			    "User %s not found in users database", unpriv_user);
			exit(1);
		}
		if (setuid(pw->pw_uid) == -1) {
			exlog_lerrno(LOG_ERR, errno, "setuid");
			exit(1);
		}
		if (seteuid(pw->pw_uid) == -1) {
			exlog_lerrno(LOG_ERR, errno, "seteuid");
			exit(1);
		}
	}

	if (access(fs_config.data_dir, R_OK|X_OK) == -1) {
		exlog_lerrno(LOG_ERR, errno, "access: %s", fs_config.data_dir);
		exit(1);
	}
	if (access(fs_config.mgr_exec, X_OK) == -1) {
		exlog_lerrno(LOG_ERR, errno, "access: %s", fs_config.mgr_exec);
		exit(1);
	}

	if (statvfs(fs_config.data_dir, &stv) == -1) {
		exlog_lerrno(LOG_ERR, errno, "statvfs");
		exit(1);
	}
	cache_size_limit = stv.f_blocks * stv.f_frsize * 90 / 100;

	/*
	 * Default to 90% of the local partition size where data_dir
	 * is hosted for the slab cache size.
	 */
	// TODO: Do something with this, we can't cache more slabs
	// locally than what's computed here.
	if (cache_size == 0 || cache_size > cache_size_limit)
		cache_size = cache_size_limit;

	uuid_clear(uuid_zero);

	exlog(LOG_INFO, "%s: cache size is %llu", __func__, cache_size);

	if (snprintf(bglock_path, sizeof(bglock_path), "%s/%s",
	    fs_config.data_dir, DEFAULT_BGLOCK_NAME) >= sizeof(bglock_path)) {
                exlog(LOG_ERR, "%s: bglock name too long", __func__);
		exit(1);
        }
	if (mknod(bglock_path, S_IFREG|0600, 0) == -1) {
		exlog_lerrno(LOG_ERR, errno, "mknod: %s", bglock_path);
		exit(1);
	}

	if (snprintf(mdb_path, sizeof(mdb_path), "%s/%s", fs_config.data_dir,
            DEFAULT_MDB_NAME) >= sizeof(mdb_path)) {
                exlog(LOG_ERR, "%s: mdb name too long", __func__);
		exit(1);
        }

	if ((r = mdb_env_create(&mdb)) != 0)
		errx(1, "mdb_env_create: %s", mdb_strerror(r));

	if ((r = mdb_env_open(mdb, mdb_path, MDB_NOSUBDIR, 0644)) != 0)
		errx(1, "mdb_env_open: %s", mdb_strerror(r));

	if (slabdb_loop(&slabdb_status, &e) == -1) {
		exlog_lerr(LOG_ERR, &e, "%s", __func__);
		exit(1);
	}

	if (fs_info_open(&info, &e) == -1) {
		exlog_lerr(LOG_ERR, &e, "%s", __func__);
		exit(1);
	}
	uuid_copy(instance_id, info.instance_id);

	if (fs_config.max_open_slabs == 0 ||
	    fs_config.max_open_slabs > (cache_size /
	    (fs_config.slab_size + sizeof(struct slab_hdr))))
		fs_config.max_open_slabs = cache_size /
		    (fs_config.slab_size + sizeof(struct slab_hdr));

	if (slab_make_dirs(&e) == -1) {
		exlog_lerr(LOG_ERR, &e, "%s", __func__);
		exit(1);
	}

	if ((lsock = socket(AF_LOCAL, SOCK_STREAM, 0)) == -1) {
		exlog_lerrno(LOG_ERR, errno, "socket");
		exit(1);
	}
	unlink(fs_config.mgr_sock_path);

	bzero(&saddr, sizeof(saddr));
	saddr.sun_family = AF_LOCAL;
	strlcpy(saddr.sun_path, fs_config.mgr_sock_path,
	    sizeof(saddr.sun_path));

	if (bind(lsock, (struct sockaddr *)&saddr, SUN_LEN(&saddr)) == -1) {
		exlog_lerrno(LOG_ERR, errno, "bind");
		exit(1);
	}

	if (listen(lsock, 64) == -1) {
		exlog_lerrno(LOG_ERR, errno, "listen");
		exit(1);
	}

	for (n = 0; n < workers + bgworkers; n++) {
		switch (fork()) {
		case -1:
			killpg(0, 15);
			err(1, "fork");
		case 0:
			if (n >= workers)
				bgworker();
			else
				worker(lsock);
			/* Never reached */
			exit(1);
		default:
			/* Nothing */
			break;
		}
	}

	for (n = 0; n < workers + bgworkers; n++)
		wait(NULL);

	mdb_env_close(mdb);

	return 0;
}
