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
#include <sys/mman.h>
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
#include <libgen.h>
#include <pwd.h>
#include <poll.h>
#include <semaphore.h>
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

struct mgr_counters {
	sem_t    sem;
	uint64_t c[COUNTER_LAST + MGR_COUNTER_LAST];
	size_t   mdb_entries;
};

char                *dbg_spec = NULL;
struct timeval       socket_timeout = {60, 0};
extern char        **environ;
MDB_env             *mdb;
uuid_t               instance_id;
uuid_t               uuid_zero;
struct mgr_counters *mgr_counters;
int                  shutdown_requested = 0;

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
	    "\t-T <timeout>\tUnix socket timeout\n"
	    "\t-S <seconds>\tHow often to trigger the scrub worker; "
	    "0 disables\n"
	    "\t-P <seconds>\tHow often to trigger the purge worker; "
	    "0 disables\n");
}

static void
handle_sig(int sig)
{
	if (shutdown_requested)
		return;
	switch (sig) {
	case SIGTERM:
	case SIGINT:
		shutdown_requested = 1;
		killpg(0, 15);
		syslog(LOG_NOTICE, "signal %d received, shutting down", sig);
		break;
	default:
		syslog(LOG_ERR, "Unhandled signal received. Exiting.");
		exit(sig);
	}
}

static void
worker_handle_sig(int sig)
{
	shutdown_requested = 1;
	syslog(LOG_NOTICE, "signal %d received, shutting down", sig);
}

static int
set_fs_error()
{
	struct fs_info   fs_info;
	struct exlog_err e = EXLOG_ERR_INITIALIZER;

	if (fs_info_read(&fs_info, &e) == -1) {
		exlog(LOG_CRIT, &e, "%s", __func__);
		return -1;
	}

	fs_info.error = 1;

	if (fs_info_write(&fs_info, &e) == -1) {
		exlog(LOG_CRIT, &e, "%s", __func__);
		return -1;
	}

	return 0;
}

static void
mgr_counter_add(int c, uint64_t v)
{
	if (sem_wait(&mgr_counters->sem) == -1) {
		exlog_strerror(LOG_ERR, errno, "sem_wait");
		return;
	}

	mgr_counters->c[c] += v;

	if (sem_post(&mgr_counters->sem) == -1)
		exlog_strerror(LOG_ERR, errno, "sem_wait");
}

static void
mgr_counter_incr_mdb_entries()
{
	if (sem_wait(&mgr_counters->sem) == -1) {
		exlog_strerror(LOG_ERR, errno, "sem_wait");
		return;
	}

	mgr_counters->mdb_entries++;

	if (sem_post(&mgr_counters->sem) == -1)
		exlog_strerror(LOG_ERR, errno, "sem_wait");
}

static int
slabdb_put(struct slab_key *key, uint64_t revision, uint32_t header_crc,
    uuid_t owner, const struct timespec *last_claimed, struct exlog_err *e)
{
	int                r;
	MDB_txn           *txn;
	MDB_dbi            dbi;
	MDB_val            mk, mv;
	MDB_cursor        *cursor;
	struct slab_key    k;
	struct slabdb_val  v;
	char               u[37];

	if ((r = mdb_txn_begin(mdb, NULL, 0, &txn)))
		return exlog_errf(e, EXLOG_MDB, r, "%s: mdb_txn_begin: %s",
		    __func__, mdb_strerror(r));

	if ((r = mdb_dbi_open(txn, NULL, 0, &dbi))) {
		exlog_errf(e, EXLOG_MDB, r, "%s: mdb_dbi_open: %s",
		    __func__, mdb_strerror(r));
		goto fail;
	}

	if ((r = mdb_cursor_open(txn, dbi, &cursor))) {
		exlog_errf(e, EXLOG_MDB, r, "%s: mdb_cursor_open: %s",
		    __func__, mdb_strerror(r));
		goto fail;
	}

	/*
	 * We could in theory just use key, but we want to be certain
	 * that the structure was zeroed to avoid random bytes in
	 * the structure gaps, as that would mess up the key in the database.
	 */
	bzero(&k, sizeof(k));
	k.ino = key->ino;
	k.base = key->base;

	mk.mv_size = sizeof(k);
	mk.mv_data = &k;

	bzero(&v, sizeof(v));
	v.revision = revision;
	v.header_crc = header_crc;
	uuid_copy(v.owner, owner);
	uuid_unparse(v.owner, u);
	memcpy(&v.last_claimed, last_claimed, sizeof(struct timespec));

	if ((r = mdb_cursor_get(cursor, &mk, &mv, MDB_SET_KEY)) == 0 &&
	    memcmp(&k, mk.mv_data, sizeof(k)) == 0 &&
	    memcmp(&v, mv.mv_data, sizeof(v)) == 0) {
		/* Found the key, same value; do nothing. */
		exlog(LOG_DEBUG, NULL, "%s: no change for k=%lu/%lu, "
		    "v=%lu/%u/%s; not writing", __func__,
		    ((struct slab_key *)mk.mv_data)->ino,
		    ((struct slab_key *)mk.mv_data)->base,
		    ((struct slabdb_val *)mv.mv_data)->revision,
		    ((struct slabdb_val *)mv.mv_data)->header_crc, u);
		mdb_cursor_close(cursor);
		mdb_txn_abort(txn);
		return 0;
	} else if (r != 0 && r != MDB_NOTFOUND) {
		exlog_errf(e, EXLOG_MDB, r, "%s: mdb_cursor_get: %s",
		    __func__, mdb_strerror(r));
		goto fail_close_cursor;
	}

	mv.mv_size = sizeof(v);
	mv.mv_data = &v;

	if ((r = mdb_cursor_put(cursor, &mk, &mv,
	    (r == MDB_NOTFOUND) ? 0 : MDB_CURRENT))) {
		exlog_errf(e, EXLOG_MDB, r, "%s: mdb_cursor_put: %s",
		    __func__, mdb_strerror(r));
		goto fail_close_cursor;
	}

	exlog(LOG_DEBUG, NULL, "%s: k=%lu/%lu, v=%lu/%u/%s", __func__,
	    ((struct slab_key *)mk.mv_data)->ino,
	    ((struct slab_key *)mk.mv_data)->base,
	    ((struct slabdb_val *)mv.mv_data)->revision,
	    ((struct slabdb_val *)mv.mv_data)->header_crc, u);

	if ((r = mdb_txn_commit(txn))) {
		exlog_errf(e, EXLOG_MDB, r, "%s: mdb_txn_commit: %s",
		    __func__, mdb_strerror(r));
		goto fail_close_cursor;
	}
	return 0;
fail_close_cursor:
	mdb_cursor_close(cursor);
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
slabdb_get(struct slab_key *key, uint32_t oflags, uint64_t *revision,
    uint32_t *header_crc, uuid_t *owner, struct timespec *last_claimed,
    struct exlog_err *e)
{
	int                r;
	MDB_txn           *txn;
	MDB_dbi            dbi;
	MDB_val            mk, mv;
	struct slab_key    k;
	struct slabdb_val  v;
	char               u[37];

	if ((r = mdb_txn_begin(mdb, NULL, 0, &txn)))
		return exlog_errf(e, EXLOG_MDB, r, "%s: mdb_txn_begin: %s",
		    __func__, mdb_strerror(r));

	if ((r = mdb_dbi_open(txn, NULL, 0, &dbi))) {
		exlog_errf(e, EXLOG_MDB, r, "%s: mdb_dbi_open: %s",
		    __func__, mdb_strerror(r));
		goto fail;
	}

	/*
	 * We could in theory just use key, but we want to be certain
	 * that the structure was zeroed to avoid random bytes in
	 * the structure gaps, as that would mess up the key in the database.
	 */
	bzero(&k, sizeof(k));
	k.ino = key->ino;
	k.base = key->base;

	mk.mv_size = sizeof(k);
	mk.mv_data = &k;

	if ((r = mdb_get(txn, dbi, &mk, &mv))) {
		if (r != MDB_NOTFOUND || (oflags & OSLAB_NOCREATE)) {
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

		// TODO: consensus resolution here; determine owner of
		// new slab.

		uuid_unparse(v.owner, u);
		exlog(LOG_DEBUG, NULL, "%s: writing new slab: mdb_put(): "
		    "k=%lu/%lu, v=%u/%lu/%s\n", __func__, k.ino,
		    k.base, *revision, *header_crc, u);
		if ((r = mdb_put(txn, dbi, &mk, &mv, 0))) {
			exlog_errf(e, EXLOG_MDB, r, "%s: mdb_put: %s",
			    __func__, mdb_strerror(r));
			goto fail;
		}

		if ((r = mdb_txn_commit(txn))) {
			exlog_errf(e, EXLOG_MDB, r, "%s: mdb_txn_commit: %s",
			    __func__, mdb_strerror(r));
			goto fail;
		}
		mgr_counter_incr_mdb_entries();
		goto end;
	}

	if (uuid_compare(((struct slabdb_val *)mv.mv_data)->owner,
	    instance_id) != 0) {
		// TODO: consensus resolution here; determine owner of
		// existing slab
		bzero(&v, sizeof(v));
		v.revision = ((struct slabdb_val *)mv.mv_data)->revision;
		v.header_crc = ((struct slabdb_val *)mv.mv_data)->header_crc;
		memcpy(&v.last_claimed,
		    &((struct slabdb_val *)mv.mv_data)->last_claimed,
		    sizeof(struct timespec));
		uuid_copy(v.owner, instance_id);

		mv.mv_size = sizeof(v);
		mv.mv_data = &v;

		uuid_unparse(v.owner, u);
		exlog(LOG_DEBUG, NULL, "%s: changing ownership: mdb_put(): "
		    "k=%lu/%lu, v=%u/%lu/%s\n", __func__, k.ino, k.base,
		    *revision, *header_crc, u);
		if ((r = mdb_put(txn, dbi, &mk, &mv, 0))) {
			exlog_errf(e, EXLOG_MDB, r, "%s: mdb_put: %s",
			    __func__, mdb_strerror(r));
			goto fail;
		}
		if ((r = mdb_txn_commit(txn))) {
			exlog_errf(e, EXLOG_MDB, r, "%s: mdb_txn_commit: %s",
			    __func__, mdb_strerror(r));
			goto fail;
		}
	} else
		mdb_txn_abort(txn);
end:
	*revision = ((struct slabdb_val *)mv.mv_data)->revision;
	*header_crc = ((struct slabdb_val *)mv.mv_data)->header_crc;
	uuid_copy(*owner, ((struct slabdb_val *)mv.mv_data)->owner);
	uuid_unparse(*owner, u);

	exlog(LOG_DEBUG, NULL, "%s: k=%lu/%lu, v=%u/%lu/%s\n", __func__,
	    k.ino, k.base, *revision, *header_crc, u);

	return 0;
fail:
	mdb_txn_abort(txn);
	return -1;
}

static int
slabdb_loop(void(*fn)(const struct slab_key *, const struct slabdb_val *),
    struct exlog_err *e)
{
	int              r;
	MDB_txn         *txn;
	MDB_dbi          dbi;
	MDB_cursor      *cursor;
	MDB_val          mk, mv;

	if ((r = mdb_txn_begin(mdb, NULL, MDB_RDONLY, &txn)))
		return exlog_errf(e, EXLOG_MDB, r, "%s: mdb_txn_begin: %s",
		    __func__, mdb_strerror(r));

	if ((r = mdb_dbi_open(txn, NULL, 0, &dbi))) {
		exlog_errf(e, EXLOG_MDB, r, "%s: mdb_dbi_open: %s",
		    __func__, mdb_strerror(r));
		mdb_txn_abort(txn);
		return -1;
	}

	if ((r = mdb_cursor_open(txn, dbi, &cursor))) {
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
		    (struct slabdb_val *)mv.mv_data);
	}

	mdb_cursor_close(cursor);
	mdb_txn_abort(txn);
	return 0;
}

static size_t
mgr_counter_get_mdb_entries()
{
	size_t entries;
	if (sem_wait(&mgr_counters->sem) == -1) {
		exlog_strerror(LOG_ERR, errno, "sem_wait");
		return ULONG_MAX;
	}

	entries = mgr_counters->mdb_entries;

	if (sem_post(&mgr_counters->sem) == -1)
		exlog_strerror(LOG_ERR, errno, "sem_wait");
	return entries;
}

static int
snd_counters(int c, struct mgr_msg *m, struct exlog_err *e)
{
	int i;
	if (sem_wait(&mgr_counters->sem) == -1) {
		exlog_strerror(LOG_ERR, errno, "sem_wait");
		goto fail;
	}

	for (i = 0; i < COUNTER_LAST; i++)
		mgr_counters->c[i] = m->v.snd_counters.c[i];

	if (sem_post(&mgr_counters->sem) == -1) {
		exlog_strerror(LOG_ERR, errno, "sem_wait");
		goto fail;
	}

	m->m = MGR_MSG_SND_COUNTERS_OK;
	return mgr_send(c, -1, m, e);
fail:
	m->m = MGR_MSG_SND_COUNTERS_ERR;
	return mgr_send(c, -1, m, e);
}

static int
rcv_counters(int c, struct mgr_msg *m, struct exlog_err *e)
{
	int i;
	if (sem_wait(&mgr_counters->sem) == -1) {
		exlog_strerror(LOG_ERR, errno, "sem_wait");
		goto fail;
	}

	for (i = 0; i < MGR_COUNTER_LAST; i++)
		m->v.rcv_counters.c[i] = mgr_counters->c[i];

	if (sem_post(&mgr_counters->sem) == -1) {
		exlog_strerror(LOG_ERR, errno, "sem_wait");
		goto fail;
	}

	m->m = MGR_MSG_RCV_COUNTERS_OK;
	return mgr_send(c, -1, m, e);
fail:
	m->m = MGR_MSG_RCV_COUNTERS_ERR;
	return mgr_send(c, -1, m, e);
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
	char *const  *a;
	char        **argv2, **a2;

	for (a = argv; *a != NULL; a++)
		/* Counting args */;

	if ((argv2 = calloc((a - argv) + 2, sizeof(char *))) == NULL)
		return exlog_errf(e, EXLOG_OS, errno, "%s: calloc", __func__);

	if ((argv2[0] = strdup(fs_config.mgr_exec)) == NULL)
		return exlog_errf(e, EXLOG_OS, errno, "%s: strdup", __func__);

	for (a = argv, a2 = argv2 + 1; *a != NULL; a++, a2++)
		*a2 = *a;

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

		if (execv(fs_config.mgr_exec, argv2) == -1) {
			close(p_out[1]);
			close(p_err[1]);
			return exlog_errf(e, EXLOG_OS, errno, "%s: execv",
			    __func__);
		}
	}

	free(argv2[0]);
	free(argv2);

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
			exlog(LOG_ERR, NULL, "%s: command timed out after %d "
			    "seconds; aborting",
			    __func__, BACKEND_TIMEOUT_SECONDS);
			kill(pid, 9);
		}

		while (nfds-- > 0) {
			if (fds[nfds].revents & POLLERR) {
				if (fds[nfds].fd == p_out[0])
					stdout_closed = 1;
				else
					stderr_closed = 1;
				exlog(LOG_ERR, NULL, "%s: file descriptor %d "
				    "closed unexpectedly", __func__,
				    fds[nfds].fd);
				continue;
			}

			if (!(fds[nfds].revents & (POLLIN|POLLHUP)))
				continue;

			if (fds[nfds].fd == p_out[0]) {
				r = read(p_out[0], stdout + stdout_r,
				    stdout_len - stdout_r);
				if (r > 0) {
					stdout_r += r;
				} else {
					stdout_closed = 1;
					close(p_out[0]);
				}
			} else {
				r = read(p_err[0], stderr + stderr_r,
				    stderr_len - stderr_r);
				if (r > 0) {
					stderr_r += r;
				} else {
					stderr_closed = 1;
					close(p_err[0]);
				}
			}
			if (r == -1)
				exlog_strerror(LOG_ERR, errno,
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

/*
 * Modifies the checksum and flags fields in 'hdr'.
 */
static int
copy_outgoing_slab(int fd, struct slab_key *sk, struct slab_hdr *hdr,
    struct exlog_err *e)
{
	int             dst_fd;
	char            dst[PATH_MAX], name[NAME_MAX + 1];
	char            buf[8192];
	struct stat     st;
	struct slab_hdr dst_hdr;
	ssize_t         r;

	if (slab_path(name, sizeof(name), sk, 1, e) == -1)
		return -1;

	if (snprintf(dst, sizeof(dst), "%s/%s/%s", fs_config.data_dir,
	    OUTGOING_DIR, name) >= sizeof(dst))
		return exlog_errf(e, EXLOG_APP, EXLOG_NAMETOOLONG,
		    "%s: outq slab name too long", __func__);

	if ((dst_fd = open_wflock(dst,
	    O_CREAT|O_WRONLY, 0600, LOCK_EX)) == -1) {
		return exlog_errf(e, EXLOG_OS, errno, "%s: failed "
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
			exlog(LOG_INFO, NULL, "%s: slab in outgoing dir has a "
			    "revision greater or equal to this one: %s "
			    "(revision %llu >= %llu)", __func__, dst,
			    dst_hdr.v.f.revision, hdr->v.f.revision);
			goto end;
		}
	}

copy_again:
	/* Make room for the header we're about to fill in. */
	if (lseek(dst_fd, sizeof(struct slab_hdr), SEEK_SET) == -1) {
		exlog_errf(e, EXLOG_OS, errno,
		    "%s: lseek", __func__);
		goto fail;
	}

	if (lseek(fd, sizeof(struct slab_hdr), SEEK_SET) == -1) {
		exlog_errf(e, EXLOG_OS, errno, "%s: lseek", __func__);
		goto fail;
	}

	memcpy(&dst_hdr, hdr, sizeof(struct slab_hdr));
	dst_hdr.v.f.checksum = crc32_z(0L, Z_NULL, 0);

	while ((r = read(fd, buf, sizeof(buf)))) {
		if (r == -1) {
			if (errno == EINTR)
				continue;
			exlog_errf(e, EXLOG_OS, errno, "%s: read", __func__);
			goto fail;
		}

		dst_hdr.v.f.checksum = crc32_z(dst_hdr.v.f.checksum,
		    (unsigned char *)buf, r);

		r = write_x(dst_fd, buf, r);
		if (r == -1) {
			if (errno == ENOSPC) {
				exlog(LOG_ERR, NULL, "%s: ran out of space; "
				    "retrying", __func__);
				sleep(5);
				goto copy_again;
			}
			exlog_errf(e, EXLOG_OS, errno, "%s: write", __func__);
			goto fail;
		}
	}

	dst_hdr.v.f.flags &= ~SLAB_DIRTY;

	if (pwrite_x(dst_fd, &dst_hdr, sizeof(dst_hdr), 0) < sizeof(dst_hdr)) {
		exlog_errf(e, EXLOG_OS, errno,
		    "%s: short write on slab header", __func__);
		goto fail;
	}
	memcpy(hdr, &dst_hdr, sizeof(dst_hdr));
end:
	close(dst_fd);
	return 0;
fail:
	if (unlink(dst) == -1)
		exlog_strerror(LOG_ERR, errno, "%s: unlink dst", __func__);
	close(dst_fd);
	return -1;
}

static int
unclaim(int c, struct mgr_msg *m, int fd, struct exlog_err *e)
{
	struct slab_hdr hdr;
	char            src[PATH_MAX];
	int             purge = 0;
	struct statvfs  stv;
	uint32_t        crc;

	if (slab_key_valid(&m->v.unclaim.key, e) == -1) {
		exlog(LOG_ERR, e, "%s", __func__);
		exlog_zerr(e);
		return exlog_errf(e, EXLOG_APP, EXLOG_INVAL,
		    "%s: aborting", __func__);
	}

	if (pread_x(fd, &hdr, sizeof(hdr), 0) < sizeof(hdr)) {
		exlog_errf(e, EXLOG_OS, errno,
		    "%s: short read on slab header", __func__);
		goto fail;
	}

	if (statvfs(fs_config.data_dir, &stv) == -1) {
		exlog_strerror(LOG_ERR, errno, "statvfs");
		goto fail;
	}
	if (stv.f_bfree <
	    stv.f_blocks * (100 - fs_config.unclaim_purge_threshold_pct) / 100)
		/*
		 * This should rarely happen, since the bgworker should
		 * handle most purges based on LRU.
		 */
		purge = 1;

	if (hdr.v.f.flags & SLAB_DIRTY) {
		hdr.v.f.revision++;
		hdr.v.f.flags &= ~SLAB_DIRTY;
		if (copy_outgoing_slab(fd, &m->v.unclaim.key, &hdr, e) == -1)
			goto fail;

		if (pwrite_x(fd, &hdr, sizeof(hdr), 0) < sizeof(hdr)) {
			exlog_errf(e, EXLOG_OS, errno,
			    "%s: short read on slab header", __func__);
			goto fail;
		}
	}

	crc = crc32_z(0L, (Bytef *)&hdr, sizeof(hdr));
	if (slabdb_put(&m->v.unclaim.key, hdr.v.f.revision, crc,
	    (purge) ? uuid_zero : instance_id,
	    &hdr.v.f.last_claimed_at, e) == -1) {
		if (exlog_err_is(e, EXLOG_MDB, MDB_MAP_FULL))
			m->err = EXLOG_NOSPC;
		set_fs_error();
		goto fail;
	}

	if (purge) {
		if (slab_path(src, sizeof(src), &m->v.unclaim.key, 0, e) == -1)
			goto fail;

		if (unlink(src) == -1) {
			exlog_strerror(LOG_ERR, errno,
			    "%s: unlink src %s", __func__, src);
			purge = 0;
		}
	}

	close(fd);

	m->m = MGR_MSG_UNCLAIM_OK;
	return mgr_send(c, -1, m, e);
fail:
	exlog(LOG_ERR, e, "%s");
	exlog_zerr(e);
	m->m = MGR_MSG_UNCLAIM_ERR;
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

	if (WEXITSTATUS(wstatus) > 2) {
		exlog_errf(e, EXLOG_APP, EXLOG_EXEC,
		    "%s: \"get\" resulted in an undefined error (exit %d)",
		    __func__, WEXITSTATUS(wstatus));
		goto fail;
	}

	/* Bad invocation error, there is no JSON to read here. */
	if (WEXITSTATUS(wstatus) == 2) {
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

	if (WEXITSTATUS(wstatus) == 1) {
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
		exlog(LOG_ERR, NULL, "%s: failed to clear JSON", __func__);
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

	if (WEXITSTATUS(wstatus) > 2)
		return exlog_errf(e, EXLOG_APP, EXLOG_EXEC,
		    "%s: \"put\" resulted in an undefined error (exit %d)",
		    __func__, WEXITSTATUS(wstatus));

	/* Bad invocation error, there is no JSON to read here. */
	if (WEXITSTATUS(wstatus) == 2)
		return exlog_errf(e, EXLOG_APP, EXLOG_EXEC,
		    "%s: \"put\" reported bad invocation (exit 2)", __func__);

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

	if (WEXITSTATUS(wstatus) == 1)
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

	if (pread_x(fd, &hdr, sizeof(hdr), 0) < sizeof(hdr))
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
copy_incoming_slab(int dst_fd, int src_fd, uint32_t header_crc,
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

	if ((r = read_x(src_fd, &hdr, sizeof(hdr))) < sizeof(hdr)) {
		if (r == -1)
			return exlog_errf(e, EXLOG_OS, errno,
			    "%s: short read on slab header", __func__);
		else
			return exlog_errf(e, EXLOG_MGR, EXLOG_SHORTIO,
			    "%s: short read on slab header", __func__);
	}

	if (hdr.v.f.revision != revision) {
		/*
		 * backend doesn't have correct (latest?) version
		 * of slab. Are we dealing with eventual consistency?
		 */
		return exlog_errf(e, EXLOG_APP, EXLOG_INVAL,
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
	if (clock_gettime(CLOCK_REALTIME, &hdr.v.f.last_claimed_at) == -1) {
		exlog_strerror(LOG_ERR, errno, "%s: clock_gettime", __func__);
		return -1;
	}
	if (write_x(dst_fd, &hdr, sizeof(hdr)) == -1) {
		if (errno == ENOSPC) {
			exlog(LOG_ERR, NULL, "%s: ran out of space during; "
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
				exlog(LOG_ERR, NULL, "%s: ran out of space; "
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
	struct stat     st;
	uint64_t        revision;
	uint32_t        header_crc;
	uuid_t          owner;
	struct timespec last_claimed;

	/*
	 * Retry open/flock() every 10ms, for 1000 times, thus 10s.
	 */
	struct timespec tp = {0, 10000000};
	int             open_retries = 1000;

	if (slab_key_valid(&m->v.claim.key, e) == -1) {
		exlog(LOG_ERR, e, "%s", __func__);
		exlog_zerr(e);
		return exlog_errf(e, EXLOG_APP, EXLOG_INVAL,
		    "%s: aborting", __func__);
	}

	/*
	 * Check existence in DB, if owned by another instance, otherwise
	 * a new entry will be allocated and returned.
	 */
	if (slabdb_get(&m->v.claim.key, m->v.claim.oflags, &revision,
	    &header_crc, &owner, &last_claimed, e) == -1) {
		if (exlog_err_is(e, EXLOG_MDB, MDB_MAP_FULL))
			m->err = EXLOG_NOSPC;
		else if (m->v.claim.oflags & OSLAB_NOCREATE &&
		    exlog_err_is(e, EXLOG_MDB, MDB_NOTFOUND)) {
			exlog_zerr(e);
			m->m = MGR_MSG_CLAIM_NOENT;
			if (mgr_send(c, -1, m, e) == -1) {
				exlog(LOG_ERR, e, "%s", __func__);
				goto fail;
			}
			return 0;
		}
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
	 * claim() or unclaim() with other potatomgr processes.
	 *
	 * The slab is first downloaded at dst during which the CRC
	 * is validated, then copied to dst_fd. dst is unlinked after
	 * successfully copying.
	 */
	if (slab_path(dst, sizeof(dst), &m->v.claim.key, 0, e) == -1 ||
	    slab_path(name, sizeof(name), &m->v.claim.key, 1, e) == -1)
		goto fail;

	if (m->v.claim.oflags & OSLAB_SYNC)
		fd_flags |= O_SYNC;

	/*
	 * We loop on open instead of simply doing a blocking flock()
	 * because the lock could be held by a unclaim which will
	 * unlink() the file at the end. Therefore we would want to
	 * reopen a new filehandle to ensure it is present in the dir
	 * entry.
	 * Note: On unclaim(), unlink() happens before close()
	 *
	 * We put a cap on how many retries because we could run into a
	 * deadlock if something external to the fuse fs is trying
	 * to grab this lock and the fs is attempting to use the only
	 * available worker to release it. The fs itself would normally never
	 * cause this since it has its own locking around the claimed slab
	 * and would never claim the same slab if it already has a claim on it.
	 */
	for (; open_retries > 0; open_retries--) {
		if ((dst_fd = open_wflock(dst, fd_flags,
		    0600, LOCK_EX|LOCK_NB)) == -1) {
			if (errno == EWOULDBLOCK) {
				nanosleep(&tp, NULL);
				continue;
			}
			exlog_errf(e, EXLOG_OS, errno,
			    "%s: open_wflock() for slab %s", __func__, dst);
			goto fail;
		}
		break;
	}
	if (open_retries == 0) {
		exlog_errf(e, EXLOG_MGR, EXLOG_BUSY,
		    "%s: open_wflock() timed out after multiple retries "
		    "for slab %s; this should not happen if the fs process"
		    "is properly managing open slabs. Unless someone "
		    "is attempting to claim this slab from another process?",
		    __func__, dst);
		goto fail;
	}

	if (revision == 0) {
		/*
		 * If revision is zero, we're dealing with a brand new slab.
		 * The entry is already in the slabdb, no need to slabdb_put()
		 * here.
		 */
		bzero(&hdr, sizeof(hdr));
		hdr.v.f.slab_version = SLAB_VERSION;
		memcpy(&hdr.v.f.key, &m->v.claim.key, sizeof(struct slab_key));
		hdr.v.f.flags = SLAB_DIRTY;
		hdr.v.f.revision = 0;
		hdr.v.f.checksum = crc32(0L, Z_NULL, 0);
		if (clock_gettime(CLOCK_REALTIME,
		    &hdr.v.f.last_claimed_at) == -1) {
			exlog_errf(e, EXLOG_OS, errno,
			    "%s: clock_gettime", __func__);
			goto fail_close_dst;
		}
		if (write_x(dst_fd, &hdr, sizeof(hdr)) < sizeof(hdr)) {
			exlog_errf(e, EXLOG_OS, errno,
			    "%s: short write on slab header", __func__);
			goto fail_close_dst;
		}
		/*
		 * Make sure to fsync() if the file wasn't opened
		 * with O_SYNC initially.
		 */
		if (!(m->v.claim.oflags & OSLAB_SYNC) && fsync(dst_fd) == -1) {
			exlog_errf(e, EXLOG_OS, errno,
			    "%s: fsync", __func__);
			goto fail_close_dst;
		}
		goto end;
	}

	if (fstat(dst_fd, &st) == -1) {
		exlog_errf(e, EXLOG_OS, errno, "%s: fstat", __func__);
		goto fail_close_dst;
	}

	if (st.st_size > 0) {
		/*
		 * This is the most common case, where a slab was previously
		 * claimed and is still present in our local disk cache.
		 * The header CRC/revision check may be superfluous, but
		 * until we are confident we can remove it, we will keep it
		 * as an extra sanity check.
		 */
		if (check_slab_header(dst_fd, header_crc, revision, e) == 0) {
			goto end;
		/*
		 * Wrong rev/header_crc is fine, just proceed
		 * with retrieving.
		 */
		} else if (!exlog_err_is(e, EXLOG_APP, EXLOG_INVAL))
			goto fail_close_dst;
		exlog_zerr(e);
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
		if (copy_incoming_slab(dst_fd, outgoing_fd, header_crc,
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
	if ((incoming_fd = open_wflock(in_path, O_RDWR, 0, LOCK_EX)) > 0) {
		/*
		 * Normally this shouldn't happen, but if for some reason
		 * we failed to unlink from our incoming queue the open could
		 * succeed. Furthermore, if the rev and CRC match, well,
		 * use it.
		 */
		if (copy_incoming_slab(dst_fd, incoming_fd, header_crc,
		    revision, e) == 0) {
			unlink(in_path);
			close(incoming_fd);
			goto end;
		}
		exlog_strerror(LOG_ERR, errno, "%s: open_wflock", __func__);
		close(incoming_fd);
		exlog_zerr(e);
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
			exlog_zerr(e);
			m->m = MGR_MSG_CLAIM_NOENT;
			if (mgr_send(c, -1, m, e) == -1) {
				exlog(LOG_ERR, e, "%s", __func__);
				goto fail;
			}
			return 0;
		} else if (exlog_err_is(e, EXLOG_APP, EXLOG_NOENT)) {
			/*
			 * Maybe the backend isn't up-to-date? Eventual
			 * consistentcy?
			 */
			exlog_zerr(e);
			exlog(LOG_ERR, NULL, "%s: slab %s expected on backend, "
			    "but backend_get() claims is doesn't exist; "
			    "retrying", __func__, name);
			sleep(5);
			goto get_again;
		} else if (exlog_err_is(e, EXLOG_OS, ENOSPC)) {
			exlog_zerr(e);
			exlog(LOG_ERR, NULL, "%s: ran out of space during "
			    "backend_get(); retrying", __func__);
			sleep(5);
			goto get_again;
		}
		goto fail_close_dst;
	}
	mgr_counter_add(MGR_COUNTER_BACKEND_IN_BYTES, in_bytes);

	if ((incoming_fd = open_wflock(in_path, O_RDWR, 0, LOCK_EX)) == -1) {
		exlog_strerror(LOG_ERR, errno, "%s: failed to open_wflock "
		    "after successful backend_get of %s", __func__, in_path);
		unlink(dst);
		goto fail_close_dst;
	}
	if (copy_incoming_slab(dst_fd, incoming_fd, header_crc,
	    revision, e) == -1) {
		if (exlog_err_is(e, EXLOG_APP, EXLOG_INVAL)) {
			exlog_zerr(e);
			exlog(LOG_ERR, NULL, "%s: wrong revision/header_crc "
			    "from backend; retrying", __func__);
			sleep(5);
			goto get_again;
		}
		unlink(dst);
		goto fail_close_dst;
	}

	unlink(in_path);
	close(incoming_fd);

end:
	m->m = MGR_MSG_CLAIM_OK;
	if (mgr_send(c, dst_fd, m, e) == -1) {
		exlog(LOG_ERR, e, "%s", __func__);
		return -1;
	}
	close(dst_fd);
	return 0;

fail_close_dst:
	close(dst_fd);
fail:
	m->m = MGR_MSG_CLAIM_ERR;
	if (mgr_send(c, -1, m, e) == -1)
		exlog(LOG_ERR, e, "%s", __func__);
	return -1;
}

/*
 * Claims an inode table slab after the one for the base inode contained
 * in the message. Useful for looping over all existing inode tables.
 */
static int
claim_next_itbls(int c, struct mgr_msg *m, struct exlog_err *e)
{
	int              r;
	MDB_txn         *txn;
	MDB_dbi          dbi;
	MDB_cursor      *cursor;
	MDB_val          mk, mv;
	struct slab_key  sk;
	struct mgr_msg   claim_msg;

	bzero(&sk, sizeof(sk));
	sk.base = m->v.claim_next_itbl.base;

	mk.mv_size = sizeof(sk);
	mk.mv_data = &sk;

	if ((r = mdb_txn_begin(mdb, NULL, MDB_RDONLY, &txn))) {
		exlog(LOG_ERR, NULL, "%s: mdb_txn_begin: %s",
		    __func__, mdb_strerror(r));
		goto fail;
	}

	if ((r = mdb_dbi_open(txn, NULL, 0, &dbi))) {
		exlog(LOG_ERR, NULL, "%s: mdb_dbi_open: %s",
		    __func__, mdb_strerror(r));
		mdb_txn_abort(txn);
		goto fail;
	}

	if ((r = mdb_cursor_open(txn, dbi, &cursor))) {
		exlog(LOG_ERR, NULL, "%s: mdb_cursor_open: %s",
		    __func__, mdb_strerror(r));
		mdb_txn_abort(txn);
		goto fail;
	}

	/*
	 * Because we work with a new cursor on every MGR_MSG_CLAIM_NEXT_ITBL
	 * message, we need to start with MDB_SET_RANGE, compare if we the
	 * entry we're at is greater than what we expected, and do MDB_NEXT
	 * if it is not. Moreover, we must ensure to stop if we start looping
	 * over inodes greater than zero, meaning we're no longer looping
	 * over inode tables.
	 */
	if ((r = mdb_cursor_get(cursor, &mk, &mv, MDB_SET_RANGE))) {
		mdb_cursor_close(cursor);
		mdb_txn_abort(txn);
		if (r == MDB_NOTFOUND) {
			m->m = MGR_MSG_CLAIM_NEXT_ITBL_END;
			if (mgr_send(c, -1, m, e) == -1)
				return -1;
			return 0;
		}
		goto fail;
	}

	if ((r = memcmp(&sk, (struct slab_key *)mk.mv_data,
	    sizeof(struct slab_key))) == 0) {
		if ((r = mdb_cursor_get(cursor, &mk, &mv, MDB_NEXT))) {
			mdb_cursor_close(cursor);
			mdb_txn_abort(txn);
			if (r == MDB_NOTFOUND) {
				m->m = MGR_MSG_CLAIM_NEXT_ITBL_END;
				if (mgr_send(c, -1, m, e) == -1)
					return -1;
				return 0;
			}
			goto fail;
		}
	}

	sk.ino = ((struct slab_key *)mk.mv_data)->ino;
	sk.base = ((struct slab_key *)mk.mv_data)->base;

	if (sk.ino > 0 || sk.base < m->v.claim_next_itbl.base) {
		mdb_cursor_close(cursor);
		mdb_txn_abort(txn);
		m->m = MGR_MSG_CLAIM_NEXT_ITBL_END;
		if (mgr_send(c, -1, m, e) == -1)
			return -1;
		return 0;
	}

	mdb_cursor_close(cursor);
	mdb_txn_abort(txn);

	claim_msg.m = MGR_MSG_CLAIM;
	claim_msg.v.claim.oflags = m->v.claim_next_itbl.oflags;
	claim_msg.v.claim.key.ino = sk.ino;
	claim_msg.v.claim.key.base = sk.base;

	return claim(c, &claim_msg, e);
fail:
	m->m = MGR_MSG_CLAIM_NEXT_ITBL_ERR;
	mgr_send(c, -1, m, e);
	return -1;
}

static int
df(int c, struct mgr_msg *m, struct exlog_err *e)
{
	if (fs_info_read(&m->v.fs_info, e) == -1) {
		exlog(LOG_ERR, e, "%s", __func__);
		m->m = MGR_MSG_FS_INFO_ERR;
	} else
		m->m = MGR_MSG_FS_INFO_OK;

	exlog_zerr(e);

	if (mgr_send(c, -1, m, e) == -1)
		return -1;

	return 0;
}

static void
bg_df()
{
	int               wstatus;
	char              stdout[1024], stderr[1024];
	json_t           *j, *o;
	json_error_t      jerr;
	char             *args[] = {"df", NULL};
	off_t             bytes_total, bytes_used;
	struct fs_info    fs_info;
	struct exlog_err  e = EXLOG_ERR_INITIALIZER;

	if (fs_info_read(&fs_info, &e) == -1) {
		exlog(LOG_ERR, &e, "%s", __func__);
		return;
	}

	if (mgr_spawn(args, &wstatus, stdout, sizeof(stdout),
	    stderr, sizeof(stderr), &e) == -1) {
		exlog(LOG_ERR, &e, "%s", __func__);
		return;
	}

	if ((j = json_loads(stdout, JSON_REJECT_DUPLICATES, &jerr)) == NULL) {
		exlog(LOG_ERR, NULL, "%s: %s", __func__, jerr.text);
		return;
	}

	if ((o = json_object_get(j, "total_bytes")) == NULL) {
		exlog(LOG_ERR, NULL, "%s: \"total_bytes\" missing from JSON",
		    __func__);
		return;
	}
	bytes_total = json_integer_value(o);

	if ((o = json_object_get(j, "used_bytes")) == NULL) {
		exlog(LOG_ERR, NULL, "%s: \"used_bytes\" missing from JSON",
		    __func__);
		return;
	}
	bytes_used = json_integer_value(o);

	fs_info.stats.f_files = fs_config.mdb_map_size /
	    (sizeof(struct slab_key) + sizeof(struct slabdb_val));
	fs_info.stats.f_ffree = fs_info.stats.f_files -
	    mgr_counter_get_mdb_entries();
	fs_info.stats.f_favail = fs_info.stats.f_ffree;

	fs_info.stats.f_blocks = bytes_total / fs_info.stats.f_bsize;
	fs_info.stats.f_bfree = (bytes_total - bytes_used) /
	    fs_info.stats.f_bsize;
	fs_info.stats.f_bavail = fs_info.stats.f_bfree;
	if (clock_gettime(CLOCK_REALTIME, &fs_info.stats_last_update) == -1) {
		exlog_strerror(LOG_ERR, errno, "%s: clock_gettime", __func__);
		return;
	}

	if (fs_info_write(&fs_info, &e) == -1)
		exlog(LOG_ERR, &e, "%s", __func__);
}

static void
bgworker(const char *name, void(*fn)(), int interval_secs, int run_at_exit)
{
	char            title[32];
	struct timespec tp = {interval_secs, 0};
	pid_t           pid;

	if ((pid = fork()) == -1){
		killpg(0, 15);
		err(1, "fork");
	} else if (pid > 0)
		return;

	bzero(title, sizeof(title));
	snprintf(title, sizeof(title), "%s-%s", MGR_PROGNAME, name);
	if (exlog_init(title, dbg_spec, 0) == -1) {
		exlog(LOG_ERR, NULL,
		    "%s: failed to initialize logging", __func__);
		exit(1);
	}

	setproctitle("bgworker: %s", name);
	exlog(LOG_INFO, NULL, "ready");

	while (!shutdown_requested) {
		fn();
		nanosleep(&tp, NULL);
	}
	exlog(LOG_INFO, NULL, "performing last run before exiting");
	if (run_at_exit)
		fn();
	exlog(LOG_INFO, NULL, "exiting");
	exit(0);
}

static void
bg_flush()
{
	char              path[PATH_MAX], outgoing_dir[PATH_MAX];
	DIR              *dir;
	struct dirent    *de;
	size_t            out_bytes;
	int               fd;
	struct exlog_err  e = EXLOG_ERR_INITIALIZER;

	if (snprintf(outgoing_dir, sizeof(outgoing_dir), "%s/%s",
	    fs_config.data_dir, OUTGOING_DIR) >= sizeof(path)) {
		exlog(LOG_ERR, NULL, "%s: outq name too long", __func__);
		return;
	}

	exlog(LOG_DEBUG, NULL, "%s: scanning %s", __func__, outgoing_dir);

	if ((dir = opendir(outgoing_dir)) == NULL) {
		exlog_strerror(LOG_ERR, errno, "%s: opendir %s",
		    __func__, outgoing_dir);
		return;
	}

	while ((de = readdir(dir))) {
		if (de->d_name[0] == '.')
			continue;

		if (snprintf(path, sizeof(path), "%s/%s",
		    outgoing_dir, de->d_name) >= sizeof(path)) {
			exlog(LOG_ERR, NULL, "%s: name too long", __func__);
			goto fail;
		}

		if ((fd = open_wflock(path, O_RDONLY, 0,
		    LOCK_EX|LOCK_NB)) == -1) {
			if (errno != EWOULDBLOCK)
				exlog_strerror(LOG_ERR, errno, "%s: failed "
				    "to open_wflock(): %s", __func__, path);
			continue;
		}

		if (backend_put(path, basename(path), &out_bytes, &e) == -1) {
			exlog(LOG_ERR, &e, "%s", __func__);
			close(fd);
			continue;
		}
		mgr_counter_add(MGR_COUNTER_BACKEND_OUT_BYTES, out_bytes);

		exlog(LOG_INFO, NULL, "%s: backend_put: %s (%lu bytes)",
		    __func__, path, out_bytes);

		if (unlink(path) == -1)
			exlog_strerror(LOG_ERR, errno, "%s: unlink %s",
			    __func__, path);

		if (close(fd) == -1)
			exlog_strerror(LOG_ERR, errno, "%s: close %s",
			    __func__, path);
	}
fail:
	closedir(dir);
}

static void
scrub(const char *path)
{
	struct slab_hdr  hdr;
	int              fd;
	uint64_t         revision;
	uint32_t         header_crc, crc;
	uuid_t           owner;
	struct slab_key  sk;
	struct timespec  last_claimed;
	struct exlog_err e = EXLOG_ERR_INITIALIZER;

	if (slab_parse_path(path, &sk, &e) == -1) {
		exlog(LOG_ERR, &e, "%s", __func__);
		return;
	}

	if (slabdb_get(&sk, OSLAB_NOCREATE, &revision, &header_crc, &owner,
	    &last_claimed, &e) == -1) {
		if (exlog_err_is(&e, EXLOG_MDB, MDB_NOTFOUND)) {
			exlog(LOG_ERR, NULL, "%s: slab %s not found in db; "
			    "unlinking", __func__, path);
			unlink(path);
			return;
		}
		exlog(LOG_ERR, &e, "%s", __func__);
		return;
	}

	if (uuid_compare(owner, instance_id) != 0) {
		exlog(LOG_ERR, NULL, "%s: slab %s is now locally-owned; "
		    "unlinking", __func__, path);
		unlink(path);
		return;
	}

	if ((fd = open_wflock(path, O_RDWR, 0, LOCK_EX|LOCK_NB)) == -1) {
		if (errno != EWOULDBLOCK) {
			exlog_strerror(LOG_ERR, errno, "%s: failed "
			    "to open_wflock(): %s", __func__, path);
		} else {
			exlog(LOG_INFO, NULL, "%s: slab %s is already "
			    "flock()'d; skipping", __func__, path);
		}
		return;
	}

	if (read_x(fd, &hdr, sizeof(hdr)) < sizeof(hdr)) {
		exlog_strerror(LOG_ERR, errno,
		    "%s: short read on slab header", __func__);
		set_fs_error();
		goto end;
	}

	if (hdr.v.f.revision < revision) {
		exlog(LOG_CRIT, NULL, "%s: slab %s has a revision older than "
		    "what is in the database", __func__, path);
		set_fs_error();
		goto end;
	}

	if ((crc = crc32_z(0L, (Bytef *)&hdr, sizeof(hdr))) != header_crc) {
		exlog(LOG_CRIT, NULL, "%s: slab %s has a header CRC that "
		    "differs from the database", __func__, path);
		set_fs_error();
		goto end;
	}

	if (hdr.v.f.flags & SLAB_DIRTY) {
		/*
		 * This slab was improperly unclaimed. Maybe we died
		 * because being able to increment and save to the slabdb?
		 */
		exlog(LOG_WARNING, NULL, "%s: slab %s was dirty despite "
		    "being unclaimed; incrementing revision and sending "
		    "to outgoing now", __func__, path);
		hdr.v.f.revision++;
		if (copy_outgoing_slab(fd, &sk, &hdr, &e) == -1) {
			exlog(LOG_ERR, &e, "%s", __func__);
			goto end;
		}
		hdr.v.f.flags &= ~SLAB_DIRTY;
		if (pwrite_x(fd, &hdr, sizeof(hdr), 0) < sizeof(hdr)) {
			exlog_strerror(LOG_ERR, errno,
			    "%s: short write on slab header", __func__);
			set_fs_error();
			goto end;
		}
		crc = crc32_z(0L, (Bytef *)&hdr, sizeof(hdr));
		if (slabdb_put(&sk, hdr.v.f.revision, crc, instance_id,
		    &hdr.v.f.last_claimed_at, &e) == -1) {
			exlog(LOG_CRIT, &e, "%s: slabdb_put", __func__);
			set_fs_error();
			goto end;
		}
	}
end:
	close(fd);
}

static void
bg_scrubber()
{
	struct exlog_err e = EXLOG_ERR_INITIALIZER;

	if (slab_loop_files(&scrub, &e) == -1)
		exlog(LOG_ERR, &e, "%s", __func__);
}

static int
purge_cmp(const void *a, const void *b)
{
	const struct timespec *t1 = &((struct slabdb_val *)a)->last_claimed;
	const struct timespec *t2 = &((struct slabdb_val *)b)->last_claimed;

	if (t1->tv_sec < t2->tv_sec) {
		return -1;
	} else if (t1->tv_sec > t2->tv_sec) {
		return 1;
	} else {
		if (t1->tv_nsec < t2->tv_nsec)
			return -1;
		else if (t1->tv_nsec > t2->tv_nsec)
			return 1;
	}
	return 0;
}

static void
bg_purge()
{
	int              r, purge_n, fd;
	MDB_txn         *txn;
	MDB_dbi          dbi;
	MDB_cursor      *cursor;
	MDB_val          mk, mv;
	struct statvfs   stv;
	struct stat      st;
	char             path[PATH_MAX];
	struct slab_hdr  hdr;
	struct exlog_err e = EXLOG_ERR_INITIALIZER;
	size_t           purge_entries_sz;
	fsblkcnt_t       used_blocks;

	struct purge_entry {
		struct slabdb_val v;
		struct slab_key   sk;
	} *purge_entries, *p_resized, *p;

	if (statvfs(fs_config.data_dir, &stv) == -1) {
		exlog_strerror(LOG_ERR, errno, "statvfs");
		return;
	}

	if (stv.f_bfree >
	    stv.f_blocks * (100 - fs_config.purge_threshold_pct) / 100) {
		/*
		 * Nothing to do.
		 */
		return;
	}
	used_blocks = stv.f_blocks - stv.f_bfree;

	exlog(LOG_INFO, NULL, "%s: cache use is at %d%% of partition size; "
	    "purging slabs", __func__,
	    (stv.f_blocks - stv.f_bfree) * 100 / stv.f_blocks);

	/*
	 * Slabs can be smaller than their max size, but to put a limit
	 * memory use in this function, let's just purge as many as if
	 * they were full-sized.
	 */
	purge_entries_sz = stv.f_blocks * stv.f_frsize /
	    (fs_config.slab_size + sizeof(struct slab_hdr));
	purge_entries = calloc(purge_entries_sz, sizeof(struct purge_entry));
	if (purge_entries == NULL) {
		exlog_strerror(LOG_ERR, errno, "%s", __func__);
		return;
	}

	if ((r = mdb_txn_begin(mdb, NULL, MDB_RDONLY, &txn))) {
		exlog(LOG_ERR, NULL, "%s: mdb_txn_begin: %s",
		    __func__, mdb_strerror(r));
		goto fail;
	}

	if ((r = mdb_dbi_open(txn, NULL, 0, &dbi))) {
		exlog(LOG_ERR, NULL, "%s: mdb_dbi_open: %s",
		    __func__, mdb_strerror(r));
		mdb_txn_abort(txn);
		goto fail;
	}

	if ((r = mdb_cursor_open(txn, dbi, &cursor))) {
		exlog(LOG_ERR, NULL, "%s: mdb_cursor_open: %s",
		    __func__, mdb_strerror(r));
		mdb_txn_abort(txn);
		goto fail;
	}

	for (p = purge_entries, r = mdb_cursor_get(cursor, &mk, &mv, MDB_FIRST);
	    r != MDB_NOTFOUND;
	    r = mdb_cursor_get(cursor, &mk, &mv, MDB_NEXT)) {
		if (r != 0) {
			exlog(LOG_ERR, NULL, "%s: mdb_cursor_get: %s",
			    __func__, mdb_strerror(r));
			mdb_cursor_close(cursor);
			mdb_txn_abort(txn);
			goto fail;
		}

		if (p - purge_entries >= purge_entries_sz) {
			p_resized = realloc(purge_entries,
			    purge_entries_sz * 2);
			/*
			 * No more memory. Just purge what we have for now.
			 */
			if (p_resized == NULL)
				break;
			purge_entries_sz *= 2;
			p = p_resized + (p - purge_entries);
			purge_entries = p_resized;
		}

		if (uuid_compare(((struct slabdb_val *)mv.mv_data)->owner,
		    instance_id) != 0)
			continue;

		memcpy(&p->sk, mk.mv_data, sizeof(struct slab_key));
		memcpy(&p->v, mv.mv_data, sizeof(struct slabdb_val));

		p++;
	}

	mdb_cursor_close(cursor);
	mdb_txn_abort(txn);

	purge_n = p - purge_entries;
	qsort(purge_entries, purge_n, sizeof(struct purge_entry), &purge_cmp);

	for (p = purge_entries; purge_n > 0; purge_n--, p++) {
		if (slab_path(path, sizeof(path), &p->sk, 0, &e) == -1) {
			exlog(LOG_ERR, &e, "%s", __func__);
			goto fail;
		}

		if ((fd = open_wflock(path, O_RDWR, 0,
		    LOCK_EX|LOCK_NB)) == -1) {
			if (errno != EWOULDBLOCK)
				exlog_strerror(LOG_ERR, errno, "%s: failed "
				    "to open_wflock(): %s", __func__, path);
			continue;
		}

		if (read_x(fd, &hdr, sizeof(hdr)) < sizeof(hdr)) {
			exlog_strerror(LOG_ERR, errno,
			    "%s: short read on slab header", __func__);
			set_fs_error();
			goto fail;
		}

		if (hdr.v.f.last_claimed_at.tv_sec !=
		    p->v.last_claimed.tv_sec ||
		    hdr.v.f.last_claimed_at.tv_nsec !=
		    p->v.last_claimed.tv_nsec) {
			/*
			 * This slab was claimed while we were sorting;
			 * skip it.
			 */
			close(fd);
			continue;
		}

		if (fstat(fd, &st) == -1) {
			close(fd);
			exlog_strerror(LOG_ERR, errno, "%s: fstat", __func__);
			set_fs_error();
			goto fail;
		}

		if (slabdb_put(&p->sk, p->v.revision, p->v.header_crc,
		    uuid_zero, &p->v.last_claimed, &e) == -1) {
			exlog(LOG_ERR, &e, "%s", __func__);
			close(fd);
			continue;
		}

		if (unlink(path) == -1)
			exlog_strerror(LOG_ERR, errno, "%s", __func__);

		close(fd);

		used_blocks -= st.st_blocks;
		if (used_blocks <
		    stv.f_blocks * fs_config.purge_threshold_pct / 100)
			break;
	}

fail:
	free(purge_entries);
	return;
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
		exlog(LOG_ERR, NULL, "failed to initialize logging in worker");
		exit(1);
	}

	setproctitle("worker");
	exlog(LOG_INFO, NULL, "ready", __func__);

	while (!shutdown_requested) {
		if ((c = accept(lsock, NULL, 0)) == -1) {
			switch (errno) {
			case EINTR:
				continue;
			case EMFILE:
				exlog_strerror(LOG_ERR, errno,
				    "%s: accept", __func__);
				sleep(5);
				continue;
			default:
				exlog_strerror(LOG_ERR, errno,
				    "%s: accept", __func__);
				exit(1);
			}
		}

		if (setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &socket_timeout,
		    sizeof(socket_timeout)) == -1) {
			exlog(LOG_ERR, &e, "%s", __func__);
			exlog_zerr(&e);
			continue;
		}

		for (;;) {
			if ((r = mgr_recv(c, &fd, &m, &e)) == -1) {
				if (exlog_err_is(&e, EXLOG_OS, EAGAIN))
					exlog(LOG_NOTICE, NULL,
					    "read timeout on socket %d", c);
				else if (!exlog_err_is(&e, EXLOG_APP,
				    EXLOG_EOF))
					exlog(LOG_ERR, &e, "%s", __func__);
				exlog_zerr(&e);
				close(c);
				break;
			}

			switch (m.m) {
			case MGR_MSG_CLAIM:
				claim(c, &m, &e);
				break;
			case MGR_MSG_UNCLAIM:
				unclaim(c, &m, fd, &e);
				break;
			case MGR_MSG_FS_INFO:
				df(c, &m, &e);
				break;
			case MGR_MSG_SET_FS_ERROR:
				if (set_fs_error() == -1)
					m.m = MGR_MSG_SET_FS_ERROR_ERR;
				else
					m.m = MGR_MSG_SET_FS_ERROR_OK;
				mgr_send(c, -1, &m, &e);
				break;
			case MGR_MSG_CLAIM_NEXT_ITBL:
				claim_next_itbls(c, &m, &e);
				break;
			case MGR_MSG_SND_COUNTERS:
				snd_counters(c, &m, &e);
				break;
			case MGR_MSG_RCV_COUNTERS:
				rcv_counters(c, &m, &e);
				break;
			default:
				exlog(LOG_ERR, NULL, "%s: wrong message %d",
				    __func__, m.m);
				close(c);
				break;
			}
			if (exlog_fail(&e)) {
				exlog(LOG_ERR, &e, "%s", __func__);
				if (e.layer == EXLOG_OS) {
					exlog_zerr(&e);
					close(c);
					break;
				}
			}
			exlog_zerr(&e);
		}
	}
	close(lsock);
	exlog(LOG_INFO, NULL, "exiting");
	exit(0);
}

void
slabdb_status(const struct slab_key *k, const struct slabdb_val *v)
{
	char u[37];

	mgr_counter_incr_mdb_entries();

	uuid_unparse(v->owner, u);
	exlog(LOG_DEBUG, NULL, "%s: found entry k=%lu/%lu, v=%lu/%u/%s",
	    __func__,
	    ((struct slab_key *)k)->ino,
	    ((struct slab_key *)k)->base,
	    ((struct slabdb_val *)v)->revision,
	    ((struct slabdb_val *)v)->header_crc, u);
}

int
main(int argc, char **argv)
{
	char                opt;
	struct              sigaction act;
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
	int                 bgworkers = 1;
	int                 purger_interval = 60;
	int                 scrubber_interval = 3600;
	struct statvfs      stv;
	struct exlog_err    e = EXLOG_ERR_INITIALIZER;
	char                mdb_path[PATH_MAX];
	int                 r;
	struct fs_info      fs_info;


	while ((opt = getopt(argc, argv, "hvd:D:w:W:e:fc:p:s:T:S:P:")) != -1) {
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
			case 'S':
				scrubber_interval = atoi(optarg);
				break;
			case 'P':
				purger_interval = atoi(optarg);
				break;
			default:
				usage();
				exit(1);
		}
	}

	setproctitle_init(argc, argv, environ);

	if (exlog_init(MGR_PROGNAME, dbg_spec, foreground) == -1)
		err(1, "exlog_init");

	config_read();

	if (!foreground) {
		if (daemon(0, 0) == -1)
			err(1, "daemon");
		setproctitle("main");
	}

        if ((pid_f = fopen(pidfile_path, "w")) == NULL) {
		exlog_strerror(LOG_ERR, errno, "fopen");
		exit(1);
        }
        if (fprintf(pid_f, "%d\n", getpid()) == -1) {
		exlog_strerror(LOG_ERR, errno, "fprintf");
                exit(1);
        }
        fclose(pid_f);

	if (geteuid() == 0) {
		if ((gr = getgrnam(unpriv_group)) == NULL) {
			exlog_strerror(LOG_ERR, errno,
			    "Group %s not found in group database",
			    unpriv_group);
			exit(1);
		}
		if (setgid(gr->gr_gid) == -1) {
			exlog_strerror(LOG_ERR, errno, "setgid");
			exit(1);
		}
		if (setegid(gr->gr_gid) == -1) {
			exlog_strerror(LOG_ERR, errno, "setegid");
			exit(1);
		}

		if ((pw = getpwnam(unpriv_user)) == NULL) {
			exlog_strerror(LOG_ERR, errno,
			    "User %s not found in users database", unpriv_user);
			exit(1);
		}
		if (setuid(pw->pw_uid) == -1) {
			exlog_strerror(LOG_ERR, errno, "setuid");
			exit(1);
		}
		if (seteuid(pw->pw_uid) == -1) {
			exlog_strerror(LOG_ERR, errno, "seteuid");
			exit(1);
		}
	}

	if (access(fs_config.data_dir, R_OK|X_OK) == -1) {
		exlog_strerror(LOG_ERR, errno, "access: %s", fs_config.data_dir);
		exit(1);
	}
	if (access(fs_config.mgr_exec, X_OK) == -1) {
		exlog_strerror(LOG_ERR, errno, "access: %s", fs_config.mgr_exec);
		exit(1);
	}

	if (statvfs(fs_config.data_dir, &stv) == -1) {
		exlog_strerror(LOG_ERR, errno, "statvfs");
		exit(1);
	}

	uuid_clear(uuid_zero);

	exlog(LOG_INFO, NULL, "%s: cache size is %llu bytes (%lu slabs)",
	    __func__, stv.f_blocks * stv.f_frsize,
	    stv.f_blocks * stv.f_frsize /
	    (fs_config.slab_size + sizeof(struct slab_hdr)));

	if (snprintf(mdb_path, sizeof(mdb_path), "%s/%s", fs_config.data_dir,
            DEFAULT_MDB_NAME) >= sizeof(mdb_path)) {
                exlog(LOG_ERR, NULL, "%s: mdb name too long", __func__);
		exit(1);
        }

	exlog(LOG_INFO, NULL, "%s: slabdb maximum map size is %u; "
	    "slabdb entries are %u bytes each", __func__, DEFAULT_MDB_MAPSIZE,
	    sizeof(struct slab_key) + sizeof(struct slabdb_val));

	exlog(LOG_INFO, NULL, "%s: slabdb capacity is %u entries; "
	    "total filesystem capacity is %.2f TiB", __func__,
	    DEFAULT_MDB_MAPSIZE /
	    (sizeof(struct slab_key) + sizeof(struct slabdb_val)),
	    (double)fs_config.slab_size * (DEFAULT_MDB_MAPSIZE /
	    (sizeof(struct slab_key) + sizeof(struct slabdb_val))) /
	    (1024ULL * 1024ULL * 1024ULL * 1024ULL));

	if ((r = mdb_env_create(&mdb)))
		errx(1, "mdb_env_create: %s", mdb_strerror(r));

	if ((r = mdb_env_set_mapsize(mdb, DEFAULT_MDB_MAPSIZE)))
		errx(1, "mdb_env_set_mapsize: %s", mdb_strerror(r));

	if ((r = mdb_env_open(mdb, mdb_path, MDB_NOSUBDIR, 0644)))
		errx(1, "mdb_env_open: %s", mdb_strerror(r));

	if (slabdb_loop(&slabdb_status, &e) == -1) {
		exlog(LOG_ERR, &e, "%s", __func__);
		exit(1);
	}

	if (fs_info_open(&fs_info, &e) == -1) {
		exlog(LOG_ERR, &e, "%s", __func__);
		exit(1);
	}
	uuid_copy(instance_id, fs_info.instance_id);

	if (slab_make_dirs(&e) == -1) {
		exlog(LOG_ERR, &e, "%s", __func__);
		exit(1);
	}

	if ((lsock = socket(AF_LOCAL, SOCK_STREAM, 0)) == -1) {
		exlog_strerror(LOG_ERR, errno, "socket");
		exit(1);
	}
	unlink(fs_config.mgr_sock_path);

	bzero(&saddr, sizeof(saddr));
	saddr.sun_family = AF_LOCAL;
	strlcpy(saddr.sun_path, fs_config.mgr_sock_path,
	    sizeof(saddr.sun_path));

	if (bind(lsock, (struct sockaddr *)&saddr, SUN_LEN(&saddr)) == -1) {
		exlog_strerror(LOG_ERR, errno, "bind");
		exit(1);
	}

	if (listen(lsock, 64) == -1) {
		exlog_strerror(LOG_ERR, errno, "listen");
		exit(1);
	}

	if ((mgr_counters = mmap(NULL, sizeof(struct mgr_counters),
	    PROT_READ|PROT_WRITE, MAP_ANON|MAP_SHARED, -1, 0)) == MAP_FAILED) {
		exlog_strerror(LOG_ERR, errno, "mmap");
		exit(1);
	}

	/* Not sure MAP_ANON initializes to zero on BSD */
	bzero(mgr_counters, sizeof(struct mgr_counters));

	if (sem_init(&mgr_counters->sem, 1, 1) == -1) {
		exlog_strerror(LOG_ERR, errno, "sem_init");
		exit(1);
	}

	/*
	 * Because we use socket timeouts, it's possible that we may
	 * end up trying to read/write on a closed socket, which would
	 * then cause a SIGPIPE. It's better to ignore this signal and
	 * handle EPIPE where needed.
	 */
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	act.sa_handler = SIG_IGN;
	if (sigaction(SIGPIPE, &act, NULL) == -1)
		exlog_strerror(LOG_ERR, errno, "sigaction");

	act.sa_handler = &worker_handle_sig;
	if (sigaction(SIGINT, &act, NULL) == -1 ||
	    sigaction(SIGTERM, &act, NULL) == -1) {
		exlog_strerror(LOG_ERR, errno, "sigaction");
	}

	for (n = 0; n < workers; n++) {
		switch (fork()) {
		case -1:
			killpg(0, 15);
			err(1, "fork");
		case 0:
			worker(lsock);
			/* Never reached */
			exit(1);
		default:
			/* Nothing */
			break;
		}
	}

	bgworker("df", &bg_df, 60, 1);
	workers++;

	if (scrubber_interval) {
		bgworker("scrubber", &bg_scrubber, scrubber_interval, 1);
		workers++;
	}
	if (purger_interval) {
		bgworker("purge", &bg_purge, purger_interval, 1);
		workers++;
	}

	for (n = 0; n < bgworkers; n++) {
		bgworker("flush", &bg_flush, 60, 1);
		workers++;
	}

	act.sa_handler = &handle_sig;
	if (sigaction(SIGINT, &act, NULL) == -1 ||
	    sigaction(SIGTERM, &act, NULL) == -1) {
		exlog_strerror(LOG_ERR, errno, "sigaction");
	}

	for (n = 0; n < workers; ) {
		if (wait(NULL) == -1) {
			if (errno == EINTR)
				continue;
			err(1, "wait");
		}
		n++;
	}

	mdb_env_close(mdb);

	if (fs_info_read(&fs_info, &e) == -1) {
		exlog(LOG_CRIT, &e, "%s", __func__);
		exit(1);
	} else {
		if (!fs_info.error)
			fs_info.clean = 1;

		if (fs_info_write(&fs_info, &e) == -1) {
			exlog(LOG_ERR, &e, "%s", __func__);
			exit(1);
		}
	}

	exlog(LOG_INFO, NULL, "exiting");
	return 0;
}
