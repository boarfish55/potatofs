/*
 *  Copyright (C) 2020-2025 Pascal Lalonde <plalonde@overnet.ca>
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
#include <uuid/uuid.h>
#include <zlib.h>
#include "config.h"
#include "fs_info.h"
#include "mgr.h"
#include "slabdb.h"
#include "slabs.h"

struct mgr_shared {
	sem_t    sem;
	uint64_t counters[COUNTER_LAST];
	uint64_t mgr_counters[MGR_COUNTER_LAST];
	int      shutdown_requested;
	int      offline;
};

struct fs_usage {
	struct statvfs stv;
	fsblkcnt_t     used_blocks;
};

struct delayed_truncates {
	struct slab_key sk[128];
	int             count;
};

static int    mgr_shared_lock();
static void   mgr_shared_unlock();
static time_t shutdown_requested();
static int    shutdown_now();
static int    set_fs_error();
static void   mgr_counter_add(int, uint64_t);
static int    snd_counters(int, struct mgr_msg *, struct xerr *);
static int    rcv_counters(int, struct mgr_msg *, struct xerr *);
static int    mgr_spawn(char *const[], int *, char *, size_t, char *, size_t,
		  char *, size_t, int, struct xerr *);
static int    copy_outgoing_slab(int, struct slab_key *,
                  struct slab_hdr *, struct xerr *);
static int    unclaim(int, struct mgr_msg *, int, struct xerr *);
static int    truncate_slab(int, struct mgr_msg *, struct xerr *);
static void   backend_hint(struct slab_key *);
static int    backend_get(const char *, const char *, size_t *,
                  struct slab_key *, uint32_t, struct xerr *);
static int    backend_put(const char *, const char *, size_t *,
                  const struct slab_key *, struct xerr *);
static int    check_slab_header(struct slab_hdr *, uint32_t,
                  uint64_t, struct xerr *);
static int    copy_incoming_slab(int, int, uint32_t, uint64_t, struct xerr *);
static int    claim(struct slab_key *, int *, uint32_t, struct xerr *);
static int    client_claim(int, struct mgr_msg *, struct xerr *);
static int    claim_next_itbls(int, struct mgr_msg *, struct xerr *);
static int    set_shutdown_requested(time_t);
static int    do_shutdown(int, struct mgr_msg *, struct xerr *);
static int    info(int, struct mgr_msg *, struct xerr *);
static void   bg_df();
static int    bgworker(const char *, void(*)(), int);
static void   bg_flush();
static void   scrub_local_slab(const char *path);
static int    delayed_truncate(const struct slab_key *,
                  const struct slabdb_val *, void *);
static void   scrub();
static int    client_scrub(int, struct mgr_msg *, struct xerr *);
static int    client_flush(int, struct mgr_msg *, struct xerr *);
static int    client_purge_all(int, struct mgr_msg *, struct xerr *);
static int    client_offline(int, struct mgr_msg *, struct xerr *);
static int    client_get_offline(int, struct mgr_msg *, struct xerr *);
static void   purge_all();
static int    purge(const struct slab_key *, const struct slabdb_val *, void *);
static void   bg_purge();
static int    worker(int);

struct timeval     socket_timeout = {300, 0};
uuid_t             instance_id;
struct mgr_shared *mgr_shared;
const uint32_t     flock_timeout = 10;
int                pid_fd;

static int
mgr_shared_lock()
{
again:
	if (sem_wait(&mgr_shared->sem) == -1) {
		if (errno == EINTR)
			goto again;
		xlog_strerror(LOG_ERR, errno, "sem_wait");
		return -1;
	}
	return 0;
}

static void
mgr_shared_unlock()
{
	if (sem_post(&mgr_shared->sem) == -1)
		xlog_strerror(LOG_CRIT, errno, "sem_post");
}

static time_t
shutdown_requested()
{
	time_t sr;

	if (mgr_shared_lock() == -1)
		return 0;
	sr = mgr_shared->shutdown_requested;
	mgr_shared_unlock();
	return sr;
}

static int
shutdown_now()
{
	time_t          sr;
	struct timespec now;

	if (mgr_shared_lock() == -1)
		return 0;
	sr = mgr_shared->shutdown_requested;
	mgr_shared_unlock();

	clock_gettime_x(CLOCK_REALTIME, &now);
	return (sr > 0 && now.tv_sec > sr) ? 1 : 0;
}

static int
set_fs_error()
{
	struct fs_info fs_info;
	struct xerr    e = XLOG_ERR_INITIALIZER;

	if (fs_info_read(&fs_info, &e) == -1) {
		xlog(LOG_CRIT, &e, "%s", __func__);
		return -1;
	}

	// TODO: We'll need to inform the fs that we ran into an error.
	//       Eventually the fs will provide a way for us to send it
	//       messages directly.
	fs_info.error = 1;

	if (fs_info_write(&fs_info, &e) == -1) {
		xlog(LOG_CRIT, &e, "%s", __func__);
		return -1;
	}

	return 0;
}

static void
mgr_counter_add(int c, uint64_t v)
{
	if (mgr_shared_lock() == -1)
		return;
	mgr_shared->mgr_counters[c] += v;
	mgr_shared_unlock();
}

static int
snd_counters(int c, struct mgr_msg *m, struct xerr *e)
{
	int i;
	if (mgr_shared_lock() == -1) {
		XERRF(&m->v.err, XLOG_ERRNO, errno, "mgr_shared_lock");
		goto fail;
	}

	for (i = 0; i < COUNTER_LAST; i++)
		mgr_shared->counters[i] = m->v.snd_counters.c[i];

	mgr_shared_unlock();

	m->m = MGR_MSG_SND_COUNTERS_OK;
	return mgr_send(c, -1, m, e);
fail:
	m->m = MGR_MSG_SND_COUNTERS_ERR;
	return mgr_send(c, -1, m, e);
}

static int
rcv_counters(int c, struct mgr_msg *m, struct xerr *e)
{
	int i;
	if (mgr_shared_lock() == -1) {
		XERRF(&m->v.err, XLOG_ERRNO, errno, "mgr_shared_lock");
		goto fail;
	}

	for (i = 0; i < COUNTER_LAST; i++)
		m->v.rcv_counters.c[i] = mgr_shared->counters[i];

	for (i = 0; i < MGR_COUNTER_LAST; i++)
		m->v.rcv_counters.mgr_c[i] = mgr_shared->mgr_counters[i];

	mgr_shared_unlock();

	m->m = MGR_MSG_RCV_COUNTERS_OK;
	return mgr_send(c, -1, m, e);
fail:
	m->m = MGR_MSG_RCV_COUNTERS_ERR;
	return mgr_send(c, -1, m, e);
}

static int
mgr_spawn(char *const argv[], int *wstatus, char *stdin, size_t stdin_len,
    char *stdout, size_t stdout_len, char *stderr, size_t stderr_len,
    int timeout_seconds, struct xerr *e)
{
	pid_t            pid, wpid;
	int              p_in[2];
	int              p_out[2];
	int              p_err[2];
	struct pollfd    fds[3];
	int              stdin_closed = 0;
	int              stdout_closed = 0;
	int              stderr_closed = 0;
	int              nfds, i;
	ssize_t          r;
	int              poll_r;
	size_t           stdout_r, stderr_r, stdin_w;
	struct timespec  tp;

	if (pipe(p_in) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "pipe");

	if (pipe(p_out) == -1) {
		CLOSE_X(p_in[0]);
		CLOSE_X(p_in[1]);
		return XERRF(e, XLOG_ERRNO, errno, "pipe");
	}

	if (pipe(p_err) == -1) {
		CLOSE_X(p_in[0]);
		CLOSE_X(p_in[1]);
		CLOSE_X(p_out[0]);
		CLOSE_X(p_out[1]);
		return XERRF(e, XLOG_ERRNO, errno, "pipe");
	}

	if ((pid = fork()) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "fork");
		CLOSE_X(p_in[0]);
		CLOSE_X(p_in[1]);
		CLOSE_X(p_out[0]);
		CLOSE_X(p_out[1]);
		CLOSE_X(p_err[0]);
		CLOSE_X(p_err[1]);
		return -1;
	} else if (pid == 0) {
		CLOSE_X(p_in[1]);
		CLOSE_X(p_out[0]);
		CLOSE_X(p_err[0]);
		if (p_in[0] != STDIN_FILENO) {
			if (dup2(p_in[0], STDIN_FILENO) == -1) {
				XERRF(e, XLOG_ERRNO, errno, "dup2");
				_exit(1);
			}
			CLOSE_X(p_in[0]);
		}
		if (p_out[1] != STDOUT_FILENO) {
			if (dup2(p_out[1], STDOUT_FILENO) == -1) {
				XERRF(e, XLOG_ERRNO, errno, "dup2");
				_exit(1);
			}
			CLOSE_X(p_out[1]);
		}
		if (p_err[1] != STDERR_FILENO) {
			if (dup2(p_err[1], STDERR_FILENO) == -1) {
				XERRF(e, XLOG_ERRNO, errno, "dup2");
				_exit(1);
			}
			CLOSE_X(p_err[1]);
		}

		if (chdir("/") == -1) {
			XERRF(e, XLOG_ERRNO, errno, "chdir");
			_exit(1);
		}

		if (setenv("POTATOFS_BACKEND_CONFIG",
		    fs_config.mgr_exec_config, 1) == -1) {
			XERRF(e, XLOG_ERRNO, errno, "chdir");
			_exit(1);
		}

		if (execv(argv[0], argv) == -1) {
			XERRF(e, XLOG_ERRNO, errno, "execv: %s", argv[0]);
			_exit(1);
		}
	}

	CLOSE_X(p_in[0]);
	CLOSE_X(p_out[1]);
	CLOSE_X(p_err[1]);

	/*
	 * Make room for \n.
	 */
	stdout_len--;
	stderr_len--;

	stdin_w = 0;
	stdout_r = 0;
	stderr_r = 0;
	*wstatus = 2;
	while (!stdin_closed || !stdout_closed || !stderr_closed) {
		nfds = 0;
		if (!stdin_closed) {
			fds[nfds].fd = p_in[1];
			fds[nfds++].events = POLLOUT;
		}
		if (!stdout_closed) {
			fds[nfds].fd = p_out[0];
			fds[nfds++].events = POLLIN;
		}
		if (!stderr_closed) {
			fds[nfds].fd = p_err[0];
			fds[nfds++].events = POLLIN;
		}

		if ((poll_r = poll(fds, nfds,
		    timeout_seconds * 1000)) == -1) {
			XERRF(e, XLOG_ERRNO, errno, "poll");
			CLOSE_X(p_in[1]);
			CLOSE_X(p_out[0]);
			CLOSE_X(p_err[0]);
			return -1;
		}

		if (poll_r == 0) {
			xlog(LOG_ERR, NULL,
			    "%s: child %d stalled; killing it now",
			    __func__, pid);
			kill(pid, 9);
			if (p_in[1] != -1)
				CLOSE_X(p_in[1]);
			if (p_out[0] != -1)
				CLOSE_X(p_out[0]);
			if (p_err[0] != -1)
				CLOSE_X(p_err[0]);
			stdout[stdout_r] = '\0';
			stderr[stderr_r] = '\0';
			for (i = 1, wpid = 0; i < 4 && wpid == 0; i++) {
				tp.tv_sec = 0;
				tp.tv_nsec = i * 10000000;
				nanosleep(&tp, NULL);
				if ((wpid = waitpid(pid, NULL,
				    WNOHANG)) == -1) {
					XERRF(e, XLOG_ERRNO, errno, "waitpid");
					return -1;
				}
			}
			if (wpid == 0)
				xlog(LOG_ERR, NULL,
				    "%s: waitpid: child not waitable, we "
				    "probably have a zombie around now",
				    __func__);
			*wstatus = 137;
			return XERRF(e, XLOG_APP, XLOG_BETIMEOUT,
			    "command timed out after %d seconds; aborting",
			    timeout_seconds);
		}

		while (nfds-- > 0) {
			if (fds[nfds].revents & POLLERR) {
				if (fds[nfds].fd == p_in[1]) {
					stdin_closed = 1;
				} else if (fds[nfds].fd == p_out[0]) {
					stdout_closed = 1;
				} else if (fds[nfds].fd ==  p_err[0]) {
					stderr_closed = 1;
				}
				xlog(LOG_ERR, NULL,"%s: file descriptor %d "
				    "closed unexpectedly", __func__,
				    fds[nfds].fd);
				continue;
			}

			if (!(fds[nfds].revents & (POLLIN|POLLOUT|POLLHUP)))
				continue;

			r = -1;
			if (fds[nfds].fd == p_in[1]) {
				r = write(p_in[1], stdin + stdin_w,
				    stdin_len - stdin_w);
				if (r == -1) {
					xlog_strerror(LOG_ERR, errno,
					    "%s: write", __func__);
					stdin_closed = 1;
					CLOSE_X(p_in[1]);
					p_in[1] = -1;
				} else {
					stdin_w += r;
					if (stdin_w == stdin_len) {
						stdin_closed = 1;
						CLOSE_X(p_in[1]);
						p_in[1] = -1;
					}
				}
			} else if (fds[nfds].fd == p_out[0]) {
				r = read(p_out[0], stdout + stdout_r,
				    stdout_len - stdout_r);
				if (r > 0) {
					stdout_r += r;
				} else {
					stdout_closed = 1;
					CLOSE_X(p_out[0]);
					p_out[0] = -1;
				}
			} else if (fds[nfds].fd == p_err[0]) {
				r = read(p_err[0], stderr + stderr_r,
				    stderr_len - stderr_r);
				if (r > 0) {
					stderr_r += r;
				} else {
					stderr_closed = 1;
					CLOSE_X(p_err[0]);
					p_err[0] = -1;
				}
			}
			if (r == -1)
				xlog(LOG_ERR, NULL,
				    "file descriptor %d did not match any "
				    "poll flags", fds[nfds].fd);
		}
	}
	stdout[stdout_r] = '\0';
	stderr[stderr_r] = '\0';
	if (waitpid(pid, wstatus, 0) == -1) {
		*wstatus = 2;
		XERRF(e, XLOG_ERRNO, errno, "waitpid");
		return -1;
	}

	return 0;
}

/*
 * Modifies the checksum and flags fields in 'hdr'.
 */
static int
copy_outgoing_slab(int fd, struct slab_key *sk, struct slab_hdr *hdr,
    struct xerr *e)
{
	int             dst_fd;
	char            dst[PATH_MAX], name[NAME_MAX + 1];
	char            buf[8192];
	struct slab_hdr dst_hdr;
	ssize_t         r;

	if (slab_path(name, sizeof(name), sk, 1, e) == -1)
		return -1;

	if (snprintf(dst, sizeof(dst), "%s/%s/%s", fs_config.data_dir,
	    OUTGOING_DIR, name) >= sizeof(dst))
		return XERRF(e, XLOG_APP, XLOG_NAMETOOLONG,
		    "outgoing slab name too long");

	if ((dst_fd = open_wflock(dst, O_CREAT|O_RDWR|O_TRUNC, 0600,
	    LOCK_EX, flock_timeout)) == -1) {
		if (errno == EWOULDBLOCK)
			return XERRF(e, XLOG_APP, XLOG_BUSY,
			    "open_wflock() timed out after multiple "
			    "retries for slab %s; this should not happen "
			    "unless something is stuck trying to send to the "
			    "backend.", dst);
		return XERRF(e, XLOG_ERRNO, errno, "open_wflock: slab %s", dst);
	}

	/* Make room for the header we're about to fill in. */
	if (lseek(dst_fd, sizeof(struct slab_hdr), SEEK_SET) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "lseek");
		goto fail;
	}

	if (lseek(fd, sizeof(struct slab_hdr), SEEK_SET) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "lseek");
		goto fail;
	}

	memcpy(&dst_hdr, hdr, sizeof(struct slab_hdr));
	dst_hdr.v.f.checksum = crc32_z(0L, Z_NULL, 0);

	while ((r = read(fd, buf, sizeof(buf)))) {
		if (r == -1) {
			if (errno == EINTR)
				continue;
			XERRF(e, XLOG_ERRNO, errno, "read");
			goto fail;
		}

		dst_hdr.v.f.checksum = crc32_z(dst_hdr.v.f.checksum,
		    (unsigned char *)buf, r);

		r = write_x(dst_fd, buf, r);
		if (r == -1) {
			if (errno == ENOSPC) {
				XERRF(e, XLOG_ERRNO, errno,
				    "%s: ran out of space while copying "
				    "slab %s, we can retry later",
				    __func__, dst);
			} else
				XERRF(e, XLOG_ERRNO, errno, "write");
			goto fail;
		}
	}

	uuid_copy(dst_hdr.v.f.last_owner, instance_id);
	dst_hdr.v.f.revision++;
	dst_hdr.v.f.flags &= ~SLAB_DIRTY;

	if (pwrite_x(dst_fd, &dst_hdr, sizeof(dst_hdr), 0) < sizeof(dst_hdr)) {
		XERRF(e, XLOG_ERRNO, errno, "short write on slab header");
		goto fail;
	}
	memcpy(hdr, &dst_hdr, sizeof(dst_hdr));
	CLOSE_X(dst_fd);
	return 0;
fail:
	if (unlink(dst) == -1)
		xlog_strerror(LOG_ERR, errno, "%s: unlink dst", __func__);
	CLOSE_X(dst_fd);
	return -1;
}

static int
unclaim(int c, struct mgr_msg *m, int fd, struct xerr *e)
{
	struct slab_hdr   hdr;
	char              src[PATH_MAX];
	int               purge = 0;
	struct statvfs    stv;
	struct slabdb_val v;
	uint32_t          put_flags;

	if (slab_key_valid(&m->v.unclaim.key, e) == -1) {
		xerr_prepend(e, __func__);
		goto fail;
	}

	if (pread_x(fd, &hdr, sizeof(hdr), 0) < sizeof(hdr)) {
		XERRF(e, XLOG_ERRNO, errno, "short read on slab header");
		goto fail;
	}

	if (statvfs(fs_config.data_dir, &stv) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "statvfs");
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
		if (copy_outgoing_slab(fd, &m->v.unclaim.key, &hdr, e) == -1) {
			if (xerr_is(e, XLOG_APP, XLOG_BUSY)) {
				xlog(LOG_WARNING, e, "%s: slab "
				    "(ino=%lu / base=%lu) is "
				    "being locked for a long time; is the "
				    "backend responsive? Continuing anyway "
				    "without sending to outgoing; "
				    "the scrubber will pick it up later",
				    __func__, m->v.unclaim.key.ino,
				    m->v.unclaim.key.base);
				xerrz(e);
				goto end;
			} else if (xerr_is(e, XLOG_ERRNO, ENOSPC)) {
				xlog(LOG_WARNING, e, __func__);
				xerrz(e);
				goto end;
			} else {
				xlog(LOG_WARNING, e, __func__);
				XERR_PREPENDFN(e);
				goto fail;
			}
		}

		if (pwrite_x(fd, &hdr, sizeof(hdr), 0) < sizeof(hdr)) {
			XERRF(e, XLOG_ERRNO, errno,
			    "short write on slab header");
			goto fail;
		}
	}

	bzero(&v, sizeof(v));
	v.revision = hdr.v.f.revision;
	v.header_crc = crc32_z(0L, (Bytef *)&hdr, sizeof(hdr));
	uuid_clear(v.owner);

	put_flags = SLABDB_PUT_REVISION|SLABDB_PUT_HEADER_CRC|SLABDB_PUT_OWNER;

	if (purge) {
		put_flags |= SLABDB_PUT_LOCAL;
		v.flags &= ~SLABDB_FLAG_LOCAL;
	}

	xlog_dbg(XLOG_MGR, "%s: inode=%lu, base=%ld, revision=%lu, "
	    "header_crc=%u, crc=%u", __func__,
	    m->v.unclaim.key.ino, m->v.unclaim.key.base,
	    hdr.v.f.revision, v.header_crc, hdr.v.f.checksum);

	if (slabdb_put(&m->v.unclaim.key, &v, put_flags, e) == -1) {
		set_fs_error();
		XERR_PREPENDFN(e);
		goto fail;
	}

	/*
	 * Only purge once we've successfully saved the new revision and
	 * checksum info to the slabdb. Otherwise we need to keep the
	 * slab, and the slab ownership.
	 */
	if (purge) {
		if (slab_path(src, sizeof(src),
		    &m->v.unclaim.key, 0, e) == -1) {
			XERR_PREPENDFN(e);
			goto fail;
		}

		if (unlink(src) == -1) {
			xlog_strerror(LOG_ERR, errno,
			    "%s: unlink src %s", __func__, src);
		} else {
			xlog(LOG_INFO, NULL, "%s: purged slab %s "
			    "(revision=%lu, header_crc=%u, crc=%u)",
			    __func__, src, hdr.v.f.revision, v.header_crc,
			    hdr.v.f.checksum);
			mgr_counter_add(MGR_COUNTER_SLABS_PURGED, 1);
		}
	}

end:
	CLOSE_X(fd);

	m->m = MGR_MSG_UNCLAIM_OK;
	return mgr_send(c, -1, m, e);
fail:
	xlog(LOG_ERR, e, NULL);
	memcpy(&m->v.err, e, sizeof(struct xerr));
	m->m = MGR_MSG_UNCLAIM_ERR;
	CLOSE_X(fd);
	return mgr_send(c, -1, m, xerrz(e));
}

static int
truncate_slab(int c, struct mgr_msg *m, struct xerr *e)
{
	struct slabdb_val v;
	if (slab_key_valid(&m->v.truncate.key, e) == -1) {
		XERR_PREPENDFN(e);
		goto fail;
	}

	bzero(&v, sizeof(v));
	v.flags |= SLABDB_FLAG_TRUNCATE;
	v.truncate_offset = m->v.truncate.offset;
	if (slabdb_put(&m->v.truncate.key, &v, SLABDB_PUT_TRUNCATE, e) == -1) {
		if (xerr_is(e, XLOG_APP, XLOG_NOSLAB)) {
			m->m = MGR_MSG_TRUNCATE_NOENT;
		} else {
			XERR_PREPENDFN(e);
			set_fs_error();
			goto fail;
		}
	} else {
		xlog_dbg(XLOG_MGR,
		    "%s: slab sk=%lu/%lu marked for delayed truncation",
		    __func__, m->v.truncate.key.ino, m->v.truncate.key.base);
		m->m = MGR_MSG_TRUNCATE_OK;
	}

	return mgr_send(c, -1, m, xerrz(e));
fail:
	xlog(LOG_ERR, e, NULL);
	memcpy(&m->v.err, e, sizeof(struct xerr));
	m->m = MGR_MSG_TRUNCATE_ERR;
	return mgr_send(c, -1, m, xerrz(e));
}

static void
backend_hint(struct slab_key *sk)
{
	char         *args[] = {(char *)fs_config.mgr_exec, "hint", NULL};
	size_t        len;
	char          stdin[LINE_MAX], stdout[1024], stderr[1024];
	struct xerr   e;
	int           wstatus;
	json_t       *j, *o;
	json_error_t  jerr;

	mgr_counter_add(MGR_COUNTER_BACKEND_HINTS, 1);

	len = snprintf(stdin, sizeof(stdin),
	    "{\"inode\": %lu, \"base\": %ld}", sk->ino, sk->base);

	if (len >= sizeof(stdin)) {
		xlog(LOG_ERR, NULL, "%s: incoming JSON too long", __func__);
		_exit(1);
	}

	if (mgr_spawn(args, &wstatus, stdin, len,
	    stdout, sizeof(stdout), stderr, sizeof(stderr),
	    fs_config.backend_hint_timeout, xerrz(&e)) == -1) {
		xlog(LOG_ERR, &e, __func__);
		_exit(1);
	}

	if (WIFSIGNALED(wstatus)) {
		xlog(LOG_ERR, NULL,
		    "%s: killed by signal %d", __func__, WTERMSIG(wstatus));
		_exit(1);
	}

	if (WEXITSTATUS(wstatus) > 2) {
		xlog(LOG_ERR, NULL,
		    "%s: resulted in an undefined error (exit %d)", __func__,
		    WTERMSIG(wstatus));
		_exit(1);
	}

	/* Bad invocation error, there is no JSON to read here. */
	if (WEXITSTATUS(wstatus) == 2) {
		xlog(LOG_ERR, NULL,
		    "%s: reported bad invocation (exit 2)", __func__);
		_exit(1);
	}

	if ((j = json_loads(stdout, JSON_REJECT_DUPLICATES, &jerr)) == NULL) {
		xlog(LOG_ERR, NULL, "%s: %s", __func__, jerr.text);
		_exit(1);
	}

	if ((o = json_object_get(j, "status")) == NULL) {
		xlog(LOG_ERR, NULL,
		    "%s: \"status\" missing from backend JSON output",
		    __func__);
		_exit(1);
	}

	if (strcmp(json_string_value(o), "OK") != 0) {
		if ((o = json_object_get(j, "msg")) == NULL) {
			xlog(LOG_ERR, NULL,
			    "%s: \"msg\" missing from JSON", __func__);
			json_decref(j);
			_exit(1);
		}

		xlog(LOG_ERR, NULL, "%s: failed: %s",
		    __func__, json_string_value(o));
		json_decref(j);
		_exit(1);
	}

	if (WEXITSTATUS(wstatus) == 1) {
		xlog(LOG_ERR, NULL,
		    "%s: exit 1; backend produced no error message", __func__);
		json_decref(j);
		_exit(1);
	}

	json_decref(j);
	_exit(0);
}

static int
backend_get(const char *local_path, const char *backend_name,
    size_t *in_bytes, struct slab_key *sk, uint32_t oflags, struct xerr *e)
{
	char            *args[] = {(char *)fs_config.mgr_exec, "get", NULL};
	int              wstatus;
	char             stdout[1024], stderr[1024];
	json_t          *j = NULL, *o;
	json_error_t     jerr;
	size_t           len;
	char             stdin[LINE_MAX];
	struct timespec  start, end;
	time_t           delta_ns;

	mgr_counter_add(MGR_COUNTER_BACKEND_GETS, 1);

	len = snprintf(stdin, sizeof(stdin),
	    "{\"backend_name\": \"%s\", "
	    "\"local_path\": \"%s\", "
	    "\"inode\": %lu, "
	    "\"base\": %ld, "
	    "\"is_preload\": %s}",
	    backend_name, local_path, sk->ino, sk->base,
	    ((oflags & OSLAB_NOHINT) ? "true" : "false"));

	if (len >= sizeof(stdin))
		return XERRF(e, XLOG_APP, XLOG_NAMETOOLONG,
		    "incoming JSON too long");

	clock_gettime_x(CLOCK_REALTIME, &start);
	if (mgr_spawn(args, &wstatus, stdin, len, stdout,
	    sizeof(stdout), stderr, sizeof(stderr),
	    fs_config.backend_get_timeout, e) == -1)
		return -1;
	clock_gettime_x(CLOCK_REALTIME, &end);
	delta_ns = ((end.tv_sec * 1000000000) + end.tv_nsec) -
	    ((start.tv_sec * 1000000000) + start.tv_nsec);
	xlog(LOG_NOTICE, NULL, "%s: sk=%lu/%ld completed in %ld.%09ld seconds",
	    __func__, sk->ino, sk->base, delta_ns / 1000000000,
	    delta_ns % 1000000000);

	if (WIFSIGNALED(wstatus)) {
		XERRF(e, XLOG_APP, XLOG_BEERROR,
		    "\"get\" killed by signal %d", WTERMSIG(wstatus));
		goto fail;
	}

	if (WEXITSTATUS(wstatus) > 2) {
		XERRF(e, XLOG_APP, XLOG_BEERROR,
		    "\"get\" resulted in an undefined error (exit %d)",
		    WEXITSTATUS(wstatus));
		goto fail;
	}

	/* Bad invocation error, there is no JSON to read here. */
	if (WEXITSTATUS(wstatus) == 2) {
		XERRF(e, XLOG_APP, XLOG_BEERROR,
		    "\"get\" reported bad invocation (exit 2)");
		goto fail;
	}

	if ((j = json_loads(stdout, JSON_REJECT_DUPLICATES, &jerr)) == NULL) {
		XERRF(e, XLOG_APP, XLOG_BEERROR, jerr.text);
		goto fail;
	}

	if ((o = json_object_get(j, "status")) == NULL) {
		XERRF(e, XLOG_APP, XLOG_BEERROR,
		    "\"status\" missing from backend JSON output");
		goto fail;
	}

	if (strcmp(json_string_value(o), "ERR_NOSLAB") == 0) {
		XERRF(e, XLOG_APP, XLOG_NOSLAB, "slab not found on backend");
		goto fail;
	}

	if (strcmp(json_string_value(o), "OK") != 0) {
		if ((o = json_object_get(j, "msg")) == NULL) {
			XERRF(e, XLOG_APP, XLOG_BEERROR, "\"msg\" missing from JSON");
			goto fail;
		}

		XERRF(e, XLOG_APP, XLOG_BEERROR,
		    "\"get\" failed: %s", json_string_value(o));
		goto fail;
	}

	if (WEXITSTATUS(wstatus) == 1) {
		XERRF(e, XLOG_APP, XLOG_BEERROR,
		    "\"get\" exit 1; backend produced no error message");
		goto fail;
	}

	if ((o = json_object_get(j, "in_bytes")) == NULL) {
		XERRF(e, XLOG_APP, XLOG_BEERROR, "\"in_bytes\" missing from JSON");
		goto fail;
	}

	*in_bytes = json_integer_value(o);

	json_decref(j);

	return 0;
fail:
	if (j != NULL)
		json_decref(j);
	unlink(local_path);
	return -1;
}

static int
backend_put(const char *local_path, const char *backend_name,
    size_t *out_bytes, const struct slab_key *sk, struct xerr *e)
{
	char            *args[] = {(char *)fs_config.mgr_exec, "put", NULL};
	int              wstatus;
	char             stdout[1024], stderr[1024];
	json_t          *j, *o;
	json_error_t     jerr;
	char             stdin[LINE_MAX];
	size_t           len;
	struct timespec  start, end;
	time_t           delta_ns;

	mgr_counter_add(MGR_COUNTER_BACKEND_PUTS, 1);

	len = snprintf(stdin, sizeof(stdin),
	    "{\"local_path\": \"%s\", "
	    "\"backend_name\": \"%s\", "
	    "\"inode\": %lu, "
	    "\"base\": %ld}",
	    local_path, backend_name, sk->ino, sk->base);

	if (len >= sizeof(stdin))
		return XERRF(e, XLOG_APP, XLOG_NAMETOOLONG,
		    "outgoing JSON too long");

	clock_gettime_x(CLOCK_REALTIME, &start);
	if (mgr_spawn(args, &wstatus, stdin, len, stdout,
	    sizeof(stdout), stderr, sizeof(stderr),
	    fs_config.backend_put_timeout, xerrz(e)) == -1)
		return XERR_PREPENDFN(e);
	clock_gettime_x(CLOCK_REALTIME, &end);
	delta_ns = ((end.tv_sec * 1000000000) + end.tv_nsec) -
	    ((start.tv_sec * 1000000000) + start.tv_nsec);
	xlog(LOG_NOTICE, NULL, "%s: completed in %ld.%09ld seconds",
	    __func__, delta_ns / 1000000000, delta_ns % 1000000000);

	if (WIFSIGNALED(wstatus))
		return XERRF(e, XLOG_APP, XLOG_BEERROR,
		    "\"put\" killed by signal %d", WTERMSIG(wstatus));

	if (WEXITSTATUS(wstatus) > 2)
		return XERRF(e, XLOG_APP, XLOG_BEERROR,
		    "\"put\" resulted in an undefined error (exit %d)",
		    WEXITSTATUS(wstatus));

	/* Bad invocation error, there is no JSON to read here. */
	if (WEXITSTATUS(wstatus) == 2)
		return XERRF(e, XLOG_APP, XLOG_BEERROR,
		    "\"put\" reported bad invocation (exit 2)");

	if ((j = json_loads(stdout, JSON_REJECT_DUPLICATES, &jerr)) == NULL)
		return XERRF(e, XLOG_APP, XLOG_BEERROR, "%s", jerr.text);

	if ((o = json_object_get(j, "status")) == NULL) {
		XERRF(e, XLOG_APP, XLOG_BEERROR,
		    "\"status\" missing from JSON");
		goto fail;
	}

	if (strcmp(json_string_value(o), "OK") != 0) {
		if ((o = json_object_get(j, "msg")) == NULL) {
			XERRF(e, XLOG_APP, XLOG_BEERROR,
			    "\"msg\" missing from JSON");
			goto fail;
		}
		XERRF(e, XLOG_APP, XLOG_BEERROR,
		    "\"put\" failed: %s", json_string_value(o));
		goto fail;
	}

	if (WEXITSTATUS(wstatus) == 1) {
		XERRF(e, XLOG_APP, XLOG_BEERROR,
		    "\"put\" exit 1; no message available");
		goto fail;
	}

	if ((o = json_object_get(j, "out_bytes")) == NULL) {
		XERRF(e, XLOG_APP, XLOG_BEERROR,
		    "\"in_bytes\" missing from JSON");
		goto fail;
	}

	*out_bytes = json_integer_value(o);

	json_decref(j);
	return 0;
fail:
	json_decref(j);
	return -1;
}

/*
 * Compare a slab's revision and header CRC against
 * expected values and return an error on mismatch.
 * Expects an open fd to the slab in question.
 * The file offset at the end of the header upon return.
 */
static int
check_slab_header(struct slab_hdr *hdr, uint32_t header_crc, uint64_t rev,
    struct xerr *e)
{
	uint32_t crc;

	if (hdr->v.f.revision != rev) {
		/*
		 * backend doesn't have correct (latest?) version
		 * of slab. Are we dealing with eventual consistency?
		 */
		return XERRF(e, XLOG_APP, XLOG_MISMATCH,
		    "mismatching slab revision: "
		    "expected=%lu, slab=%lu", rev, hdr->v.f.revision);
	}

	if ((crc = crc32_z(0L, (Bytef *)hdr,
	    sizeof(struct slab_hdr))) != header_crc) {
		return XERRF(e, XLOG_APP, XLOG_MISMATCH,
		    "mismatching header CRC: "
		    "expected=%u, slab=%u", header_crc, crc);
	}

	return 0;
}

/*
 * Unqueue q_path into dst_fd if the queued slab's header_crc and
 * revision match what's passed in the function args.
 */
static int
copy_incoming_slab(int dst_fd, int src_fd, uint32_t header_crc,
    uint64_t revision, struct xerr *e)
{
	struct slab_hdr hdr;
	ssize_t         r;
	char            buf[BUFSIZ];
	uint32_t        crc;
	char            u[37];

	if (lseek(src_fd, 0, SEEK_SET) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "lseek src_fd");

	if ((r = read_x(src_fd, &hdr, sizeof(hdr))) < sizeof(hdr)) {
		if (r == -1)
			return XERRF(e, XLOG_ERRNO, errno,
			    "short read on slab header");
		else
			return XERRF(e, XLOG_APP, XLOG_IO,
			    "short read on slab header");
	}

	// TODO: eventually this should compare against all possible valid
	//       instances.
	if (uuid_compare(hdr.v.f.last_owner, instance_id) != 0) {
		uuid_unparse(hdr.v.f.last_owner, u);
		return XERRF(e, XLOG_APP, XLOG_MISMATCH,
		    "unknown slab owner %s; do we have a rogue instance "
		    "writing slabs to our backend?", u);
	}

	if (hdr.v.f.revision != revision) {
		/*
		 * backend doesn't have correct (latest?) version
		 * of slab. Are we dealing with eventual consistency?
		 */
		return XERRF(e, XLOG_APP, XLOG_MISMATCH,
		    "mismatching slab revision: "
		    "expected=%lu, slab=%lu", revision, hdr.v.f.revision);
	}

	if ((crc = crc32_z(0L, (Bytef *)&hdr, sizeof(hdr))) != header_crc)
		return XERRF(e, XLOG_APP, XLOG_MISMATCH,
		    "mismatching header CRC: expected=%u, slab=%u",
		    header_crc, crc);

	if (ftruncate(dst_fd, 0) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "ftruncate");

write_hdr_again:
	if (pwrite_x(dst_fd, &hdr, sizeof(hdr), 0) == -1) {
		if (errno == ENOSPC) {
			xlog(LOG_ERR, NULL, "%s: ran out of space; retrying",
			    __func__);
			sleep(1);
			goto write_hdr_again;
		}
		return XERRF(e, XLOG_ERRNO, errno, "write");
	}

copy_again:
	if (lseek(src_fd, sizeof(struct slab_hdr), SEEK_SET) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "lseek src_fd");
	if (lseek(dst_fd, sizeof(struct slab_hdr), SEEK_SET) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "lseek dst_fd");
	crc = crc32_z(0L, Z_NULL, 0);
	while ((r = read_x(src_fd, buf, sizeof(buf)))) {
		if (r == -1)
			return XERRF(e, XLOG_ERRNO, errno, "read");

		crc = crc32_z(crc, (Bytef *)buf, r);

		if (write_x(dst_fd, buf, r) == -1) {
			if (errno == ENOSPC) {
				xlog(LOG_ERR, NULL, "%s: ran out of space "
				    "while copying slab with key "
				    "ino=%lu / base=%lu; retrying",
				    __func__, hdr.v.f.key.ino,
				    hdr.v.f.key.base);
				sleep(1);
				goto copy_again;
			}
			return XERRF(e, XLOG_ERRNO, errno, "write");
		}
	}

	if (hdr.v.f.checksum != crc) {
		/*
		 * slab content doesn't match our checksum. Maybe
		 * the data was corrupted on the backend?
		 */
		return XERRF(e, XLOG_APP, XLOG_MISMATCH,
		    "mismatching slab content checksum: "
		    "expected=%u, slab=%u", hdr.v.f.checksum, crc);
	}

	return 0;
}

/*
 * Errors:
 *   XLOG_APP / XLOG_IO:
 *       statvfs() failed, I/O error, consensus issue
 *   XLOG_APP / XLOG_INVAL:
 *       from slab_key_valid()
 *   XLOG_APP / XLOG_MISMATCH:
 *       unexpected revision/CRC/version on a slab or on the fs_info structure
 *   XLOG_APP / XLOG_BUSY:
 *       DB lock could not be acquired or contention for a slab, and
 *       possibly an flock() deadlock.
 *   XLOG_APP / XLOG_BEERROR:
 *       Backend script encountered an error.
 *   XLOG_APP / XLOG_BETIMEOUT:
 *       Backend script failed to return within set timeout.
 *   XLOG_APP / XLOG_NAMETOOLONG:
 *       a slab's name expanded to a value that is too long.
 *   XLOG_DB:
 *       from slabdb_*()
 *   XLOG_ERRNO:
 *       - from clock_gettime()
 *       - from open_wflock()
 *       - from read_x() on fs_info structure
 *       - from write_x() on slab header writes
 *       - from fsync() after new slab creation
 *       - from fstat() on new slab creation
 *       - from sendmsg() on mgr reply
 */
static int
claim(struct slab_key *sk, int *dst_fd, uint32_t oflags, struct xerr *e)
{
	char              name[NAME_MAX + 1];
	char              in_path[PATH_MAX], out_path[PATH_MAX], dst[PATH_MAX];
	int               fd_flags = O_RDWR|O_CREAT|O_CLOEXEC;
	int               incoming_fd, outgoing_fd;
	size_t            in_bytes;
	struct slab_hdr   hdr;
	struct stat       st;
	struct statvfs    stv;
	struct slabdb_val v;
	struct fs_info    fs_info;
	pid_t             pid;

	if (slab_key_valid(sk, e) == -1)
		return XERR_PREPENDFN(e);

	for (;;) {
		if (statvfs(fs_config.data_dir, &stv) == -1)
			return XERRF(e, XLOG_APP, XLOG_IO,
			    "statvfs: %s", strerror(errno));

		if (stv.f_bfree >= stv.f_blocks *
		    (100 - fs_config.unclaim_purge_threshold_pct) / 100)
			break;

		/*
		 * We are tight on space, we should avoid filling the
		 * partition to prevent the slabdb from breaking.
		 */
		xlog(LOG_WARNING, NULL, "%s: free space is below "
		    "%lu%%, blocking on claim() for sk=%lu/%ld",
		    __func__, fs_config.unclaim_purge_threshold_pct,
		    sk->ino, sk->base);
		sleep(1);
	}

	/*
	 * Check existence in DB, if owned by another instance, otherwise
	 * a new entry will be allocated and returned.
	 */
	if (slabdb_get(sk, &v, oflags, e) == -1)
		return XERR_PREPENDFN(e);

	/*
	 * TODO: compare owners; need to reach consensus about who really
	 * owns this slab. If the owner is another instance, we'll need
	 * to relay bytes instead. For now, we just fail.
	 */
	if (uuid_compare(v.owner, instance_id) != 0)
		return XERRF(e, XLOG_APP, XLOG_IO,
		    "consensus for ownership not implemented");

	/*
	 * We compute the absolute path for the destination path. We use
	 * the destination file as a lock with flock() to handle concurrent
	 * claim() or unclaim() with other potatomgr processes.
	 *
	 * The slab is first downloaded at dst during which the CRC
	 * is validated, then copied to dst_fd. dst is unlinked after
	 * successfully copying.
	 */
	if (slab_path(dst, sizeof(dst), sk, 0, e) == -1 ||
	    slab_path(name, sizeof(name), sk, 1, e) == -1)
		return XERR_PREPENDFN(e);

	if (oflags & OSLAB_SYNC)
		fd_flags |= O_SYNC;

	/*
	 * Note: On unclaim(), unlink() happens before close(). Here
	 * open_wflock() will loop on open()+flock() until it can either
	 * acquire the lock or time out. It will re-open the file on every
	 * attempt, this way we don't end up with an fd for a file about
	 * to be unlinked.
	 *
	 * If the timeout expires, it means something external to the fuse fs
	 * is trying to grab this lock and we potentially just avoided a
	 * deadlock. This can easily happen if we have a single worker, then
	 * something outside the fuse process is trying to do a claim (and the
	 * fuse fs has a lock on it), meaning the fuse FS is now unable to
	 * reach us to unclaim because the worker is busy processing the external
	 * process' request.
	 *
	 * The fs itself would normally never cause this since it has its own
	 * locking around the claimed slab and would never claim the same slab
	 * if it already has a claim on it.
	 */
	if ((*dst_fd = open_wflock(dst, fd_flags, 0600,
	    ((oflags & OSLAB_NONBLOCK) ? (LOCK_NB|LOCK_EX) : LOCK_EX),
	    ((oflags & OSLAB_NONBLOCK) ? 0 : flock_timeout))) == -1) {
		if (errno == EWOULDBLOCK) {
			/*
			 * We only want to count contentions for requests
			 * coming from the filesystem, which will never have
			 * NONBLOCK set.
			 */
			if (!(oflags & OSLAB_NONBLOCK))
				mgr_counter_add(
				    MGR_COUNTER_CLAIM_CONTENTION, 1);
			XERRF(e, XLOG_APP, XLOG_BUSY,
			    "open_wflock() failed to acquire lock "
			    "for slab %s (EWOULDBLOCK)", dst);
		} else {
			XERRF(e, XLOG_ERRNO, errno,
			    "open_wflock: slab %s", dst);
		}
		return -1;
	}

new_slab_again:
	if (v.revision == 0) {
		if (fs_info_read(&fs_info, e) == -1) {
			XERR_PREPENDFN(e);
			goto fail_close_dst;
		}

		if (fs_info.stats.f_bfree < fs_info.stats.f_blocks / 100) {
			XERRF(e, XLOG_FS, ENOSPC,
			    "backend is at 99%% capacity");
			goto fail_close_dst;
		}

		/*
		 * If revision is zero, we're dealing with a brand new slab that
		 * the fs did not have a change to unclaim yet. This _could_ be
		 * due to an fs process crash.
		 * The entry is already in the slabdb, no need to slabdb_put()
		 * here.
		 */
		bzero(&hdr, sizeof(hdr));
		hdr.v.f.slab_version = SLAB_VERSION;
		memcpy(&hdr.v.f.key, sk, sizeof(struct slab_key));
		hdr.v.f.flags = SLAB_DIRTY;
		hdr.v.f.revision = 0;
		hdr.v.f.checksum = crc32(0L, Z_NULL, 0);
		if (write_x(*dst_fd, &hdr, sizeof(hdr)) < sizeof(hdr)) {
			if (errno == ENOSPC) {
				xlog(LOG_ERR, NULL,
				    "%s: ran out of space while creating new "
				    "slab sk=%lu/%ld; retrying", __func__,
				    hdr.v.f.key.ino, hdr.v.f.key.base);
				sleep(1);
				goto new_slab_again;
			}
			XERRF(e, XLOG_ERRNO, errno,
			    "short write on slab header");
			goto fail_close_dst;
		}
		/*
		 * Make sure to fsync() if the file wasn't opened
		 * with O_SYNC initially.
		 */
		if (!(oflags & OSLAB_SYNC) && fsync(*dst_fd) == -1) {
			XERRF(e, XLOG_ERRNO, errno, "fsync");
			goto fail_close_dst;
		}
		goto end;
	}

	if (fstat(*dst_fd, &st) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "fstat");
		goto fail_close_dst;
	}

	if (st.st_size >= sizeof(hdr) &&
	    pread_x(*dst_fd, &hdr, sizeof(hdr), 0) == sizeof(hdr)) {
		/*
		 * This is the most common case, where a slab was previously
		 * claimed and is still present in our local disk cache.
		 * The header CRC/revision check may be superfluous, but
		 * until we are confident we can remove it, we will keep it
		 * as an extra sanity check.
		 */
		if (check_slab_header(&hdr, v.header_crc, v.revision, e) == 0) {
			if (!(oflags & OSLAB_NOHINT)) {
				if ((pid = fork()) == -1) {
					XERRF(e, XLOG_ERRNO, errno, "fork");
					goto fail_close_dst;
				} else if (pid == 0) {
					CLOSE_X(*dst_fd);
					backend_hint(sk);
				}
			}
			goto end;
		} else if (!xerr_is(e, XLOG_APP, XLOG_MISMATCH))
			goto fail_close_dst;

		/*
		 * Wrong rev/header_crc is fine, just proceed with retrieving.
		 * This could mean we're dealing with a previous fs crash.
		 */
		xlog(LOG_CRIT, e,
		    "%s: possibly dealing with a past fs crash", __func__);
		xerrz(e);
	}

	/*
	 * See if we still have the slab in our outgoing dir to avoid having to
	 * pull it from the backend.
	 */
	if (snprintf(out_path, sizeof(out_path), "%s/%s/%s",
	    fs_config.data_dir, OUTGOING_DIR, name) >= sizeof(out_path)) {
		XERRF(e, XLOG_APP, XLOG_NAMETOOLONG,
		    "outgoing slab name too long");
		goto fail_close_dst;
	}
	if ((outgoing_fd = open_wflock(out_path, O_RDONLY, 0,
	    LOCK_SH, flock_timeout)) != -1) {
		xlog_dbg(XLOG_MGR, "found slab in outgoing at %s", out_path);
		if (copy_incoming_slab(*dst_fd, outgoing_fd, v.header_crc,
		    v.revision, xerrz(e)) == 0) {
			CLOSE_X(outgoing_fd);
			if (!(oflags & OSLAB_NOHINT)) {
				if ((pid = fork()) == -1) {
					XERRF(e, XLOG_ERRNO, errno, "fork");
					goto fail_close_dst;
				} else if (pid == 0) {
					CLOSE_X(*dst_fd);
					backend_hint(sk);
				}
			}
			goto end;
		}
		xlog(LOG_WARNING, e, "%s: fetching slab %s from backend even "
		    "though it was found in outgoing", __func__, name);
		CLOSE_X(outgoing_fd);
	}

	/*
	 * At this point we need to pull it from the backend.
	 */
	if (snprintf(in_path, sizeof(in_path), "%s/%s/%s",
	    fs_config.data_dir, INCOMING_DIR, name) >= sizeof(in_path)) {
		XERRF(e, XLOG_APP, XLOG_NAMETOOLONG,
		    "incoming slab name too long");
		goto fail_close_dst;
	}

	/*
	 * Preloads always have nohint set. We can subtrack from the total
	 * number of backend gets to know which gets actually caused the
	 * user to wait.
	 */
	if (oflags & OSLAB_NOHINT)
		mgr_counter_add(MGR_COUNTER_BACKEND_PRELOADS, 1);
get_again:
	in_bytes = 0;
	if (backend_get(in_path, name, &in_bytes, sk, oflags, xerrz(e)) == -1) {
		if (xerr_is(e, XLOG_APP, XLOG_NOSLAB)) {
			/*
			 * Maybe the backend isn't up-to-date? Eventual
			 * consistentcy issues or the backend actually
			 * lost data.
			 */
			xlog(LOG_ERR, NULL, "%s: slab %s expected on backend, "
			    "but backend_get() claims it doesn't exist",
			    __func__, name);
		} else if (xerr_is(e, XLOG_APP, XLOG_BETIMEOUT)) {
			xlog(LOG_ERR, e,
			    "%s: backend script timed out", __func__);
		} else if (xerr_is(e, XLOG_APP, XLOG_BEERROR)) {
			xlog(LOG_ERR, e, "%s: backend script failed", __func__);
		} else if (xerr_is(e, XLOG_ERRNO, ENOSPC)) {
			xlog(LOG_ERR, NULL, "%s: ran out of space during "
			    "backend_get()", __func__);
			goto get_again;
		}
		goto fail_close_dst;
	}
	mgr_counter_add(MGR_COUNTER_BACKEND_IN_BYTES, in_bytes);

	/*
	 * We don't normally need a lock on the incoming slab, but in case
	 * we want to scrub them at some point, it's probably a good idea.
	 */
	if ((incoming_fd = open_wflock(in_path, O_RDONLY, 0,
	    LOCK_SH, flock_timeout)) == -1) {
		xlog_strerror(LOG_ERR, errno, "%s: failed to open_wflock "
		    "after successful backend_get of %s", __func__, in_path);
		goto fail_close_dst;
	}
	if (copy_incoming_slab(*dst_fd, incoming_fd, v.header_crc,
	    v.revision, e) == -1) {
		xlog(LOG_ERR, e, "%s: slab %s", __func__, in_path);
		CLOSE_X(incoming_fd);
		goto fail_close_dst;
	}

	unlink(in_path);
	CLOSE_X(incoming_fd);
end:
	if (!(oflags & OSLAB_EPHEMERAL)) {
		/*
		 * We don't update last_claimed for "ephemeral" slabs,
		 * since we don't mind if they get purged shortly after.
		 */
		clock_gettime_x(CLOCK_REALTIME, &v.last_claimed);
	}

	uuid_copy(v.owner, instance_id);
	v.flags |= SLABDB_FLAG_LOCAL;

	// TODO: if we're truncating to zero, don't go through the
	// trouble of downloading the slab above, just write the empty
	// on like we do here.
	if (v.flags & SLABDB_FLAG_TRUNCATE) {
		if (pread_x(*dst_fd, &hdr, sizeof(hdr), 0) == -1) {
			XERRF(e, XLOG_ERRNO, errno, "%s: pread_x");
			xlog_strerror(LOG_ERR, errno, "%s: pread_x",
			    __func__);
			goto fail_close_dst;
		}
		hdr.v.f.flags |= SLAB_DIRTY;
		if (v.truncate_offset == 0)
			hdr.v.f.flags |= SLAB_REMOVED;
		if ((ftruncate(*dst_fd,
		    v.truncate_offset + sizeof(struct slab_hdr))) == -1) {
			xlog_strerror(LOG_CRIT, errno,
			    "%s: ftruncate", __func__);
			goto fail_close_dst;
		}

		if (pwrite_x(*dst_fd, &hdr, sizeof(hdr), 0) == -1) {
			set_fs_error();
			XERRF(e, XLOG_ERRNO, errno, "%s: pwrite_x");
			xlog_strerror(LOG_ERR, errno, "%s: pwrite_x",
			    __func__);
			goto fail_close_dst;
		}

		v.header_crc = crc32_z(0L, (Bytef *)&hdr, sizeof(hdr));

		/*
		 * Even if we're not in O_SYNC, fsync now because
		 * truncation is important for security. A crash at the
		 * right time could leave previous slab data accessible
		 * to processes.
		 */
		if (!(fd_flags & O_SYNC) && fsync(*dst_fd) == -1) {
			set_fs_error();
			xlog_strerror(LOG_CRIT, errno, "%s: fsync", __func__);
			/*
			 * Don't abort here, let the claim go through but
			 * mark an fs error. This is so we have a consistent
			 * slabdb that matches what we just wrote.
			 */
		}

		v.flags &= ~SLABDB_FLAG_TRUNCATE;
		v.truncate_offset = 0;
	}

	if (slabdb_put(sk, &v, SLABDB_PUT_ALL, e) == -1)
		goto fail_close_dst;

	return 0;
fail_close_dst:
	unlink(dst);
	CLOSE_X(*dst_fd);
	*dst_fd = -1;
	return -1;
}

static int
client_claim(int c, struct mgr_msg *m, struct xerr *e)
{
	int dst_fd = -1;

	if (claim(&m->v.claim.key, &dst_fd, m->v.claim.oflags, e) == -1) {
		if ((m->v.claim.oflags & OSLAB_NOCREATE) &&
		    xerr_is(e, XLOG_APP, XLOG_NOSLAB)) {
			m->m = MGR_MSG_CLAIM_NOENT;
		} else {
			if ((m->v.claim.oflags & OSLAB_NONBLOCK) &&
			    xerr_is(e, XLOG_APP, XLOG_BUSY)) {
				xlog(LOG_INFO, NULL,
				    "%s: failed non-blocking claim on slab "
				    "sk=%lu/%ld; already locked", __func__,
				    m->v.claim.key.ino, m->v.claim.key.base);
			} else {
				xlog(LOG_ERR, e, __func__);
			}
			m->m = MGR_MSG_CLAIM_ERR;
			memcpy(&m->v.err, e, sizeof(struct xerr));
			if (mgr_send(c, -1, m, xerrz(e)) == -1)
				xlog(LOG_ERR, e, __func__);
			return -1;
		}
	} else
		m->m = MGR_MSG_CLAIM_OK;

	if (mgr_send(c, dst_fd, m, xerrz(e)) == -1) {
		if (dst_fd != -1)
			CLOSE_X(dst_fd);
		xlog(LOG_ERR, e, __func__);
		return -1;
	}
	if (dst_fd != -1)
		CLOSE_X(dst_fd);
	return 0;
}

/*
 * Claims an inode table slab after the one for the base inode contained
 * in the message. Useful for looping over all existing inode tables.
 */
static int
claim_next_itbls(int c, struct mgr_msg *m, struct xerr *e)
{
	off_t          base;
	struct mgr_msg claim_msg;
	struct xerr    e_local;

	base = m->v.claim_next_itbl.base;

	if (slabdb_get_next_itbl(&base, xerrz(e)) == -1) {
		if (xerr_is(e, XLOG_APP, XLOG_NOSLAB)) {
			m->m = MGR_MSG_CLAIM_NEXT_ITBL_END;
			if (mgr_send(c, -1, m, xerrz(e)) == -1)
				return -1;
			return 0;
		}
		goto fail;
	}

	bzero(&claim_msg, sizeof(claim_msg));
	claim_msg.m = MGR_MSG_CLAIM;
	claim_msg.v.claim.oflags = m->v.claim_next_itbl.oflags;
	claim_msg.v.claim.key.ino = 0;
	claim_msg.v.claim.key.base = base;

	return client_claim(c, &claim_msg, e);
fail:
	m->m = MGR_MSG_CLAIM_NEXT_ITBL_ERR;
	if (mgr_send(c, -1, m, xerrz(&e_local)) == -1)
		xlog(LOG_ERR, &e_local, __func__);
	return -1;
}

static int
set_shutdown_requested(time_t grace_period)
{
	struct timespec now;

	if (mgr_shared_lock() == -1) {
		return -1;
	} else {
		clock_gettime_x(CLOCK_REALTIME, &now);
		mgr_shared->shutdown_requested = now.tv_sec + grace_period;
		mgr_shared_unlock();
	}
	return 0;
}

static int
do_shutdown(int c, struct mgr_msg *m, struct xerr *e)
{
	if (set_shutdown_requested(m->v.shutdown.grace_period) == -1) {
		XERRF(&m->v.err, XLOG_ERRNO, errno, "set_shutdown_requested");
		m->m = MGR_MSG_SHUTDOWN_ERR;
	} else {
		m->m = MGR_MSG_SHUTDOWN_OK;
	}

	xlog(LOG_NOTICE, NULL, "shutdown requested; grace period %lu",
	    m->v.shutdown.grace_period);

	if (mgr_send(c, -1, m, xerrz(e)) == -1)
		return -1;
	return 0;
}

static int
info(int c, struct mgr_msg *m, struct xerr *e)
{
	pid_t mgr_pid;
	if (fs_info_read(&m->v.info.fs_info, e) == -1) {
		xlog(LOG_ERR, e, __func__);
		memcpy(&m->v.err, e, sizeof(struct xerr));
		m->m = MGR_MSG_INFO_ERR;
	} else {
		m->m = MGR_MSG_INFO_OK;
		if ((mgr_pid = getppid()) > 1)
			m->v.info.mgr_pid = mgr_pid;
		else
			m->v.info.mgr_pid = -1;
		strlcpy(m->v.info.version_string, VERSION,
		    sizeof(m->v.info.version_string));
	}

	if (mgr_send(c, -1, m, xerrz(e)) == -1)
		return -1;

	return 0;
}

static void
bg_df()
{
	int             wstatus;
	char            stdout[1024], stderr[1024];
	json_t         *j, *o;
	json_error_t    jerr;
	char           *args[] = {(char *)fs_config.mgr_exec, "df", NULL};
	off_t           bytes_total, bytes_used;
	struct fs_info  fs_info;
	struct xerr     e = XLOG_ERR_INITIALIZER;
	ssize_t         count;

	if (fs_info_read(&fs_info, &e) == -1) {
		xlog(LOG_ERR, &e, __func__);
		return;
	}

	if (fs_info.stats.f_bsize == 0) {
		xlog(LOG_ERR, NULL,
		    "%s: fs_info.stats.f_bsize is zero", __func__);
		return;
	}
	if (fs_info.slab_size == 0) {
		xlog(LOG_ERR, NULL,
		    "%s: fs_info.slab_size is zero", __func__);
		return;
	}


	if (mgr_spawn(args, &wstatus, NULL, 0, stdout, sizeof(stdout),
	    stderr, sizeof(stderr), fs_config.backend_df_timeout, &e) == -1) {
		xlog(LOG_ERR, &e, __func__);
		return;
	}

	if ((j = json_loads(stdout, JSON_REJECT_DUPLICATES, &jerr)) == NULL) {
		xlog(LOG_ERR, NULL, "%s: failed but will retry; "
		    "JSON was invalid: %s", __func__, jerr.text);
		return;
	}

	if ((o = json_object_get(j, "total_bytes")) == NULL) {
		xlog(LOG_ERR, NULL, "%s: \"total_bytes\" missing from JSON",
		    __func__);
		goto clear;
	}
	bytes_total = json_integer_value(o);

	if ((o = json_object_get(j, "used_bytes")) == NULL) {
		xlog(LOG_ERR, NULL, "%s: \"used_bytes\" missing from JSON",
		    __func__);
		goto clear;
	}
	bytes_used = json_integer_value(o);

	fs_info.stats.f_blocks = bytes_total / fs_info.stats.f_bsize;
	fs_info.stats.f_bfree = (bytes_total - bytes_used) /
	    fs_info.stats.f_bsize;
	fs_info.stats.f_bavail = fs_info.stats.f_bfree;

	fs_info.stats.f_files = (bytes_total / fs_info.slab_size) *
	    slab_inode_max();
	if ((count = slabdb_count(&e)) == -1) {
		xlog(LOG_ERR, &e, __func__);
		goto clear;
	}
	fs_info.stats.f_ffree = fs_info.stats.f_files -
	    (count * slab_inode_max());
	fs_info.stats.f_favail = fs_info.stats.f_ffree;

	clock_gettime_x(CLOCK_REALTIME, &fs_info.stats_last_update);

	if (fs_info_write(&fs_info, &e) == -1)
		xlog(LOG_ERR, &e, __func__);
clear:
	json_decref(j);
}

static int
bgworker(const char *name, void(*fn)(), int interval_secs)
{
	char            title[32];
	struct timespec tp = {1, 0};
	struct timespec rem;
	int             r, i;
	pid_t           pid;
	struct xerr     e = XLOG_ERR_INITIALIZER;

	if ((pid = fork()) == -1) {
		xlog_strerror(LOG_ERR, errno, "%s: fork", __func__);
		set_shutdown_requested(0);
		return -1;
	} else if (pid > 0)
		return 0;

	CLOSE_X(pid_fd);

	bzero(title, sizeof(title));
	snprintf(title, sizeof(title), "%s-%s", MGR_PROGNAME, name);
	if (xlog_init(title, fs_config.dbg, fs_config.log_file_path, 0) == -1) {
		xlog(LOG_ERR, NULL,
		    "%s: failed to initialize logging", __func__);
		_exit(1);
	}

	setproctitle("bgworker: %s", name);
	xlog(LOG_NOTICE, NULL, "%s bgworker ready", name);

	if (slabdb_init(instance_id, &e) == -1) {
                xlog(LOG_ERR, &e, "%s", __func__);
		_exit(1);
	}

	while (!shutdown_now()) {
		fn();
		for (i = 0; i < interval_secs && !shutdown_now(); i++) {
			do {
				while (waitpid(-1, NULL, WNOHANG) > 0);
				if ((r = nanosleep(&tp, &rem)) == -1) {
					tp.tv_sec = rem.tv_sec;
					tp.tv_nsec = rem.tv_nsec;
					xlog_strerror(LOG_NOTICE, errno,
					    "%s: nanosleep", __func__);
				}
			} while(r != 0 && !shutdown_now());
		}
	}
	slabdb_shutdown();
	xlog(LOG_NOTICE, NULL, "exiting");
	_exit(0);
}

static void
bg_flush()
{
	char             path[PATH_MAX], outgoing_dir[PATH_MAX];
	DIR             *dir;
	struct dirent   *de;
	size_t           out_bytes;
	int              fd;
	struct xerr      e;
	struct slab_key  sk;

	if (snprintf(outgoing_dir, sizeof(outgoing_dir), "%s/%s",
	    fs_config.data_dir, OUTGOING_DIR) >= sizeof(path)) {
		xlog(LOG_ERR, NULL, "%s: outq name too long", __func__);
		return;
	}

	xlog_dbg(XLOG_MGR, "%s: scanning %s", __func__, outgoing_dir);

	if ((dir = opendir(outgoing_dir)) == NULL) {
		xlog_strerror(LOG_ERR, errno, "%s: opendir %s",
		    __func__, outgoing_dir);
		return;
	}

	while ((de = readdir(dir))) {
		if (de->d_name[0] == '.')
			continue;

		if (snprintf(path, sizeof(path), "%s/%s",
		    outgoing_dir, de->d_name) >= sizeof(path)) {
			xlog(LOG_ERR, NULL, "%s: name too long", __func__);
			goto fail;
		}

		/*
		 * Has to be exclusive since we may be running multiple
		 * flush workers.
		 */
		if ((fd = open_wflock(path, O_RDONLY|O_CLOEXEC, 0,
		    LOCK_EX|LOCK_NB, 0)) == -1) {
			if (errno != EWOULDBLOCK && errno != ENOENT)
				xlog_strerror(LOG_ERR, errno, "%s: failed "
				    "to open_wflock(): %s", __func__, path);
			continue;
		}

		if (slab_parse_path(path, &sk, xerrz(&e)) == -1) {
			CLOSE_X(fd);
			xlog(LOG_ERR, &e, "%s", __func__);
			continue;
		}

		out_bytes = 0;
		if (backend_put(path, basename(path), &out_bytes,
		    &sk, xerrz(&e)) == -1) {
			xlog(LOG_ERR, &e, "%s: failed but will retry",
			    __func__);
			CLOSE_X(fd);
			continue;
		}
		mgr_counter_add(MGR_COUNTER_BACKEND_OUT_BYTES, out_bytes);

		xlog(LOG_INFO, NULL, "%s: backend_put: %s (%lu bytes)",
		    __func__, path, out_bytes);

		if (unlink(path) == -1)
			xlog_strerror(LOG_ERR, errno, "%s: unlink %s",
			    __func__, path);

		CLOSE_X(fd);

		if (shutdown_now())
			break;
	}
fail:
	closedir(dir);
}

static void
scrub_local_slab(const char *path)
{
	struct slab_hdr   hdr;
	int               fd;
	struct slab_key   sk;
	struct slabdb_val v;
	struct xerr       e = XLOG_ERR_INITIALIZER;

	if (slab_parse_path(path, &sk, &e) == -1) {
		xlog(LOG_ERR, &e, "%s", __func__);
		return;
	}

	if ((fd = open_wflock(path, O_RDWR, 0, LOCK_EX|LOCK_NB, 0)) == -1) {
		if (errno == EWOULDBLOCK) {
			xlog_dbg(XLOG_MGR, "%s: slab %s is already "
			    "flock()'d; skipping", __func__, path);
		} else {
			xlog_strerror(LOG_ERR, errno, "%s: failed "
			    "to open_wflock(): %s", __func__, path);
		}
		return;
	}

	if (slabdb_get(&sk, &v, OSLAB_NOCREATE, &e) == -1) {
		if (xerr_is(&e, XLOG_APP, XLOG_NOSLAB)) {
			xlog(LOG_ERR, NULL, "%s: slab %s not found in db; "
			    "unlinking", __func__, path);
			unlink(path);
			goto end;
		}
		xlog(LOG_ERR, &e, "%s", __func__);
		goto end;
	}

	if (read_x(fd, &hdr, sizeof(hdr)) < sizeof(hdr)) {
		xlog_strerror(LOG_ERR, errno,
		    "%s: short read on slab header for %s",
		    __func__, path);
		set_fs_error();
		goto end;
	}

	if (check_slab_header(&hdr, v.header_crc, v.revision, &e) != 0) {
		if (hdr.v.f.revision == 0) {
			xlog(LOG_ERR, NULL, "%s: slab %s has revision 0, "
			    "meaning it was never unclaimed yet did not have "
			    "a lock on it. Are we dealing with a slab from a "
			    "previous fs crash?", __func__, path);
			return;
		}
		xlog(LOG_CRIT, &e, "%s: %s", __func__, path);
		set_fs_error();
		goto end;
	}

	if (hdr.v.f.flags & SLAB_DIRTY) {
		/*
		 * This slab was unclaimed but not written to outgoing.
		 * A common reason for this could be a delayed truncation.
		 */
		xlog(LOG_INFO, NULL, "%s: slab %s was dirty despite "
		    "being unclaimed; incrementing revision and sending "
		    "to outgoing now", __func__, path);
		if (copy_outgoing_slab(fd, &sk, &hdr, &e) == -1) {
			if (xerr_is(&e, XLOG_APP, XLOG_BUSY) ||
			    xerr_is(&e, XLOG_ERRNO, ENOSPC)) {
				xlog(LOG_WARNING, &e, __func__);
				xerrz(&e);
				goto end;
			}
			xlog(LOG_ERR, &e, __func__);
			set_fs_error();
			goto end;
		}

		if (pwrite_x(fd, &hdr, sizeof(hdr), 0) < sizeof(hdr)) {
			xlog_strerror(LOG_ERR, errno,
			    "%s: short write on slab header", __func__);
			set_fs_error();
			goto end;
		}

		v.revision = hdr.v.f.revision;
		v.header_crc = crc32_z(0L, (Bytef *)&hdr, sizeof(hdr));
		uuid_clear(v.owner);
		if (slabdb_put(&sk, &v,
		    SLABDB_PUT_REVISION|SLABDB_PUT_HEADER_CRC|SLABDB_PUT_OWNER,
		    &e) == -1) {
			xlog(LOG_CRIT, &e, __func__);
			set_fs_error();
			goto end;
		}
	}

	/*
	 * At this point, the slab is not dirty and matches the rev/crc
	 * that we expect. If it's not marked as local yet it is here,
	 * it can never be purged, so we should purge it.
	 */
	if (!(v.flags & SLABDB_FLAG_LOCAL)) {
		xlog(LOG_ERR, NULL, "%s: slab %s is not locally-owned; "
		    "unlinking", __func__, path);
		unlink(path);
		goto end;
	}
end:
	CLOSE_X(fd);
}

static int
delayed_truncate(const struct slab_key *sk, const struct slabdb_val *v,
    void *data)
{
	struct delayed_truncates *to_truncate =
	    (struct delayed_truncates *)data;

	if (v->flags & SLABDB_FLAG_TRUNCATE) {
		to_truncate->sk[to_truncate->count].ino = sk->ino;
		to_truncate->sk[to_truncate->count].base = sk->base;
		to_truncate->count++;
	}

	if ((to_truncate->count * sizeof(struct slab_key)) >=
	    sizeof(to_truncate->sk))
		return 1;

	return 0;
}

static void
scrub()
{
	struct xerr              e = XLOG_ERR_INITIALIZER;
	struct delayed_truncates to_truncate;
	int                      fd, i;
	uint32_t                 oflags;

	xlog(LOG_NOTICE, NULL, "%s: scrubbing now", __func__);

	// TODO: We need to cleanup INCOMING_DIR as well. For example:
	//  * if the CRC is wrong
	//  * if the slab is already in our main dir with >= rev

	/*
	 * We loop here just in case we're seeing a large burst
	 * of delayed truncations, to make sure we process them
	 * as soon as possible and reclaim space.
	 */
	for (;;) {
		bzero(&to_truncate, sizeof(to_truncate));
		if (slabdb_loop(SLABDB_FLAG_TRUNCATE,
		    &delayed_truncate, &to_truncate, &e) == -1)
			xlog(LOG_ERR, &e, "%s", __func__);

		if (to_truncate.count == 0)
			break;

		xlog(LOG_NOTICE, NULL, "%s: processing %d delayed truncations",
		    __func__, to_truncate.count);

		/*
		 * Perform truncations by simply claiming slabs. claim() will
		 * truncate to the desired offset prior to returning the fd.
		 */

		oflags = OSLAB_NOCREATE|OSLAB_NONBLOCK|OSLAB_EPHEMERAL|OSLAB_NOHINT;
		for (i = 0; i < to_truncate.count; i++) {
			if (claim(&to_truncate.sk[i], &fd, oflags,
			    xerrz(&e)) == -1) {
				if (xerr_is(&e, XLOG_APP, XLOG_BUSY))
					continue;

				if (xerr_is(&e, XLOG_APP, XLOG_NOSPC)) {
					xlog(LOG_WARNING, &e, __func__);
					continue;
				}

				if (xerr_is(&e, XLOG_APP, XLOG_NOSLAB)) {
					xlog(LOG_WARNING, &e,
					    "%s: slab sk=%lu/%ld was marked "
					    "for truncation but cannot be "
					    "claimed", __func__,
					    to_truncate.sk[i].ino,
					    to_truncate.sk[i].base);
					continue;
				}

				xlog(LOG_ERR, &e, __func__);
				set_fs_error();
				continue;
			}
			CLOSE_X(fd);
		}
	}

	if (slab_loop_files(&scrub_local_slab, &e) == -1)
		xlog(LOG_ERR, &e, "%s", __func__);

	xlog(LOG_NOTICE, NULL, "%s: scrubbing complete", __func__);
}

static int
client_scrub(int c, struct mgr_msg *m, struct xerr *e)
{
	scrub();
	m->m = MGR_MSG_SCRUB_OK;
	if (mgr_send(c, -1, m, xerrz(e)) == -1) {
		xlog(LOG_ERR, e, __func__);
		return -1;
	}
	return 0;
}

static int
client_flush(int c, struct mgr_msg *m, struct xerr *e)
{
	bg_flush();
	m->m = MGR_MSG_FLUSH_OK;
	if (mgr_send(c, -1, m, xerrz(e)) == -1) {
		xlog(LOG_ERR, e, __func__);
		return -1;
	}
	return 0;
}

static int
client_purge_all(int c, struct mgr_msg *m, struct xerr *e)
{
	purge_all();
	m->m = MGR_MSG_PURGE_ALL_OK;
	if (mgr_send(c, -1, m, xerrz(e)) == -1) {
		xlog(LOG_ERR, e, __func__);
		return -1;
	}
	return 0;
}

static int
client_offline(int c, struct mgr_msg *m, struct xerr *e)
{
	if (m->m == MGR_MSG_OFFLINE) {
		if (mgr_shared_lock() == -1) {
			m->m = MGR_MSG_OFFLINE_ERR;
			XERRF(&m->v.err, XLOG_ERRNO, errno,
			    "set offline status");
		} else {
			m->m = MGR_MSG_OFFLINE_OK;
			mgr_shared->offline = 1;
			mgr_shared_unlock();
		}
	} else {
		if (mgr_shared_lock() == -1) {
			m->m = MGR_MSG_ONLINE_ERR;
			XERRF(&m->v.err, XLOG_ERRNO, errno,
			    "set online status");
		} else {
			m->m = MGR_MSG_ONLINE_OK;
			mgr_shared->offline = 0;
			mgr_shared_unlock();
		}
	}
	if (mgr_send(c, -1, m, xerrz(e)) == -1) {
		xlog(LOG_ERR, e, __func__);
		return -1;
	}
	return 0;
}

static int
client_get_offline(int c, struct mgr_msg *m, struct xerr *e)
{
	if (mgr_shared_lock() == -1) {
		m->m = MGR_MSG_GET_OFFLINE_ERR;
		XERRF(&m->v.err, XLOG_ERRNO, errno,
		    "get offline status");
	} else {
		m->m = MGR_MSG_GET_OFFLINE_OK;
		m->v.get_offline.offline = mgr_shared->offline;
		mgr_shared_unlock();
	}
	if (mgr_send(c, -1, m, xerrz(e)) == -1) {
		xlog(LOG_ERR, e, __func__);
		return -1;
	}
	return 0;
}

static void
purge_all()
{
	struct xerr     e = XLOG_ERR_INITIALIZER;
	struct timespec start, end;
	time_t          delta_ns;

	clock_gettime_x(CLOCK_REALTIME, &start);

	if (slabdb_loop(SLABDB_FLAG_LOCAL, &purge, NULL, &e) == -1)
		xlog(LOG_ERR, &e, "%s", __func__);

	clock_gettime_x(CLOCK_REALTIME, &end);

	delta_ns = ((end.tv_sec * 1000000000) + end.tv_nsec) -
	    ((start.tv_sec * 1000000000) + start.tv_nsec);
	xlog(LOG_NOTICE, NULL, "%s: purging took %lu.%09ld seconds",
	    __func__, delta_ns / 1000000000, delta_ns % 1000000000);
}

static int
purge(const struct slab_key *sk, const struct slabdb_val *v, void *usage)
{
	int                fd;
	struct fs_usage   *fs_usage = (struct fs_usage *)usage;
	struct stat        st;
	char               path[PATH_MAX];
	struct slab_hdr    hdr;
	struct slabdb_val  pv;
	struct xerr        e = XLOG_ERR_INITIALIZER;
	fsblkcnt_t         threshold;

	if (slab_path(path, sizeof(path), sk, 0, &e) == -1) {
		xlog(LOG_ERR, &e, "%s", __func__);
		return 0;
	}

	if ((fd = open_wflock(path, O_RDWR, 0, LOCK_EX|LOCK_NB, 0)) == -1) {
		if (errno != EWOULDBLOCK && errno != ENOENT)
			xlog_strerror(LOG_ERR, errno, "%s: failed "
			    "to open_wflock(): %s", __func__, path);
		return 0;
	}

	if (read_x(fd, &hdr, sizeof(hdr)) < sizeof(hdr)) {
		CLOSE_X(fd);
		xlog_strerror(LOG_ERR, errno,
		    "%s: short read on slab header", __func__);
		set_fs_error();
		return 0;
	}

	if (hdr.v.f.flags & SLAB_DIRTY) {
		CLOSE_X(fd);
		return 0;
	}

	if (fstat(fd, &st) == -1) {
		CLOSE_X(fd);
		xlog_strerror(LOG_ERR, errno, "%s: fstat", __func__);
		set_fs_error();
		return 0;
	}

	memcpy(&pv, v, sizeof(pv));
	pv.revision = v->revision;
	pv.header_crc = v->header_crc;
	uuid_clear(pv.owner);
	pv.flags &= ~SLABDB_FLAG_LOCAL;

	if (slabdb_put_nolock(sk, &pv, &e) == -1) {
		xlog(LOG_ERR, &e, "%s", __func__);
		CLOSE_X(fd);
		return 0;
	}

	if (unlink(path) == -1) {
		xlog_strerror(LOG_ERR, errno, "%s", __func__);
		CLOSE_X(fd);
		return 0;
	} else {
		xlog(LOG_INFO, NULL, "%s: purged slab %s "
		    "(revision=%lu, crc=%u)", __func__, path,
		    v->revision, v->header_crc);
		mgr_counter_add(MGR_COUNTER_SLABS_PURGED, 1);
		if (fs_usage != NULL)
			fs_usage->used_blocks -=
			    (st.st_blocks / (fs_usage->stv.f_bsize / 512));
	}

	CLOSE_X(fd);

	if (fs_usage != NULL) {
		threshold = fs_usage->stv.f_blocks *
		    fs_config.purge_threshold_pct / 100;
		if (fs_usage->used_blocks < threshold) {
			xlog(LOG_INFO, NULL,
			    "%s: ending purge, used blocks %lu "
			    "within threshold %lu", __func__,
			    fs_usage->used_blocks, threshold);
			return 1;
		}
	}

	return 0;
}

static void
bg_purge()
{
	struct xerr     e = XLOG_ERR_INITIALIZER;
	struct fs_usage fs_usage;
	struct timespec start, end;
	time_t          delta_ns;

	if (statvfs(fs_config.data_dir, &fs_usage.stv) == -1) {
		xlog_strerror(LOG_ERR, errno, "statvfs");
		return;
	}

	if (fs_usage.stv.f_bfree >
	    fs_usage.stv.f_blocks *
	    (100 - fs_config.purge_threshold_pct) / 100) {
		/*
		 * Nothing to do.
		 */
		return;
	}

	fs_usage.used_blocks = fs_usage.stv.f_blocks - fs_usage.stv.f_bfree;

	xlog(LOG_NOTICE, NULL, "%s: cache use is at %lu%% of partition size; "
	    "purging slabs", __func__,
	    (fs_usage.stv.f_blocks - fs_usage.stv.f_bfree) * 100
	    / fs_usage.stv.f_blocks);

	clock_gettime_x(CLOCK_REALTIME, &start);

	if (slabdb_loop(SLABDB_FLAG_LOCAL, &purge, &fs_usage, &e) == -1)
		xlog(LOG_ERR, &e, "%s", __func__);

	clock_gettime_x(CLOCK_REALTIME, &end);

	delta_ns = ((end.tv_sec * 1000000000) + end.tv_nsec) -
	    ((start.tv_sec * 1000000000) + start.tv_nsec);
	xlog(LOG_NOTICE, NULL, "%s: purging took %lu.%09ld seconds",
	    __func__, delta_ns / 1000000000, delta_ns % 1000000000);
}

static int
worker(int lsock)
{
	int            fd;
	struct mgr_msg m;
	struct xerr    e = XLOG_ERR_INITIALIZER;
	struct xerr    e2;
	int            c;
	int            r;
	pid_t          pid;
	struct pollfd  fds;

	if ((pid = fork()) == -1) {
		xlog_strerror(LOG_ERR, errno, "%s: fork", __func__);
		set_shutdown_requested(0);
		return -1;
	} else if (pid > 0)
		return 0;

	CLOSE_X(pid_fd);

	if (xlog_init(MGR_PROGNAME "-worker", fs_config.dbg,
	    fs_config.log_file_path, 0) == -1) {
		xlog(LOG_ERR, NULL, "failed to initialize logging in worker");
		_exit(1);
	}

	setproctitle("worker");
	xlog(LOG_NOTICE, NULL, "worker ready");

	if (slabdb_init(instance_id, xerrz(&e)) == -1) {
                xlog(LOG_ERR, &e, "%s", __func__);
		_exit(1);
	}

	while (!shutdown_requested()) {
		fds.fd = lsock;
		fds.events = POLLIN;
		if ((r = poll(&fds, 1, 1000)) <= 0) {
			if (r == -1 && errno != EINTR)
				xlog_strerror(LOG_ERR, errno,
				    "%s: accept", __func__);
			continue;
		}
		if ((c = accept(lsock, NULL, 0)) == -1) {
			switch (errno) {
			case EINTR:
			case EAGAIN:
				continue;
			case EMFILE:
				xlog_strerror(LOG_ERR, errno,
				    "%s: accept", __func__);
				sleep(5);
				continue;
			default:
				xlog_strerror(LOG_ERR, errno,
				    "%s: accept", __func__);
				_exit(1);
			}
		}

		if (fcntl(c, F_SETFD, FD_CLOEXEC) == -1) {
			xlog_strerror(LOG_ERR, errno, "fcntl");
			CLOSE_X(c);
			continue;
		}

		if (setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &socket_timeout,
		    sizeof(socket_timeout)) == -1) {
			xlog_strerror(LOG_ERR, errno, "setsockopt");
			CLOSE_X(c);
			continue;
		}

		// TODO: occasional zombie; eventually gets reaped if
		// the worker gets a new request.

		while (c > -1) {
			while (waitpid(-1, NULL, WNOHANG) > 0);
			if (mgr_recv(c, &fd, &m, xerrz(&e)) == -1) {
				if (xerr_is(&e, XLOG_ERRNO, EAGAIN)) {
					xlog(LOG_NOTICE, NULL,
					    "read timeout on socket %d", c);
				} else if (!xerr_is(&e, XLOG_APP, XLOG_EOF)) {
					xlog(LOG_ERR, &e, __func__);
				}
				CLOSE_X(c);
				c = -1;
				break;
			}

			xerrz(&e);
			switch (m.m) {
			case MGR_MSG_CLAIM:
				client_claim(c, &m, xerrz(&e));
				break;
			case MGR_MSG_UNCLAIM:
				unclaim(c, &m, fd, xerrz(&e));
				break;
			case MGR_MSG_TRUNCATE:
				truncate_slab(c, &m, xerrz(&e));
				break;
			case MGR_MSG_INFO:
				info(c, &m, xerrz(&e));
				break;
			case MGR_MSG_SHUTDOWN:
				do_shutdown(c, &m, xerrz(&e));
				break;
			case MGR_MSG_SET_FS_ERROR:
				if (set_fs_error() == -1) {
					XERRF(&m.v.err, XLOG_APP, XLOG_IO,
					    "set_fs_error");
					m.m = MGR_MSG_SET_FS_ERROR_ERR;
				} else {
					m.m = MGR_MSG_SET_FS_ERROR_OK;
				}
				if (mgr_send(c, -1, &m, xerrz(&e2)) == -1) {
					xlog(LOG_ERR, &e2, __func__);
					CLOSE_X(c);
					c = -1;
				}
				break;
			case MGR_MSG_CLAIM_NEXT_ITBL:
				claim_next_itbls(c, &m, xerrz(&e));
				break;
			case MGR_MSG_SND_COUNTERS:
				snd_counters(c, &m, xerrz(&e));
				break;
			case MGR_MSG_RCV_COUNTERS:
				rcv_counters(c, &m, xerrz(&e));
				break;
			case MGR_MSG_SCRUB:
				client_scrub(c, &m, xerrz(&e));
				break;
			case MGR_MSG_FLUSH:
				client_flush(c, &m, xerrz(&e));
				break;
			case MGR_MSG_PURGE_ALL:
				client_purge_all(c, &m, xerrz(&e));
				break;
			case MGR_MSG_ONLINE:
			case MGR_MSG_OFFLINE:
				client_offline(c, &m, xerrz(&e));
				break;
			case MGR_MSG_GET_OFFLINE:
				client_get_offline(c, &m, xerrz(&e));
				break;
			default:
				xlog(LOG_ERR, NULL, "%s: wrong message %d",
				    __func__, m.m);
				CLOSE_X(c);
				c = -1;
			}
			if (xerr_fail(&e)) {
				xlog(LOG_ERR, &e, __func__);
				if (e.sp == XLOG_ERRNO) {
					CLOSE_X(c);
					c = -1;
					break;
				}
			}
		}
	}
	CLOSE_X(lsock);
	slabdb_shutdown();
	xlog(LOG_NOTICE, NULL, "exiting");
	_exit(0);
}

int
mgr_start(int workers, int bgworkers)
{
	struct              sigaction act;
	char                pid_line[32];
	struct passwd      *pw;
	struct group       *gr;
	// TODO: use config
	char               *unpriv_user = MGR_DEFAULT_UNPRIV_USER;
	char               *unpriv_group = MGR_DEFAULT_UNPRIV_GROUP;
	int                 lsock, lsock_flags;
	struct sockaddr_un  saddr;
	int                 n;
	int                 wait_for_workers = 0;
	int                 null_fd;
	struct statvfs      stv;
	struct xerr         e;
	struct fs_info      fs_info;
	char                u[37];
	pid_t               pid;

	if ((pid_fd = open(fs_config.pidfile_path,
	    O_CREAT|O_WRONLY|O_CLOEXEC, 0644)) == -1)
		return -1;
	if (flock(pid_fd, LOCK_EX|LOCK_NB) == -1) {
		if (errno == EWOULDBLOCK) {
			warnx("pid file %s is already locked; "
			    "is another instance running?",
			    fs_config.pidfile_path);
		}
		return -1;
	}

	if ((pid = fork()) == -1) {
		CLOSE_X(pid_fd);
		return -1;
	} else if (pid != 0) {
		CLOSE_X(pid_fd);
		return 0;
	}

	chdir(fs_config.data_dir);

	if ((null_fd = open("/dev/null", O_RDWR)) == -1)
		err(1, "open");

	dup2(null_fd, STDIN_FILENO);
	dup2(null_fd, STDOUT_FILENO);
	dup2(null_fd, STDERR_FILENO);
	if (null_fd > 2)
		CLOSE_X(null_fd);

	if (xlog_init(MGR_PROGNAME, fs_config.dbg,
	    fs_config.log_file_path, 0) == -1)
		err(1, "xlog_init");

	snprintf(pid_line, sizeof(pid_line), "%d\n", getpid());
	if (write(pid_fd, pid_line, strlen(pid_line)) == -1) {
		xlog_strerror(LOG_ERR, errno, "write");
		_exit(1);
	}
	if (fsync(pid_fd) == -1) {
		xlog_strerror(LOG_ERR, errno, "fsync");
		_exit(1);
	}

	if (geteuid() == 0) {
		if ((gr = getgrnam(unpriv_group)) == NULL) {
			xlog(LOG_ERR, NULL,
			    "Group %s not found in group database",
			    unpriv_group);
			_exit(1);
		}
		if (setgid(gr->gr_gid) == -1) {
			xlog_strerror(LOG_ERR, errno, "setgid");
			_exit(1);
		}
		if (setegid(gr->gr_gid) == -1) {
			xlog_strerror(LOG_ERR, errno, "setegid");
			_exit(1);
		}

		if ((pw = getpwnam(unpriv_user)) == NULL) {
			xlog_strerror(LOG_ERR, errno,
			    "User %s not found in users database", unpriv_user);
			_exit(1);
		}
		if (setuid(pw->pw_uid) == -1) {
			xlog_strerror(LOG_ERR, errno, "setuid");
			_exit(1);
		}
		if (seteuid(pw->pw_uid) == -1) {
			xlog_strerror(LOG_ERR, errno, "seteuid");
			_exit(1);
		}
	}

	if (mkdir(fs_config.data_dir, 0700) == -1) {
		if (errno != EEXIST) {
			xlog_strerror(LOG_ERR, errno,
			    "mkdir: %s", fs_config.data_dir);
			_exit(1);
		}
	}
	if (access(fs_config.data_dir, R_OK|X_OK) == -1) {
		xlog_strerror(LOG_ERR, errno, "access: %s",
		    fs_config.data_dir);
		_exit(1);
	}

	if (access(fs_config.mgr_exec, X_OK) == -1) {
		xlog_strerror(LOG_ERR, errno, "access: %s",
		    fs_config.mgr_exec);
		_exit(1);
	}

	if (statvfs(fs_config.data_dir, &stv) == -1) {
		xlog_strerror(LOG_ERR, errno, "statvfs");
		_exit(1);
	}

	xlog(LOG_INFO, NULL, "%s: cache size is %llu bytes (%lu slabs)",
	    __func__, stv.f_blocks * stv.f_frsize,
	    stv.f_blocks * stv.f_frsize /
	    (fs_config.slab_size + sizeof(struct slab_hdr)));

	if (fs_info_open(&fs_info, xerrz(&e)) == -1) {
		xlog(LOG_ERR, &e, "%s", __func__);
		_exit(1);
	}
	uuid_copy(instance_id, fs_info.instance_id);

	if (slab_make_dirs(xerrz(&e)) == -1) {
		xlog(LOG_ERR, &e, "%s", __func__);
		_exit(1);
	}

	if ((lsock = socket(AF_LOCAL, SOCK_STREAM, 0)) == -1) {
		xlog_strerror(LOG_ERR, errno, "socket");
		_exit(1);
	}
	unlink(fs_config.mgr_sock_path);

	if (fcntl(lsock, F_SETFD, FD_CLOEXEC) == -1) {
		xlog_strerror(LOG_ERR, errno, "fcntl");
		_exit(1);
	}
	if ((lsock_flags = fcntl(lsock, F_GETFL, 0)) == -1) {
		xlog_strerror(LOG_ERR, errno, "fcntl");
		_exit(1);
	}
	if (fcntl(lsock, F_SETFL, lsock_flags | O_NONBLOCK) == -1) {
		xlog_strerror(LOG_ERR, errno, "fcntl");
		_exit(1);
	}

	bzero(&saddr, sizeof(saddr));
	saddr.sun_family = AF_LOCAL;
	strlcpy(saddr.sun_path, fs_config.mgr_sock_path,
	    sizeof(saddr.sun_path));

	if (bind(lsock, (struct sockaddr *)&saddr, SUN_LEN(&saddr)) == -1) {
		xlog_strerror(LOG_ERR, errno, "bind");
		_exit(1);
	}

	if (listen(lsock, 64) == -1) {
		xlog_strerror(LOG_ERR, errno, "listen");
		_exit(1);
	}

	if ((mgr_shared = mmap(NULL, sizeof(struct mgr_shared),
	    PROT_READ|PROT_WRITE, MAP_ANON|MAP_SHARED, -1, 0)) == MAP_FAILED) {
		xlog_strerror(LOG_ERR, errno, "mmap");
		_exit(1);
	}

	/* Not sure MAP_ANON initializes to zero on BSD */
	bzero(mgr_shared, sizeof(struct mgr_shared));

	if (sem_init(&mgr_shared->sem, 1, 1) == -1) {
		xlog_strerror(LOG_ERR, errno, "sem_init");
		_exit(1);
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
	if (sigaction(SIGHUP, &act, NULL) == -1 ||
	    sigaction(SIGINT, &act, NULL) == -1 ||
	    sigaction(SIGPIPE, &act, NULL) == -1 ||
	    sigaction(SIGQUIT, &act, NULL) == -1 ||
	    sigaction(SIGTERM, &act, NULL) == -1) {
		xlog_strerror(LOG_ERR, errno, "sigaction");
	}

	if (bgworker("df", &bg_df, fs_config.df_interval) == 0)
		wait_for_workers++;

	if (workers < 1)
		workers = 1;
	for (n = 0; n < workers; n++)
		if (worker(lsock) == 0)
			wait_for_workers++;

	if (fs_config.scrubber_interval) {
		if (bgworker("scrubber", &scrub,
		    fs_config.scrubber_interval) == 0)
			wait_for_workers++;
	}

	if (fs_config.purger_interval) {
		if (bgworker("purge", &bg_purge,
		    fs_config.purger_interval) == 0)
			wait_for_workers++;
	}

	if (bgworkers < 0)
		bgworkers = 0;
	for (n = 0; n < bgworkers; n++) {
		if (bgworker("flush", &bg_flush, 5) == 0)
			wait_for_workers++;
	}

	setproctitle("mgr");
	uuid_unparse(instance_id, u);
	xlog(LOG_NOTICE, NULL, "mgr ready; initialized instance %s (version %s)", u,
	    VERSION);

	for (n = 0; n < wait_for_workers; ) {
		if (wait(NULL) == -1) {
			if (errno == EINTR)
				continue;
			warn("wait");
		}
		n++;
	}

	if (fs_info_read(&fs_info, xerrz(&e)) == -1) {
		xlog(LOG_CRIT, &e, "%s", __func__);
		_exit(1);
	} else {
		if (fs_info.error == 0)
			fs_info.clean = 1;

		if (fs_info_write(&fs_info, &e) == -1) {
			xlog(LOG_ERR, &e, "%s", __func__);
			_exit(1);
		}
	}
	CLOSE_X(pid_fd);

	xlog(LOG_INFO, NULL, "exiting");
	_exit(0);
}
