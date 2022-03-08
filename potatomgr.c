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
#include <uuid/uuid.h>
#include <zlib.h>
#include "config.h"
#include "fs_info.h"
#include "mgr.h"
#include "slabdb.h"
#include "slabs.h"

struct mgr_counters {
	sem_t    sem;
	uint64_t c[COUNTER_LAST];
	uint64_t mgr_c[MGR_COUNTER_LAST];
};

struct fs_usage {
	struct statvfs stv;
	fsblkcnt_t     used_blocks;
};

char                *dbg_spec = NULL;
struct timeval       socket_timeout = {60, 0};
extern char        **environ;
uuid_t               instance_id;
struct mgr_counters *mgr_counters;
int                  shutdown_requested = 0;
const uint32_t       flock_timeout = 10;

static void
usage()
{
	fprintf(stderr, "Usage: " MGR_PROGNAME " [options]\n");
	fprintf(stderr,
	    "\t-h\t\tPrints this help\n"
	    "\t-v\t\tPrints version\n"
	    "\t-d <spec>\tDebug specification\n"
	    "\t-w <workers>\tHow many workers to spawn\n"
	    "\t-W <workers>\tHow many background workers to spawn\n"
	    "\t-f\t\tRun in the foreground, do not fork\n"
	    "\t-c <path>\tPath to configuration\n"
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

	// TODO: We'll need to inform the fs that we ran into an error.
	//       Eventually the fs will provide a way for us to send it
	//       messages directly.
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

	mgr_counters->mgr_c[c] += v;

	if (sem_post(&mgr_counters->sem) == -1)
		exlog_strerror(LOG_ERR, errno, "sem_wait");
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

	for (i = 0; i < COUNTER_LAST; i++)
		m->v.rcv_counters.c[i] = mgr_counters->c[i];

	for (i = 0; i < MGR_COUNTER_LAST; i++)
		m->v.rcv_counters.mgr_c[i] = mgr_counters->mgr_c[i];

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
			exlog(LOG_ERR, NULL, "%s: child %d stalled; "
			    "killing it now", __func__, pid);
			kill(pid, 9);
			close(p_out[0]);
			close(p_err[0]);
			stdout[stdout_r] = '\0';
			stderr[stderr_r] = '\0';
			// TODO: nanosleep, loop a few times ...
			// Then we should probably have something in the
			// worker loop to do waitpid(-1 ...) to clean up
			// zombies.
			sleep(2);
			if (waitpid(pid, wstatus, WNOHANG) == -1)
				exlog_strerror(LOG_ERR, errno,
				    "%s: waitpid", __func__);
			return exlog_errf(e, EXLOG_APP, EXLOG_EXEC,
			    "%s: command timed out after %d seconds; aborting",
			    __func__, BACKEND_TIMEOUT_SECONDS);
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
	struct slab_hdr dst_hdr;
	ssize_t         r;

	if (slab_path(name, sizeof(name), sk, 1, e) == -1)
		return -1;

	if (snprintf(dst, sizeof(dst), "%s/%s/%s", fs_config.data_dir,
	    OUTGOING_DIR, name) >= sizeof(dst))
		return exlog_errf(e, EXLOG_APP, EXLOG_NAMETOOLONG,
		    "%s: outq slab name too long", __func__);

	if ((dst_fd = open_wflock(dst, O_CREAT|O_RDWR, 0600,
	    LOCK_EX, flock_timeout)) == -1) {
		if (errno == EWOULDBLOCK)
			return exlog_errf(e, EXLOG_MGR, EXLOG_BUSY,
			    "%s: open_wflock() timed out after multiple "
			    "retries for slab %s; this should not happen "
			    "unless something is stuck trying to send to the "
			    "backend.", __func__, dst);
		return exlog_errf(e, EXLOG_OS, errno,
		    "%s: open_wflock() for slab %s", __func__, dst);
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
				exlog(LOG_ERR, NULL, "%s: ran out of space "
				    "while copying slab %s; retrying",
				    __func__, dst);
				sleep(5);
				goto copy_again;
			}
			exlog_errf(e, EXLOG_OS, errno, "%s: write", __func__);
			goto fail;
		}
	}

	uuid_copy(dst_hdr.v.f.last_owner, instance_id);
	dst_hdr.v.f.revision++;
	dst_hdr.v.f.flags &= ~SLAB_DIRTY;

	if (pwrite_x(dst_fd, &dst_hdr, sizeof(dst_hdr), 0) < sizeof(dst_hdr)) {
		exlog_errf(e, EXLOG_OS, errno,
		    "%s: short write on slab header", __func__);
		goto fail;
	}
	memcpy(hdr, &dst_hdr, sizeof(dst_hdr));
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
	struct slab_hdr   hdr;
	char              src[PATH_MAX];
	int               purge = 0;
	struct statvfs    stv;
	struct slabdb_val v;

	if (slab_key_valid(&m->v.unclaim.key, e) == -1)
		goto fail;

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
		if (copy_outgoing_slab(fd, &m->v.unclaim.key, &hdr, e) == -1) {
			if (exlog_err_is(e, EXLOG_MGR, EXLOG_BUSY)) {
				exlog(LOG_NOTICE, e, "%s: slab "
				    "(ino=%lu / base=%lu) is "
				    "being locked for a long time; is the "
				    "backend responsive? Continuing anyway "
				    "without sending to outgoing; "
				    "the scrubber will pick it up later",
				    __func__, m->v.unclaim.key.ino,
				    m->v.unclaim.key.base);
				exlog_zerr(e);
				goto end;
			} else
				goto fail;
		}

		if (pwrite_x(fd, &hdr, sizeof(hdr), 0) < sizeof(hdr)) {
			exlog_errf(e, EXLOG_OS, errno,
			    "%s: short write on slab header", __func__);
			goto fail;
		}
	}

	v.revision = hdr.v.f.revision;
	v.header_crc = crc32_z(0L, (Bytef *)&hdr, sizeof(hdr));
	if (purge)
		uuid_clear(v.owner);
	else
		uuid_copy(v.owner, instance_id);

	if (slabdb_put(&m->v.unclaim.key, &v,
	    SLABDB_PUT_REVISION|SLABDB_PUT_HEADER_CRC|SLABDB_PUT_OWNER,
	    e) == -1) {
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
		} else {
			exlog(LOG_INFO, NULL, "%s: purged slab %s "
			    "(revision=%lu, crc=%u)",
			    __func__, src, hdr.v.f.revision, v.header_crc);
			mgr_counter_add(MGR_COUNTER_SLABS_PURGED, 1);
		}
	}

end:
	close(fd);

	m->m = MGR_MSG_UNCLAIM_OK;
	return mgr_send(c, -1, m, e);
fail:
	exlog(LOG_ERR, e, "%s");
	exlog_zerr(e);
	m->m = MGR_MSG_UNCLAIM_ERR;
	close(fd);
	return mgr_send(c, -1, m, e);
}

static int
backend_get(const char *local_path, const char *backend_path,
    size_t *in_bytes, struct slab_key *sk, struct exlog_err *e)
{
	char            *args[6];
	int              wstatus;
	char             stdout[1024], stderr[1024];
	json_t          *j = NULL, *o;
	json_error_t     jerr;
	char             str_ino[21];
	char             str_base[21];

	snprintf(str_ino, sizeof(str_ino), "%020lu", sk->ino);
	snprintf(str_base, sizeof(str_base), "%020lu", sk->base);

	args[0] = "get";
	args[1] = (char *)backend_path;
	args[2] = (char *)local_path;
	args[3] = str_ino;
	args[4] = str_base;
	args[5] = NULL;

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

	if (json_object_clear(j) == -1)
		exlog(LOG_ERR, NULL, "%s: failed to clear JSON", __func__);

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
		exlog_errf(e, EXLOG_APP, EXLOG_EXEC,
		    "%s: \"status\" missing from JSON", __func__);
		goto fail;
	}

	if (strcmp(json_string_value(o), "OK") != 0) {
		if ((o = json_object_get(j, "msg")) == NULL) {
			return exlog_errf(e, EXLOG_APP, EXLOG_EXEC,
			    "%s: \"msg\" missing from JSON", __func__);
		}
		exlog_errf(e, EXLOG_APP, EXLOG_EXEC,
		    "%s: \"put\" failed: %s", __func__, json_string_value(o));
		goto fail;
	}

	if (WEXITSTATUS(wstatus) == 1)
		return exlog_errf(e, EXLOG_APP, EXLOG_EXEC,
		    "%s: \"put\" exit 1; no message available", __func__);

	if ((o = json_object_get(j, "out_bytes")) == NULL) {
		exlog_errf(e, EXLOG_APP, EXLOG_EXEC,
		    "%s: \"in_bytes\" missing from JSON", __func__);
		goto fail;
	}

	*out_bytes = json_integer_value(o);

	if (json_object_clear(j) == -1)
		exlog(LOG_ERR, NULL, "%s: failed to clear JSON", __func__);

	return 0;
fail:
	if (json_object_clear(j) == -1)
		exlog(LOG_ERR, NULL, "%s: failed to clear JSON", __func__);
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
    struct exlog_err *e)
{
	uint32_t crc;

	if (hdr->v.f.revision != rev) {
		/*
		 * backend doesn't have correct (latest?) version
		 * of slab. Are we dealing with eventual consistency?
		 */
		exlog_errf(e, EXLOG_APP, EXLOG_INVAL,
		    "%s: mismatching slab revision: "
		    "expected=%lu, slab=%lu", __func__,
		    rev, hdr->v.f.revision);
	}

	if ((crc = crc32_z(0L, (Bytef *)hdr,
	    sizeof(struct slab_hdr))) != header_crc) {
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
	char            u[37];

	if (lseek(src_fd, 0, SEEK_SET) == -1)
		return exlog_errf(e, EXLOG_OS, errno,
		    "%s: lseek src_fd", __func__);

	if ((r = read_x(src_fd, &hdr, sizeof(hdr))) < sizeof(hdr)) {
		if (r == -1)
			return exlog_errf(e, EXLOG_OS, errno,
			    "%s: short read on slab header", __func__);
		else
			return exlog_errf(e, EXLOG_MGR, EXLOG_SHORTIO,
			    "%s: short read on slab header", __func__);
	}

	// TODO: eventually this should compare against all possible valid
	//       instances.
	if (uuid_compare(hdr.v.f.last_owner, instance_id) != 0) {
		uuid_unparse(hdr.v.f.last_owner, u);
		return exlog_errf(e, EXLOG_APP, EXLOG_INVAL,
		    "%s: unknown slab owner %s; do we have a rogue instance "
		    "writing slabs to our backend?", u);
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

	if ((crc = crc32_z(0L, (Bytef *)&hdr, sizeof(hdr))) != header_crc)
		return exlog_errf(e, EXLOG_APP, EXLOG_INVAL,
		    "%s: mismatching header CRC: "
		    "expected=%u, slab=%u", __func__, header_crc, crc);

write_hdr_again:
	if (pwrite_x(dst_fd, &hdr, sizeof(hdr), 0) == -1) {
		if (errno == ENOSPC) {
			exlog(LOG_ERR, NULL, "%s: ran out of space during; "
			    "retrying", __func__);
			sleep(5);
			goto write_hdr_again;
		}
		return exlog_errf(e, EXLOG_OS, errno, "%s: write", __func__);
	}

copy_again:
	if (lseek(src_fd, sizeof(struct slab_hdr), SEEK_SET) == -1)
		return exlog_errf(e, EXLOG_OS, errno,
		    "%s: lseek src_fd", __func__);
	if (lseek(dst_fd, sizeof(struct slab_hdr), SEEK_SET) == -1)
		return exlog_errf(e, EXLOG_OS, errno,
		    "%s: lseek dst_fd", __func__);
	crc = crc32_z(0L, Z_NULL, 0);
	while ((r = read_x(src_fd, buf, sizeof(buf)))) {
		if (r == -1)
			return exlog_errf(e, EXLOG_OS, errno,
			    "%s: read", __func__);

		crc = crc32_z(crc, (Bytef *)buf, r);

		if (write_x(dst_fd, buf, r) == -1) {
			if (errno == ENOSPC) {
				exlog(LOG_ERR, NULL, "%s: ran out of space "
				    "while copying slab with key "
				    "ino=%lu / base=%lu; retrying",
				    __func__, hdr.v.f.key.ino,
				    hdr.v.f.key.base);
				sleep(5);
				goto copy_again;
			}
			return exlog_errf(e, EXLOG_OS, errno,
			    "%s: write", __func__);
		}
	}

	if (hdr.v.f.checksum != crc) {
		/*
		 * slab content doesn't match our checksum. Maybe
		 * the data was corrupted on the backend?
		 */
		return exlog_errf(e, EXLOG_APP, EXLOG_INVAL,
		    "%s: mismatching slab content checksum: "
		    "expected=%u, slab=%u", __func__,
		    hdr.v.f.checksum, crc);
	}

	return 0;
}

static int
claim(int c, struct mgr_msg *m, struct exlog_err *e)
{
	char              name[NAME_MAX + 1];
	char              in_path[PATH_MAX], out_path[PATH_MAX], dst[PATH_MAX];
	int               fd_flags = O_RDWR|O_CREAT;
	int               dst_fd, incoming_fd, outgoing_fd;
	size_t            in_bytes;
	struct slab_hdr   hdr;
	struct stat       st;
	struct statvfs    stv;
	struct slabdb_val v;
	struct fs_info    fs_info;

	do {
		if (statvfs(fs_config.data_dir, &stv) == -1) {
			exlog_errf(e, EXLOG_OS, errno, "%s: statvfs",
			    __func__);
			goto fail;
		}

		if (stv.f_bfree < stv.f_blocks *
		    (100 - fs_config.unclaim_purge_threshold_pct) / 100) {
			/*
			 * We are tight on space, we should avoid filling the
			 * partition to prevent the slabdb from breaking.
			 */
			exlog(LOG_WARNING, NULL, "%s: free space is below "
			    "%lu%%, blocking on claim() for 3 seconds",
			    __func__, fs_config.unclaim_purge_threshold_pct);
			sleep(5);
			continue;
		}
	} while(0);

	if (slab_key_valid(&m->v.claim.key, e) == -1) {
		exlog(LOG_ERR, e, "%s", __func__);
		exlog_zerr(e);
		exlog_errf(e, EXLOG_APP, EXLOG_INVAL,
		    "%s: aborting", __func__);
		goto fail;
	}

	/*
	 * Check existence in DB, if owned by another instance, otherwise
	 * a new entry will be allocated and returned.
	 */
	if (slabdb_get(&m->v.claim.key, &v, m->v.claim.oflags, e) == -1) {
		if (m->v.claim.oflags & OSLAB_NOCREATE &&
		    exlog_err_is(e, EXLOG_APP, EXLOG_NOENT)) {
			m->m = MGR_MSG_CLAIM_NOENT;
			if (mgr_send(c, -1, m, exlog_zerr(e)) == -1) {
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
	if (uuid_compare(v.owner, instance_id) != 0) {
		exlog_errf(e, EXLOG_MGR, EXLOG_INVAL,
		    "%s: consensus for ownership not implemented", __func__);
		goto fail;
	}

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
	if ((dst_fd = open_wflock(dst, fd_flags, 0600,
	    LOCK_EX, flock_timeout)) == -1) {
		if (errno == EWOULDBLOCK)
			exlog_errf(e, EXLOG_MGR, EXLOG_BUSY,
			    "%s: open_wflock() timed out after multiple "
			    "retries for slab %s; this should not happen if "
			    "the fs process is properly managing open slabs. "
			    "Unless someone is attempting to claim this slab "
			    "from another process?", __func__, dst);
		else
			exlog_errf(e, EXLOG_OS, errno,
			    "%s: open_wflock() for slab %s", __func__, dst);
		goto fail;
	}

	if (v.revision == 0) {
		if (fs_info_read(&fs_info, e) == -1)
			goto fail;

		if (fs_info.stats.f_bfree < fs_info.stats.f_blocks / 100) {
			exlog_errf(e, EXLOG_APP, EXLOG_NOSPC,
			    "%s: backend is at 99%% capacity", __func__);
			goto fail;
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
		memcpy(&hdr.v.f.key, &m->v.claim.key, sizeof(struct slab_key));
		hdr.v.f.flags = SLAB_DIRTY;
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

	if (st.st_size >= sizeof(hdr) &&
	    pread_x(dst_fd, &hdr, sizeof(hdr), 0) == sizeof(hdr)) {
		/*
		 * This is the most common case, where a slab was previously
		 * claimed and is still present in our local disk cache.
		 * The header CRC/revision check may be superfluous, but
		 * until we are confident we can remove it, we will keep it
		 * as an extra sanity check.
		 */
		if (check_slab_header(&hdr, v.header_crc, v.revision, e) == 0) {
			goto end;

		/*
		 * Wrong rev/header_crc is fine, just proceed
		 * with retrieving.
		 */
		} else if (!exlog_err_is(e, EXLOG_APP, EXLOG_INVAL))
			goto fail_close_dst;

		/*
		 * Still log it though, since this means we're dealing with a
		 * previous fs crash.
		 */
		exlog(LOG_CRIT, e,
		    "%s: possibly dealing with a past fs crash", __func__);
		exlog_zerr(e);
		goto end;
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
	if ((outgoing_fd = open_wflock(out_path, O_RDONLY, 0,
	    LOCK_SH, flock_timeout)) != -1) {
		if (copy_incoming_slab(dst_fd, outgoing_fd, v.header_crc,
		    v.revision, e) == 0) {
			close(outgoing_fd);
			goto end;
		}
		exlog(LOG_WARNING, e, "%s: fetching slab %s from backend even "
		    "though it was found in outgoing", __func__, name);
		exlog_zerr(e);
	}
	close(outgoing_fd);

	/*
	 * At this point we need to pull it from the backend.
	 */
	if (snprintf(in_path, sizeof(in_path), "%s/%s/%s",
	    fs_config.data_dir, INCOMING_DIR, name) >= sizeof(in_path)) {
		exlog_errf(e, EXLOG_APP, EXLOG_NAMETOOLONG,
		    "%s: inq slab name too long", __func__);
		goto fail_close_dst;
	}

get_again:
	if (backend_get(in_path, name, &in_bytes, &m->v.claim.key, e) == -1) {
		if (exlog_err_is(e, EXLOG_APP, EXLOG_NOENT)) {
			/*
			 * Maybe the backend isn't up-to-date? Eventual
			 * consistentcy? Or the backend actually lost data.
			 */
			exlog_zerr(e);
			exlog(LOG_ERR, NULL, "%s: slab %s expected on backend, "
			    "but backend_get() claims is doesn't exist; "
			    "retrying", __func__, name);
			sleep(5);
			goto get_again;
		} else if (exlog_err_is(e, EXLOG_APP, EXLOG_EXEC)) {
			exlog(LOG_ERR, e, "%s: backend script failed, "
			    "will retry; reason: %s", __func__);
			exlog_zerr(e);
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

	/*
	 * We don't normally need a lock on the incoming slab, but in case
	 * we want to scrub them at some point, it's probably a good idea.
	 */
	if ((incoming_fd = open_wflock(in_path, O_RDONLY, 0,
	    LOCK_SH, flock_timeout)) == -1) {
		exlog_strerror(LOG_ERR, errno, "%s: failed to open_wflock "
		    "after successful backend_get of %s", __func__, in_path);
		goto fail_close_dst;
	}
	if (copy_incoming_slab(dst_fd, incoming_fd, v.header_crc,
	    v.revision, e) == -1) {
		close(incoming_fd);
		if (exlog_err_is(e, EXLOG_APP, EXLOG_INVAL)) {
			exlog(LOG_ERR, e, "%s: retrying; ", __func__);
			exlog_zerr(e);
			sleep(5);
			goto get_again;
		}
		goto fail_close_dst;
	}

	unlink(in_path);
	close(incoming_fd);

end:
	if (!(m->v.claim.oflags & OSLAB_EPHEMERAL)) {
		/*
		 * We don't update last_claimed for "ephemeral" slabs,
		 * since we don't mind if they get purged shortly after.
		 */
		if (clock_gettime(CLOCK_REALTIME, &v.last_claimed) == -1) {
			exlog_strerror(LOG_ERR, errno, "%s: clock_gettime",
			    __func__);
			goto fail_close_dst;
		}
	}
	uuid_copy(v.owner, instance_id);
	if (slabdb_put(&m->v.claim.key, &v, SLABDB_PUT_ALL, e) == -1)
		goto fail_close_dst;

	m->m = MGR_MSG_CLAIM_OK;
	if (mgr_send(c, dst_fd, m, e) == -1) {
		exlog(LOG_ERR, e, "%s", __func__);
		close(dst_fd);
		return -1;
	}
	close(dst_fd);
	return 0;

fail_close_dst:
	unlink(dst);
	close(dst_fd);
fail:
	if (exlog_fail(e)) {
		exlog_prepend(e, __func__);
		m->err = e->err;
		exlog(LOG_ERR, e, "%s", __func__);
		exlog_zerr(e);
	}
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
	off_t          base;
	struct mgr_msg claim_msg;

	base = m->v.claim_next_itbl.base;

	if (slabdb_get_next_itbl(&base, exlog_zerr(e)) == -1) {
		if (exlog_err_is(e, EXLOG_APP, EXLOG_NOENT)) {
			m->m = MGR_MSG_CLAIM_NEXT_ITBL_END;
			if (mgr_send(c, -1, m, exlog_zerr(e)) == -1)
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

	return claim(c, &claim_msg, e);
fail:
	m->m = MGR_MSG_CLAIM_NEXT_ITBL_ERR;
	mgr_send(c, -1, m, exlog_zerr(e));
	return -1;
}

static int
do_shutdown(int c, struct mgr_msg *m, struct exlog_err *e)
{
	pid_t p;

	if ((p = getppid()) > 1) {
		if (kill(p, 15) == -1) {
			exlog_strerror(LOG_ERR, errno, "%s: kill", __func__);
			m->m = MGR_MSG_SHUTDOWN_ERR;
		} else {
			m->m = MGR_MSG_SHUTDOWN_OK;
		}
	} else {
		m->m = MGR_MSG_SHUTDOWN_ERR;
	}

	if (mgr_send(c, -1, m, e) == -1)
		return -1;
	return 0;
}

static int
info(int c, struct mgr_msg *m, struct exlog_err *e)
{
	pid_t mgr_pid;
	if (fs_info_read(&m->v.info.fs_info, e) == -1) {
		exlog(LOG_ERR, e, "%s", __func__);
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
	ssize_t           count;

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
		exlog(LOG_ERR, NULL, "%s: failed but will retry; "
		    "JSON was invalid: %s", __func__, jerr.text);
		return;
	}

	if ((o = json_object_get(j, "total_bytes")) == NULL) {
		exlog(LOG_ERR, NULL, "%s: \"total_bytes\" missing from JSON",
		    __func__);
		goto clear;
	}
	bytes_total = json_integer_value(o);

	if ((o = json_object_get(j, "used_bytes")) == NULL) {
		exlog(LOG_ERR, NULL, "%s: \"used_bytes\" missing from JSON",
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
		exlog(LOG_ERR, &e, "%s", __func__);
		goto clear;
	}
	fs_info.stats.f_ffree = fs_info.stats.f_files -
	    (count * slab_inode_max());
	fs_info.stats.f_favail = fs_info.stats.f_ffree;

	if (clock_gettime(CLOCK_REALTIME, &fs_info.stats_last_update) == -1) {
		exlog_strerror(LOG_ERR, errno, "%s: clock_gettime", __func__);
		goto clear;
	}

	if (fs_info_write(&fs_info, &e) == -1)
		exlog(LOG_ERR, &e, "%s", __func__);
clear:
	if (json_object_clear(j) == -1)
		exlog(LOG_ERR, NULL, "%s: failed to clear JSON", __func__);
}

static void
bgworker(const char *name, void(*fn)(), int interval_secs, int run_at_exit)
{
	char             title[32];
	struct timespec  tp = {interval_secs, 0};
	pid_t            pid;
	struct exlog_err e = EXLOG_ERR_INITIALIZER;

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

	if (slabdb_init(instance_id, &e) == -1) {
                exlog(LOG_ERR, &e, "%s", __func__);
		exit(1);
	}

	while (!shutdown_requested) {
		fn();
		nanosleep(&tp, NULL);
	}
	exlog(LOG_INFO, NULL, "performing last run before exiting");
	if (run_at_exit)
		fn();
	exlog(LOG_INFO, NULL, "exiting");
	slabdb_shutdown();
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

		/*
		 * Has to be exclusive since we may be running multiple
		 * flush workers.
		 */
		if ((fd = open_wflock(path, O_RDONLY, 0,
		    LOCK_EX|LOCK_NB, 0)) == -1) {
			if (errno != EWOULDBLOCK && errno != ENOENT)
				exlog_strerror(LOG_ERR, errno, "%s: failed "
				    "to open_wflock(): %s", __func__, path);
			continue;
		}

		if (backend_put(path, basename(path), &out_bytes, &e) == -1) {
			exlog(LOG_ERR, &e, "%s: failed but will retry; "
			    "reason: ", __func__);
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

		// TODO: Maybe don't try to sync every single slab
		// if we have shutdown_requested. We don't want to hold
		// the user hostage forever. Though this should be
		// configurable. We should use the grace_period sent by
		// potatoctl.
		if (shutdown_requested)
			break;
	}
fail:
	closedir(dir);
}

static void
scrub(const char *path)
{
	struct slab_hdr   hdr;
	int               fd;
	struct slab_key   sk;
	struct slabdb_val v;
	struct exlog_err  e = EXLOG_ERR_INITIALIZER;

	if (slab_parse_path(path, &sk, &e) == -1) {
		exlog(LOG_ERR, &e, "%s", __func__);
		return;
	}

	if (slabdb_get(&sk, &v, OSLAB_NOCREATE, &e) == -1) {
		if (exlog_err_is(&e, EXLOG_APP, EXLOG_NOENT)) {
			exlog(LOG_ERR, NULL, "%s: slab %s not found in db; "
			    "unlinking", __func__, path);
			unlink(path);
			return;
		}
		exlog(LOG_ERR, &e, "%s", __func__);
		return;
	}

	if (uuid_compare(v.owner, instance_id) != 0) {
		exlog(LOG_ERR, NULL, "%s: slab %s is now locally-owned; "
		    "unlinking", __func__, path);
		unlink(path);
		return;
	}

	if ((fd = open_wflock(path, O_RDWR, 0, LOCK_EX|LOCK_NB, 0)) == -1) {
		if (errno == EWOULDBLOCK) {
			exlog(LOG_INFO, NULL, "%s: slab %s is already "
			    "flock()'d; skipping", __func__, path);
		} else {
			exlog_strerror(LOG_ERR, errno, "%s: failed "
			    "to open_wflock(): %s", __func__, path);
		}
		return;
	}

	if (read_x(fd, &hdr, sizeof(hdr)) < sizeof(hdr)) {
		exlog_strerror(LOG_ERR, errno,
		    "%s: short read on slab header for %s",
		    __func__, path);
		set_fs_error();
		goto end;
	}

	if (check_slab_header(&hdr, v.header_crc, v.revision, &e) != 0) {
		if (hdr.v.f.revision == 0) {
			exlog(LOG_ERR, NULL, "%s: slab %s has revision 0, "
			    "meaning it was never unclaimed yet did not have "
			    "a lock on it. Are we dealing with a slab from a "
			    "previous fs crash?", __func__, path);
			return;
		}
		exlog(LOG_CRIT, &e, "%s: %s", __func__, path);
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
		if (copy_outgoing_slab(fd, &sk, &hdr, &e) == -1) {
			if (exlog_err_is(&e, EXLOG_MGR, EXLOG_BUSY)) {
				exlog_zerr(&e);
				exlog(LOG_NOTICE, NULL, "%s: slab %s is "
				    "being locked for a long time; is the "
				    "backend responsive?", __func__, path);
				goto end;
			}
			exlog(LOG_ERR, &e, "%s", __func__);
			goto end;
		}

		if (pwrite_x(fd, &hdr, sizeof(hdr), 0) < sizeof(hdr)) {
			exlog_strerror(LOG_ERR, errno,
			    "%s: short write on slab header", __func__);
			set_fs_error();
			goto end;
		}

		v.revision = hdr.v.f.revision;
		v.header_crc = crc32_z(0L, (Bytef *)&hdr, sizeof(hdr));
		uuid_copy(v.owner, instance_id);
		if (slabdb_put(&sk, &v,
		    SLABDB_PUT_REVISION|SLABDB_PUT_HEADER_CRC|SLABDB_PUT_OWNER,
		    &e) == -1) {
			exlog(LOG_CRIT, &e, "%s", __func__);
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
purge(const struct slab_key *sk, const struct slabdb_val *v, void *usage)
{
	int                fd;
	struct fs_usage   *fs_usage = (struct fs_usage *)usage;
	struct stat        st;
	char               path[PATH_MAX];
	struct slab_hdr    hdr;
	struct slabdb_val  pv;
	struct exlog_err   e = EXLOG_ERR_INITIALIZER;

	if (uuid_compare(v->owner, instance_id) != 0)
		return 0;

	if (slab_path(path, sizeof(path), sk, 0, &e) == -1) {
		exlog(LOG_ERR, &e, "%s", __func__);
		return 0;
	}

	if ((fd = open_wflock(path, O_RDWR, 0,
	    LOCK_EX|LOCK_NB, 0)) == -1) {
		if (errno != EWOULDBLOCK && errno != ENOENT)
			exlog_strerror(LOG_ERR, errno, "%s: failed "
			    "to open_wflock(): %s", __func__, path);
		return 0;
	}

	if (read_x(fd, &hdr, sizeof(hdr)) < sizeof(hdr)) {
		close(fd);
		exlog_strerror(LOG_ERR, errno,
		    "%s: short read on slab header", __func__);
		set_fs_error();
		return 0;
	}

	if (hdr.v.f.flags & SLAB_DIRTY) {
		close(fd);
		return 0;
	}

	if (fstat(fd, &st) == -1) {
		close(fd);
		exlog_strerror(LOG_ERR, errno, "%s: fstat", __func__);
		set_fs_error();
		return 0;
	}

	pv.revision = v->revision;
	pv.header_crc = v->header_crc;
	uuid_clear(pv.owner);
	memcpy(&pv.last_claimed, &v->last_claimed, sizeof(struct timespec));

	if (slabdb_put_nolock(sk, &pv, &e) == -1) {
		exlog(LOG_ERR, &e, "%s", __func__);
		close(fd);
		return 0;
	}

	if (unlink(path) == -1) {
		exlog_strerror(LOG_ERR, errno, "%s", __func__);
		close(fd);
		return 0;
	} else {
		exlog(LOG_INFO, NULL, "%s: purged slab %s "
		    "(revision=%lu, crc=%u)", __func__, path,
		    v->revision, v->header_crc);
		mgr_counter_add(MGR_COUNTER_SLABS_PURGED, 1);
		fs_usage->used_blocks -= st.st_blocks;
	}

	close(fd);

	if (fs_usage->used_blocks <
	    fs_usage->stv.f_blocks * fs_config.purge_threshold_pct / 100)
		return 1;

	return 0;
}

static void
bg_purge()
{
	struct exlog_err e = EXLOG_ERR_INITIALIZER;
	struct fs_usage  fs_usage;
	struct timespec  start, end;
	time_t           delta_ns;

	if (statvfs(fs_config.data_dir, &fs_usage.stv) == -1) {
		exlog_strerror(LOG_ERR, errno, "statvfs");
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

	exlog(LOG_NOTICE, NULL, "%s: cache use is at %d%% of partition size; "
	    "purging slabs", __func__,
	    (fs_usage.stv.f_blocks - fs_usage.stv.f_bfree) * 100
	    / fs_usage.stv.f_blocks);

	if (clock_gettime(CLOCK_REALTIME, &start) == -1) {
		exlog_strerror(LOG_ERR, errno, "%s: clock_gettime");
		return;
	}
	if (slabdb_loop(&purge, &fs_usage, &e) == -1)
		exlog(LOG_ERR, &e, "%s", __func__);
	if (clock_gettime(CLOCK_REALTIME, &end) == -1) {
		exlog_strerror(LOG_ERR, errno, "%s: clock_gettime");
		return;
	}

	delta_ns = ((end.tv_sec * 1000000000) + end.tv_nsec) -
	    ((start.tv_sec * 1000000000) + start.tv_nsec);
	exlog(LOG_NOTICE, NULL, "%s: purging took %u.%09u seconds",
	    __func__, delta_ns / 1000000000, delta_ns % 1000000000);
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

	if (slabdb_init(instance_id, &e) == -1) {
                exlog(LOG_ERR, &e, "%s", __func__);
		exit(1);
	}

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

		if (fcntl(c, F_SETFD, FD_CLOEXEC) == -1) {
			exlog_strerror(LOG_ERR, errno, "fcntl");
			close(c);
			continue;
		}

		if (setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &socket_timeout,
		    sizeof(socket_timeout)) == -1) {
			exlog(LOG_ERR, &e, "%s", __func__);
			exlog_zerr(&e);
			close(c);
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
			case MGR_MSG_INFO:
				info(c, &m, &e);
				break;
			case MGR_MSG_SHUTDOWN:
				do_shutdown(c, &m, &e);
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
	slabdb_shutdown();
	exlog(LOG_INFO, NULL, "exiting");
	exit(0);
}

int
main(int argc, char **argv)
{
	char                opt;
	struct              sigaction act;
	int                 foreground = 0;
	int                 pid_fd;
	char                pid_line[32];
	struct passwd      *pw;
	struct group       *gr;
	char               *unpriv_user = MGR_DEFAULT_UNPRIV_USER;
	char               *unpriv_group = MGR_DEFAULT_UNPRIV_GROUP;
	int                 lsock;
	struct sockaddr_un  saddr;
	int                 workers = 12, n;
	int                 bgworkers = 2;
	int                 purger_interval = 30;
	int                 scrubber_interval = 3600;
	struct statvfs      stv;
	struct exlog_err    e = EXLOG_ERR_INITIALIZER;
	struct fs_info      fs_info;
	char                u[37];

	if (getenv("POTATOFS_CONFIG"))
		fs_config.cfg_path = getenv("POTATOFS_CONFIG");

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

	if ((pid_fd = open(fs_config.pidfile_path,
	    O_CREAT|O_WRONLY, 0644)) == -1) {
		exlog_strerror(LOG_ERR, errno, "open");
		exit(1);
	}
	if (fcntl(pid_fd, F_SETFD, FD_CLOEXEC) == -1) {
		exlog_strerror(LOG_ERR, errno, "fcntl");
		exit(1);
	}
	if (flock(pid_fd, LOCK_EX|LOCK_NB) == -1) {
		if (errno == EWOULDBLOCK) {
			exlog(LOG_ERR, NULL, "pid file %s is already locked; "
			    "is another instance running?",
			    fs_config.pidfile_path);
		} else {
			exlog_strerror(LOG_ERR, errno, "flock");
		}
		exit(1);
	}

	snprintf(pid_line, sizeof(pid_line), "%d\n", getpid());
	if (write(pid_fd, pid_line, strlen(pid_line)) == -1) {
		exlog_strerror(LOG_ERR, errno, "write");
		exit(1);
	}
	fsync(pid_fd);

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
		exlog_strerror(LOG_ERR, errno, "access: %s",
		    fs_config.data_dir);
		exit(1);
	}
	if (access(fs_config.mgr_exec, X_OK) == -1) {
		exlog_strerror(LOG_ERR, errno, "access: %s",
		    fs_config.mgr_exec);
		exit(1);
	}

	if (statvfs(fs_config.data_dir, &stv) == -1) {
		exlog_strerror(LOG_ERR, errno, "statvfs");
		exit(1);
	}

	exlog(LOG_INFO, NULL, "%s: cache size is %llu bytes (%lu slabs)",
	    __func__, stv.f_blocks * stv.f_frsize,
	    stv.f_blocks * stv.f_frsize /
	    (fs_config.slab_size + sizeof(struct slab_hdr)));

	if (fs_info_open(&fs_info, &e) == -1) {
		exlog(LOG_ERR, &e, "%s", __func__);
		exit(1);
	}
	if (fs_info.error) {
		exlog(LOG_ERR, NULL, "filesystem has errors; aborting startup",
		    __func__);
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

	if (fcntl(lsock, F_SETFD, FD_CLOEXEC) == -1) {
		exlog_strerror(LOG_ERR, errno, "fcntl");
		exit(1);
	}

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
		bgworker("flush", &bg_flush, 5, 1);
		workers++;
	}

	act.sa_handler = &handle_sig;
	if (sigaction(SIGINT, &act, NULL) == -1 ||
	    sigaction(SIGTERM, &act, NULL) == -1) {
		exlog_strerror(LOG_ERR, errno, "sigaction");
	}

	uuid_unparse(instance_id, u);
	exlog(LOG_NOTICE, NULL, "initialized instance %s", u);

	for (n = 0; n < workers; ) {
		if (wait(NULL) == -1) {
			if (errno == EINTR)
				continue;
			err(1, "wait");
		}
		n++;
	}

	if (fs_info_read(&fs_info, &e) == -1) {
		exlog(LOG_CRIT, &e, "%s", __func__);
		exit(1);
	} else {
		if (fs_info.error == 0)
			fs_info.clean = 1;

		if (fs_info_write(&fs_info, &e) == -1) {
			exlog(LOG_ERR, &e, "%s", __func__);
			exit(1);
		}
	}

	exlog(LOG_INFO, NULL, "exiting");
	return 0;
}
