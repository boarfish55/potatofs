/*
 *  Copyright (C) 2020-2021 Pascal Lalonde <plalonde@overnet.ca>
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
#include "config.h"
#include "fs_info.h"
#include "mgr.h"
#include "slabs.h"

char            *dbg_spec = NULL;
struct timeval   socket_timeout = {60, 0};
extern char    **environ;

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

int
mgr_spawn(char **argv, int *wstatus, char *stdout, size_t stdout_len,
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

	switch ((pid = fork())) {
	case -1:
		return exlog_errf(e, EXLOG_OS, errno, "%s: fork", __func__);
	case 0:
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
	default:
		// TODO: need a timeout of some sort? Or let the script handle
		// itself?
		close(p_out[1]);
		close(p_err[1]);

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

			if ((poll_r = poll(fds, nfds, 10000)) == -1)
				return exlog_errf(e, EXLOG_OS, errno,
				    "%s: poll", __func__);

			if (poll_r == 0) {
				exlog(LOG_ERR, "%s: command timed out; "
				    "aborting", __func__);
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
					    "%s: file descriptor %d "
					    "error", __func__, fds[nfds].fd);
			}
		}
		stdout[stdout_r] = '\0';
		stderr[stderr_r] = '\0';
		if (waitpid(pid, wstatus, 0) == -1)
			return exlog_errf(e, EXLOG_OS, errno, "%s: waitpid",
			    __func__);
	}
	return 0;
}

static int
disown(int c, struct mgr_msg *m, int fd, struct exlog_err *e)
{
	// check dirty+age; copy to outgoing if old enough and dirty

	// Block if we already have the same slab (older rev) being
	// uploaded.

	// If a certain cache space usage is reached, unlink
	// Unlink must happen before close, while we hold the lock.

	m->m = MGR_MSG_DISOWN_OK;
	if (mgr_send(c, -1, m, e) == -1) {
		exlog_lerr(LOG_ERR, e, "%s", __func__);
		exit(1);
	}
	close(fd);
	return 0;
}

static int
claim(int c, struct mgr_msg *m, struct exlog_err *e)
{
	char path[PATH_MAX];
	int  fd_flags = O_RDWR;
	int  fd;

	if (slab_path(path, sizeof(path), m->ino, m->offset, m->flags, e) == -1)
		goto fail;

	if (m->oflags & OSLAB_SYNC)
		fd_flags |= O_SYNC;

	// TODO: Check freshness (if exists), download and verify checksum

	if (m->oflags & OSLAB_NOCREATE) {
		if ((fd = open(path, fd_flags, 0600)) == -1) {
			if (errno == ENOENT) {
				m->m = MGR_MSG_CLAIM_NOENT;
				if (mgr_send(c, fd, m, e) == -1) {
					exlog_lerr(LOG_ERR, e, "%s", __func__);
					return -1;
				}
				return 0;
			} else {
				exlog_errf(e, EXLOG_OS, errno, "%s: failed "
				    "to load slab %s", __func__, path);
			}
			goto fail;
		}
	} else {
		fd_flags |= O_CREAT;
		if ((fd = open(path, fd_flags, 0600)) == -1) {
			exlog_errf(e, EXLOG_OS, errno,
			    "%s: failed to load slab %s", __func__, path);
			goto fail;
		}
	}

	if (flock(fd, LOCK_EX) == -1) {
		exlog_errf(e, EXLOG_OS, errno,
		    "%s: failed to flock() slab %s", __func__, path);
		goto fail;
	}

	m->m = MGR_MSG_CLAIM_OK;
	if (mgr_send(c, fd, m, e) == -1) {
		exlog_lerr(LOG_ERR, e, "%s", __func__);
		return -1;
	}
	close(fd);
	return 0;
fail:
	m->m = MGR_MSG_CLAIM_ERR;
	if (mgr_send(c, fd, m, e) == -1)
		exlog_lerr(LOG_ERR, e, "%s", __func__);
	return -1;
}

static int
df(int c, struct mgr_msg *m, struct exlog_err *e)
{
	int               wstatus;
	char              stdout[1024], stderr[1024];
	json_t           *j, *o;
	json_error_t      jerr;
	char             *args[] = {"df", NULL};

	// TODO: This need to move to a bgworker, we won't
	// let potatofs wait for this command to complete.
	// This needs to be read from fs_info, so we can
	// get a LOCK_SH on it.

	if (mgr_spawn(args, &wstatus, stdout, sizeof(stdout),
	    stderr, sizeof(stderr), e) == -1) {
		exlog_lerr(LOG_ERR, e, "%s", __func__);
		m->m = MGR_MSG_FS_USAGE_ERR;
	} else
		m->m = MGR_MSG_FS_USAGE_OK;

	exlog_zerr(e);

	if ((j = json_loads(stdout, JSON_REJECT_DUPLICATES, &jerr)) == NULL) {
		exlog(LOG_ERR, "%s: %s", __func__, jerr.text);
		m->m = MGR_MSG_FS_USAGE_ERR;
	}

	if ((o = json_object_get(j, "total_bytes")) == NULL) {
		exlog(LOG_ERR, "%s: \"total_bytes\" missing from JSON",
		    __func__);
		m->m = MGR_MSG_FS_USAGE_ERR;
	}
	m->capacity = json_integer_value(o);

	if ((o = json_object_get(j, "used_bytes")) == NULL) {
		exlog(LOG_ERR, "%s: \"used_bytes\" missing from JSON",
		    __func__);
		m->m = MGR_MSG_FS_USAGE_ERR;
	}
	m->offset = json_integer_value(o);

	if (json_object_clear(j) == -1)
		exlog(LOG_ERR, "%s: failed to clear JSON", __func__);

	if (mgr_send(c, -1, m, e) == -1)
		return -1;

	return 0;
}

static void
bgworker()
{
	if (exlog_init(MGR_PROGNAME "-bgworker", dbg_spec, 0) == -1) {
		exlog(LOG_ERR, "failed to initialize logging in bgworker");
		exit(1);
	}

	setproctitle("bgworker");
	exlog(LOG_INFO, "%s: ready", __func__);

	for (;;) {
		// Refresh 'df' data
			// Lock fs_info file
			// Run command
			// Unlock fs_info
		// Scan out queue
			// for each slab in out queue:
				// open, LOCK_EX|LOCK_NB
				// Compute checksum
				// upload, unlink
				// close fd
			// for each slab in main data dir:
				// open, LOCK_EX|LOCK_NB
				// copy to out queue if old enough and dirty
					// check LOCK_EX|LOCK_NB on out queue target
				// close
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
			case MGR_MSG_FS_USAGE:
				df(c, &m, &e);
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
	off_t               cache_size = 0, cache_size_limit;

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
	 * Default to 90% partition size for the slab cache size.
	 */
	// TODO: Do something with this, we can't cache more slabs
	// locally than what's computed here.
	if (cache_size == 0 || cache_size > cache_size_limit)
		cache_size = cache_size_limit;

	exlog(LOG_INFO, "%s: cache size is %llu", __func__, cache_size);

	if (fs_info_create(&e) == -1) {
		exlog_lerr(LOG_ERR, &e, "%s", __func__);
		exit(1);
	}

	// max_open = cache_size / (fs_config.slab_size + sizeof(struct slab_hdr));

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

	return 0;
}
