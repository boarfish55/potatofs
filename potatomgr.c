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
#include "mgr.h"
#include "slabs.h"

int   debug_level = 0;
char *mgr_exec = MGR_DEFAULT_BACKEND_EXEC;
char *data_path = FS_DEFAULT_DATA_PATH;

static void
usage()
{
	fprintf(stderr, "Usage: " MGR_PROGNAME
	    " [-fhv] [-d level] [-c config] [-p pidfile] [-s socket path]\n");
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

		chdir(data_path);

		if (execv(mgr_exec, argv) == -1) {
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
		// TODO: send error before returning
		return -1;

	if (m->oflags & OSLAB_SYNC)
		fd_flags |= O_SYNC;

	// TODO: Check freshness (if exists), download and verify checksum

	if (m->oflags & OSLAB_NOCREATE) {
		if ((fd = open(path, fd_flags, 0600)) == -1) {
			if (errno == ENOENT)
				exlog_errf(e, EXLOG_APP, EXLOG_ENOENT,
				    "%s: no such slab", __func__);
			else
				exlog_errf(e, EXLOG_OS, errno, "%s: failed "
				    "to load slab %s", __func__, path);
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
		exit(1);
	}
	close(fd);
	return 0;
fail:
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
worker(int lsock)
{
	int              fd;
	struct mgr_msg   m;
	struct exlog_err e = EXLOG_ERR_INITIALIZER;
	int              c;
	struct timeval   tv = {5, 0};

	for (;;) {
		if ((c = accept(lsock, NULL, 0)) == -1) {
			if (errno != EINTR)
				exlog_lerrno(LOG_ERR, errno,
				    "%s: accept", __func__);
			continue;
		}

		if (setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv,
		    sizeof(tv)) == -1) {
			exlog_lerr(LOG_ERR, &e, "%s", __func__);
			continue;
		}

		if (mgr_recv(c, &fd, &m, &e) == -1) {
			if (exlog_err_is(&e, EXLOG_OS, EAGAIN))
				exlog(LOG_NOTICE,
				    "read timeout on client socket %d", c);
			else
				exlog_lerr(LOG_ERR, &e, "%s", __func__);
		}

		switch (m.m) {
		case MGR_MSG_CLAIM:
			if (claim(c, &m, &e) == -1)
				exlog_lerr(LOG_ERR, &e, "%s", __func__);
			break;
		case MGR_MSG_DISOWN:
			if (disown(c, &m, fd, &e) == -1)
				exlog_lerr(LOG_ERR, &e, "%s", __func__);
			break;
		case MGR_MSG_FS_USAGE:
			if (df(c, &m, &e) == -1)
				exlog_lerr(LOG_ERR, &e, "%s", __func__);
			break;
		default:
			exlog(LOG_ERR, "%s: wrong message %d", __func__, m.m);
		}
	}
}

void
bgtasks()
{
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
}

int
main(int argc, char **argv)
{
	char                opt;
	struct              sigaction act, oact;
	char               *config_path = MGR_DEFAULT_CONFIG_PATH;
	char               *pidfile_path = MGR_DEFAULT_PIDFILE_PATH;
	int                 foreground = 0;
	FILE               *pid_f;
        struct passwd      *pw;
        struct group       *gr;
	char               *unpriv_user = MGR_DEFAULT_UNPRIV_USER;
	char               *unpriv_group = MGR_DEFAULT_UNPRIV_GROUP;
	char               *sock_path = MGR_DEFAULT_SOCKET_PATH;
	int                 lsock;
	struct sockaddr_un  saddr;
	int                 workers = 12, n;

	while ((opt = getopt(argc, argv, "hvkc:d:p:e:")) != -1) {
		switch (opt) {
			case 'h':
				usage();
				exit(0);
			case 'v':
				printf(MGR_PROGNAME " version " VERSION "\n");
				exit(0);
			case 'd':
				debug_level = atoi(optarg);
				break;
			case 'D':
				if ((data_path = strdup(optarg)) == NULL)
					err(1, "strdup");
				break;
			case 'n':
				workers = atoi(optarg);
				break;
			case 'e':
				if ((mgr_exec = strdup(optarg)) == NULL)
					err(1, "strdup");
				break;
			case 'f':
				foreground = 1;
				break;
			case 'c':
				if ((config_path = strdup(optarg)) == NULL)
					err(1, "strdup");
				break;
			case 'p':
				if ((pidfile_path = strdup(optarg)) == NULL)
					err(1, "strdup");
				break;
			case 's':
				if ((sock_path = strdup(optarg)) == NULL)
					err(1, "strdup");
				break;
			default:
				usage();
				exit(1);
		}
	}

	act.sa_handler = &handle_sig;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	if (sigaction(SIGINT, &act, &oact) == -1
			|| sigaction(SIGPIPE, &act, &oact) == -1
			|| sigaction(SIGTERM, &act, &oact) == -1) {
		err(1, "sigaction");
	}

	if (!foreground && daemon(0, 0) == -1)
		err(1, "daemon");

	openlog(MGR_PROGNAME, LOG_PID, LOG_DAEMON);

        if ((pid_f = fopen(pidfile_path, "w")) == NULL) {
		syslog(LOG_ERR, "fopen: %m");
		exit(1);
        }
        if (fprintf(pid_f, "%d\n", getpid()) == -1) {
                syslog(LOG_ERR, "fprintf: %m");
                exit(1);
        }
        fclose(pid_f);

	if (geteuid() == 0) {
		// TODO: not err, syslog ...
		if ((pw = getpwnam(unpriv_user)) == NULL)
			err(1, "User %s not found in users database",
			    unpriv_user);
		if (setuid(pw->pw_uid) == -1)
			err(1, "setuid");
		if (seteuid(pw->pw_uid) == -1)
			err(1, "seteuid");

		if ((gr = getgrnam(unpriv_group)) == NULL)
			err(1, "Group %s not found in group database",
			    unpriv_group);
		if (setgid(gr->gr_gid) == -1)
			err(1, "setgid");
		if (setegid(gr->gr_gid) == -1)
			err(1, "setegid");
	}

	if (access(data_path, R_OK|X_OK) == -1)
		err(1, "access");
	if (access(mgr_exec, X_OK) == -1)
		err(1, "access");

	// TODO: create BG processes for scanning slabs for upload.

	if ((lsock = socket(AF_LOCAL, SOCK_STREAM, 0)) == -1)
		err(1, "socket");
	unlink(sock_path);

	bzero(&saddr, sizeof(saddr));
	saddr.sun_family = AF_LOCAL;
	strncpy(saddr.sun_path, sock_path, sizeof(saddr.sun_path) - 1);

	if (bind(lsock, (struct sockaddr *)&saddr, SUN_LEN(&saddr)) == -1)
		err(1, "bind");

	if (listen(lsock, 64) == -1)
		err(1, "listen");

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

	return 0;
}
