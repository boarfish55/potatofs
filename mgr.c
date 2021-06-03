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

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include "config.h"
#include "mgr.h"

static char mgr_path[PATH_MAX];

void
mgr_init(const char *path)
{
	strlcpy(mgr_path, path, sizeof(mgr_path));
}

int
mgr_connect(struct exlog_err *e)
{
	int                 mgr;
	struct sockaddr_un  mgr_addr;
	struct timespec     tp = {1, 0};

	for (;;) {
		if ((mgr = socket(AF_LOCAL, SOCK_STREAM, 0)) == -1) {
			exlog_lerrno(LOG_ERR, errno, "%s: socket", __func__);
			goto fail;
		}

		bzero(&mgr_addr, sizeof(mgr_addr));
		mgr_addr.sun_family = AF_LOCAL;
		strlcpy(mgr_addr.sun_path, mgr_path, sizeof(mgr_addr.sun_path));

		if (connect(mgr, (struct sockaddr *)&mgr_addr, sizeof(mgr_addr)) == -1) {
			exlog_lerrno(LOG_ERR, errno, "%s: connect", __func__);
			goto fail;
		}
		return mgr;
fail:
		if (mgr != -1)
			close(mgr);
		nanosleep(&tp, NULL);
	}
	/* Never reached. */
	return -1;
}

int
mgr_recv(int mgr, int *fd, struct mgr_msg *m, struct exlog_err *e)
{
	int             r;
	struct msghdr   msg;
	struct cmsghdr *cmsg;
	union {
		struct cmsghdr hdr;
		unsigned char  buf[CMSG_SPACE(sizeof(int))];
	} cmsgbuf;
	struct iovec iov[1];

	iov[0].iov_base = m;
	iov[0].iov_len = sizeof(struct mgr_msg);

	bzero(&msg, sizeof(msg));
	msg.msg_control = &cmsgbuf.buf;
	msg.msg_controllen = sizeof(cmsgbuf.buf);
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

again:
	if ((r = recvmsg(mgr, &msg, 0)) == -1) {
		if (errno == EINTR)
			goto again;
		return exlog_errf(e, EXLOG_OS, errno, "%s: recvmsg", __func__);
	}

	if (r == 0)
		return exlog_errf(e, EXLOG_APP, EXLOG_EOF,
		    "%s: recvmsg: eof", __func__);

	if ((msg.msg_flags & MSG_TRUNC) || (msg.msg_flags & MSG_CTRUNC))
		return exlog_errf(e, EXLOG_APP, EXLOG_EINVAL,
		    "%s: recvmsg: control message truncated", __func__);

	if (fd != NULL) {
		*fd = -1;
		for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
		    cmsg = CMSG_NXTHDR(&msg, cmsg)) {
			if (cmsg->cmsg_len == CMSG_LEN(sizeof(int)) &&
			    cmsg->cmsg_level == SOL_SOCKET &&
			    cmsg->cmsg_type == SCM_RIGHTS) {
				*fd = *(int *)CMSG_DATA(cmsg);
				/* We only care about a single descriptor */
				break;
			}
		}
	}
	return 0;
}

int
mgr_send(int mgr, int fd, struct mgr_msg *m, struct exlog_err *e)
{
	struct msghdr   msg;
	struct cmsghdr *cmsg;
	struct iovec    iov[1];
	union {
		struct cmsghdr hdr;
		unsigned char  buf[CMSG_SPACE(sizeof(int))];
	} cmsgbuf;

	iov[0].iov_base = m;
	iov[0].iov_len = sizeof(struct mgr_msg);

	bzero(&msg, sizeof(msg));
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	if (fd >= 0) {
		msg.msg_control = &cmsgbuf.buf;
		msg.msg_controllen = sizeof(cmsgbuf.buf);

		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		*(int *)CMSG_DATA(cmsg) = fd;
	}

again:
	if (sendmsg(mgr, &msg, 0) == -1) {
		if (errno == EINTR)
			goto again;
		return exlog_errf(e, EXLOG_OS, errno,
		    "%s: sendmsg", __func__);
	}

	return 0;
}
