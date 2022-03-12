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

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include "config.h"
#include "mgr.h"

static char mgr_sock_path[PATH_MAX];

void
mgr_init(const char *path)
{
	strlcpy(mgr_sock_path, path, sizeof(mgr_sock_path));
}

int
mgr_connect(int retry, struct xerr *e)
{
	int                 mgr;
	struct sockaddr_un  mgr_addr;
	struct timespec     tp = {1, 0};

	for (;;) {
		if ((mgr = socket(AF_LOCAL, SOCK_STREAM, 0)) == -1) {
			xlog_strerror(LOG_ERR, errno, "%s: socket", __func__);
			goto fail;
		}

		bzero(&mgr_addr, sizeof(mgr_addr));
		mgr_addr.sun_family = AF_LOCAL;
		strlcpy(mgr_addr.sun_path, mgr_sock_path,
		    sizeof(mgr_addr.sun_path));

		if (connect(mgr, (struct sockaddr *)&mgr_addr,
		    sizeof(mgr_addr)) == -1) {
			if (errno == ENOENT)
				xlog(LOG_NOTICE, NULL, "%s: no socket; "
				    "waiting for mgr to start", __func__);
			else
				xlog_strerror(LOG_ERR, errno,
				    "%s: connect", __func__);
			goto fail;
		}
		return mgr;
fail:
		if (mgr != -1)
			close(mgr);
		if (!retry)
			break;
		nanosleep(&tp, NULL);
	}
	/* Never reached. */
	return -1;
}

int
mgr_recv(int mgr, int *fd, struct mgr_msg *m, struct xerr *e)
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
		return XERRF(e, XLOG_ERRNO, errno, "recvmsg");
	}

	if (r == 0)
		return XERRF(e, XLOG_APP, XLOG_EOF, "recvmsg: eof");

	if ((msg.msg_flags & MSG_TRUNC) || (msg.msg_flags & MSG_CTRUNC))
		return XERRF(e, XLOG_APP, XLOG_INVAL,
		    "recvmsg: control message truncated");

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
mgr_send(int mgr, int fd, struct mgr_msg *m, struct xerr *e)
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
	bzero(&cmsgbuf, sizeof(cmsgbuf));
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
		return XERRF(e, XLOG_ERRNO, errno, "sendmsg");
	}

	return 0;
}
