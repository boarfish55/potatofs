#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <err.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include "xlog.h"

struct oinode {
	int   fd;
	ino_t inode;
};

#define INODES_H
#include "dirinodes.h"


off_t
inode_max_inline_b()
{
	return 3800;
}

ssize_t
inode_write(struct oinode *oi, off_t offset, const void *buf, size_t count,
    struct xerr *e)
{
	ssize_t r;
	if ((r = pwrite(oi->fd, buf, count, offset)) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "pwrite");
	return r;
}

ssize_t
inode_read(struct oinode *oi, off_t offset, void *buf, size_t count,
    struct xerr *e)
{
	ssize_t r;
	if ((r = pread(oi->fd, buf, count, offset)) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "pread");
	return r;
}

off_t
inode_getsize(struct oinode *oi)
{
	return lseek(oi->fd, 0, SEEK_END);
}

int
inode_truncate(struct oinode *oi, off_t offset, struct xerr *e)
{
	int r;
	if ((r = ftruncate(oi->fd, offset)) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "ftruncate");
	return r;
}

int
inode_isdir(struct oinode *oi)
{
	return 1;
}

ino_t
inode_ino(struct oinode *oi)
{
	return oi->inode;
}

int
main(int argc, char **argv)
{
	struct oinode oi;
	struct xerr   e;

	if (argc < 2)
		errx(1, "Usage: fake_fs <file>");

	oi.fd = open(argv[1], O_CREAT|O_RDWR|O_TRUNC, 0666);
	if (oi.fd == -1)
		err(1, "open");

	oi.inode = 2;
	if (di_create(&oi, 1, xerrz(&e)) == -1) {
		xerr_print(&e);
		exit(1);
	}

	close(oi.fd);
	return 0;
}
