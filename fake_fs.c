#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <err.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
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
	struct oinode    oi;
	struct xerr      e;
	struct dir_entry de;
	struct dir_entry dirs[32];
	ssize_t          r, i;
	off_t            d_off;

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

	strlcpy(de.name, "oneoneone", sizeof(de.name));
	de.inode = 111;
	de.d_off = 0;
	if (di_mkdirent(&oi, &de, 0, xerrz(&e)) == -1) {
		xerr_print(&e);
		exit(1);
	}

	strlcpy(de.name, "twotwotwo", sizeof(de.name));
	de.inode = 222;
	de.d_off = 0;
	if (di_mkdirent(&oi, &de, 0, xerrz(&e)) == -1) {
		xerr_print(&e);
		exit(1);
	}

	strlcpy(de.name, "333", sizeof(de.name));
	de.inode = 333;
	de.d_off = 0;
	if (di_mkdirent(&oi, &de, 0, xerrz(&e)) == -1) {
		xerr_print(&e);
		exit(1);
	}

	if (di_lookup(&oi, &de, "oneoneone", xerrz(&e)) == -1) {
		xerr_print(&e);
		exit(1);
	}

	if ((r = di_readdir(&oi, dirs, 0, 32, xerrz(&e))) == -1) {
		xerr_print(&e);
		exit(1);
	}
	for (i = 0; i < r; i++) {
		printf("* name=\"%s\", inode=%lu, d_off=%lu\n",
		    dirs[i].name, dirs[i].inode, dirs[i].d_off);
	}

	strlcpy(de.name, "twotwotwo", sizeof(de.name));
	de.inode = 222;
	de.d_off = 0;
	if (di_unlink(&oi, &de, xerrz(&e)) == -1) {
		xerr_print(&e);
		exit(1);
	}
	printf("*** Unlinked %s\n", de.name);

	for (d_off = 0;;) {
		if ((r = di_readdir(&oi, dirs, d_off, 1, xerrz(&e))) == -1) {
			xerr_print(&e);
			exit(1);
		}
		if (r == 0)
			break;
		for (i = 0; i < r; i++) {
			printf("* name=\"%s\", inode=%lu, d_off=%lu\n",
			    dirs[i].name, dirs[i].inode, dirs[i].d_off);
			d_off = dirs[i].d_off;
		}
	}

	close(oi.fd);
	return 0;
}
